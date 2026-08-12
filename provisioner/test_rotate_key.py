# test_rotate_key.py — what a failed rotation leaves behind
#
# rotateKey is the one route that both removes and adds a WireGuard peer, and
# the device on the other end of the tunnel exists only for as long as its peer
# does. So the question these tests ask is not "does a bad key get rejected" --
# the exit node has answered that since wg-agent learned to check its argv --
# but "what is still bound when the rejection arrives".
#
# The old order removed first. Any later failure (a key the exit node refuses,
# an exit node that does not answer, a database that will not take the update)
# therefore ended with no peer at all and a record still naming the deleted key:
# the device gone, and the two sides disagreeing about which key it had. It is
# self-inflicted -- a caller can only rotate a device it owns -- so this is a
# correctness and availability defect rather than a security one. It is still a
# device that stops working because it asked for something to be checked.
#
# Run:  python3 -m unittest discover -s provisioner -t provisioner
# Deps: fastapi + httpx (already in requirements.txt). No test framework needed.

import base64
import json
import os
import sys
import types
import unittest
import urllib.parse
from unittest import mock

import httpx

# main imports db (asyncpg at module scope) and nanoid. Neither is reachable
# from here -- the db functions are patched per test -- so stand them up rather
# than pull in a driver. setdefault, because test_auth.py installs its own stub
# and whichever module the loader imports first should win.
sys.modules.setdefault("db", types.ModuleType("db"))

try:  # the real thing in the image; a stub on a bare checkout
    import nanoid  # noqa: F401
except ModuleNotFoundError:
    _nanoid = types.ModuleType("nanoid")
    _nanoid.generate = lambda size=12: "x" * size
    sys.modules["nanoid"] = _nanoid

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402
import peer_manager  # noqa: E402

FAKE_SECRET = "FAKE-SECRET-FOR-TEST-NOT-REAL"
FAKE_AGENT_URL = "http://wg-agent.invalid:8081"
NSID = main.NSID


def _synthetic_key(label: bytes) -> str:
    """A well-formed public key that is obviously not one.

    32 bytes of ASCII padded with NULs: the right length and alphabet for
    key_from_base64(), and readable in a failure message as the fixture it is.
    """
    return base64.b64encode(label.ljust(32, b"\0")).decode()


OLD_KEY = _synthetic_key(b"vpn-test-old-key")
NEW_KEY = _synthetic_key(b"vpn-test-new-key")
MALFORMED_KEY = "not-a-wireguard-public-key"

DEVICE_ID = "dev-test-1"
CALLER_DID = "did:plc:testcaller"
ASSIGNED_IP = "10.8.0.42/32"


class RotateKeyTestCase(unittest.TestCase):
    """A device whose peer is bound, and an exit node that records what it is told."""

    def setUp(self):
        self.set_env("PROVISIONER_SECRET", FAKE_SECRET)
        self.set_env("WG_AGENT_URL", FAKE_AGENT_URL)
        self.set_env("WG_AGENT_SECRET", FAKE_SECRET)

        # What the exit node does with each request, recorded in order. A
        # rotation is a sequence of peer mutations, so the sequence is the
        # observation -- an assertion on the final state alone cannot tell
        # "never removed" from "removed and put back".
        self.calls = []
        self.connect_error_on_post = False
        self.status_for = {}

        self._saved_client = peer_manager._client
        peer_manager._client = httpx.AsyncClient(
            transport=httpx.MockTransport(self._exit_node), timeout=10.0
        )
        self.addCleanup(self._restore_client)

        self.device = {
            "device_id": DEVICE_ID,
            "device_name": "test device",
            "public_key": OLD_KEY,
            "assigned_ip": ASSIGNED_IP,
            "server_id": "srv-1",
        }
        self.updated_to = None

        self.patch_db("get_device", self._get_device)
        self.patch_db("public_key_exists", self._public_key_exists)
        self.patch_db("update_device_key", self._update_device_key)

    # ── environment / doubles ────────────────────────────────────────────────

    def set_env(self, key, value):
        saved = os.environ.get(key)
        os.environ[key] = value
        self.addCleanup(self._restore_env, key, saved)

    @staticmethod
    def _restore_env(key, saved):
        if saved is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = saved

    def patch_db(self, name, fn):
        patcher = mock.patch.object(main.db, name, fn, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _restore_client(self):
        peer_manager._client = self._saved_client

    def _exit_node(self, request: httpx.Request) -> httpx.Response:
        """Stand-in for wg-agent.

        It refuses a key that is not 44 characters of base64 ending in '=',
        which is the shape wg-agent's require_public_key() enforces before the
        value reaches a root `wg`. The full rule (canonical trailing bits, a
        re-encode round trip, the allowed-ips form) lives there and is tested
        there, in wg-agent/test_peer_argv.py; what matters here is only that a
        refusal arrives at the point in the sequence where it really would.
        """
        if request.method == "POST":
            if self.connect_error_on_post:
                raise httpx.ConnectError("exit node unreachable", request=request)
            key = json.loads(request.content)["public_key"]
            self.calls.append(("add", key))
        else:
            key = urllib.parse.unquote(request.url.path.rsplit("/", 1)[-1])
            self.calls.append(("remove", key))

        forced = self.status_for.get(request.method)
        if forced is not None:
            return httpx.Response(forced, json={"detail": "forced by test"})

        if not (len(key) == 44 and key.endswith("=")):
            return httpx.Response(
                422,
                json={"detail": "InvalidPublicKey: expected 32 bytes of standard base64"},
            )
        return httpx.Response(200, json={"ok": True})

    async def _get_device(self, did, device_id):
        if did == CALLER_DID and device_id == DEVICE_ID:
            return dict(self.device)
        return None

    async def _public_key_exists(self, public_key):
        return public_key == OLD_KEY

    async def _update_device_key(self, did, device_id, new_public_key):
        self.updated_to = new_public_key
        return True

    # ── the request under test ───────────────────────────────────────────────

    def rotate(self, new_public_key):
        # raise_server_exceptions=False so an unhandled fault becomes a 500
        # response rather than escaping the client, the way it would in the pod.
        client = TestClient(main.app, raise_server_exceptions=False)
        return client.post(
            f"/xrpc/{NSID}.rotateKey",
            json={
                "deviceId": DEVICE_ID,
                "newPublicKey": new_public_key,
                "callerDid": CALLER_DID,
            },
            headers={"x-internal-trust": FAKE_SECRET},
        )

    def assertNothingUnbound(self):
        removed = [key for kind, key in self.calls if kind == "remove"]
        self.assertEqual(
            [], removed,
            "the caller's peer was removed by a rotation that did not complete",
        )
        self.assertIsNone(
            self.updated_to, "the record was changed by a rotation that did not complete"
        )


class TestAFailedRotationLeavesTheDeviceWorking(RotateKeyTestCase):
    """Nothing may be unbound until the replacement is bound."""

    def test_malformed_key_does_not_unbind_the_existing_peer(self):
        resp = self.rotate(MALFORMED_KEY)
        self.assertNotEqual(200, resp.status_code)
        self.assertNothingUnbound()

    def test_malformed_key_is_answered_as_the_callers_error(self):
        # The exit node says 422. Before this change raise_for_status() turned
        # that into an httpx.HTTPStatusError and the caller saw a 500 -- the
        # service reporting itself broken for something the caller sent.
        resp = self.rotate(MALFORMED_KEY)
        self.assertEqual(422, resp.status_code)
        self.assertEqual("InvalidPeerArgument", resp.json()["error"])

    def test_unreachable_exit_node_does_not_unbind_the_existing_peer(self):
        # Not every failure is a bad argument, which is why validating at this
        # boundary would not have been enough on its own.
        self.connect_error_on_post = True
        resp = self.rotate(NEW_KEY)
        self.assertEqual(500, resp.status_code)
        self.assertNothingUnbound()

    def test_record_failure_restores_the_previous_peer(self):
        async def _fails(did, device_id, new_public_key):
            raise RuntimeError("database refused the update")

        self.patch_db("update_device_key", _fails)

        resp = self.rotate(NEW_KEY)
        self.assertEqual(503, resp.status_code)
        # The address moved to the new key, then back to the old one, and the
        # old peer was never removed -- so the device on the other end is still
        # the device that was working before the request.
        self.assertEqual([("add", NEW_KEY), ("add", OLD_KEY)], self.calls)


class TestASuccessfulRotationStillRotates(RotateKeyTestCase):
    """Positive controls: the safe order must not be a refusal to act."""

    def test_well_formed_key_rotates(self):
        resp = self.rotate(NEW_KEY)
        self.assertEqual(200, resp.status_code, resp.text)
        self.assertTrue(resp.json()["ok"])
        self.assertEqual(NEW_KEY, self.updated_to)

    def test_the_new_peer_is_bound_before_the_old_one_is_removed(self):
        # The ordering itself, pinned. Asserting only "the old peer was
        # eventually removed" would also pass for the order that caused this.
        self.rotate(NEW_KEY)
        self.assertEqual([("add", NEW_KEY), ("remove", OLD_KEY)], self.calls)

    def test_cleanup_failure_does_not_fail_a_completed_rotation(self):
        # By the time the old peer is removed the address has already moved, so
        # a peer left behind holds no allowed-ips and routes nothing. Failing
        # the request here would report a rotation that did in fact happen as
        # not having happened.
        self.status_for["DELETE"] = 500
        resp = self.rotate(NEW_KEY)
        self.assertEqual(200, resp.status_code, resp.text)
        self.assertEqual(NEW_KEY, self.updated_to)

    def test_the_stand_in_exit_node_accepts_a_well_formed_key(self):
        # Guards the refusal tests above from passing vacuously: if the double
        # refused everything, "nothing was unbound" would be true for the wrong
        # reason.
        self.assertEqual(
            200,
            self._exit_node(
                httpx.Request(
                    "POST",
                    f"{FAKE_AGENT_URL}/peers",
                    json={"public_key": NEW_KEY, "allowed_ip": ASSIGNED_IP},
                )
            ).status_code,
        )


class TestOnlyTheCallersErrorsAreReportedAsTheirs(RotateKeyTestCase):
    """422 is forwarded because it is about the argument. Nothing else is."""

    def test_exit_node_refusing_our_credential_is_not_the_callers_error(self):
        # A 403 from the exit node means the provisioner's own WG_AGENT_SECRET
        # was refused. Reporting that to the caller as a 422 would tell them to
        # fix a key that is fine, and would hide a misconfiguration on this side.
        self.status_for["POST"] = 403
        resp = self.rotate(NEW_KEY)
        self.assertEqual(500, resp.status_code)
        self.assertNothingUnbound()


if __name__ == "__main__":
    unittest.main()
