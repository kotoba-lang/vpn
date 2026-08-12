# test_revoke_device.py — what a failed revocation leaves behind
#
# revokeDevice destroys the two things provisionDevice creates, and the order it
# destroys them in is the mirror of the order they were made: the peer routes
# traffic, the row is the only thing that can find the peer again. So the peer
# has to stop routing while the row still names it.
#
# The old order deleted the row first, with a hard `DELETE ... RETURNING` and no
# tombstone, and then caught the unbind as `# non-fatal` and answered
# {"ok": True} anyway. Both halves are under test here, and the second is the
# one that makes the first invisible: a caller who is told their device is
# revoked has no reason to look, and there is no longer any row for them to look
# at. On a no-logs VPN that is a tunnel still carrying traffic that nothing in
# the service can name.
#
# The questions are therefore about failure, not about success: at each point
# where this request can fail, is what is left behind something the system can
# still see and still act on. Success is here only as a control -- an order that
# is safe because it refuses to do anything would pass every test above.
#
# Run:  python3 -m unittest discover -s provisioner -t provisioner
# Deps: fastapi + httpx (already in requirements.txt). No test framework needed.

import base64
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


DEVICE_KEY = _synthetic_key(b"vpn-test-device-key")
MALFORMED_KEY = "not-a-wireguard-public-key"

DEVICE_ID = "dev-test-1"
UNBOUND_DEVICE_ID = "dev-test-2"
CALLER_DID = "did:plc:testcaller"
OTHER_DID = "did:plc:someoneelse"
# The documented tunnel pool (peer_manager.allocate_ip), not a deployment.
ASSIGNED_IP = "10.8.0.42/32"


class RevokeDeviceTestCase(unittest.TestCase):
    """One device, bound, and an exit node that records what it is told."""

    def setUp(self):
        self.set_env("PROVISIONER_SECRET", FAKE_SECRET)
        self.set_env("WG_AGENT_URL", FAKE_AGENT_URL)
        self.set_env("WG_AGENT_SECRET", FAKE_SECRET)

        # One ordered log for both sides. The defect under test is which of the
        # two happens first, so they have to be recorded on the same timeline --
        # asserting on final state alone cannot tell "never unbound" from
        # "unbound after the row was already gone".
        self.events = []
        self.connect_error_on_delete = False
        self.status_for = {}
        self.delete_fails = False

        # Which key holds which address on the fake exit node.
        self.bound = {DEVICE_KEY: ASSIGNED_IP}

        # The device table, keyed by device_id. It is the only handle on a peer,
        # so the tests read it directly and through listDevices.
        self.rows = {
            DEVICE_ID: {
                "did": CALLER_DID,
                "device_id": DEVICE_ID,
                "device_name": "test device",
                "public_key": DEVICE_KEY,
                "assigned_ip": ASSIGNED_IP,
                "server_id": "srv-test-1",
                "created_at": "2026-01-01T00:00:00+00:00",
            }
        }

        self._saved_client = peer_manager._client
        peer_manager._client = httpx.AsyncClient(
            transport=httpx.MockTransport(self._exit_node), timeout=10.0
        )
        self.addCleanup(self._restore_client)

        self.patch_db("get_device", self._get_device)
        self.patch_db("delete_device", self._delete_device)
        self.patch_db("list_devices", self._list_devices)
        self.patch_db("get_subscription", self._get_subscription)

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

        Two behaviours of the real one are modelled, because the fix rests on
        them:

        * it refuses a key that is not 44 characters of base64 ending in '=',
          which is the shape require_public_key() enforces before the value
          reaches a root `wg` -- and it enforces it on a remove exactly as on an
          add (wg-agent/main.py, tested in wg-agent/test_peer_argv.py);
        * a remove of a peer that is not bound succeeds. `wg set <iface> peer
          <key> remove` parses to WGPEER_REMOVE_ME (wireguard-tools config.c),
          arrives as WGPEER_F_REMOVE_ME, and set_peer() assigns ret = 0 before
          looking the peer up, so an absent peer falls through `if (!peer) ...
          goto out` with success (drivers/net/wireguard/netlink.c). wg-agent
          never consults the peer list and answers {"ok": True} either way.
        """
        if request.method == "DELETE":
            if self.connect_error_on_delete:
                raise httpx.ConnectError("exit node unreachable", request=request)
            key = urllib.parse.unquote(request.url.path.rsplit("/", 1)[-1])
        else:
            key = "<unexpected>"

        forced = self.status_for.get(request.method)
        if forced is not None:
            # Recorded as attempted, not as done: a refused remove unbinds
            # nothing.
            self.events.append(("exit-node-refused", key))
            return httpx.Response(forced, json={"detail": "forced by test"})

        if not (len(key) == 44 and key.endswith("=")):
            self.events.append(("exit-node-refused", key))
            return httpx.Response(
                422,
                json={"detail": "InvalidPublicKey: expected 32 bytes of standard base64"},
            )

        self.bound.pop(key, None)
        self.events.append(("remove", key))
        return httpx.Response(200, json={"ok": True})

    async def _get_device(self, did, device_id):
        row = self.rows.get(device_id)
        if row is None or row["did"] != did:
            return None
        return dict(row)

    async def _delete_device(self, did, device_id):
        if self.delete_fails:
            self.events.append(("delete-refused", device_id))
            raise RuntimeError("database refused the delete")
        row = self.rows.get(device_id)
        if row is None or row["did"] != did:
            return None
        del self.rows[device_id]
        self.events.append(("delete", device_id))
        return dict(row)

    async def _list_devices(self, did):
        return [dict(r) for r in self.rows.values() if r["did"] == did]

    async def _get_subscription(self, did):
        return {"tier": "pro", "device_limit": 5, "expires_at": None}

    # ── the requests under test ──────────────────────────────────────────────

    def _client(self):
        # raise_server_exceptions=False so an unhandled fault becomes a 500
        # response rather than escaping the client, the way it would in the pod.
        return TestClient(main.app, raise_server_exceptions=False)

    def revoke(self, device_id=DEVICE_ID, caller_did=CALLER_DID):
        return self._client().post(
            f"/xrpc/{NSID}.revokeDevice",
            json={"deviceId": device_id, "callerDid": caller_did},
            headers={"x-internal-trust": FAKE_SECRET},
        )

    def listed_device_ids(self, caller_did=CALLER_DID):
        resp = self._client().post(
            f"/xrpc/{NSID}.listDevices",
            json={"callerDid": caller_did},
            headers={"x-internal-trust": FAKE_SECRET},
        )
        self.assertEqual(200, resp.status_code, resp.text)
        return [d["deviceId"] for d in resp.json()["devices"]]

    # ── the invariant ────────────────────────────────────────────────────────

    def assertNothingRoutesUnnamed(self):
        """No peer may hold an address that no record names.

        The whole defect in one assertion. A peer the database does not know
        about cannot be listed, cannot be counted against a device limit, and
        cannot be revoked -- revokeDevice finds the key by the row -- so it is a
        working tunnel with no handle on it.
        """
        named = {r["public_key"]: r["assigned_ip"] for r in self.rows.values()}
        unnamed = {k: ip for k, ip in self.bound.items() if named.get(k) != ip}
        self.assertEqual(
            {}, unnamed,
            "a peer holds a tunnel address that no device record names, so "
            "nothing in this service can see or withdraw it",
        )


class TestAFailedRevocationLeavesTheDeviceNameable(RevokeDeviceTestCase):
    """Nothing may be deleted until the peer it names is unbound."""

    def test_an_unreachable_exit_node_is_not_reported_as_a_revocation(self):
        # The half that made the other half invisible. The unbind was caught as
        # `# non-fatal` and the handler answered {"ok": True} regardless, so the
        # caller was told the device was revoked while its tunnel was up.
        self.connect_error_on_delete = True

        resp = self.revoke()

        self.assertNotEqual(
            200, resp.status_code,
            "a revocation that could not unbind the peer reported success",
        )

    def test_an_unreachable_exit_node_leaves_the_record_and_the_tunnel(self):
        # Not every failure is a bad argument, and this is the discriminating
        # one: under the old order the row was already gone by the time the
        # exit node was asked, so the peer stayed bound with nothing naming it.
        self.connect_error_on_delete = True

        self.revoke()

        self.assertEqual({DEVICE_KEY: ASSIGNED_IP}, self.bound)
        self.assertIn(DEVICE_ID, self.rows, "the record for a still-bound peer was deleted")
        self.assertEqual([DEVICE_ID], self.listed_device_ids())
        self.assertNothingRoutesUnnamed()

    def test_the_exit_node_refusing_our_credential_leaves_the_device_working(self):
        # A 403 from the exit node means the provisioner's own WG_AGENT_SECRET
        # was refused -- a fault on this side. The caller's device must survive
        # our misconfiguration rather than be forgotten by it.
        self.status_for["DELETE"] = 403

        resp = self.revoke()

        self.assertEqual(500, resp.status_code)
        self.assertEqual({DEVICE_KEY: ASSIGNED_IP}, self.bound)
        self.assertIn(DEVICE_ID, self.rows)
        self.assertNothingRoutesUnnamed()

    def test_a_failed_revocation_can_be_retried(self):
        # Recoverable means recoverable by the ordinary route, not by an
        # operator with a database prompt. Under the old order the retry got a
        # 404 -- the row was gone and the peer was not.
        self.connect_error_on_delete = True
        self.revoke()

        self.connect_error_on_delete = False
        resp = self.revoke()

        self.assertEqual(200, resp.status_code, resp.text)
        self.assertEqual({}, self.bound)
        self.assertEqual({}, self.rows)

    def test_the_peer_is_unbound_before_the_record_is_deleted(self):
        # The ordering itself, pinned. Asserting only "both happened" would
        # also pass for the order that caused this.
        self.revoke()

        self.assertEqual([("remove", DEVICE_KEY), ("delete", DEVICE_ID)], self.events)

    def test_a_record_that_cannot_be_deleted_leaves_no_bound_peer(self):
        # The residue this order chooses: a row naming a peer that is gone. It
        # routes nothing, it is visible in listDevices, and it over-counts
        # rather than under-counts -- the opposite of a peer with no row.
        self.delete_fails = True

        resp = self.revoke()

        self.assertEqual(503, resp.status_code)
        self.assertEqual({}, self.bound, "the tunnel was left up by a failed revocation")
        self.assertEqual([DEVICE_ID], self.listed_device_ids(),
                         "the residue must be something the caller can still see")

    def test_a_record_that_cannot_be_deleted_is_repaired_by_a_retry(self):
        # And the retry is safe precisely because the unbind it repeats is a
        # no-op on a peer that is already gone.
        self.delete_fails = True
        self.revoke()

        self.delete_fails = False
        resp = self.revoke()

        self.assertEqual(200, resp.status_code, resp.text)
        self.assertEqual({}, self.rows)
        self.assertEqual({}, self.bound)


class TestASuccessfulRevocationStillRevokes(RevokeDeviceTestCase):
    """Positive controls: the safe order must not be a refusal to act."""

    def test_a_device_is_revoked(self):
        resp = self.revoke()

        self.assertEqual(200, resp.status_code, resp.text)
        self.assertTrue(resp.json()["ok"])
        self.assertEqual(DEVICE_ID, resp.json()["deviceId"])
        self.assertEqual({}, self.bound)
        self.assertEqual([], self.listed_device_ids())

    def test_an_unknown_device_is_a_404_and_touches_nothing(self):
        resp = self.revoke(device_id="dev-does-not-exist")

        self.assertEqual(404, resp.status_code)
        self.assertEqual([], self.events)
        self.assertEqual({DEVICE_KEY: ASSIGNED_IP}, self.bound)

    def test_another_callers_device_cannot_be_revoked(self):
        # Ownership is still decided before anything is mutated -- it just moved
        # from the delete's RETURNING to the lookup that now precedes it.
        resp = self.revoke(caller_did=OTHER_DID)

        self.assertEqual(404, resp.status_code)
        self.assertEqual([], self.events)
        self.assertIn(DEVICE_ID, self.rows)
        self.assertEqual({DEVICE_KEY: ASSIGNED_IP}, self.bound)

    def test_revoking_a_device_whose_peer_is_already_gone_still_succeeds(self):
        # The property the whole fix rests on, stated as a test: unbinding is
        # idempotent, so putting it first costs nothing when there is nothing
        # to unbind. If this ever stops being true, the retry paths above stop
        # being recoveries.
        self.bound = {}

        resp = self.revoke()

        self.assertEqual(200, resp.status_code, resp.text)
        self.assertEqual([("remove", DEVICE_KEY), ("delete", DEVICE_ID)], self.events)
        self.assertEqual({}, self.rows)

    def test_a_key_the_exit_node_refuses_does_not_make_the_row_undeletable(self):
        # A row whose stored key wg-agent will not accept names a peer that
        # cannot exist, because the same check runs on the add. Refusing to
        # delete it would strand it forever -- and it is exactly the residue
        # provisionDevice leaves when it cannot withdraw a record, which it
        # leaves on the understanding that this route can clear it.
        self.rows[UNBOUND_DEVICE_ID] = {
            "did": CALLER_DID,
            "device_id": UNBOUND_DEVICE_ID,
            "device_name": "never bound",
            "public_key": MALFORMED_KEY,
            "assigned_ip": "10.8.0.43/32",
            "server_id": "srv-test-1",
            "created_at": "2026-01-01T00:00:00+00:00",
        }

        resp = self.revoke(device_id=UNBOUND_DEVICE_ID)

        self.assertEqual(200, resp.status_code, resp.text)
        self.assertNotIn(UNBOUND_DEVICE_ID, self.rows)
        self.assertEqual({DEVICE_KEY: ASSIGNED_IP}, self.bound,
                         "the bound device was disturbed by revoking another")

    def test_the_stand_in_exit_node_accepts_a_well_formed_key(self):
        # Guards the refusal tests above from passing vacuously: if the double
        # refused everything, "the record survived" would be true for the wrong
        # reason.
        resp = self._exit_node(
            httpx.Request(
                "DELETE",
                f"{FAKE_AGENT_URL}/peers/{urllib.parse.quote(DEVICE_KEY, safe='')}",
            )
        )
        self.assertEqual(200, resp.status_code)
        self.assertEqual({}, self.bound)


if __name__ == "__main__":
    unittest.main()
