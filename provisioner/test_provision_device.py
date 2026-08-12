# test_provision_device.py — what a failed provision leaves behind
#
# provisionDevice creates two things that must agree: a WireGuard peer on the
# exit node, and the row that names it. Only the row can be looked up. Every
# later operation on a device goes through it -- listDevices reads it,
# count_devices enforces the device limit from it, revokeDevice finds the key to
# remove by it, and the address pool itself is derived from it (peer_manager
# .allocate_ip reads db.get_assigned_ips, not the exit node).
#
# So the question is the same one rotateKey's tests ask, in its create-shaped
# form: not "is a bad key rejected" but "what is bound when the rejection
# arrives". The old order bound the peer first. A failed insert therefore left
# a peer holding a tunnel address that no row named -- invisible to listDevices,
# uncounted against the caller's limit, and unreachable by revokeDevice, which
# has no key to remove without the row. It routes traffic and nothing can
# withdraw it.
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


DEVICE_KEY = _synthetic_key(b"vpn-test-device-key")
OTHER_KEY = _synthetic_key(b"vpn-test-other-key")
TAKEN_KEY = _synthetic_key(b"vpn-test-taken-key")
MALFORMED_KEY = "not-a-wireguard-public-key"

CALLER_DID = "did:plc:testcaller"
SERVER_ID = "srv-test-1"
# 10.8.0.1 is the server, so the first device on an empty server gets .2. The
# documented pool (peer_manager.allocate_ip) and a documentation range for the
# fake exit node's own address -- neither is a real deployment.
FIRST_FREE_IP = "10.8.0.2/32"


class ProvisionDeviceTestCase(unittest.TestCase):
    """An empty server, and an exit node that records what it is told."""

    def setUp(self):
        self.set_env("PROVISIONER_SECRET", FAKE_SECRET)
        self.set_env("WG_AGENT_URL", FAKE_AGENT_URL)
        self.set_env("WG_AGENT_SECRET", FAKE_SECRET)

        # One ordered log for both sides. A provision is a peer mutation and a
        # row write, and the defect under test is which happens first, so the
        # two have to be recorded on the same timeline -- asserting on final
        # state alone cannot distinguish "never bound" from "bound and undone".
        self.events = []
        self.connect_error_on_post = False
        self.status_for = {}
        self.insert_fails = False
        self.delete_fails = False

        # The device table, keyed by device_id. This is the thing that is meant
        # to be the only handle on a peer, so the tests read it directly.
        self.rows = {}

        # Distinct device ids regardless of whether the real nanoid is
        # installed: the bare-checkout stub the other test modules register
        # returns a constant, and whichever module the loader imports first
        # wins, so two devices in one test would otherwise share an id and the
        # second row would silently overwrite the first.
        self._next_id = 0
        self.patch_nanoid()

        self._saved_client = peer_manager._client
        peer_manager._client = httpx.AsyncClient(
            transport=httpx.MockTransport(self._exit_node), timeout=10.0
        )
        self.addCleanup(self._restore_client)

        self.subscription = {"tier": "pro", "device_limit": 5, "expires_at": None}
        self.server = {
            "server_id": SERVER_ID,
            "region": "test",
            "city": "test",
            "public_ip": "192.0.2.10",          # TEST-NET-1, RFC 5737
            "public_key": _synthetic_key(b"vpn-test-server-key"),
            "listen_port": 51820,
            "dns_ip": "192.0.2.53",             # TEST-NET-1, RFC 5737
            "capacity_pct": 0,
            "status": "active",
            "tier": "free",
        }
        self.taken_keys = {TAKEN_KEY}

        self.patch_db("get_subscription", self._get_subscription)
        self.patch_db("count_devices", self._count_devices)
        self.patch_db("public_key_exists", self._public_key_exists)
        self.patch_db("get_server", self._get_server)
        self.patch_db("get_assigned_ips", self._get_assigned_ips)
        self.patch_db("insert_device", self._insert_device)
        self.patch_db("delete_device", self._delete_device)
        # revokeDevice looks the device up before it unbinds anything, so the
        # recovery test below needs the read as well as the delete.
        self.patch_db("get_device", self._get_device)

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

    def patch_nanoid(self):
        def _generate(size=12):
            self._next_id += 1
            return f"dev-test-{self._next_id}".ljust(size, "0")[:size]

        patcher = mock.patch.object(main.nanoid, "generate", _generate)
        patcher.start()
        self.addCleanup(patcher.stop)

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
        value reaches a root `wg`. The full rule lives and is tested there, in
        wg-agent/test_peer_argv.py; what matters here is only that a refusal
        arrives at the point in the sequence where it really would.
        """
        if request.method == "POST":
            if self.connect_error_on_post:
                raise httpx.ConnectError("exit node unreachable", request=request)
            body = json.loads(request.content)
            key, allowed_ip = body["public_key"], body["allowed_ip"]
        else:
            key = urllib.parse.unquote(request.url.path.rsplit("/", 1)[-1])
            allowed_ip = None

        forced = self.status_for.get(request.method)
        if forced is not None:
            # Recorded as attempted, not as bound: a refused add binds nothing.
            self.events.append(("exit-node-refused", key))
            return httpx.Response(forced, json={"detail": "forced by test"})

        if not (len(key) == 44 and key.endswith("=")):
            self.events.append(("exit-node-refused", key))
            return httpx.Response(
                422,
                json={"detail": "InvalidPublicKey: expected 32 bytes of standard base64"},
            )

        self.events.append(
            ("add", key, allowed_ip) if request.method == "POST" else ("remove", key)
        )
        return httpx.Response(200, json={"ok": True})

    async def _get_subscription(self, did):
        return dict(self.subscription)

    async def _count_devices(self, did):
        return len([r for r in self.rows.values() if r["did"] == did])

    async def _public_key_exists(self, public_key):
        return public_key in self.taken_keys or any(
            r["public_key"] == public_key for r in self.rows.values()
        )

    async def _get_server(self, server_id):
        return dict(self.server) if server_id == SERVER_ID else None

    async def _get_assigned_ips(self, server_id):
        return {
            r["assigned_ip"].split("/")[0]
            for r in self.rows.values()
            if r["server_id"] == server_id
        }

    async def _insert_device(self, did, device_id, device_name, public_key,
                             assigned_ip, server_id):
        if self.insert_fails:
            self.events.append(("insert-refused", device_id))
            raise RuntimeError("database refused the insert")
        self.events.append(("insert", device_id, assigned_ip))
        self.rows[device_id] = {
            "did": did, "device_id": device_id, "device_name": device_name,
            "public_key": public_key, "assigned_ip": assigned_ip,
            "server_id": server_id,
        }

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

    # ── the requests under test ──────────────────────────────────────────────

    def _client(self):
        # raise_server_exceptions=False so an unhandled fault becomes a 500
        # response rather than escaping the client, the way it would in the pod.
        return TestClient(main.app, raise_server_exceptions=False)

    def provision(self, public_key=DEVICE_KEY, device_name="test device",
                  caller_did=CALLER_DID):
        return self._client().post(
            f"/xrpc/{NSID}.provisionDevice",
            json={
                "publicKey": public_key,
                "deviceName": device_name,
                "serverId": SERVER_ID,
                "callerDid": caller_did,
            },
            headers={"x-internal-trust": FAKE_SECRET},
        )

    def revoke(self, device_id, caller_did=CALLER_DID):
        return self._client().post(
            f"/xrpc/{NSID}.revokeDevice",
            json={"deviceId": device_id, "callerDid": caller_did},
            headers={"x-internal-trust": FAKE_SECRET},
        )

    # ── the invariant ────────────────────────────────────────────────────────

    def bound_peers(self) -> dict:
        """Which key currently holds which address on the fake exit node.

        A later add of the same address moves it, exactly as `wg` does: an
        allowed-ip belongs to one peer.
        """
        bound = {}
        for event in self.events:
            if event[0] == "add":
                _, key, allowed_ip = event
                bound = {k: v for k, v in bound.items() if v != allowed_ip}
                bound[key] = allowed_ip
            elif event[0] == "remove":
                bound.pop(event[1], None)
        return bound

    def assertNothingRoutesUnnamed(self):
        """No peer may hold an address that no record names.

        This is the whole defect in one assertion. A peer the database does not
        know about cannot be listed, cannot be counted against a device limit,
        and cannot be revoked -- revokeDevice looks the key up by row -- so it
        is a working tunnel with no handle on it.
        """
        named = {r["public_key"]: r["assigned_ip"] for r in self.rows.values()}
        unnamed = {k: ip for k, ip in self.bound_peers().items() if named.get(k) != ip}
        self.assertEqual(
            {}, unnamed,
            "a peer holds a tunnel address that no device record names, so "
            "nothing in this service can see or withdraw it",
        )


class TestAFailedProvisionLeavesNothingUnnamed(ProvisionDeviceTestCase):
    """The record must exist before the peer that it is the only handle on."""

    def test_a_record_that_cannot_be_written_leaves_no_peer_behind(self):
        # The discriminating failure. A refused KEY fails before either side is
        # touched under both orders, so it proves nothing; a refused INSERT is
        # where binding first and recording first differ.
        self.insert_fails = True

        resp = self.provision()

        self.assertNotEqual(200, resp.status_code)
        self.assertEqual({}, self.bound_peers(), "a peer was bound for a device that was never recorded")
        self.assertNothingRoutesUnnamed()

    def test_the_record_is_written_before_the_peer_is_bound(self):
        # The ordering itself, pinned. Asserting only "both happened" would
        # also pass for the order that caused this.
        self.provision()
        kinds = [e[0] for e in self.events]
        self.assertEqual(["insert", "add"], kinds)

    def test_a_record_that_cannot_be_written_does_not_hold_an_address(self):
        # The other half of the same wrong state, and the half that was
        # described backwards: an unrecorded peer does not LEAK its address
        # from the pool, because the pool is read from the device table. The
        # address is handed out again while the orphan still holds it, so the
        # next caller's add silently moves it and the orphan is only cleaned up
        # by accident. Either way the fix is that no orphan exists.
        self.insert_fails = True
        self.provision()

        self.insert_fails = False
        resp = self.provision(public_key=OTHER_KEY)

        self.assertEqual(200, resp.status_code, resp.text)
        self.assertEqual(FIRST_FREE_IP, resp.json()["assignedIp"])
        self.assertEqual({OTHER_KEY: FIRST_FREE_IP}, self.bound_peers())
        self.assertNothingRoutesUnnamed()

    def test_an_unreachable_exit_node_withdraws_the_record(self):
        # Not every failure is a bad argument. The record exists by the time
        # this is discovered, so it has to be taken back or the caller is left
        # with a device that does not work and that they did not ask to keep.
        self.connect_error_on_post = True

        resp = self.provision()

        self.assertEqual(500, resp.status_code)
        self.assertEqual({}, self.rows, "a device that was never bound was left on record")
        self.assertNothingRoutesUnnamed()

    def test_a_refused_key_withdraws_the_record_and_is_the_callers_error(self):
        resp = self.provision(public_key=MALFORMED_KEY)

        self.assertEqual(422, resp.status_code)
        self.assertEqual("InvalidPeerArgument", resp.json()["error"])
        self.assertEqual({}, self.rows)
        self.assertEqual({}, self.bound_peers())

    def test_the_exit_node_refusing_our_credential_withdraws_the_record(self):
        # A 403 from the exit node means the provisioner's own WG_AGENT_SECRET
        # was refused -- a fault on this side, not the caller's. It must still
        # not leave a half-made device behind.
        self.status_for["POST"] = 403

        resp = self.provision()

        self.assertEqual(500, resp.status_code)
        self.assertEqual({}, self.rows)
        self.assertNothingRoutesUnnamed()

    def test_a_record_that_cannot_be_withdrawn_leaves_something_revocable(self):
        # The worst residue this order can produce: the peer could not be bound
        # AND the record could not be taken back. That is a row with no peer,
        # which is the harmless direction -- it routes nothing, and unlike a
        # peer with no row it has a handle on it. Proven by using the handle.
        self.connect_error_on_post = True
        self.delete_fails = True

        resp = self.provision()
        self.assertEqual(500, resp.status_code)
        self.assertEqual(1, len(self.rows), "the residue should be a row, not a peer")
        self.assertEqual({}, self.bound_peers(), "the residual row must route nothing")

        # Recoverable means recoverable by the ordinary route, not by an
        # operator with a database prompt.
        self.delete_fails = False
        device_id = next(iter(self.rows))
        self.assertEqual(200, self.revoke(device_id).status_code)
        self.assertEqual({}, self.rows)


class TestASuccessfulProvisionStillProvisions(ProvisionDeviceTestCase):
    """Positive controls: the safe order must not be a refusal to act."""

    def test_a_device_is_created_and_returned(self):
        resp = self.provision()

        self.assertEqual(200, resp.status_code, resp.text)
        payload = resp.json()
        self.assertEqual(FIRST_FREE_IP, payload["assignedIp"])
        self.assertEqual(self.server["public_key"], payload["serverPublicKey"])
        self.assertEqual("192.0.2.10:51820", payload["serverEndpoint"])
        self.assertIn(payload["deviceId"], self.rows)

    def test_the_record_and_the_peer_agree(self):
        resp = self.provision()
        row = self.rows[resp.json()["deviceId"]]
        self.assertEqual({DEVICE_KEY: row["assigned_ip"]}, self.bound_peers())
        self.assertNothingRoutesUnnamed()

    def test_two_devices_do_not_share_an_address(self):
        first = self.provision()
        second = self.provision(public_key=OTHER_KEY)
        self.assertEqual(200, second.status_code, second.text)
        self.assertNotEqual(first.json()["assignedIp"], second.json()["assignedIp"])
        self.assertEqual(2, len(self.bound_peers()))

    def test_the_device_limit_is_still_enforced(self):
        self.subscription["device_limit"] = 1
        self.assertEqual(200, self.provision().status_code)

        resp = self.provision(public_key=OTHER_KEY)

        self.assertEqual(400, resp.status_code)
        self.assertEqual("DeviceLimitExceeded", resp.json()["error"])
        self.assertEqual(1, len(self.rows))

    def test_a_duplicate_public_key_is_still_refused_before_anything_is_written(self):
        resp = self.provision(public_key=TAKEN_KEY)

        self.assertEqual(400, resp.status_code)
        self.assertEqual("DuplicatePublicKey", resp.json()["error"])
        self.assertEqual([], self.events)

    def test_an_inactive_server_is_still_refused_before_anything_is_written(self):
        self.server["status"] = "draining"

        resp = self.provision()

        self.assertEqual(503, resp.status_code)
        self.assertEqual([], self.events)

    def test_the_stand_in_exit_node_accepts_a_well_formed_key(self):
        # Guards the refusal tests above from passing vacuously: if the double
        # refused everything, "nothing was bound" would be true for the wrong
        # reason.
        resp = self._exit_node(
            httpx.Request(
                "POST",
                f"{FAKE_AGENT_URL}/peers",
                json={"public_key": DEVICE_KEY, "allowed_ip": FIRST_FREE_IP},
            )
        )
        self.assertEqual(200, resp.status_code)
        self.assertEqual({DEVICE_KEY: FIRST_FREE_IP}, self.bound_peers())


class TestTheAddressPoolIsDerivedFromTheRecord(ProvisionDeviceTestCase):
    """Why an unrecorded peer is not merely invisible.

    Pins the fact the argument above rests on, which holds before and after the
    change: allocate_ip reads the device table, so a peer the table does not
    know about does not reserve anything.
    """

    def test_allocate_ip_reads_the_device_table_and_not_the_exit_node(self):
        client = self._client()
        # A peer exists on the exit node with no row anywhere.
        client.post(  # noqa: F841 -- the exit node double records it
            f"/xrpc/{NSID}.provisionDevice",
            json={"publicKey": MALFORMED_KEY, "deviceName": "d",
                  "serverId": SERVER_ID, "callerDid": CALLER_DID},
            headers={"x-internal-trust": FAKE_SECRET},
        )
        self.assertEqual({}, self.rows)

        resp = self.provision()

        self.assertEqual(200, resp.status_code, resp.text)
        self.assertEqual(
            FIRST_FREE_IP, resp.json()["assignedIp"],
            "the pool re-offered the first address, which is only safe because "
            "no unrecorded peer is holding it",
        )


if __name__ == "__main__":
    unittest.main()
