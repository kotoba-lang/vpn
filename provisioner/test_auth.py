# test_auth.py — what an uncredentialed caller is allowed to reach
#
# Every route here except /health is reachable only by the vpn portal Worker,
# and the only thing that establishes "this is the Worker" is the
# x-internal-trust shared secret. Authorisation is then a DID that the caller
# supplies in a header or body -- the Worker puts it there after verifying a
# session, but the pod cannot tell a real one from an asserted one. So the
# secret is not one control among several; it is the control. These tests exist
# to hold the line that the service refuses to run without it, because the
# earlier `if SECRET and ...` guard skipped the check entirely when the secret
# was blank, which turned every route below into an anonymous one.
#
# Run:  python3 -m unittest discover -s provisioner -t provisioner
# Deps: fastapi + httpx (already in requirements.txt).

import asyncio
import os
import sys
import types
import unittest

# main imports db (asyncpg at module scope) and nanoid. Nothing here reaches
# storage or mints an id -- the point is that the request stops before it
# could -- so stand both up as stubs rather than pull in a driver.
_db = types.ModuleType("db")


class _StorageWasTouched(AssertionError):
    """Raised if a rejected request nonetheless reached the database."""


def _forbidden_call(name):
    async def _call(*args, **kwargs):
        raise _StorageWasTouched(f"db.{name} was called by a request that should have been refused")

    return _call


for _name in (
    "get_subscription", "count_devices", "public_key_exists", "get_server",
    "insert_device", "delete_device", "list_devices", "list_servers",
    "get_device", "update_device_key", "get_assigned_ips",
):
    setattr(_db, _name, _forbidden_call(_name))
sys.modules.setdefault("db", _db)

try:  # the real thing in the image; a stub on a bare checkout
    import nanoid  # noqa: F401
except ModuleNotFoundError:
    _nanoid = types.ModuleType("nanoid")
    _nanoid.generate = lambda size=12: "x" * size
    sys.modules["nanoid"] = _nanoid

from fastapi.testclient import TestClient  # noqa: E402

import main  # noqa: E402

FAKE_SECRET = "FAKE-SECRET-FOR-TEST-NOT-REAL"
WRONG_SECRET = "FAKE-WRONG-SECRET-FOR-TEST"
NSID = main.NSID

# Every route that must not be anonymous, with a request shaped well enough to
# reach its handler. If the auth gate lets one through, the db stubs above turn
# that into a loud failure rather than a passing test.
PROTECTED = [
    ("POST", f"/xrpc/{NSID}.provisionDevice",
     {"json": {"publicKey": "K", "deviceName": "d", "serverId": "s", "callerDid": "did:plc:x"}}),
    ("POST", f"/xrpc/{NSID}.revokeDevice",
     {"json": {"deviceId": "dev-1", "callerDid": "did:plc:x"}}),
    ("POST", f"/xrpc/{NSID}.listDevices", {"json": {"callerDid": "did:plc:x"}}),
    ("GET", f"/xrpc/{NSID}.getServerList", {}),
    ("POST", f"/xrpc/{NSID}.rotateKey",
     {"json": {"deviceId": "dev-1", "newPublicKey": "K2", "callerDid": "did:plc:x"}}),
    ("GET", f"/xrpc/{NSID}.downloadConfig",
     {"params": {"deviceId": "dev-1", "callerDid": "did:plc:x"}}),
    ("POST", f"/xrpc/{NSID}.getSubscription", {"json": {"callerDid": "did:plc:x"}}),
]


class SecretEnvTestCase(unittest.TestCase):
    def set_secret(self, value):
        saved = os.environ.get("PROVISIONER_SECRET")
        if value is None:
            os.environ.pop("PROVISIONER_SECRET", None)
        else:
            os.environ["PROVISIONER_SECRET"] = value
        self.addCleanup(self._restore, saved)

    @staticmethod
    def _restore(saved):
        if saved is None:
            os.environ.pop("PROVISIONER_SECRET", None)
        else:
            os.environ["PROVISIONER_SECRET"] = saved

    def request(self, method, path, kwargs):
        # Bare TestClient: no lifespan, so this exercises the per-request gate.
        return TestClient(main.app).request(method, path, **kwargs)


class TestNoSecretMeansNoService(SecretEnvTestCase):
    """A blank secret must close the door, not remove it."""

    async def _boot(self):
        async with main.lifespan(main.app):
            pass

    def test_unset_secret_refuses_startup(self):
        self.set_secret(None)
        with self.assertRaises(RuntimeError) as ctx:
            asyncio.run(self._boot())
        self.assertIn("PROVISIONER_SECRET", str(ctx.exception))

    def test_whitespace_secret_refuses_startup(self):
        self.set_secret("   ")
        with self.assertRaises(RuntimeError):
            asyncio.run(self._boot())

    def test_configured_secret_permits_startup(self):
        # Positive control for the startup check: it must not be a blanket
        # refusal, or the service could never run at all.
        self.set_secret(FAKE_SECRET)
        asyncio.run(self._boot())

    def test_every_protected_route_refuses_when_secret_unset(self):
        self.set_secret(None)
        for method, path, kwargs in PROTECTED:
            with self.subTest(route=path):
                resp = self.request(method, path, kwargs)
                self.assertEqual(503, resp.status_code, f"{path} served without a configured secret")


class TestCredentialIsChecked(SecretEnvTestCase):
    """With a secret configured, presenting the wrong one (or none) is refused."""

    def test_every_protected_route_refuses_missing_credential(self):
        self.set_secret(FAKE_SECRET)
        for method, path, kwargs in PROTECTED:
            with self.subTest(route=path):
                resp = self.request(method, path, kwargs)
                self.assertEqual(403, resp.status_code, f"{path} served an anonymous caller")

    def test_every_protected_route_refuses_wrong_credential(self):
        self.set_secret(FAKE_SECRET)
        for method, path, kwargs in PROTECTED:
            with self.subTest(route=path):
                call = dict(kwargs)
                call["headers"] = {"x-internal-trust": WRONG_SECRET}
                resp = self.request(method, path, call)
                self.assertEqual(403, resp.status_code, f"{path} accepted a wrong credential")

    def test_correct_credential_passes_the_gate(self):
        # Positive control. The db stubs raise _StorageWasTouched, so reaching
        # them proves the gate admitted the request -- exactly what must still
        # happen for a correctly credentialed caller.
        self.set_secret(FAKE_SECRET)
        admitted = []
        for method, path, kwargs in PROTECTED:
            call = dict(kwargs)
            call["headers"] = {"x-internal-trust": FAKE_SECRET}
            try:
                self.request(method, path, call)
            except _StorageWasTouched:
                admitted.append(path)
        self.assertEqual(
            [p for _, p, _ in PROTECTED], admitted,
            "a correctly credentialed request was refused",
        )


class TestHealthStaysOpen(SecretEnvTestCase):
    """The kubelet probes /health and cannot present a credential."""

    def test_health_open_with_secret_configured(self):
        self.set_secret(FAKE_SECRET)
        resp = self.request("GET", "/health", {})
        self.assertEqual(200, resp.status_code)
        self.assertTrue(resp.json()["ok"])

    def test_health_discloses_nothing_beyond_liveness(self):
        # If it ever grows a field, it must not be one that helps a caller who
        # could not authenticate. Pinned so that stays a deliberate choice.
        self.set_secret(FAKE_SECRET)
        self.assertEqual(
            {"ok": True, "app": "vpn-provisioner"},
            self.request("GET", "/health", {}).json(),
        )


if __name__ == "__main__":
    unittest.main()
