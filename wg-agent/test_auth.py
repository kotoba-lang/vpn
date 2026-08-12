# test_auth.py — what an uncredentialed caller may do to the WireGuard interface
#
# This service runs as root on the exit node and its /peers routes are a thin
# wrapper over `wg set`. There is no per-user authorisation here at all: the
# WG_AGENT_SECRET shared secret is the whole access control model, so a guard
# that skips itself when the secret is blank does not weaken the model, it
# removes it. These tests hold the service to install.sh's contract, which has
# always required the secret (`${WG_AGENT_SECRET:?Set WG_AGENT_SECRET}`) even
# while the code treated it as optional.
#
# Run:  python3 -m unittest discover -s wg-agent -t wg-agent
# Deps: fastapi + httpx (httpx is a test-only dependency; the service itself
#       needs only fastapi/uvicorn/pydantic, as install.sh installs).

import asyncio
import os
import unittest

from fastapi.testclient import TestClient

import main

FAKE_SECRET = "FAKE-SECRET-FOR-TEST-NOT-REAL"
WRONG_SECRET = "FAKE-WRONG-SECRET-FOR-TEST"
FAKE_PUBKEY = "FAKE-WG-PUBKEY-FOR-TEST="

# Requests that reconfigure the interface, plus the read that enumerates it.
PROTECTED = [
    ("GET", "/peers", {}),
    ("POST", "/peers", {"json": {"public_key": FAKE_PUBKEY, "allowed_ip": "10.8.0.42/32"}}),
    ("DELETE", f"/peers/{FAKE_PUBKEY}", {}),
]


class WgAgentTestCase(unittest.TestCase):
    def setUp(self):
        # Record what reached `wg` instead of running it. A refused request
        # must leave this empty -- the assertion is not merely about the status
        # code but about whether the interface was touched.
        self.wg_calls = []
        saved = main.run_wg
        main.run_wg = lambda *args: (self.wg_calls.append(args), "")[1]
        self.addCleanup(lambda: setattr(main, "run_wg", saved))

    def set_secret(self, value):
        saved = os.environ.get("WG_AGENT_SECRET")
        if value is None:
            os.environ.pop("WG_AGENT_SECRET", None)
        else:
            os.environ["WG_AGENT_SECRET"] = value
        self.addCleanup(self._restore, saved)

    @staticmethod
    def _restore(saved):
        if saved is None:
            os.environ.pop("WG_AGENT_SECRET", None)
        else:
            os.environ["WG_AGENT_SECRET"] = saved

    def request(self, method, path, kwargs):
        # Bare TestClient: no lifespan, so this exercises the per-request gate.
        return TestClient(main.app).request(method, path, **kwargs)

    async def _boot(self):
        async with main.lifespan(main.app):
            pass


class TestNoSecretMeansNoService(WgAgentTestCase):
    def test_unset_secret_refuses_startup(self):
        self.set_secret(None)
        with self.assertRaises(RuntimeError) as ctx:
            asyncio.run(self._boot())
        self.assertIn("WG_AGENT_SECRET", str(ctx.exception))

    def test_whitespace_secret_refuses_startup(self):
        self.set_secret("   ")
        with self.assertRaises(RuntimeError):
            asyncio.run(self._boot())

    def test_configured_secret_permits_startup(self):
        # Positive control: the check must not refuse unconditionally.
        self.set_secret(FAKE_SECRET)
        asyncio.run(self._boot())

    def test_peer_routes_refuse_when_secret_unset(self):
        self.set_secret(None)
        for method, path, kwargs in PROTECTED:
            with self.subTest(route=f"{method} {path}"):
                resp = self.request(method, path, kwargs)
                self.assertEqual(503, resp.status_code)
        self.assertEqual([], self.wg_calls, "`wg` ran for a request with no configured secret")


class TestCredentialIsChecked(WgAgentTestCase):
    def test_peer_routes_refuse_missing_credential(self):
        self.set_secret(FAKE_SECRET)
        for method, path, kwargs in PROTECTED:
            with self.subTest(route=f"{method} {path}"):
                resp = self.request(method, path, kwargs)
                self.assertEqual(403, resp.status_code)
        self.assertEqual([], self.wg_calls, "`wg` ran for an anonymous caller")

    def test_peer_routes_refuse_wrong_credential(self):
        self.set_secret(FAKE_SECRET)
        for method, path, kwargs in PROTECTED:
            with self.subTest(route=f"{method} {path}"):
                call = dict(kwargs)
                call["headers"] = {"x-internal-trust": WRONG_SECRET}
                resp = self.request(method, path, call)
                self.assertEqual(403, resp.status_code)
        self.assertEqual([], self.wg_calls, "`wg` ran for a wrong credential")

    def test_correct_credential_still_administers_peers(self):
        # Positive control: the service must still do its job.
        self.set_secret(FAKE_SECRET)
        auth = {"x-internal-trust": FAKE_SECRET}

        resp = self.request("POST", "/peers", {
            "json": {"public_key": FAKE_PUBKEY, "allowed_ip": "10.8.0.42/32"},
            "headers": auth,
        })
        self.assertEqual(200, resp.status_code)
        self.assertTrue(resp.json()["ok"])

        resp = self.request("DELETE", f"/peers/{FAKE_PUBKEY}", {"headers": auth})
        self.assertEqual(200, resp.status_code)

        self.assertEqual(
            [
                ("set", main.WG_IFACE, "peer", FAKE_PUBKEY, "allowed-ips", "10.8.0.42/32"),
                ("set", main.WG_IFACE, "peer", FAKE_PUBKEY, "remove"),
            ],
            self.wg_calls,
        )


class TestHealthStaysOpen(WgAgentTestCase):
    """systemd and the provisioner's reachability check need this unauthenticated."""

    def test_health_open_without_credential(self):
        self.set_secret(FAKE_SECRET)
        resp = self.request("GET", "/health", {})
        self.assertEqual(200, resp.status_code)
        self.assertTrue(resp.json()["ok"])
        self.assertEqual([], self.wg_calls, "/health must not shell out to `wg`")


if __name__ == "__main__":
    unittest.main()
