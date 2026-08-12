# test_peer_manager.py — which host receives the peer push, and its credential
#
# add_peer/remove_peer are the only paths in this service that transmit the
# WG_AGENT_SECRET shared secret and a WireGuard peer public key off-box. They
# send both to whatever host WG_AGENT_URL names, so these tests are about one
# question: can a request be built without anyone having chosen that host?
#
# Run:  python3 -m unittest discover -s provisioner -t provisioner
# Deps: httpx only (already in requirements.txt). No test framework needed.

import asyncio
import sys
import types
import unittest

import httpx

# peer_manager imports `db`, which imports asyncpg at module scope. Nothing
# under test touches the database, so stub it rather than pull in a driver.
sys.modules.setdefault("db", types.ModuleType("db"))

import peer_manager  # noqa: E402


# The value that ships in 50-infra/k8s/vpn-provisioner/configmap.yaml. It is a
# scaffold marker, not a host: the exit node VPS was never bought. It is spelled
# out here because a fix that only rejects an *empty* endpoint would not fire on
# the one deployment that exists.
SHIPPED_PLACEHOLDER = "http://" + "TODO_EXIT_NODE_IP" + ":8081"

FAKE_SECRET = "FAKE-SECRET-FOR-TEST-NOT-REAL"
FAKE_PUBKEY = "FAKE-WG-PUBKEY-FOR-TEST="


class PeerPushTestCase(unittest.TestCase):
    """Base: records every request that reaches the transport."""

    def setUp(self):
        self.requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            self.requests.append(request)
            return httpx.Response(200, json={"ok": True})

        self._saved_client = peer_manager._client
        peer_manager._client = httpx.AsyncClient(
            transport=httpx.MockTransport(handler), timeout=10.0
        )
        self.addCleanup(self._restore_client)

    def _restore_client(self):
        peer_manager._client = self._saved_client

    def set_env(self, url, secret=FAKE_SECRET):
        """Set (or clear, with url=None) the endpoint for one test."""
        import os

        for key, value in (("WG_AGENT_URL", url), ("WG_AGENT_SECRET", secret)):
            saved = os.environ.get(key)
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
            self.addCleanup(self._restore_env, key, saved)

    @staticmethod
    def _restore_env(key, saved):
        import os

        if saved is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = saved


class TestEndpointMustBeChosen(PeerPushTestCase):
    """An endpoint nobody chose must stop the request, not address it."""

    def assert_no_request_built(self, coro_factory):
        with self.assertRaises(RuntimeError) as ctx:
            asyncio.run(coro_factory())
        # The point is not merely that it raised — it is that the secret and the
        # peer key never reached a socket.
        self.assertEqual(
            [], self.requests, "a request was built despite an unusable endpoint"
        )
        return str(ctx.exception)

    def test_add_peer_unset_endpoint_raises_and_sends_nothing(self):
        self.set_env(None)
        msg = self.assert_no_request_built(
            lambda: peer_manager.add_peer(FAKE_PUBKEY, "10.8.0.42/32")
        )
        self.assertIn("WG_AGENT_URL", msg)

    def test_add_peer_blank_endpoint_raises_and_sends_nothing(self):
        self.set_env("   ")
        msg = self.assert_no_request_built(
            lambda: peer_manager.add_peer(FAKE_PUBKEY, "10.8.0.42/32")
        )
        self.assertIn("WG_AGENT_URL", msg)

    def test_add_peer_shipped_placeholder_raises_and_sends_nothing(self):
        # The deployed ConfigMap sets WG_AGENT_URL to this. "Set" is not "chosen".
        self.set_env(SHIPPED_PLACEHOLDER)
        msg = self.assert_no_request_built(
            lambda: peer_manager.add_peer(FAKE_PUBKEY, "10.8.0.42/32")
        )
        self.assertIn("WG_AGENT_URL", msg)

    def test_remove_peer_unset_endpoint_raises_and_sends_nothing(self):
        self.set_env(None)
        self.assert_no_request_built(lambda: peer_manager.remove_peer(FAKE_PUBKEY))

    def test_remove_peer_shipped_placeholder_raises_and_sends_nothing(self):
        self.set_env(SHIPPED_PLACEHOLDER)
        self.assert_no_request_built(lambda: peer_manager.remove_peer(FAKE_PUBKEY))


class TestExplicitEndpointStillWorks(PeerPushTestCase):
    """Positive control: a real endpoint must behave exactly as before."""

    def test_add_peer_sends_key_and_secret_to_explicit_host(self):
        self.set_env("http://10.9.0.5:8081")
        asyncio.run(peer_manager.add_peer(FAKE_PUBKEY, "10.8.0.42/32"))

        self.assertEqual(1, len(self.requests))
        req = self.requests[0]
        self.assertEqual("POST", req.method)
        self.assertEqual("http://10.9.0.5:8081/peers", str(req.url))
        self.assertEqual(FAKE_SECRET, req.headers.get("x-internal-trust"))
        self.assertEqual(
            {"public_key": FAKE_PUBKEY, "allowed_ip": "10.8.0.42/32"},
            __import__("json").loads(req.content),
        )

    def test_remove_peer_percent_encodes_key_into_path(self):
        self.set_env("http://10.9.0.5:8081")
        asyncio.run(peer_manager.remove_peer("abc/def+ghi="))

        self.assertEqual(1, len(self.requests))
        req = self.requests[0]
        self.assertEqual("DELETE", req.method)
        # The key is a path segment, so "/" and "+" must not survive raw.
        self.assertEqual(
            "http://10.9.0.5:8081/peers/abc%2Fdef%2Bghi%3D", str(req.url)
        )
        self.assertEqual(FAKE_SECRET, req.headers.get("x-internal-trust"))

    def test_trailing_slash_does_not_double_up(self):
        self.set_env("http://10.9.0.5:8081/")
        asyncio.run(peer_manager.add_peer(FAKE_PUBKEY, "10.8.0.42/32"))
        self.assertEqual("http://10.9.0.5:8081/peers", str(self.requests[0].url))

    def test_secret_omitted_when_unset(self):
        # Pre-existing behaviour, pinned so a later change to it is deliberate:
        # a blank secret sends no auth header at all.
        self.set_env("http://10.9.0.5:8081", secret="")
        asyncio.run(peer_manager.add_peer(FAKE_PUBKEY, "10.8.0.42/32"))
        self.assertIsNone(self.requests[0].headers.get("x-internal-trust"))


if __name__ == "__main__":
    unittest.main()
