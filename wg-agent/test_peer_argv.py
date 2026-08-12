# test_peer_argv.py — what a caller may put into the argv of a root `wg` call
#
# Both /peers routes hand a caller-supplied string to `wg` as an argument, and
# `wg` here runs as root (systemd User=root). The strings are passed as a list,
# not through a shell, so there is no shell injection; what remains is whether
# `wg` reads any of them as something other than a value.
#
# It was reported that a public key beginning with `-` could be parsed as an
# option. Measured against wireguard-tools v1.0.20260223, it cannot: after
# `peer`, `wg set` reads exactly one argument and passes it to
# key_from_base64(), which requires 44 base64 characters ending in `=`.
#
#     $ wg set wg0 peer -foo allowed-ips 10.8.0.42/32
#     Key is not the correct length or format: `-foo'
#
# One argument later it is a different story. `allowed-ips` values honour a
# leading `-` or `+` as an incremental-change prefix (config.c,
# parse_ip_prefix), and the value is a comma-separated list:
#
#     $ wg set wg0 peer <key> allowed-ips -foo
#     Unable to parse IP address: `foo'          # the dash was consumed
#
# allowed-ips is the crypto-key routing table, so which addresses appear in it
# is the whole of a peer's authorisation. These tests hold both fields to the
# form the service actually produces, so that neither one reaches argv while
# still able to mean something other than "this peer, this address".
#
# Run:  python3 -m unittest discover -s wg-agent -t wg-agent

import base64
import unittest
import urllib.parse

from test_auth import FAKE_PUBKEY, FAKE_SECRET, WgAgentTestCase

import main

# A second well-formed synthetic key, for the case where a caller names an
# address that is not the one they were allocated.
OTHER_PUBKEY = base64.b64encode(b"FAKE-OTHER-KEY-NOT-A-REAL-WG-KEY").decode()

ALLOCATED_IP = "10.8.0.42/32"

# Every one of these is 44 characters or fails for a reason other than length,
# so that a check on length alone would not be enough to explain the result.
MALFORMED_KEYS = {
    "leading dash": "-" + FAKE_PUBKEY[1:],
    "option-shaped": "--help",
    "one character short": FAKE_PUBKEY[:-1],
    "one character long": FAKE_PUBKEY + "A",
    "no trailing padding": FAKE_PUBKEY[:-1] + "A",
    "non-base64 character": FAKE_PUBKEY[:10] + "!" + FAKE_PUBKEY[11:],
    # `wg` rejects this too: the final character carries bits that a 32-byte
    # key cannot have. Accepting it would let two spellings name one key.
    "non-canonical trailing bits": FAKE_PUBKEY[:42] + "B=",
    "empty": "",
}

MALFORMED_ALLOWED_IPS = {
    # The prefix `wg` reads as "remove this allowed-ip", which also cancels the
    # replace-all semantics the rest of the command relies on.
    "incremental remove prefix": "-" + ALLOCATED_IP,
    "incremental add prefix": "+" + ALLOCATED_IP,
    # A peer may only be authorised for the address it was allocated; a list
    # lets it claim a second one.
    "second address": f"{ALLOCATED_IP},10.8.0.7/32",
    "wider than a host": "0.0.0.0/0",
    "whole subnet": "10.8.0.0/24",
    # `wg` accepts an empty allowed-ips and reads it as "clear them all".
    "empty": "",
    "not an address": "--help",
}


class TestPublicKeyIsValidatedBeforeWg(WgAgentTestCase):
    def test_add_refuses_malformed_key(self):
        self.set_secret(FAKE_SECRET)
        for name, key in MALFORMED_KEYS.items():
            with self.subTest(key=name):
                resp = self.request("POST", "/peers", {
                    "json": {"public_key": key, "allowed_ip": ALLOCATED_IP},
                    "headers": {"x-internal-trust": FAKE_SECRET},
                })
                self.assertEqual(422, resp.status_code)
        self.assertEqual([], self.wg_calls, "`wg` ran with a malformed public key")

    def test_remove_refuses_malformed_key(self):
        # The path segment is unquoted before it becomes argv, so the check has
        # to happen after unquoting rather than on the raw segment.
        self.set_secret(FAKE_SECRET)
        for name, key in MALFORMED_KEYS.items():
            if not key:
                continue  # an empty segment is a different route, not this one
            with self.subTest(key=name):
                path = "/peers/" + urllib.parse.quote(key, safe="")
                resp = self.request("DELETE", path, {"headers": {"x-internal-trust": FAKE_SECRET}})
                self.assertEqual(422, resp.status_code)
        self.assertEqual([], self.wg_calls, "`wg` ran with a malformed public key")


class TestAllowedIpIsValidatedBeforeWg(WgAgentTestCase):
    def test_add_refuses_allowed_ip_that_is_not_one_host(self):
        self.set_secret(FAKE_SECRET)
        for name, allowed_ip in MALFORMED_ALLOWED_IPS.items():
            with self.subTest(allowed_ip=name):
                resp = self.request("POST", "/peers", {
                    "json": {"public_key": FAKE_PUBKEY, "allowed_ip": allowed_ip},
                    "headers": {"x-internal-trust": FAKE_SECRET},
                })
                self.assertEqual(422, resp.status_code)
        self.assertEqual([], self.wg_calls, "`wg` ran with an allowed-ips value that is not one host")


class TestValidationIsNotTheAuthCheck(WgAgentTestCase):
    """Malformed input from an anonymous caller is still 403, not 422.

    Answering 422 first would tell an uncredentialed caller which of its two
    guesses was wrong, and would mean input handling runs before the only
    access control this service has.
    """

    def test_anonymous_caller_with_malformed_key_is_forbidden(self):
        self.set_secret(FAKE_SECRET)
        resp = self.request("POST", "/peers", {
            "json": {"public_key": "-" + FAKE_PUBKEY[1:], "allowed_ip": ALLOCATED_IP},
        })
        self.assertEqual(403, resp.status_code)
        self.assertEqual([], self.wg_calls)


class TestWellFormedInputStillReachesWgUnchanged(WgAgentTestCase):
    """Positive control: this passes before the validation exists and after it.

    It also pins that the values are passed through rather than normalised —
    a key or address that came back rewritten would not be the one the
    provisioner recorded in the database.
    """

    def test_add_and_remove_pass_the_values_through(self):
        self.set_secret(FAKE_SECRET)
        auth = {"x-internal-trust": FAKE_SECRET}

        resp = self.request("POST", "/peers", {
            "json": {"public_key": FAKE_PUBKEY, "allowed_ip": ALLOCATED_IP},
            "headers": auth,
        })
        self.assertEqual(200, resp.status_code)
        self.assertEqual(FAKE_PUBKEY, resp.json()["public_key"])

        resp = self.request(
            "DELETE",
            "/peers/" + urllib.parse.quote(OTHER_PUBKEY, safe=""),
            {"headers": auth},
        )
        self.assertEqual(200, resp.status_code)

        self.assertEqual(
            [
                ("set", main.WG_IFACE, "peer", FAKE_PUBKEY, "allowed-ips", ALLOCATED_IP),
                ("set", main.WG_IFACE, "peer", OTHER_PUBKEY, "remove"),
            ],
            self.wg_calls,
        )

    def test_every_address_the_allocator_can_produce_is_accepted(self):
        # peer_manager.allocate_ip() hands out /32s from 10.8.0.0/24. If the
        # check rejected any of them the service would fail for a real user,
        # so the boundaries of the pool are exercised rather than assumed.
        self.set_secret(FAKE_SECRET)
        auth = {"x-internal-trust": FAKE_SECRET}
        for host in ("10.8.0.2/32", "10.8.0.42/32", "10.8.0.254/32"):
            with self.subTest(allowed_ip=host):
                resp = self.request("POST", "/peers", {
                    "json": {"public_key": FAKE_PUBKEY, "allowed_ip": host},
                    "headers": auth,
                })
                self.assertEqual(200, resp.status_code)
        self.assertEqual(3, len(self.wg_calls))


if __name__ == "__main__":
    unittest.main()
