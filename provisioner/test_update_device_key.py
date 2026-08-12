# test_update_device_key.py — what the ignored return value is actually made of
#
# db.update_device_key returns a bool that rotateKey does not act on. That looks
# like a missed check: a zero-row update would desync the record from the
# device, and the value that would have caught it is discarded.
#
# These tests exist because the value is not a row count. asyncpg's
# Connection.execute() returns `status.decode()` -- the CommandComplete tag the
# SERVER sent, verbatim (asyncpg 0.30/0.31 connection.py, ":return str: Status
# of the last SQL command"). So `result == "UPDATE 1"` asks whether this
# particular server spells a one-row update the way PostgreSQL does, and the
# deployment is RisingWave over the PostgreSQL wire -- a server db.py already
# works around in two other places where it diverges (UNLISTEN on pool reset,
# no ON CONFLICT).
#
# The tests below pin the consequence: under a tag that reports no count, the
# value is False for an update that may well have happened. A caller that failed
# the rotation on False would then refuse every rotation the service can
# perform, which is worse than the desync it was meant to catch. Hence the tag
# is reported and not enforced, until someone has seen what this server sends.
#
# Run:  python3 -m unittest discover -s provisioner -t provisioner

import asyncio
import importlib.util
import sys
import types
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest import mock

# Load db.py directly rather than `import db`. The other test modules register a
# stub under that name (sys.modules.setdefault) and whichever imports first
# wins, so the real module has to be loaded under a name of its own. asyncpg is
# only needed at import time here -- every connection is replaced below.
if "asyncpg" not in sys.modules:
    try:
        import asyncpg  # noqa: F401
    except ModuleNotFoundError:
        sys.modules["asyncpg"] = types.ModuleType("asyncpg")

_spec = importlib.util.spec_from_file_location(
    "vpn_db_under_test", Path(__file__).with_name("db.py")
)
db = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(db)

FAKE_DID = "did:plc:testcaller"
FAKE_DEVICE_ID = "dev-test-1"
FAKE_KEY = "FAKE-KEY-FOR-TEST-NOT-REAL"


class FakeConnection:
    """Answers every execute() with one chosen CommandComplete tag."""

    def __init__(self, tag):
        self.tag = tag
        self.executed = []

    async def execute(self, query, *args):
        self.executed.append((query, args))
        return self.tag


class UpdateDeviceKeyTestCase(unittest.TestCase):
    def update_with_tag(self, tag):
        conn = FakeConnection(tag)

        @asynccontextmanager
        async def _conn():
            yield conn

        with mock.patch.object(db, "_conn", _conn):
            result = asyncio.run(
                db.update_device_key(FAKE_DID, FAKE_DEVICE_ID, FAKE_KEY)
            )
        self.conn = conn
        return result


class TestTheValueIsTheServersTagNotARowCount(UpdateDeviceKeyTestCase):
    """Whatever the server says, verbatim, is what this is compared against."""

    def test_the_postgresql_one_row_tag_is_true(self):
        self.assertTrue(self.update_with_tag("UPDATE 1"))
        # The statement really was the parameterised UPDATE, so the tag under
        # test is the one this function's caller depends on.
        query, args = self.conn.executed[0]
        self.assertIn("UPDATE vertex_vpn_device", query)
        self.assertEqual((FAKE_DID, FAKE_DEVICE_ID, FAKE_KEY), args)

    def test_a_genuine_zero_row_update_is_false(self):
        # The case the check was wanted for.
        self.assertFalse(self.update_with_tag("UPDATE 0"))

    def test_a_tag_without_a_count_is_also_false(self):
        # And the case that makes enforcing it unsafe: this is indistinguishable
        # from the one above at the call site, but here the update may have
        # succeeded. Nothing in this repo records which of the two a RisingWave
        # deployment produces.
        self.assertFalse(self.update_with_tag("UPDATE"))

    def test_a_tag_this_code_has_never_seen_is_also_false(self):
        self.assertFalse(self.update_with_tag("UPDATE 1 0"))


class TestAnUnfamiliarTagIsReported(UpdateDeviceKeyTestCase):
    """Observation, not a decision. This is the experiment, left running."""

    def test_an_unfamiliar_tag_names_itself(self):
        with mock.patch("builtins.print") as printed:
            self.update_with_tag("UPDATE")
        self.assertTrue(printed.called, "an unrecognised command tag went unreported")
        message = " ".join(str(a) for call in printed.call_args_list for a in call.args)
        self.assertIn("UPDATE", message)
        self.assertIn("update_device_key", message)

    def test_the_report_names_no_user_and_no_key(self):
        # The no-logs invariant is about what this service records of its users.
        # The tag is what the database said to it, and carries neither.
        with mock.patch("builtins.print") as printed:
            self.update_with_tag("UPDATE 0")
        message = " ".join(str(a) for call in printed.call_args_list for a in call.args)
        self.assertNotIn(FAKE_DID, message)
        self.assertNotIn(FAKE_DEVICE_ID, message)
        self.assertNotIn(FAKE_KEY, message)

    def test_the_expected_tag_is_not_reported(self):
        # Positive control: if this printed too, the report would be noise and
        # would say nothing about which server sent what.
        with mock.patch("builtins.print") as printed:
            self.update_with_tag("UPDATE 1")
        self.assertFalse(printed.called)


if __name__ == "__main__":
    unittest.main()
