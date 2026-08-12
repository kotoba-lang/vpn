# RisingWave (PostgreSQL wire) persistence for vertex_vpn_* tables
# No session/connection logs — no-logs invariant (ADR-2605252200 §5)
#
# Note: asyncpg pool reset sends UNLISTEN * which RisingWave rejects.
# Use per-request connections via contextmanager instead of pooling.

import asyncpg
import os
from contextlib import asynccontextmanager
from typing import Optional


def _dsn() -> str:
    return os.environ["RW_DSN"]  # postgresql://root:pass@graph.etzhayyim.com:4566/dev


@asynccontextmanager
async def _conn():
    conn = await asyncpg.connect(_dsn())
    try:
        yield conn
    finally:
        await conn.close()


# ── vertex_vpn_subscription ──────────────────────────────────────────────────

async def get_subscription(did: str) -> dict:
    async with _conn() as conn:
        row = await conn.fetchrow(
            "SELECT tier, device_limit, stripe_sub_id, expires_at FROM vertex_vpn_subscription WHERE did = $1",
            did,
        )
        if row is None:
            # check-then-insert (no ON CONFLICT — RisingWave constraint)
            existing = await conn.fetchval(
                "SELECT did FROM vertex_vpn_subscription WHERE did = $1", did
            )
            if existing is None:
                await conn.execute(
                    "INSERT INTO vertex_vpn_subscription (did, tier, device_limit) VALUES ($1, 'free', 1)",
                    did,
                )
            return {"tier": "free", "device_limit": 1, "stripe_sub_id": None, "expires_at": None}
        return dict(row)


# ── vertex_vpn_device ────────────────────────────────────────────────────────

async def list_devices(did: str) -> list[dict]:
    async with _conn() as conn:
        rows = await conn.fetch(
            "SELECT device_id, device_name, public_key, assigned_ip, server_id, created_at "
            "FROM vertex_vpn_device WHERE did = $1 ORDER BY created_at",
            did,
        )
        return [dict(r) for r in rows]


async def get_device(did: str, device_id: str) -> Optional[dict]:
    async with _conn() as conn:
        row = await conn.fetchrow(
            "SELECT device_id, device_name, public_key, assigned_ip, server_id, created_at "
            "FROM vertex_vpn_device WHERE did = $1 AND device_id = $2",
            did, device_id,
        )
        return dict(row) if row else None


async def count_devices(did: str) -> int:
    async with _conn() as conn:
        return await conn.fetchval("SELECT COUNT(*) FROM vertex_vpn_device WHERE did = $1", did)


async def insert_device(did: str, device_id: str, device_name: str, public_key: str,
                        assigned_ip: str, server_id: str):
    async with _conn() as conn:
        await conn.execute(
            "INSERT INTO vertex_vpn_device (did, device_id, device_name, public_key, assigned_ip, server_id) "
            "VALUES ($1, $2, $3, $4, $5, $6)",
            did, device_id, device_name, public_key, assigned_ip, server_id,
        )


async def delete_device(did: str, device_id: str) -> Optional[dict]:
    async with _conn() as conn:
        row = await conn.fetchrow(
            "DELETE FROM vertex_vpn_device WHERE did = $1 AND device_id = $2 "
            "RETURNING device_id, public_key, assigned_ip, server_id",
            did, device_id,
        )
        return dict(row) if row else None


async def update_device_key(did: str, device_id: str, new_public_key: str) -> bool:
    """Point a device's record at a new public key.

    The return value is NOT enforced by the caller, on purpose, and this is the
    reason rather than an oversight.

    What is compared here is not a row count the driver computed. asyncpg's
    Connection.execute() returns ``status.decode()`` -- the CommandComplete tag
    the server sent, verbatim, with no normalisation (asyncpg 0.30/0.31
    connection.py, ``:return str: Status of the last SQL command``). So
    ``result == "UPDATE 1"`` asks whether THIS server spells a one-row update
    exactly the way PostgreSQL does, and the deployment is RisingWave over the
    PostgreSQL wire -- a server this module already works around in two other
    places where it diverges (UNLISTEN on pool reset above, no ON CONFLICT).

    Reading RisingWave's own pgwire says it probably does: the CommandComplete
    arm in src/utils/pgwire/src/pg_message.rs appends the row count for any
    statement type is_command() accepts, and UPDATE is one, so the tag is
    ``UPDATE <n>``; the count is read out of the batch executor's result stream
    rather than stubbed. That is enough to expect ``"UPDATE 1"``. It is not
    enough to enforce it, for three reasons, and the third is the one that
    matters:

    1. No RisingWave version is recorded in this repo or its manifests, and the
       extended-protocol path that carries the count was rewritten in 2023.
    2. Upstream has no test asserting the tag -- their own extended-mode e2e
       discards execute()'s return and verifies with a follow-up SELECT. It is
       not a contract they defend.
    3. **The tag was never the whole question.** This function is called by
       rotateKey after get_device() has already found the row. A genuine zero
       here therefore does not mean "the write was lost"; it means the row
       disappeared between the read and the write -- a concurrent revokeDevice.
       And rotateKey's rollback for a failed update is to re-bind the OLD key,
       which in that scenario puts back the peer of a device the caller has
       just revoked. Enforcing this value against the existing rollback would
       turn a desync into an un-revoke. The right compensation for zero rows is
       the opposite one -- remove the NEW peer, since it names a device that no
       longer exists -- and that is a separate change with its own failure
       analysis, not a check bolted onto this return.

    So the value is reported and not acted on. The line below is the experiment
    left running: the first real rotation prints the tag if it is not the
    PostgreSQL one. Seeing it never print, against a known-successful rotation
    on the deployed version, is what settles (1) and (2); (3) has to be built.
    """
    async with _conn() as conn:
        result = await conn.execute(
            "UPDATE vertex_vpn_device SET public_key = $3 WHERE did = $1 AND device_id = $2",
            did, device_id, new_public_key,
        )
        if result != "UPDATE 1":
            # Observation only -- never a decision. Names the tag, because the
            # tag is the missing fact; names no did, device or key, because the
            # no-logs invariant is about what this service records of its users
            # and this is about what the database says to it.
            print(
                "[vpn-provisioner] db.update_device_key: the server reported "
                f"{result!r}, not 'UPDATE 1'. Either the update matched no row "
                "or this server does not spell the tag the way PostgreSQL does; "
                "the caller cannot tell these apart and does not act on it."
            )
        return result == "UPDATE 1"


async def get_assigned_ips(server_id: str) -> set[str]:
    async with _conn() as conn:
        rows = await conn.fetch(
            "SELECT assigned_ip FROM vertex_vpn_device WHERE server_id = $1", server_id
        )
        return {r["assigned_ip"].split("/")[0] for r in rows}


async def public_key_exists(public_key: str) -> bool:
    async with _conn() as conn:
        val = await conn.fetchval(
            "SELECT COUNT(*) FROM vertex_vpn_device WHERE public_key = $1", public_key
        )
        return val > 0


# ── vertex_vpn_server ────────────────────────────────────────────────────────

async def list_servers() -> list[dict]:
    async with _conn() as conn:
        rows = await conn.fetch(
            "SELECT server_id, region, city, public_ip, public_key, listen_port, dns_ip, "
            "       capacity_pct, status, tier "
            "FROM vertex_vpn_server WHERE status != 'retired' ORDER BY region"
        )
        return [dict(r) for r in rows]


async def get_server(server_id: str) -> Optional[dict]:
    async with _conn() as conn:
        row = await conn.fetchrow(
            "SELECT server_id, region, city, public_ip, public_key, listen_port, dns_ip, "
            "       capacity_pct, status, tier "
            "FROM vertex_vpn_server WHERE server_id = $1",
            server_id,
        )
        return dict(row) if row else None
