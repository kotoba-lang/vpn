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
    async with _conn() as conn:
        result = await conn.execute(
            "UPDATE vertex_vpn_device SET public_key = $3 WHERE did = $1 AND device_id = $2",
            did, device_id, new_public_key,
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
