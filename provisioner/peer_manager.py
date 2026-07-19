# peer_manager.py — pushes peer add/remove to vpn-wg-agent on exit node
# Transport: HTTP + x-internal-trust shared secret

import httpx
import os
import ipaddress
import db


WG_AGENT_BASE = os.environ.get("WG_AGENT_URL", "http://TODO_EXIT_NODE_IP:8081")
WG_AGENT_SECRET = os.environ.get("WG_AGENT_SECRET", "")

_client = httpx.AsyncClient(timeout=10.0)


def _headers() -> dict:
    h = {"content-type": "application/json"}
    if WG_AGENT_SECRET:
        h["x-internal-trust"] = WG_AGENT_SECRET
    return h


async def add_peer(public_key: str, assigned_ip: str):
    """Register a new WireGuard peer on the exit node."""
    resp = await _client.post(
        f"{WG_AGENT_BASE}/peers",
        json={"public_key": public_key, "allowed_ip": assigned_ip},
        headers=_headers(),
    )
    resp.raise_for_status()


async def remove_peer(public_key: str):
    """Remove a WireGuard peer from the exit node."""
    import urllib.parse
    key_enc = urllib.parse.quote(public_key, safe="")
    resp = await _client.delete(
        f"{WG_AGENT_BASE}/peers/{key_enc}",
        headers=_headers(),
    )
    resp.raise_for_status()


async def allocate_ip(server_id: str) -> str:
    """Find the next free /32 in 10.8.0.0/24 (server is .1)."""
    used = await db.get_assigned_ips(server_id)
    network = ipaddress.IPv4Network("10.8.0.0/24")
    for host in network.hosts():
        addr = str(host)
        if addr == "10.8.0.1":
            continue
        if addr not in used:
            return f"{addr}/32"
    raise RuntimeError("IP address pool exhausted for server " + server_id)
