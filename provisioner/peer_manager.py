# peer_manager.py — pushes peer add/remove to vpn-wg-agent on exit node
# Transport: HTTP + x-internal-trust shared secret

import httpx
import os
import ipaddress
import db


# The scaffold marker that stood in for the exit node's address before the VPS
# existed. It is not merely a stale comment: it ships verbatim as the
# WG_AGENT_URL value in 50-infra/k8s/vpn-provisioner/configmap.yaml, so the
# variable being *set* is not evidence that anyone chose a host. Reject it by
# name, otherwise the only deployment we have would sail past a blank check.
_PLACEHOLDER_MARKER = "todo_exit_node_ip"

_client = httpx.AsyncClient(timeout=10.0)


def _agent_base() -> str:
    """Return the exit node's base URL, or refuse to name one.

    There is no host this project owns that would be a safe fallback here, so
    there is no default. Every request built from this value carries the
    WG_AGENT_SECRET shared secret and a WireGuard peer public key, and both go
    to whoever answers for the name. An unconfigured deployment must therefore
    fail where it is configured, not at whatever host the resolver happens to
    find.
    """
    base = os.environ.get("WG_AGENT_URL", "").strip().rstrip("/")
    if not base:
        raise RuntimeError(
            "WG_AGENT_URL is not set. It must name the wg-agent exit node; "
            "there is no default because the peer push carries a shared secret "
            "and peer public keys to whatever host it resolves."
        )
    if _PLACEHOLDER_MARKER in base.lower():
        raise RuntimeError(
            "WG_AGENT_URL is still the scaffold placeholder "
            f"({_PLACEHOLDER_MARKER!r}) and does not name a real exit node. "
            "Set it to the wg-agent address for this environment."
        )
    return base


def _headers() -> dict:
    h = {"content-type": "application/json"}
    secret = os.environ.get("WG_AGENT_SECRET", "")
    if secret:
        h["x-internal-trust"] = secret
    return h


async def add_peer(public_key: str, assigned_ip: str):
    """Register a new WireGuard peer on the exit node."""
    resp = await _client.post(
        f"{_agent_base()}/peers",
        json={"public_key": public_key, "allowed_ip": assigned_ip},
        headers=_headers(),
    )
    resp.raise_for_status()


async def remove_peer(public_key: str):
    """Remove a WireGuard peer from the exit node."""
    import urllib.parse
    key_enc = urllib.parse.quote(public_key, safe="")
    resp = await _client.delete(
        f"{_agent_base()}/peers/{key_enc}",
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
