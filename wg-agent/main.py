#!/usr/bin/env python3
# vpn-wg-agent — systemd service on exit node VM (Ubuntu 22.04)
# Exposes HTTP API for provisioner to add/remove WireGuard peers
# No connection logs written — no-logs invariant (ADR-2605252200 §5)

import base64
import hmac
import ipaddress
import os
import subprocess
import urllib.parse
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import uvicorn

LISTEN_PORT  = int(os.environ.get("WG_AGENT_PORT", "8081"))
WG_IFACE     = os.environ.get("WG_IFACE", "wg0")


def _secret() -> str:
    """The shared secret proving a request came from the provisioner."""
    return os.environ.get("WG_AGENT_SECRET", "").strip()


def require_secret() -> str:
    """Return the shared secret, or refuse to name one.

    /peers reconfigures the WireGuard interface through `wg` as root. This
    secret is the only thing standing between that and any caller who can open
    a socket to this port, so there is no default and no unauthenticated mode.
    install.sh already refuses to install without it (`${WG_AGENT_SECRET:?}`);
    this makes the running service hold to the same contract.
    """
    secret = _secret()
    if not secret:
        raise RuntimeError(
            "WG_AGENT_SECRET is not set. It is the only credential protecting "
            "peer administration on this exit node, which runs `wg` as root."
        )
    return secret


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Refuse to serve rather than serve unauthenticated. systemd's
    # Restart=on-failure will retry and journalctl will carry the reason.
    require_secret()
    yield


app = FastAPI(lifespan=lifespan)


def check_auth(request: Request):
    secret = _secret()
    if not secret:
        # Reachable only if the app is served without its lifespan.
        raise HTTPException(
            status_code=503,
            detail="ServiceMisconfigured: WG_AGENT_SECRET is not set",
        )
    presented = request.headers.get("x-internal-trust") or ""
    if not hmac.compare_digest(presented, secret):
        raise HTTPException(status_code=403, detail="Forbidden")


def run_wg(*args: str) -> str:
    result = subprocess.run(["wg", *args], capture_output=True, text=True, check=True)
    return result.stdout


# ── What may become an argument to a root `wg` ───────────────────────────────
#
# The two /peers routes put caller-supplied strings into the argv of a command
# this service runs as root. They are passed as a list, so no shell sees them
# and there is no shell injection; the question is only whether `wg` reads any
# of them as something other than a value.
#
# For the public key it does not. Measured against wireguard-tools
# v1.0.20260223, `wg set` is a keyword parser rather than getopt: after `peer`
# it takes exactly one argument and hands it to key_from_base64(), so a key
# beginning with `-` is rejected as malformed rather than read as an option
# ("Key is not the correct length or format: `-foo'").
#
# For allowed-ips it does. A leading `-` or `+` there is an incremental-change
# prefix (config.c, parse_ip_prefix): `-` means "remove this allowed-ip" and
# both spellings clear the replace-all flag the rest of the command depends
# on. The value is also a comma-separated list. allowed-ips *is* the
# crypto-key routing table, so an argument that can name more than one address,
# or unset one, can decide which traffic belongs to which peer -- the same
# primitive as the takeover recorded in ADR-2608122800, reached by a different
# route. That field, not the key, is where a leading dash changes the meaning
# of the command.
#
# Both are checked here rather than escaped, because both have an exact form
# and anything outside it is a caller error, not something to be made safe.


def require_public_key(value: str) -> str:
    """Return a WireGuard public key, or refuse to pass it to `wg`.

    A public key is 32 bytes in standard base64: 44 characters ending in '='.
    key_from_base64() accepts exactly that and nothing else -- not 43
    characters, not a non-base64 character, and not a final character carrying
    bits a 32-byte key cannot have. Matching it means anything accepted here is
    something `wg` would also have accepted, so the check narrows what reaches
    argv without changing what the service can do.
    """
    if len(value) == 44 and value.endswith("="):
        try:
            # binascii.Error, raised for a non-base64 character or bad
            # padding, is a ValueError.
            raw = base64.b64decode(value, validate=True)
        except ValueError:
            raw = b""
        # Re-encoding rejects a non-canonical final character, which would
        # otherwise let two spellings name one key.
        if len(raw) == 32 and base64.b64encode(raw).decode() == value:
            return value
    raise HTTPException(
        status_code=422,
        detail="InvalidPublicKey: expected 32 bytes of standard base64 (44 characters ending in '=')",
    )


def require_allowed_ip(value: str) -> str:
    """Return a single peer address, or refuse to pass it to `wg`.

    Every value this service has ever been given is one host: peer_manager's
    allocate_ip() hands out /32s from the tunnel subnet. Holding the argument to
    that leaves no room for the spellings that mean something else -- a `-` or
    `+` prefix, a comma-separated second address, or a prefix wide enough to
    cover another peer's address. A caller that genuinely needs to route a
    subnet to a peer is asking for a different contract, and should have to say
    so rather than arrive as an unremarkable-looking string.
    """
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        network = None
    if network is not None and network.num_addresses == 1:
        if getattr(network.network_address, "scope_id", None) is None:
            return value
    raise HTTPException(
        status_code=422,
        detail="InvalidAllowedIp: expected a single host address (e.g. 10.8.0.42/32)",
    )


class PeerAdd(BaseModel):
    public_key: str
    allowed_ip: str   # e.g. "10.8.0.42/32"


@app.get("/health")
async def health():
    return {"ok": True, "app": "vpn-wg-agent", "iface": WG_IFACE}


@app.get("/peers")
async def list_peers(request: Request):
    check_auth(request)
    output = run_wg("show", WG_IFACE, "peers")
    peers = [p.strip() for p in output.splitlines() if p.strip()]
    return {"peers": peers, "count": len(peers)}


@app.post("/peers")
async def add_peer(request: Request, body: PeerAdd):
    # Authenticate first: an anonymous caller learns nothing about which of its
    # two guesses was malformed, and the only access control this service has
    # runs before any of its input handling.
    check_auth(request)
    public_key = require_public_key(body.public_key)
    allowed_ip = require_allowed_ip(body.allowed_ip)
    run_wg("set", WG_IFACE, "peer", public_key, "allowed-ips", allowed_ip)
    return {"ok": True, "public_key": public_key, "allowed_ip": allowed_ip}


@app.delete("/peers/{public_key_enc}")
async def remove_peer(request: Request, public_key_enc: str):
    check_auth(request)
    # After unquoting, not before: the path segment arrives percent-encoded
    # (peer_manager quotes it), so the raw segment is not what becomes argv.
    public_key = require_public_key(urllib.parse.unquote(public_key_enc))
    run_wg("set", WG_IFACE, "peer", public_key, "remove")
    return {"ok": True, "public_key": public_key}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=LISTEN_PORT)
