#!/usr/bin/env python3
# vpn-wg-agent — systemd service on exit node VM (Ubuntu 22.04)
# Exposes HTTP API for provisioner to add/remove WireGuard peers
# No connection logs written — no-logs invariant (ADR-2605252200 §5)

import os
import subprocess
import urllib.parse
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import uvicorn

LISTEN_PORT  = int(os.environ.get("WG_AGENT_PORT", "8081"))
WG_IFACE     = os.environ.get("WG_IFACE", "wg0")
AGENT_SECRET = os.environ.get("WG_AGENT_SECRET", "")

app = FastAPI()


def check_auth(request: Request):
    if AGENT_SECRET and request.headers.get("x-internal-trust") != AGENT_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")


def run_wg(*args: str) -> str:
    result = subprocess.run(["wg", *args], capture_output=True, text=True, check=True)
    return result.stdout


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
    check_auth(request)
    run_wg("set", WG_IFACE, "peer", body.public_key, "allowed-ips", body.allowed_ip)
    return {"ok": True, "public_key": body.public_key, "allowed_ip": body.allowed_ip}


@app.delete("/peers/{public_key_enc}")
async def remove_peer(request: Request, public_key_enc: str):
    check_auth(request)
    public_key = urllib.parse.unquote(public_key_enc)
    run_wg("set", WG_IFACE, "peer", public_key, "remove")
    return {"ok": True, "public_key": public_key}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=LISTEN_PORT)
