# vpn-provisioner — FastAPI pod (L8, Vultr VKE SJC)
# Handles all 7 XRPC vpn endpoints proxied from CF Worker
# ADR-2605252200 — no session logs, no connection timestamps

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import nanoid

import db
import peer_manager
import config_generator

PROVISIONER_SECRET = os.environ.get("PROVISIONER_SECRET", "")
NSID = "ai.etzhayyim.apps.vpn"


def check_internal_trust(request: Request):
    if PROVISIONER_SECRET and request.headers.get("x-internal-trust") != PROVISIONER_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")


def get_caller_did(request: Request, body: dict | None = None) -> str:
    did = (body or {}).get("callerDid") or request.headers.get("x-caller-did", "")
    if not did:
        raise HTTPException(status_code=401, detail="AuthRequired")
    return did


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(lifespan=lifespan)


@app.get("/health")
async def health():
    return {"ok": True, "app": "vpn-provisioner"}


# ── provisionDevice ──────────────────────────────────────────────────────────

class ProvisionDeviceInput(BaseModel):
    publicKey: str
    deviceName: str
    serverId: str
    callerDid: str = ""


@app.post(f"/xrpc/{NSID}.provisionDevice")
async def provision_device(request: Request, body: ProvisionDeviceInput):
    check_internal_trust(request)
    did = get_caller_did(request, body.model_dump())

    # subscription check
    sub = await db.get_subscription(did)
    count = await db.count_devices(did)
    if count >= sub["device_limit"]:
        return JSONResponse({"error": "DeviceLimitExceeded", "message": f"Limit: {sub['device_limit']}"}, status_code=400)

    # duplicate key check
    if await db.public_key_exists(body.publicKey):
        return JSONResponse({"error": "DuplicatePublicKey"}, status_code=400)

    server = await db.get_server(body.serverId)
    if server is None or server["status"] != "active":
        return JSONResponse({"error": "ServerUnavailable"}, status_code=503)

    # tier check: free tier only on "free" servers
    if sub["tier"] == "free" and server["tier"] == "pro":
        return JSONResponse({"error": "ServerUnavailable", "message": "Upgrade to Pro for this server"}, status_code=403)

    assigned_ip = await peer_manager.allocate_ip(body.serverId)
    device_id = nanoid.generate(size=12)

    await peer_manager.add_peer(body.publicKey, assigned_ip)
    await db.insert_device(did, device_id, body.deviceName, body.publicKey, assigned_ip, body.serverId)

    return {
        "deviceId": device_id,
        "assignedIp": assigned_ip,
        "serverPublicKey": server["public_key"],
        "serverEndpoint": f"{server['public_ip']}:{server['listen_port']}",
        "serverDns": str(server["dns_ip"]),
    }


# ── revokeDevice ─────────────────────────────────────────────────────────────

class RevokeDeviceInput(BaseModel):
    deviceId: str
    callerDid: str = ""


@app.post(f"/xrpc/{NSID}.revokeDevice")
async def revoke_device(request: Request, body: RevokeDeviceInput):
    check_internal_trust(request)
    did = get_caller_did(request, body.model_dump())

    deleted = await db.delete_device(did, body.deviceId)
    if deleted is None:
        raise HTTPException(status_code=404, detail="DeviceNotFound")

    try:
        await peer_manager.remove_peer(deleted["public_key"])
    except Exception as e:
        # device already removed from DB — log but don't fail
        print(f"[vpn-provisioner] wg-agent remove_peer failed (non-fatal): {e}")

    return {"ok": True, "deviceId": body.deviceId}


# ── listDevices ──────────────────────────────────────────────────────────────

@app.post(f"/xrpc/{NSID}.listDevices")
async def list_devices(request: Request):
    check_internal_trust(request)
    body = await request.json()
    did = get_caller_did(request, body)

    devices = await db.list_devices(did)
    sub = await db.get_subscription(did)
    return {
        "devices": [
            {
                "deviceId": d["device_id"],
                "deviceName": d["device_name"],
                "publicKeyFingerprint": d["public_key"][:8],
                "serverId": d["server_id"],
                "assignedIp": d["assigned_ip"],
                "createdAt": d["created_at"].isoformat() if hasattr(d["created_at"], "isoformat") else str(d["created_at"]),
            }
            for d in devices
        ],
        "deviceLimit": sub["device_limit"],
        "tier": sub["tier"],
    }


# ── getServerList ────────────────────────────────────────────────────────────

@app.get(f"/xrpc/{NSID}.getServerList")
async def get_server_list(request: Request):
    check_internal_trust(request)
    servers = await db.list_servers()
    return {
        "servers": [
            {
                "serverId": s["server_id"],
                "region": s["region"],
                "city": s.get("city", s["region"]),
                "capacityPct": s["capacity_pct"],
                "status": s["status"],
                "tier": s["tier"],
            }
            for s in servers
        ]
    }


# ── rotateKey ────────────────────────────────────────────────────────────────

class RotateKeyInput(BaseModel):
    deviceId: str
    newPublicKey: str
    callerDid: str = ""


@app.post(f"/xrpc/{NSID}.rotateKey")
async def rotate_key(request: Request, body: RotateKeyInput):
    check_internal_trust(request)
    did = get_caller_did(request, body.model_dump())

    device = await db.get_device(did, body.deviceId)
    if device is None:
        raise HTTPException(status_code=404, detail="DeviceNotFound")

    if await db.public_key_exists(body.newPublicKey):
        return JSONResponse({"error": "DuplicatePublicKey"}, status_code=400)

    # atomic key swap on exit node
    await peer_manager.remove_peer(device["public_key"])
    await peer_manager.add_peer(body.newPublicKey, device["assigned_ip"])
    await db.update_device_key(did, body.deviceId, body.newPublicKey)

    return {"ok": True, "deviceId": body.deviceId}


# ── downloadConfig ───────────────────────────────────────────────────────────

@app.get(f"/xrpc/{NSID}.downloadConfig")
async def download_config(request: Request, deviceId: str = "", callerDid: str = ""):
    check_internal_trust(request)
    did = callerDid or request.headers.get("x-caller-did", "")
    if not did:
        raise HTTPException(status_code=401, detail="AuthRequired")

    device = await db.get_device(did, deviceId)
    if device is None:
        raise HTTPException(status_code=404, detail="DeviceNotFound")

    server = await db.get_server(device["server_id"])
    if server is None:
        raise HTTPException(status_code=503, detail="ServerUnavailable")

    conf = config_generator.generate_conf(
        assigned_ip=device["assigned_ip"],
        server_public_key=server["public_key"],
        server_public_ip=str(server["public_ip"]),
        server_listen_port=server["listen_port"],
        server_dns_ip=str(server["dns_ip"]),
    )
    filename = f"etzhayyim-vpn-{device['device_name'].replace(' ', '_')}.conf"
    return Response(
        content=conf,
        media_type="text/plain",
        headers={"content-disposition": f'attachment; filename="{filename}"'},
    )


# ── getSubscription ──────────────────────────────────────────────────────────

@app.post(f"/xrpc/{NSID}.getSubscription")
async def get_subscription(request: Request):
    check_internal_trust(request)
    body = await request.json()
    did = get_caller_did(request, body)

    sub = await db.get_subscription(did)
    count = await db.count_devices(did)
    return {
        "tier": sub["tier"],
        "deviceLimit": sub["device_limit"],
        "deviceCount": count,
        "expiresAt": sub["expires_at"].isoformat() if sub.get("expires_at") else None,
    }
