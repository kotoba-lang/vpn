# vpn-provisioner — FastAPI pod (L8, Vultr VKE SJC)
# Handles all 7 XRPC vpn endpoints proxied from CF Worker
# ADR-2605252200 — no session logs, no connection timestamps

import hmac
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import nanoid

import db
import peer_manager
import config_generator

NSID = "ai.etzhayyim.apps.vpn"


def _secret() -> str:
    """The shared secret proving a request came from the vpn portal Worker.

    Read per call rather than captured at import so that the startup check and
    the request check cannot disagree about what is configured.
    """
    return os.environ.get("PROVISIONER_SECRET", "").strip()


def require_secret() -> str:
    """Return the shared secret, or refuse to name one.

    There is no safe way to serve these routes without it. The DID that
    authorises every operation below arrives in a caller-supplied header, put
    there by the portal Worker after it has verified a session; this secret is
    the only thing establishing that the caller *is* that Worker. Absent it,
    `x-caller-did` is an unverified claim and anyone who can reach the pod may
    assert any user's identity.
    """
    secret = _secret()
    if not secret:
        raise RuntimeError(
            "PROVISIONER_SECRET is not set. It is the only credential "
            "separating the portal Worker from any other caller that can reach "
            "this service, so there is no default and no unauthenticated mode."
        )
    return secret


def check_internal_trust(request: Request):
    secret = _secret()
    if not secret:
        # Reachable only if the app is served without its lifespan (the startup
        # check below would otherwise have stopped the process). Refuse rather
        # than admit the request, and name the variable so it is diagnosable.
        raise HTTPException(
            status_code=503,
            detail="ServiceMisconfigured: PROVISIONER_SECRET is not set",
        )
    presented = request.headers.get("x-internal-trust") or ""
    # compare_digest: the comparison is against a shared secret, so it should
    # not leak its prefix through timing.
    if not hmac.compare_digest(presented, secret):
        raise HTTPException(status_code=403, detail="Forbidden")


def get_caller_did(request: Request, body: dict | None = None) -> str:
    did = (body or {}).get("callerDid") or request.headers.get("x-caller-did", "")
    if not did:
        raise HTTPException(status_code=401, detail="AuthRequired")
    return did


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Fail closed, and fail at the moment the operator changed something rather
    # than at the first request an attacker makes. The deployment already
    # declares this secret mandatory -- deployment.yaml pulls it from a
    # secretKeyRef with no `optional: true`, so a missing Secret already stops
    # the container. This closes the remaining case: a Secret that exists with
    # an empty value, which the kubelet is happy to inject.
    require_secret()
    yield


app = FastAPI(lifespan=lifespan)


@app.exception_handler(peer_manager.PeerRejected)
async def peer_rejected_handler(request: Request, exc: peer_manager.PeerRejected):
    """Answer a refused peer argument as the caller's error, which it is.

    The exit node is where peer arguments become argv for a root `wg`, so that
    is where they are checked; see peer_manager.PeerRejected for why the check
    is not also restated here. Without this handler its 422 arrives as an
    httpx.HTTPStatusError and leaves as a 500, telling the caller the service
    broke when in fact it declined.
    """
    return JSONResponse(
        {"error": "InvalidPeerArgument", "message": exc.detail}, status_code=422
    )


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

    # ── Write the record before binding the peer it names ────────────────────
    #
    # This used to bind first. A failed insert then left a peer on the exit
    # node with no row anywhere naming it: not in listDevices, not counted by
    # count_devices against the caller's device limit, and not reachable by
    # revokeDevice, which finds the key to remove by looking the device up. A
    # tunnel that works and that nothing can see or withdraw, on a no-logs VPN.
    #
    # It is not the reverse of rotateKey's fix, though it is the same rule.
    # There, binding first was safe because an allowed-ip belongs to exactly
    # one peer, so the add MOVED the address off the old key and the record
    # kept naming something real throughout. There is no old peer here, so
    # binding first creates a peer that no record has ever named -- the state
    # rotateKey's ordering exists to avoid.
    #
    # The rule both follow: never create the thing that routes traffic before
    # the record that can find it again. The record is the only handle the rest
    # of this service has.
    #
    # "Reserve the address first" is the same act as this one, not a third
    # option: the pool is derived from the device table (peer_manager
    # .allocate_ip reads db.get_assigned_ips), so the row IS the reservation. A
    # separate reservation table would add a second row that can be orphaned
    # and would need a migration on a database this module already works around
    # elsewhere; it would move the leak rather than close it.
    await db.insert_device(did, device_id, body.deviceName, body.publicKey, assigned_ip, body.serverId)

    # ── Withdraw the record if the peer cannot be bound ──────────────────────
    #
    # A device recorded but not bound is a device that does not work, so it
    # should not be reported as provisioned. Delete it and let the failure
    # reach the caller -- a PeerRejected keeps its 422 through the handler
    # above, and anything else stays a fault on this side, as in rotateKey.
    #
    # If the withdrawal ALSO fails, what is left is a row with no peer, and
    # that is the harmless direction of the same disagreement: it routes
    # nothing, it appears in listDevices, it holds its own address in the pool,
    # and the caller can revokeDevice it -- that path already tolerates a peer
    # that is not there. The other order's residue is a peer with no row, which
    # routes traffic and has no such handle. Both orders can leave something
    # behind; only one leaves something the service can name.
    try:
        await peer_manager.add_peer(body.publicKey, assigned_ip)
    except Exception:
        try:
            await db.delete_device(did, device_id)
        except Exception as withdraw_error:
            print(
                "[vpn-provisioner] provisionDevice: the peer was not bound and "
                f"the record could not be withdrawn ({withdraw_error}); device "
                f"{device_id} exists but routes nothing and should be revoked"
            )
        raise

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

    # Ownership is decided before anything is mutated, as it was before -- only
    # now by a read rather than by the delete's own RETURNING. Nothing else
    # about this branch changes: a device this caller does not have is still a
    # 404 that touches neither side.
    device = await db.get_device(did, body.deviceId)
    if device is None:
        raise HTTPException(status_code=404, detail="DeviceNotFound")

    # ── Unbind the peer before deleting the record that names it ─────────────
    #
    # This used to delete first and swallow the unbind, and the two together
    # were worse than either. db.delete_device is a hard `DELETE ... RETURNING`
    # with no tombstone, and the row is the only handle this service has on a
    # peer: list_devices reads it, count_devices enforces the device limit from
    # it, allocate_ip derives the address pool from it (db.get_assigned_ips),
    # and this function finds the key to remove by it. So a failed unbind after
    # a completed delete left a bound tunnel that nothing could name -- and the
    # `# non-fatal` catch reported exactly that outcome as {"ok": True}. A
    # revocation that says it succeeded while the tunnel is still up, on a
    # no-logs VPN.
    #
    # Destroy is the third of this file's three orders, and it is the reverse of
    # provisionDevice's for the same reason rather than in spite of it. Create
    # writes the record first because the peer is what routes and the record is
    # what finds it again; destroy stops the routing first because the record
    # that finds it is about to go away. One rule underneath both: the record
    # never stops naming a resource that exists, and no resource exists that the
    # record never named.
    #
    # Reordering is the whole fix, and it is safe because the unbind is
    # idempotent -- so the failed-then-retried path does not need a second
    # mechanism. Traced rather than assumed: `wg set <iface> peer <key> remove`
    # parses to WGPEER_REMOVE_ME (wireguard-tools config.c), which reaches the
    # kernel as WGPEER_F_REMOVE_ME, and set_peer() sets ret = 0 *before* looking
    # the peer up, so an absent peer takes `if (!peer) ... goto out` and returns
    # success (drivers/net/wireguard/netlink.c). `wg` exits non-zero only when
    # the ipc call fails, so run_wg's check=True does not fire, and wg-agent's
    # DELETE /peers answers {"ok": True} without consulting the peer list at
    # all. Ubuntu 22.04's in-tree WireGuard is what install.sh puts on the exit
    # node, so that is the path being described.
    #
    # A failure here is now the caller's answer instead of a log line. Nothing
    # has been mutated, so there is nothing to roll back: the row is intact and
    # the device still works. It is left to propagate rather than dressed up,
    # for the reason peer_manager.PeerRejected gives -- a 403 means our
    # credential was refused and a 5xx means the exit node is unwell, and
    # neither is anything the caller did.
    try:
        await peer_manager.remove_peer(device["public_key"])
    except peer_manager.PeerRejected:
        # The one refusal that is evidence rather than an obstacle. wg-agent
        # applies the same require_public_key() to a remove as to an add, so a
        # key it will not accept here is a key it never bound; there is no peer
        # to unbind and the precondition for the delete already holds. Refusing
        # would instead make such a row permanently undeletable -- and the row
        # it describes is one provisionDevice tried and failed to withdraw,
        # which is the residue that path deliberately leaves *because* this one
        # can clear it.
        print(
            "[vpn-provisioner] revokeDevice: the exit node refused the stored "
            f"key for device {body.deviceId} as malformed, so it can never have "
            "been bound; removing the record"
        )

    # ── Delete the record last ───────────────────────────────────────────────
    #
    # If this fails the peer is gone and the row remains: a record naming a peer
    # that no longer exists. That is the direction this order chooses on
    # purpose. It over-counts rather than under-counts -- the device shows in
    # listDevices, holds its own address in the pool and still counts against
    # the limit -- it routes nothing, and repeating the request finishes it,
    # because the unbind it repeats is a no-op. The other order's residue was a
    # peer with no row: invisible, uncounted, still carrying traffic, and with
    # no handle left to withdraw it by.
    #
    # So the answer understates rather than overstates. The tunnel is already
    # down by this point, which is the half that matters on a VPN; what is
    # reported as failed is the bookkeeping, and it is what the retry completes.
    try:
        deleted = await db.delete_device(did, body.deviceId)
    except Exception as delete_error:
        print(
            "[vpn-provisioner] revokeDevice: the peer was unbound but the "
            f"record could not be deleted ({delete_error}); device "
            f"{body.deviceId} routes nothing and remains listed until the "
            "request is retried"
        )
        raise HTTPException(
            status_code=503, detail="RevokeDeviceFailed"
        ) from delete_error

    if deleted is None:
        # get_device found the row and the delete did not match it. The peer is
        # unbound either way, so the state the caller asked for is the state
        # they have; this is a concurrent revoke of the same device, not a
        # device they do not own -- that was already answered above, before
        # anything was touched.
        print(
            "[vpn-provisioner] revokeDevice: the record for device "
            f"{body.deviceId} was already gone when the delete ran; the peer is "
            "unbound"
        )

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

    old_public_key = device["public_key"]
    assigned_ip = device["assigned_ip"]

    # ── Bind the new key before unbinding the old one ────────────────────────
    #
    # This used to remove first. Every way the rest of the rotation could fail
    # -- a key the exit node refuses, an unreachable exit node, a database that
    # will not take the update -- then left the caller with no peer at all and a
    # record still naming the key that had just been deleted. The device was
    # gone and the two sides disagreed about why.
    #
    # Adding first inverts that. An allowed-ip belongs to exactly one peer, so
    # binding the tunnel address to the new key moves it off the old one; if
    # this call fails, nothing has moved and the caller's existing device keeps
    # working. The rotation fails; the tunnel does not.
    #
    # A malformed key is refused here, by the service that will run `wg`, and
    # comes back as a 422 with nothing mutated -- which is what validating at
    # this boundary was meant to achieve, without a second copy of the rule.
    await peer_manager.add_peer(body.newPublicKey, assigned_ip)

    # ── Make the record agree before removing the fallback ───────────────────
    #
    # If the record cannot be updated, put the tunnel address back on the key it
    # names. The old peer has not been removed yet, so this restores a working
    # device rather than merely a consistent row.
    try:
        # The bool this returns is deliberately not enforced -- see
        # db.update_device_key for what it is actually derived from and what
        # would have to be observed before a check on it could be trusted. A
        # raised exception is unambiguous, and that is what is acted on here.
        await db.update_device_key(did, body.deviceId, body.newPublicKey)
    except Exception as update_error:
        try:
            await peer_manager.add_peer(old_public_key, assigned_ip)
        except Exception as restore_error:
            # Both the record and the restore failed: the address is on a key
            # the database does not know. Say so plainly -- this is the one
            # outcome an operator has to act on.
            print(
                "[vpn-provisioner] rotateKey: could not update the record and "
                f"could not restore the previous peer ({restore_error}); the "
                f"tunnel address for device {body.deviceId} is bound to a key "
                "that is not in the database"
            )
            raise HTTPException(
                status_code=500, detail="RotateKeyInconsistent"
            ) from restore_error
        print(f"[vpn-provisioner] rotateKey: record not updated, rolled back ({update_error})")
        raise HTTPException(status_code=503, detail="RotateKeyFailed") from update_error

    # ── Retire the old peer ──────────────────────────────────────────────────
    #
    # Last, because it is the only step whose failure is harmless: the address
    # already moved, so a peer left behind here holds no allowed-ips and can
    # route nothing. Same reasoning as revokeDevice -- do not fail a completed
    # rotation over cleanup.
    try:
        await peer_manager.remove_peer(old_public_key)
    except Exception as e:
        print(f"[vpn-provisioner] rotateKey: stale peer left on exit node (non-fatal): {e}")

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
