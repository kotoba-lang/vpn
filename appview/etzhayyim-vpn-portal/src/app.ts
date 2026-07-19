// vpn.etzhayyim.com — CF Worker portal (ADR-2605252200)
//
// L1 Edge: CF Worker proxies XRPC → vpn-provisioner pod (L8, Vultr VKE SJC)
// Auth: etzhayyim_session JWT cookie or Bearer JWT → resolves caller DID
// No DB access in Worker (ADR-2605111200 — CF Worker edge-only)
//
// secrets (wrangler secret put):
//   VPN_PROVISIONER_URL  — http://<provisioner-lb-ip>:8080
//   PROVISIONER_SECRET   — x-internal-trust shared secret
//   AUTHN_SERVICE_URL    — https://auth.etzhayyim.com

import { Hono } from "hono";

type Env = {
  VPN_VERSION?: string;
  VPN_ACTOR_DID?: string;
  VPN_PROVISIONER_URL?: string;
  PROVISIONER_SECRET?: string;
  AUTHN_SERVICE_URL?: string;
  AUTHN_SERVICE?: { fetch(req: Request): Promise<Response> };
};

interface Viewer {
  did: string;
  handle: string;
}

const app = new Hono<{ Bindings: Env }>();

// ── Health / meta ────────────────────────────────────────────────────────────

app.get("/health", (c) =>
  c.json({ ok: true, app: "vpn", version: c.env.VPN_VERSION ?? "dev", ts: new Date().toISOString() }),
);

app.get("/_app/meta", (c) =>
  c.json({
    app: "etzhayyim-project-vpn",
    did: c.env.VPN_ACTOR_DID ?? "did:web:vpn.etzhayyim.com",
    version: c.env.VPN_VERSION ?? "unknown",
    beta: true,
  }),
);

app.get("/.well-known/did.json", (c) => {
  const did = c.env.VPN_ACTOR_DID ?? "did:web:vpn.etzhayyim.com";
  return c.json({
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: did,
    service: [
      { id: `${did}#xrpc`, type: "AtprotoPersonalDataServer", serviceEndpoint: "https://vpn.etzhayyim.com" },
    ],
  });
});

// ── Auth ─────────────────────────────────────────────────────────────────────

async function resolveViewer(c: any): Promise<Viewer | null> { // eslint-disable-line @typescript-eslint/no-explicit-any
  const env           = c.env as Env;
  const authorization = c.req.header("authorization") ?? "";
  const cookie        = c.req.header("cookie") ?? "";

  const hasJwtBearer = /^Bearer\s+eyJ/.test(authorization);
  if (!hasJwtBearer && !/(?:^|;\s*)etzhayyim_session=/.test(cookie)) return null;

  if (env.AUTHN_SERVICE) {
    try {
      const resp = await env.AUTHN_SERVICE.fetch(
        new Request("https://authn.internal/rpc/verify-session", {
          method: "POST",
          headers: { cookie, authorization, "content-type": "application/json" },
          body: "{}",
        }),
      );
      if (!resp.ok) return null;
      const body = (await resp.json()) as { valid?: boolean; did?: string; handle?: string };
      if (!body.valid || !body.did) return null;
      return { did: body.did, handle: body.handle ?? body.did };
    } catch (err) {
      console.warn("[vpn] resolveViewer via service binding failed", err);
    }
  }

  const authnUrl = env.AUTHN_SERVICE_URL ?? "https://auth.etzhayyim.com";
  try {
    const resp = await fetch(`${authnUrl}/rpc/verify-session`, {
      method: "POST",
      headers: { cookie, authorization, "content-type": "application/json" },
      body: "{}",
    });
    if (!resp.ok) return null;
    const body = (await resp.json()) as { valid?: boolean; did?: string; handle?: string };
    if (!body.valid || !body.did) return null;
    return { did: body.did, handle: body.handle ?? body.did };
  } catch {
    // fallback: decode JWT without verification (dev mode)
  }

  if (hasJwtBearer) {
    const token = authorization.replace(/^Bearer\s+/, "");
    const parts = token.split(".");
    if (parts.length === 3) {
      try {
        const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
        const did = payload.iss ?? payload.sub;
        if (did && typeof did === "string") return { did, handle: did };
      } catch { /* ignore */ }
    }
  }
  return null;
}

// ── Provisioner proxy ────────────────────────────────────────────────────────

const NSID = "ai.etzhayyim.apps.vpn";

async function proxyToProvisioner(
  env: Env,
  nsid: string,
  callerDid: string,
  body: unknown,
  method: "GET" | "POST" = "POST",
): Promise<Response> {
  const baseUrl = env.VPN_PROVISIONER_URL ?? "http://localhost:8080";
  const url = `${baseUrl}/xrpc/${nsid}`;
  return fetch(url, {
    method,
    headers: {
      "content-type": "application/json",
      "x-caller-did": callerDid,
      ...(env.PROVISIONER_SECRET ? { "x-internal-trust": env.PROVISIONER_SECRET } : {}),
    },
    body: method === "POST" ? JSON.stringify({ ...((body ?? {}) as object), callerDid }) : undefined,
  });
}

function jsonPassthrough(resp: Response): Response {
  return new Response(resp.body, {
    status: resp.status,
    headers: { "content-type": "application/json" },
  });
}

// ── XRPC routes ──────────────────────────────────────────────────────────────

// procedure: デバイス公開鍵を登録 → サーバー設定を返す
app.post(`/xrpc/${NSID}.provisionDevice`, async (c) => {
  const viewer = await resolveViewer(c);
  if (!viewer) return c.json({ error: "AuthRequired" }, 401);
  const body = await c.req.json().catch(() => ({}));
  return jsonPassthrough(await proxyToProvisioner(c.env, `${NSID}.provisionDevice`, viewer.did, body));
});

// procedure: デバイス削除
app.post(`/xrpc/${NSID}.revokeDevice`, async (c) => {
  const viewer = await resolveViewer(c);
  if (!viewer) return c.json({ error: "AuthRequired" }, 401);
  const body = await c.req.json().catch(() => ({}));
  return jsonPassthrough(await proxyToProvisioner(c.env, `${NSID}.revokeDevice`, viewer.did, body));
});

// query: デバイス一覧
app.get(`/xrpc/${NSID}.listDevices`, async (c) => {
  const viewer = await resolveViewer(c);
  if (!viewer) return c.json({ error: "AuthRequired" }, 401);
  return jsonPassthrough(await proxyToProvisioner(c.env, `${NSID}.listDevices`, viewer.did, {}, "POST"));
});

// query: exit node 一覧 (認証不要)
app.get(`/xrpc/${NSID}.getServerList`, async (c) => {
  const baseUrl = c.env.VPN_PROVISIONER_URL ?? "http://localhost:8080";
  const resp = await fetch(`${baseUrl}/xrpc/${NSID}.getServerList`, {
    headers: c.env.PROVISIONER_SECRET ? { "x-internal-trust": c.env.PROVISIONER_SECRET } : {},
  });
  return jsonPassthrough(resp);
});

// procedure: デバイス公開鍵ローテーション
app.post(`/xrpc/${NSID}.rotateKey`, async (c) => {
  const viewer = await resolveViewer(c);
  if (!viewer) return c.json({ error: "AuthRequired" }, 401);
  const body = await c.req.json().catch(() => ({}));
  return jsonPassthrough(await proxyToProvisioner(c.env, `${NSID}.rotateKey`, viewer.did, body));
});

// query: .conf ファイル生成 (Content-Disposition: attachment)
app.get(`/xrpc/${NSID}.downloadConfig`, async (c) => {
  const viewer = await resolveViewer(c);
  if (!viewer) return c.json({ error: "AuthRequired" }, 401);
  const deviceId = c.req.query("deviceId") ?? "";
  const baseUrl = c.env.VPN_PROVISIONER_URL ?? "http://localhost:8080";
  const resp = await fetch(
    `${baseUrl}/xrpc/${NSID}.downloadConfig?deviceId=${encodeURIComponent(deviceId)}&callerDid=${encodeURIComponent(viewer.did)}`,
    { headers: c.env.PROVISIONER_SECRET ? { "x-internal-trust": c.env.PROVISIONER_SECRET } : {} },
  );
  const headers = new Headers();
  headers.set("content-type", resp.headers.get("content-type") ?? "text/plain");
  const cd = resp.headers.get("content-disposition");
  if (cd) headers.set("content-disposition", cd);
  return new Response(resp.body, { status: resp.status, headers });
});

// query: サブスクリプション確認
app.get(`/xrpc/${NSID}.getSubscription`, async (c) => {
  const viewer = await resolveViewer(c);
  if (!viewer) return c.json({ error: "AuthRequired" }, 401);
  return jsonPassthrough(
    await proxyToProvisioner(c.env, `${NSID}.getSubscription`, viewer.did, {}, "POST"),
  );
});

export default app;
