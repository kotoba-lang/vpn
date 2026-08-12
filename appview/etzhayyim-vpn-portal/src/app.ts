// vpn.etzhayyim.com — CF Worker portal (ADR-2605252200)
//
// L1 Edge: CF Worker proxies XRPC → the vpn-provisioner pod
// Auth: etzhayyim_session JWT cookie or Bearer JWT → resolves caller DID
// No DB access in Worker (ADR-2605111200 — CF Worker edge-only)
//
// secrets (wrangler secret put):
//   VPN_PROVISIONER_URL  — https://<provisioner-tunnel-hostname>
//       Reached through a Cloudflare Tunnel, which resolves the Service by its
//       in-cluster DNS name. This is NOT the LoadBalancer IP over plain HTTP
//       that this comment used to give: the same deploy that created that port
//       mapping also moved this Worker off it (ADR-2608123400), and the LB it
//       named was deleted with the SJC cluster in June 2026 (ADR-2606120930).
//       Where the provisioner runs next is undecided in both repos, so treat
//       this as "whatever fronts it", not as an address that exists today.
//   PROVISIONER_SECRET   — x-internal-trust shared secret. The provisioner
//       refuses to start without it and answers 403 to a request that arrives
//       without it, so there is no mode in which calling it uncredentialed is
//       useful; see provisionerConfig() below for why that is enforced here too.
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

/** Thrown when a call cannot be built because this Worker was never configured. */
class ProvisionerUnconfigured extends Error {
  readonly variable: string;

  constructor(variable: string) {
    super(`${variable} is not set`);
    this.variable = variable;
  }
}

/**
 * The provisioner's address and credential, or a refusal to call it.
 *
 * This used to spread the trust header in only when the secret happened to be
 * set, and fall back to http://localhost:8080 when the address was not. Both
 * are one shape: with nothing configured the Worker still made the call, just
 * without the thing that made it legitimate.
 *
 * That shape is what made the fail-open in ADR-2608122800 invisible. The
 * provisioner skipped its check when its secret was blank and this Worker
 * skipped the header when its own was, so a deployment with nothing configured
 * worked end to end with no authentication anywhere in it, and nothing in its
 * behaviour said so. Failing open on both sides of a boundary does not halve
 * the problem; it removes the boundary and the evidence at the same time.
 *
 * The provisioner now fails closed, so the omission produces a 403 rather than
 * a hole -- but a 403 blames the credential, which is the wrong thing to hand
 * an operator who never set one. Refuse here and name the variable.
 *
 * Thrown per request, never at module scope: `wrangler deploy` runs the global
 * scope to validate the upload and `wrangler dev` has no secrets, so a
 * top-level throw would turn an unset secret into a Worker that cannot be
 * deployed or run locally at all. /health, /_app/meta and did.json stay up for
 * the same reason the provisioner keeps /health open under this rule -- what
 * probes them cannot present a credential either.
 */
function provisionerConfig(env: Env): { baseUrl: string; secret: string } {
  const baseUrl = (env.VPN_PROVISIONER_URL ?? "").trim().replace(/\/+$/, "");
  if (!baseUrl) throw new ProvisionerUnconfigured("VPN_PROVISIONER_URL");
  const secret = (env.PROVISIONER_SECRET ?? "").trim();
  if (!secret) throw new ProvisionerUnconfigured("PROVISIONER_SECRET");
  return { baseUrl, secret };
}

app.onError((err, c) => {
  if (err instanceof ProvisionerUnconfigured) {
    console.error(`[vpn] refusing to call the provisioner uncredentialed: ${err.message}`);
    return c.json({ error: "ServiceMisconfigured", message: err.message }, 503);
  }
  throw err;
});

async function proxyToProvisioner(
  env: Env,
  nsid: string,
  callerDid: string,
  body: unknown,
  method: "GET" | "POST" = "POST",
): Promise<Response> {
  const { baseUrl, secret } = provisionerConfig(env);
  const url = `${baseUrl}/xrpc/${nsid}`;
  return fetch(url, {
    method,
    headers: {
      "content-type": "application/json",
      "x-caller-did": callerDid,
      "x-internal-trust": secret,
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
  const { baseUrl, secret } = provisionerConfig(c.env);
  const resp = await fetch(`${baseUrl}/xrpc/${NSID}.getServerList`, {
    headers: { "x-internal-trust": secret },
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
  const { baseUrl, secret } = provisionerConfig(c.env);
  const resp = await fetch(
    `${baseUrl}/xrpc/${NSID}.downloadConfig?deviceId=${encodeURIComponent(deviceId)}&callerDid=${encodeURIComponent(viewer.did)}`,
    { headers: { "x-internal-trust": secret } },
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
