// app.test.ts — what this Worker does when nobody configured it
//
// The portal is the only intended caller of the provisioner, and the
// x-internal-trust secret is the only thing that says so. It used to spread
// that header in only when the secret happened to be set, and to fall back to
// http://localhost:8080 when the address was not -- so an unconfigured Worker
// still made the call, minus the part that made it legitimate.
//
// That is the client half of the fail-open in ADR-2608122800. The provisioner
// skipped its check when its secret was blank and the Worker skipped the
// header when its own was, and a deployment with nothing configured worked end
// to end with no authentication anywhere in it. These tests hold the line that
// a missing credential stops the request here, and name the variable while
// doing it, rather than sending a request that can only come back 403.
//
// Run:  npm test        (node --test; no test framework, no new dependency)

import { test } from "node:test";
import assert from "node:assert/strict";

import app from "../src/app.ts";

const AUTHN_URL = "https://authn.test.invalid";
const PROVISIONER_URL = "https://provisioner.test.invalid";
const FAKE_SECRET = "FAKE-SECRET-FOR-TEST-NOT-REAL";
const VIEWER_DID = "did:plc:testcaller";
const SESSION = { cookie: "etzhayyim_session=fake-session-for-test" };

const NSID = "ai.etzhayyim.apps.vpn";

type Call = { url: string; method: string; headers: Record<string, string> };

/** Every route that reaches the provisioner, with a request shaped to get there. */
const PROXIED: Array<[string, string, RequestInit]> = [
  ["POST", `/xrpc/${NSID}.provisionDevice`, { body: JSON.stringify({ publicKey: "K", deviceName: "d", serverId: "s" }) }],
  ["POST", `/xrpc/${NSID}.revokeDevice`, { body: JSON.stringify({ deviceId: "dev-1" }) }],
  ["GET", `/xrpc/${NSID}.listDevices`, {}],
  ["POST", `/xrpc/${NSID}.rotateKey`, { body: JSON.stringify({ deviceId: "dev-1", newPublicKey: "K2" }) }],
  ["GET", `/xrpc/${NSID}.downloadConfig?deviceId=dev-1`, {}],
  ["GET", `/xrpc/${NSID}.getSubscription`, {}],
  // No viewer check by design (exit node list is public), but it still carries
  // the credential, so it is still a route that must refuse without one.
  ["GET", `/xrpc/${NSID}.getServerList`, {}],
];

/**
 * Record every outbound request and answer it.
 *
 * The observation these tests need is not the status code alone -- a 403 from
 * a real provisioner would also be "not 200". It is whether a request left the
 * Worker at all.
 */
function stubFetch(): { calls: Call[]; restore: () => void } {
  const calls: Call[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(input as RequestInfo, init);
    calls.push({ url: req.url, method: req.method, headers: Object.fromEntries(req.headers) });
    if (req.url.startsWith(AUTHN_URL)) {
      return Response.json({ valid: true, did: VIEWER_DID, handle: "tester" });
    }
    return Response.json({ ok: true, upstream: true });
  }) as typeof fetch;
  return { calls, restore: () => { globalThis.fetch = original; } };
}

const toProvisioner = (calls: Call[]) => calls.filter((c) => !c.url.startsWith(AUTHN_URL));

const call = (method: string, path: string, init: RequestInit, env: unknown) =>
  app.request(path, { method, headers: SESSION, ...init }, env as never);

test("without PROVISIONER_SECRET, no route calls the provisioner", async (t) => {
  const env = { VPN_PROVISIONER_URL: PROVISIONER_URL, AUTHN_SERVICE_URL: AUTHN_URL };
  for (const [method, path, init] of PROXIED) {
    await t.test(path, async () => {
      const { calls, restore } = stubFetch();
      try {
        const resp = await call(method, path, init, env);
        assert.equal(resp.status, 503, `${path} did not refuse`);
        const body = (await resp.json()) as { error: string; message: string };
        assert.equal(body.error, "ServiceMisconfigured");
        // Name the variable. A 403 from the provisioner would blame the
        // credential, which is the wrong thing to hand an operator who never
        // set one.
        assert.match(body.message, /PROVISIONER_SECRET/);
        assert.deepEqual(toProvisioner(calls), [], `${path} called out uncredentialed`);
      } finally {
        restore();
      }
    });
  }
});

test("without VPN_PROVISIONER_URL, no route falls back to localhost", async (t) => {
  const env = { PROVISIONER_SECRET: FAKE_SECRET, AUTHN_SERVICE_URL: AUTHN_URL };
  for (const [method, path, init] of PROXIED) {
    await t.test(path, async () => {
      const { calls, restore } = stubFetch();
      try {
        const resp = await call(method, path, init, env);
        assert.equal(resp.status, 503, `${path} did not refuse`);
        assert.match(((await resp.json()) as { message: string }).message, /VPN_PROVISIONER_URL/);
        // The old default shipped the shared secret to whatever answered on
        // localhost:8080, which in a Worker is nothing -- an obscure failure
        // standing in for a plain one.
        assert.deepEqual(toProvisioner(calls), [], `${path} called an unconfigured address`);
      } finally {
        restore();
      }
    });
  }
});

test("configured, every route calls the provisioner and carries the credential", async (t) => {
  // Positive control. Refusing is only correct if it is not the only thing
  // this Worker does.
  const env = {
    VPN_PROVISIONER_URL: PROVISIONER_URL,
    PROVISIONER_SECRET: FAKE_SECRET,
    AUTHN_SERVICE_URL: AUTHN_URL,
  };
  for (const [method, path, init] of PROXIED) {
    await t.test(path, async () => {
      const { calls, restore } = stubFetch();
      try {
        const resp = await call(method, path, init, env);
        assert.equal(resp.status, 200, `${path} failed when fully configured`);
        const sent = toProvisioner(calls);
        assert.equal(sent.length, 1, `${path} made ${sent.length} provisioner calls`);
        assert.ok(sent[0].url.startsWith(PROVISIONER_URL));
        assert.equal(sent[0].headers["x-internal-trust"], FAKE_SECRET);
      } finally {
        restore();
      }
    });
  }
});

test("configured, a proxied call names the caller it resolved", async () => {
  const { calls, restore } = stubFetch();
  try {
    await call("POST", `/xrpc/${NSID}.rotateKey`, { body: "{}" }, {
      VPN_PROVISIONER_URL: PROVISIONER_URL,
      PROVISIONER_SECRET: FAKE_SECRET,
      AUTHN_SERVICE_URL: AUTHN_URL,
    });
    assert.equal(toProvisioner(calls)[0].headers["x-caller-did"], VIEWER_DID);
  } finally {
    restore();
  }
});

test("an unauthenticated caller is refused before the configuration is mentioned", async () => {
  // Misconfiguration is an operator's business. Someone who could not present
  // a session learns only that they could not.
  const { calls, restore } = stubFetch();
  try {
    const resp = await app.request(`/xrpc/${NSID}.listDevices`, { method: "GET" }, {
      AUTHN_SERVICE_URL: AUTHN_URL,
    } as never);
    assert.equal(resp.status, 401);
    assert.deepEqual(toProvisioner(calls), []);
  } finally {
    restore();
  }
});

test("liveness and identity routes answer with nothing configured at all", async () => {
  // The deploy story. `wrangler deploy` runs the global scope to validate the
  // upload and `wrangler dev` has no secrets, so the refusal above must be per
  // request -- a module-scope throw would make an unset secret an
  // undeployable Worker rather than a diagnosable one. These three routes
  // prove the module still stands up on an empty env, and stay open for the
  // same reason the provisioner keeps /health open: whatever probes them
  // cannot present a credential either.
  for (const path of ["/health", "/_app/meta", "/.well-known/did.json"]) {
    const resp = await app.request(path, {}, {} as never);
    assert.equal(resp.status, 200, `${path} needed configuration to answer`);
  }
});
