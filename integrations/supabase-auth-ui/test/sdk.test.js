import { expect, test } from "bun:test";
import { AuthController } from "../src/controller.js";
import { createProviderClient } from "../src/sdk.js";
import { AUTHORIZATION_ID, callback, details, factor, flush, publicConfig, user } from "./fixtures.js";

// Exercise the installed pinned SDK at its actual HTTP boundary. This transport
// never delegates to fetch and cannot contact a Supabase project.
function sdkHarness({ totp = false, priorConsent = false } = {}) {
  const config = publicConfig();
  const calls = [];
  const navigations = [];
  const states = [];
  const account = { ...user(), aud: "authenticated", created_at: "2026-01-01T00:00:00Z", app_metadata: {}, user_metadata: {}, factors: totp ? [factor()] : [] };
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const token = (aal) => `${encode({ alg: "RS256", typ: "JWT" })}.${encode({ sub: account.id, exp: Math.floor(Date.now() / 1000) + 3600, aal, amr: [{ method: aal === "aal2" ? "totp" : "password", timestamp: Math.floor(Date.now() / 1000) }] })}.${Buffer.from("synthetic-signature").toString("base64url")}`;
  const session = (aal) => ({ access_token: token(aal), refresh_token: "synthetic-refresh-token", token_type: "bearer", expires_in: 3600, expires_at: Math.floor(Date.now() / 1000) + 3600, user: account });
  let client;
  const controller = new AuthController({
    config, authorizationId: AUTHORIZATION_ID,
    createClient: (selectedConfig, signal) => {
      client = createProviderClient(selectedConfig, signal, async (input, options) => {
        const url = new URL(String(input));
        const body = options.body ? JSON.parse(options.body) : null;
        const headers = new Headers(options.headers);
        calls.push({ url, options, body, headers });
        const respond = (value) => Response.json(value);
        if (url.pathname === "/auth/v1/token" && url.searchParams.get("grant_type") === "password") return respond(session("aal1"));
        if (url.pathname === "/auth/v1/user") return respond(account);
        if (url.pathname === `/auth/v1/factors/${factor().id}/challenge`) return respond({ id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", type: "totp", expires_at: Math.floor(Date.now() / 1000) + 300 });
        if (url.pathname === `/auth/v1/factors/${factor().id}/verify`) return respond(session("aal2"));
        if (url.pathname === `/auth/v1/oauth/authorizations/${AUTHORIZATION_ID}`) return respond(priorConsent ? { redirect_url: callback() } : details());
        if (url.pathname === `/auth/v1/oauth/authorizations/${AUTHORIZATION_ID}/consent`) return respond({ redirect_url: callback(body.action) });
        throw new Error("Unexpected synthetic provider request");
      });
      return client;
    },
    onChange: (state) => states.push(state),
    navigate: (url) => navigations.push(url),
  });
  return { config, controller, calls, navigations, states, client: () => client };
}

test("real SDK password, server user, details and denial use the expected endpoints and no saved session survives", async () => {
  const h = sdkHarness();
  await h.controller.signIn("operator@example.invalid", "synthetic-password");
  expect(h.controller.state.phase).toBe("consent");
  expect(h.calls[0].url.pathname).toBe("/auth/v1/token");
  expect(h.calls[0].body.email).toBe("operator@example.invalid");
  expect(h.calls[0].body.password).toBe("synthetic-password");
  expect(h.calls.some((call) => call.url.pathname === "/auth/v1/user")).toBe(true);
  expect(h.calls.at(-1).url.pathname).toBe(`/auth/v1/oauth/authorizations/${AUTHORIZATION_ID}`);
  expect(h.calls.every((call) => call.options.redirect === "error" && call.options.cache === "no-store" && call.options.credentials === "omit" && call.options.referrerPolicy === "no-referrer")).toBe(true);
  expect(h.calls.every((call) => call.headers.get("apikey") === h.config.publishableKey)).toBe(true);
  expect(h.calls.at(-1).headers.get("authorization")).toStartWith("Bearer ");
  await h.controller.decide("deny");
  expect(h.calls.at(-1).body).toEqual({ action: "deny" });
  expect(h.navigations).toEqual([callback("deny")]);
  await flush();
  expect((await h.client().auth.getSession()).data.session).toBeNull();
  expect(h.calls.some((call) => call.url.pathname.endsWith("/logout"))).toBe(false);
});

test("real SDK TOTP challenge/verify upgrades the session before the first authorization request", async () => {
  const h = sdkHarness({ totp: true });
  await h.controller.signIn("operator@example.invalid", "synthetic-password");
  expect(h.controller.state.phase).toBe("mfa");
  expect(h.calls.some((call) => call.url.pathname.includes("/oauth/"))).toBe(false);
  await h.controller.verifyTotp(factor().id, "123456");
  expect(h.controller.state.phase).toBe("consent");
  const verification = h.calls.find((call) => call.url.pathname.endsWith("/verify"));
  expect(verification.body).toEqual({ challenge_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", code: "123456" });
  const authorization = h.calls.find((call) => call.url.pathname.includes("/oauth/"));
  const accessToken = authorization.headers.get("authorization").slice("Bearer ".length);
  expect(JSON.parse(Buffer.from(accessToken.split(".")[1], "base64url").toString()).aal).toBe("aal2");
  await h.controller.decide("approve");
  expect(h.calls.at(-1).body).toEqual({ action: "approve" });
  expect(h.navigations).toEqual([callback()]);
  await flush();
  expect((await h.client().auth.getSession()).data.session).toBeNull();
});

test("actual memory session is cleared on switch without sending a server logout", async () => {
  const h = sdkHarness({ priorConsent: true });
  await h.controller.signIn("operator@example.invalid", "synthetic-password");
  expect(h.controller.state.phase).toBe("return");
  expect((await h.client().auth.getSession()).data.session).not.toBeNull();
  expect(h.calls.some((call) => call.url.pathname.endsWith("/consent"))).toBe(false);
  h.controller.switchAccount();
  await flush();
  expect((await h.client().auth.getSession()).data.session).toBeNull();
  expect(h.calls.every((call) => call.options.signal.aborted)).toBe(true);
  expect(h.calls.some((call) => call.url.pathname.endsWith("/logout"))).toBe(false);
  expect(h.navigations).toEqual([]);
  expect(JSON.stringify(h.states)).not.toContain("synthetic-refresh-token");
  expect(JSON.stringify(h.states)).not.toContain("synthetic-code");
});

test("cancelled transport rejects new SDK auth requests before they can reach HTTP", async () => {
  const abort = new AbortController();
  let requests = 0;
  const client = createProviderClient(publicConfig(), abort.signal, async () => { requests += 1; throw new Error("Must not request HTTP"); });
  abort.abort();
  const response = await client.auth.signInWithPassword({ email: "operator@example.invalid", password: "synthetic-password" });
  expect(response.error).not.toBeNull();
  expect(requests).toBe(0);
  expect((await client.auth.getSession()).data.session).toBeNull();
});
