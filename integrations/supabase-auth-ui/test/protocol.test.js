import { describe, expect, test } from "bun:test";
import { authorizationResponse, consumeAuthorizationRequest, parseAuthorizationRequest, requiredMfa, UiError, validateConfig, validateDetails, validateRedirect, verifiedUser } from "../src/protocol.js";
import { AUTHORIZATION_ID, callback, details, factor, publicConfig, user } from "./fixtures.js";

describe("closed public configuration", () => {
  test("accepts a publishable key and distinct exact callbacks; freezes its copied allowlist", () => {
    const input = publicConfig();
    const config = validateConfig(input);
    input.clients[0].redirectUris[0] = "https://attacker.example.invalid/callback";
    expect(config.clients[0].redirectUris[0]).not.toContain("attacker");
    expect(Object.isFrozen(config.clients[0].redirectUris)).toBe(true);
  });

  test.each([
    ["secret key", (c) => { c.publishableKey = "sb_secret_DO_NOT_PUBLISH_0123456789"; }],
    ["legacy service-role or anon JWT", (c) => { c.publishableKey = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.signature"; }],
    ["management credentials", (c) => { c.managementToken = "secret"; }],
    ["client secret", (c) => { c.clients[0].secret = "secret"; }],
    ["HTTP project", (c) => { c.supabaseUrl = "http://project.example.invalid"; }],
    ["project path", (c) => { c.supabaseUrl += "/auth/v1"; }],
    ["project userinfo", (c) => { c.supabaseUrl = "https://secret@project.example.invalid"; }],
    ["query-bearing callback", (c) => { c.clients[0].redirectUris[0] += "?next=https://evil.invalid"; }],
    ["fragment callback", (c) => { c.clients[0].redirectUris[0] += "#"; }],
    ["wildcard callback", (c) => { c.clients[0].redirectUris[0] += "/*"; }],
    ["encoded callback path", (c) => { c.clients[0].redirectUris[0] += "/%2fadmin"; }],
    ["shared callback cannot identify an already-consented client", (c) => { c.clients[1].redirectUris = c.clients[0].redirectUris; }],
    ["shared client ID", (c) => { c.clients[1].id = c.clients[0].id; }],
  ])("rejects %s", (_label, change) => {
    const config = publicConfig();
    change(config);
    expect(() => validateConfig(config)).toThrow(UiError);
  });
});

describe("authorization request input", () => {
  const url = `https://identity.example.invalid/oauth/consent?authorization_id=${AUTHORIZATION_ID}`;
  test("accepts the bounded opaque provider authorization identifier", () => {
    expect(parseAuthorizationRequest(url)).toBe(AUTHORIZATION_ID);
  });
  test("consumes the request into memory and prevents reload from reusing its identifier", () => {
    let address = url;
    expect(consumeAuthorizationRequest(address, (clean) => { address = clean; })).toBe(AUTHORIZATION_ID);
    expect(address).toBe("https://identity.example.invalid/oauth/consent");
    expect(() => consumeAuthorizationRequest(address, () => { throw new Error("Must not replace invalid input"); })).toThrow(UiError);
    let called = false;
    expect(() => consumeAuthorizationRequest(`${url}&return_to=https://attacker.example.invalid`, () => { called = true; })).toThrow(UiError);
    expect(called).toBe(false);
  });
  test.each([
    "https://identity.example.invalid/oauth/consent",
    `${url}&authorization_id=${AUTHORIZATION_ID}`,
    `${url}&%61uthorization_id=${AUTHORIZATION_ID}`,
    `${url}&return_to=https://attacker.example.invalid`,
    `${url}&client_id=11111111-1111-4111-8111-111111111111`,
    `${url}#access_token=secret`,
    `${url}#`,
    `${url}&`,
    `${url}%00`,
    `${url}%ZZ`,
    `${url}${"x".repeat(129)}`,
    "https://identity.example.invalid/?authorization_id=../../consent",
  ])("rejects ambiguous or caller-controlled input %s", (input) => {
    expect(() => parseAuthorizationRequest(input)).toThrow(UiError);
  });
});

describe("provider identity and details", () => {
  test("requires actual server-returned email confirmation", () => {
    expect(verifiedUser(user())).toEqual({ id: user().id, email: user().email });
    const unverified = { ...user(), email_confirmed_at: undefined, email_verified: true, user_metadata: { email_verified: true } };
    expect(() => verifiedUser(unverified)).toThrow(UiError);
  });
  test("binds details to the requested authorization, configured client and verified account", () => {
    const config = validateConfig(publicConfig());
    expect(validateDetails(details(), config, AUTHORIZATION_ID, user()).scopes).toEqual(["openid", "email", "profile"]);
    for (const change of [
      (d) => { d.authorization_id = "wrong-authorization"; },
      (d) => { d.client.id = "unknown-client-identifier"; },
      (d) => { d.user.id = "wrong-user-identifier"; },
      (d) => { d.user.email = "other@example.invalid"; },
      (d) => { d.redirect_uri = publicConfig().clients[1].redirectUris[0]; },
      (d) => { d.scope = "openid email email"; },
      (d) => { d.scope = "openid\nemail"; },
    ]) {
      const value = details();
      change(value);
      expect(() => validateDetails(value, config, AUTHORIZATION_ID, user())).toThrow(UiError);
    }
  });
  test("rejects an ambiguous details-and-redirect response", () => {
    expect(() => authorizationResponse({ ...details(), redirect_url: callback() }, validateConfig(publicConfig()), AUTHORIZATION_ID, user())).toThrow(UiError);
  });
  test("requires a supported enrolled TOTP for unmet MFA", () => {
    const aal1 = { currentLevel: "aal1", nextLevel: "aal2" };
    expect(requiredMfa(aal1, { all: [factor()] })).toHaveLength(1);
    expect(() => requiredMfa(aal1, { all: [factor("phone")] })).toThrow(UiError);
    expect(() => requiredMfa(aal1, { all: [] })).toThrow(UiError);
    expect(() => requiredMfa(aal1, { all: [{ ...factor(), status: "unknown" }] })).toThrow(UiError);
    expect(requiredMfa({ currentLevel: "aal1", nextLevel: "aal1" }, { all: [factor()] })).toHaveLength(1);
    expect(requiredMfa({ currentLevel: "aal2", nextLevel: "aal2" }, { all: [factor()] })).toEqual([]);
  });
});

describe("callback safety", () => {
  const config = validateConfig(publicConfig());
  const expected = validateDetails(details(), config, AUTHORIZATION_ID, user());
  test("accepts exact success and access_denied responses and optional exact issuer", () => {
    expect(validateRedirect(callback(), config, "approve", expected).url).toBe(callback());
    expect(validateRedirect(callback("deny"), config, "deny", expected).url).toBe(callback("deny"));
    const issuer = `${callback()}&iss=${encodeURIComponent(`${config.supabaseUrl}/auth/v1`)}`;
    expect(validateRedirect(issuer, config, "approve", expected).url).toBe(issuer);
  });
  test.each([
    callback().replace("https:", "http:"),
    callback().replace("elevenid.example.invalid", "elevenid.example.invalid.attacker.invalid"),
    callback().replace("https://", "https://operator:password@"),
    callback().replace("/v1/auth/callback", "/v1/auth/callback/"),
    callback().replace("/v1/auth/callback", "/fake/../v1/auth/callback"),
    callback().replace("/v1/auth/callback", "/v1/auth/%63allback"),
    callback().replace("elevenid.example.invalid/v1/auth/callback", "rifare.example.invalid/auth/customer/oidc/callback"),
    `${callback()}&state=second`,
    `${callback()}&%73tate=second`,
    `${callback()}&redirect_uri=https://attacker.example.invalid`,
    `${callback()}&access_token=secret`,
    `${callback()}#access_token=secret`,
    `${callback()}#`,
    `${callback()}&iss=https://attacker.example.invalid/auth/v1`,
    `${callback()}&error=access_denied`,
    callback().replace("synthetic-code", "code%00secret"),
    callback().replace("synthetic-state", "%E0%A4%A"),
    "//elevenid.example.invalid/v1/auth/callback?code=abc",
  ])("rejects unsafe or mismatched redirect %s", (url) => {
    expect(() => validateRedirect(url, config, "approve", expected)).toThrow(UiError);
  });
  test("denial cannot return a success code or an arbitrary provider error", () => {
    expect(() => validateRedirect(callback(), config, "deny", expected)).toThrow(UiError);
    expect(() => validateRedirect(callback("deny").replace("access_denied", "server_error"), config, "deny", expected)).toThrow(UiError);
  });
});
