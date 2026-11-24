import { describe, expect, test } from "bun:test";
import { AuthController } from "../src/controller.js";
import { nativeCallbackPost, validateConfig, validateRedirect } from "../src/protocol.js";
import { AUTHORIZATION_ID, callback, deferred, factor, fakeClient, ok, publicConfig, user } from "./fixtures.js";

const TOKEN = "synthetic_header.synthetic_payload.synthetic_signature";
const config = () => ({ ...publicConfig(), schema: "elevenid.supabase-auth-ui/v2", clients: publicConfig().clients.map((client, i) => ({ ...client, callbackMode: i === 0 ? "native_mfa_post" : "redirect" })) });

function setup(options = {}) {
  const fake = fakeClient({ factors: [factor()], nextLevel: "aal2", ...options });
  fake.client.auth.getSession = async () => typeof fake.model.getSession === "function" ? fake.model.getSession() : ok({ session: { user: user(), access_token: TOKEN } });
  const states = [], posts = [], navigations = [];
  const controller = new AuthController({ config: config(), authorizationId: AUTHORIZATION_ID,
    createClient: () => fake.client, onChange: (state) => states.push(state),
    navigate: (url) => navigations.push(url), postCallback: (post) => posts.push(post) });
  return { fake, states, posts, navigations, controller };
}

async function authenticate(h) {
  await h.controller.signIn("operator@example.invalid", "synthetic-password");
  await h.controller.verifyTotp(factor().id, "123456");
}

describe("explicit native MFA callback transport", () => {
  test("v1 cannot opt into token delivery; v2 requires a known mode for every client", () => {
    const legacy = publicConfig();
    legacy.clients[0].callbackMode = "native_mfa_post";
    expect(() => validateConfig(legacy)).toThrow();
    for (const mode of [undefined, "post", "native_mfa_post ", { url: "https://attacker.invalid" }]) {
      const bad = config(); bad.clients[0].callbackMode = mode;
      expect(() => validateConfig(bad)).toThrow();
    }
    expect(validateConfig(validateConfig(config()))).toEqual(validateConfig(config()));
  });

  test("posts proof, code and state only to the exact allowlisted callback without query", async () => {
    const h = setup();
    await authenticate(h);
    expect(h.posts).toEqual([]);
    await h.controller.decide("approve");
    expect(h.posts).toEqual([{ action: publicConfig().clients[0].redirectUris[0], fields: {
      code: "synthetic-code", state: "synthetic-state", native_access_token: TOKEN } }]);
    expect(h.navigations).toEqual([]);
    expect(JSON.stringify(h.states)).not.toContain(TOKEN);
    expect(JSON.stringify(h.states)).not.toContain("synthetic-code");
  });

  test("prior consent still needs explicit Continue before proof delivery", async () => {
    const h = setup({ details: { redirect_url: callback() } });
    await authenticate(h);
    expect(h.controller.state.phase).toBe("return");
    expect(h.posts).toEqual([]);
    await h.controller.continueToApp();
    expect(h.posts).toHaveLength(1);
    expect(h.fake.count("approve")).toBe(0);
  });

  test("denial never obtains or sends the native token", async () => {
    const h = setup({ getSession: () => { throw new Error("must not read native token"); } });
    await authenticate(h);
    await h.controller.decide("deny");
    expect(h.posts).toEqual([]);
    expect(h.navigations).toEqual([callback("deny")]);
  });

  test("password-only accounts are blocked before an approval action", async () => {
    const h = setup({ factors: [], currentLevel: "aal1", nextLevel: "aal1" });
    await h.controller.signIn("operator@example.invalid", "synthetic-password");
    expect(h.controller.state.error).toBe("mfa_incomplete");
    await h.controller.decide("approve");
    expect(h.fake.count("approve")).toBe(0);
    expect(h.posts).toEqual([]);
  });

  test("account switch while getSession is pending prevents proof delivery", async () => {
    const pending = deferred();
    const h = setup({ getSession: () => pending.promise });
    await authenticate(h);
    const decision = h.controller.decide("approve");
    // Wait for the provider approval and native-session boundary.
    for (let i = 0; i < 30; i++) await Promise.resolve();
    h.controller.switchAccount();
    pending.resolve(ok({ session: { user: user(), access_token: TOKEN } }));
    await decision;
    expect(h.posts).toEqual([]);
    expect(h.navigations).toEqual([]);
  });

  test("missing, changed-account, malformed or failed native session never redirects", async () => {
    for (const session of [null, { user: { ...user(), id: "other-subject" }, access_token: TOKEN }, { user: user(), access_token: "not-a-jwt" }]) {
      const h = setup({ getSession: () => ok({ session }) });
      await authenticate(h);
      await h.controller.decide("approve");
      expect(h.posts).toEqual([]);
      expect(h.navigations).toEqual([]);
      expect(h.controller.state.error).toBe("session");
    }
  });

  test("proof cannot target a redirect-only client, missing state or attacker callback", () => {
    const c = validateConfig(config());
    const redirect = validateRedirect(callback(), c, "approve");
    expect(() => nativeCallbackPost({ ...redirect, url: callback().replace("&state=synthetic-state", "") }, c, TOKEN)).toThrow();
    expect(() => nativeCallbackPost({ ...redirect, url: "https://attacker.invalid/callback?code=x&state=y" }, c, TOKEN)).toThrow();
    const legacy = validateConfig(publicConfig());
    expect(() => nativeCallbackPost(validateRedirect(callback(), legacy, "approve"), legacy, TOKEN)).toThrow();
  });
});
