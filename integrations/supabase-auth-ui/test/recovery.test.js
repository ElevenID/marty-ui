import { describe, expect, test } from "bun:test";
import { consumeRecoveryRequest, RecoveryController } from "../src/recovery.js";
import { validateConfig } from "../src/protocol.js";
import { createProviderClient } from "../src/sdk.js";
import { deferred, factor, fakeClient, flush, ok, publicConfig, user } from "./fixtures.js";

const HASH = "a".repeat(64);
const PASSWORD = "synthetic-new-password";
const ORIGIN = "https://authorization.example.invalid";
const SIGN_IN = "https://elevenid.example.invalid/v1/auth/login";
const config = () => ({ ...publicConfig(), schema: "elevenid.supabase-auth-ui/v3",
  clients: publicConfig().clients.map((entry) => ({ ...entry, callbackMode: "native_mfa_post" })),
  accountLifecycle: { clientId: publicConfig().clients[0].id, signInUri: SIGN_IN } });

function setup(options = {}) {
  const fake = fakeClient({ factors: [factor()], nextLevel: "aal2", ...options });
  const operations = [], states = [], navigations = [];
  for (const method of ["verifyOtp", "resetPasswordForEmail", "updateUser"]) {
    fake.client.auth[method] = async (...args) => {
      operations.push({ method, args });
      return typeof options[method] === "function" ? options[method](...args) : ok({});
    };
  }
  const controller = new RecoveryController({ config: config(), mode: options.mode ?? "verify", tokenHash: HASH,
    origin: ORIGIN, createClient: () => fake.client, onChange: (state) => states.push(state), navigate: (url) => navigations.push(url) });
  return { controller, operations, states, navigations, fake };
}

describe("closed recovery entry and configuration", () => {
  test("removes the credential fragment from history before returning its memory-only value", () => {
    let address = `${ORIGIN}/account/verify#token_hash=${HASH}&type=recovery`;
    const parsed = consumeRecoveryRequest(address, (clean) => { address = clean; });
    expect(address).toBe(`${ORIGIN}/account/verify`);
    expect(parsed).toEqual({ mode: "verify", tokenHash: HASH });
    expect(() => consumeRecoveryRequest(address, () => {})).toThrow();
  });
  test.each([
    `?token_hash=${HASH}&type=recovery`, `#token_hash=${HASH}&type=email`,
    `#token_hash=${HASH}&type=recovery&next=https://attacker.invalid`,
    `#token_hash=${HASH}&token_hash=${HASH}&type=recovery`,
    `#token_hash=${HASH}&type=recovery&type=recovery`,
    "#access_token=synthetic-token&type=recovery", "#token_hash=short&type=recovery",
    `?#token_hash=${HASH}&type=recovery`,
  ])("rejects and scrubs ambiguous, wrong-purpose or redirect-bearing input %s", (suffix) => {
    let cleaned;
    expect(() => consumeRecoveryRequest(`${ORIGIN}/account/verify${suffix}`, (value) => { cleaned = value; })).toThrow();
    expect(cleaned).toBe(`${ORIGIN}/account/verify`);
  });
  test("requires explicit v3 and a registered native client's exact sign-in entry", () => {
    expect(validateConfig(validateConfig(config())).accountLifecycle.signInUri).toBe(SIGN_IN);
    for (const target of ["https://attacker.invalid/v1/auth/login", SIGN_IN+"?next=bad", SIGN_IN+"#fragment", "https://elevenid.example.invalid/other"]) {
      const invalid = config(); invalid.accountLifecycle.signInUri = target;
      expect(() => validateConfig(invalid)).toThrow();
    }
    const legacy = config(); legacy.schema = "elevenid.supabase-auth-ui/v2";
    expect(() => validateConfig(legacy)).toThrow();
    const redirect = config(); redirect.clients[0].callbackMode = "redirect";
    expect(() => validateConfig(redirect)).toThrow();
  });
});

describe("password recovery security and transitions", () => {
  test("page initialization does not burn a one-time email token; required MFA precedes password update", async () => {
    const h = setup();
    expect(h.controller.state.phase).toBe("confirm");
    expect(h.operations).toEqual([]);
    expect(JSON.stringify(h.controller)).not.toContain(HASH);
    await h.controller.confirmRecovery();
    expect(h.operations[0]).toEqual({ method: "verifyOtp", args: [{ token_hash: HASH, type: "recovery" }] });
    expect(h.controller.state.phase).toBe("mfa");
    await h.controller.savePassword(PASSWORD, PASSWORD);
    expect(h.operations.some((operation) => operation.method === "updateUser")).toBe(false);
    await h.controller.verifyTotp(factor().id, "123456");
    expect(h.controller.state.phase).toBe("password");
    await h.controller.savePassword(PASSWORD, PASSWORD);
    expect(h.operations.filter((operation) => operation.method === "updateUser")).toHaveLength(1);
    expect(h.fake.calls.find((call) => call.name === "signOut").args).toEqual([{ scope: "local" }]);
    expect(h.navigations).toEqual([SIGN_IN]);
    expect(JSON.stringify(h.states)).not.toContain(HASH);
    expect(JSON.stringify(h.states)).not.toContain(PASSWORD);
    expect(JSON.stringify(h.states)).not.toContain("123456");
  });
  test("expired links and provider errors cannot display a password form or raw errors", async () => {
    const h = setup({ verifyOtp: () => ({ data: null, error: { message: "private-provider-token" } }) });
    await h.controller.confirmRecovery();
    expect(h.controller.state.phase).toBe("blocked");
    expect(h.fake.count("getUser")).toBe(0);
    expect(JSON.stringify(h.states)).not.toContain("private-provider-token");
  });
  test("duplicate confirmation is one provider verification and disposed work cannot redirect", async () => {
    const pending = deferred();
    const h = setup({ verifyOtp: () => pending.promise });
    const first = h.controller.confirmRecovery();
    await h.controller.confirmRecovery();
    expect(h.operations).toHaveLength(1);
    h.controller.dispose(); pending.resolve(ok({})); await first;
    expect(h.fake.count("getUser")).toBe(0);
    expect(h.navigations).toEqual([]);
  });
  test("account or factor changes before update stop the write", async () => {
    for (const change of ["account", "factor"]) {
      const h = setup(); await h.controller.confirmRecovery(); await h.controller.verifyTotp(factor().id, "123456");
      if (change === "account") h.fake.model.user = { ...user(), id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" };
      else h.fake.model.factors = [];
      await h.controller.savePassword(PASSWORD, PASSWORD);
      expect(h.operations.some((operation) => operation.method === "updateUser")).toBe(false);
      expect(h.navigations).toEqual([]);
    }
  });
  test("missing assurance, unsupported MFA and false-success verification cannot bypass MFA", async () => {
    for (const type of ["phone", "future-factor"]) {
      const h = setup({ factors: [factor(type)] }); await h.controller.confirmRecovery();
      expect(h.controller.state.phase).toBe("blocked");
    }
    const h = setup({ verify: () => ok({}) });
    await h.controller.confirmRecovery(); await h.controller.verifyTotp(factor().id, "123456");
    expect(h.controller.state.phase).toBe("mfa");
  });
  test("password mismatch is local and a cleanup failure reports saved without automatic navigation", async () => {
    const h = setup({ factors: [], nextLevel: "aal1", signOut: () => ({ error: { message: "private-logout" } }) });
    await h.controller.confirmRecovery();
    await h.controller.savePassword(PASSWORD, "different-password");
    expect(h.operations.some((operation) => operation.method === "updateUser")).toBe(false);
    await h.controller.savePassword(PASSWORD, PASSWORD);
    expect(h.controller.state.phase).toBe("saved");
    expect(h.controller.state.error).toBe("cleanup");
    expect(h.navigations).toEqual([]);
    expect(JSON.stringify(h.states)).not.toContain("private-logout");
  });
  test("recovery request uses a fixed page callback and a non-enumerating success state", async () => {
    const h = setup({ mode: "request" });
    await h.controller.requestEmail("not-an-email"); expect(h.operations).toEqual([]);
    await h.controller.requestEmail("operator@example.invalid");
    expect(h.operations).toEqual([{ method: "resetPasswordForEmail", args: ["operator@example.invalid", { redirectTo: ORIGIN+"/account/verify" }] }]);
    expect(h.controller.state).toEqual({ phase: "sent", busy: false, error: null });
  });
});

test("real pinned SDK recovery preserves factor verification, uses PUT password and local logout, then clears its memory session", async () => {
  const selected = config(), calls = [], navigations = [];
  const account = { ...user(), aud: "authenticated", created_at: "2026-01-01T00:00:00Z", factors: [factor()], app_metadata: {}, user_metadata: {} };
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const session = (aal) => ({ access_token: `${encode({alg:"ES256"})}.${encode({sub:account.id,aal,exp:Math.floor(Date.now()/1000)+3600,amr:[{method:"otp",timestamp:Math.floor(Date.now()/1000)}]})}.${Buffer.from("synthetic-signature").toString("base64url")}`, refresh_token:"synthetic-refresh", token_type:"bearer", expires_in:3600, user:account });
  let client;
  const controller = new RecoveryController({ config:selected, mode:"verify", tokenHash:HASH, origin:ORIGIN,
    createClient: (config,signal) => {
      client = createProviderClient(config,signal,async(input,options) => {
        const url = new URL(String(input)), body = options.body ? JSON.parse(options.body) : null;
        calls.push({ path:url.pathname, method:options.method, body, query:url.search, options });
        if (url.pathname === "/auth/v1/verify") return Response.json(session("aal1"));
        if (url.pathname === "/auth/v1/user") return Response.json(account);
        if (url.pathname.endsWith("/challenge")) return Response.json({ id:"dddddddd-dddd-4ddd-8ddd-dddddddddddd",type:"totp",expires_at:Math.floor(Date.now()/1000)+300 });
        if (url.pathname.endsWith("/verify")) return Response.json(session("aal2"));
        if (url.pathname === "/auth/v1/logout") return new Response(null,{status:204});
        throw new Error("Unexpected synthetic provider request");
      }); return client;
    }, onChange:()=>{}, navigate:(url)=>navigations.push(url) });
  expect(calls).toEqual([]);
  await controller.confirmRecovery(); expect(controller.state.phase).toBe("mfa");
  expect(calls.find((call)=>call.path === "/auth/v1/verify").body).toEqual({token_hash:HASH,type:"recovery",gotrue_meta_security:{}});
  await controller.verifyTotp(factor().id,"123456"); expect(controller.state.phase).toBe("password");
  await controller.savePassword(PASSWORD,PASSWORD);
  expect(navigations).toEqual([SIGN_IN]);
  expect(calls.find((call)=>call.method === "PUT").body).toEqual({password:PASSWORD, code_challenge:null, code_challenge_method:null});
  expect(calls.find((call)=>call.path.endsWith("/logout")).query).toBe("?scope=local");
  expect(calls.every((call)=>call.options.credentials === "omit" && call.options.referrerPolicy === "no-referrer")).toBe(true);
  expect((await client.auth.getSession()).data.session).toBeNull();
  await flush();
});

test("real pinned SDK recovery email request uses the fixed redirect and never creates a signed-in session", async () => {
  const calls = [];
  let client;
  const controller = new RecoveryController({ config:config(), mode:"request", origin:ORIGIN,
    createClient:(selected,signal) => {
      client = createProviderClient(selected,signal,async(input,options) => {
        const url = new URL(String(input));
        expect(url.pathname).toBe("/auth/v1/recover");
        expect(url.searchParams.get("redirect_to")).toBe(ORIGIN+"/account/verify");
        calls.push(JSON.parse(options.body));
        return Response.json({});
      }); return client;
    }, onChange:()=>{}, navigate:()=>{throw new Error("Email request cannot redirect to an authenticated application");} });
  await controller.requestEmail("fixture@example.invalid");
  expect(calls).toEqual([{ email:"fixture@example.invalid", code_challenge:null, code_challenge_method:null, gotrue_meta_security:{} }]);
  expect(controller.state).toEqual({phase:"sent",busy:false,error:null});
  expect((await client.auth.getSession()).data.session).toBeNull();
});
