import { describe, expect, test } from "bun:test";
import { AccountSetupController, consumeSetupRequest } from "../src/account-setup.js";
import { deferred, factor, fakeClient, ok, publicConfig } from "./fixtures.js";

const ORIGIN = "https://authorization.example.invalid";
const SIGN_IN = "https://elevenid.example.invalid/v1/auth/login";
const HASH = "a".repeat(64);
const PASSWORD = "synthetic-password-only";
const SECRET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const config = () => ({ ...publicConfig(), schema: "elevenid.supabase-auth-ui/v3",
  clients: publicConfig().clients.map((entry) => ({ ...entry, callbackMode: "native_mfa_post" })),
  accountLifecycle: { clientId: publicConfig().clients[0].id, signInUri: SIGN_IN } });

function setup(options = {}) {
  const fake = fakeClient(options), operations = [], states = [], navigations = [];
  for (const name of ["signUp", "resend", "verifyOtp"]) fake.client.auth[name] = async (args) => {
    operations.push({ name, args });
    return options[name] ? options[name](args) : ok({ session: null });
  };
  fake.client.auth.mfa.enroll = async (args) => {
    operations.push({ name: "enroll", args });
    if (options.enroll) return options.enroll(args);
    fake.model.factors.push({ ...factor(), status: "unverified" });
    return ok({ id: factor().id, type: "totp", totp: { secret: SECRET,
      qr_code: 'data:image/svg+xml;utf-8,<svg xmlns="http://www.w3.org/2000/svg"><text>Synthetic only</text></svg>' } });
  };
  if (!options.verify) fake.model.verify = async () => {
    fake.model.currentLevel = "aal2"; fake.model.nextLevel = "aal2";
    fake.model.factors[0].status = "verified"; return ok({});
  };
  const controller = new AccountSetupController({ config: config(), origin: ORIGIN,
    mode: options.mode ?? "security", tokenHash: HASH, createClient: () => fake.client,
    onChange: (state) => states.push(state), navigate: (url) => navigations.push(url) });
  return { controller, fake, operations, states, navigations };
}
async function enroll(h) {
  await h.controller.signIn("operator@example.invalid", PASSWORD);
  await h.controller.beginEnrollment();
}

describe("email setup boundaries", () => {
  test("scrubs a confirmation credential before returning it, and rejects cross-purpose links", () => {
    let clean;
    expect(consumeSetupRequest(`${ORIGIN}/account/confirm#token_hash=${HASH}&type=email`, (value) => { clean = value; }))
      .toEqual({ mode: "confirm", tokenHash: HASH });
    expect(clean).toBe(`${ORIGIN}/account/confirm`);
    for (const suffix of [`?next=evil#token_hash=${HASH}&type=email`, `#token_hash=${HASH}&type=recovery`,
      `#token_hash=${HASH}&type=email&next=evil`, `#token_hash=${HASH}&type=email&type=email`]) {
      expect(() => consumeSetupRequest(`${ORIGIN}/account/confirm${suffix}`, (value) => { clean = value; })).toThrow();
      expect(clean).toBe(`${ORIGIN}/account/confirm`);
    }
  });
  test("confirmation requires a human action, verified server account, and local logout before setup", async () => {
    const h = setup({ mode: "confirm" });
    expect(h.operations).toEqual([]);
    expect(JSON.stringify(h.controller)).not.toContain(HASH);
    await h.controller.confirmEmail();
    expect(h.operations).toEqual([{ name: "verifyOtp", args: { token_hash: HASH, type: "email" } }]);
    expect(h.fake.count("getUser")).toBe(1);
    expect(h.fake.calls.find((call) => call.name === "signOut").args).toEqual([{ scope: "local" }]);
    expect(h.navigations).toEqual([ORIGIN+"/account/security"]);
    await h.controller.confirmEmail();
    expect(h.operations).toHaveLength(1);
  });
  test("expired confirmation reveals no provider error or application session", async () => {
    const h = setup({ mode: "confirm", verifyOtp: () => ({ error: new Error("private-provider-detail") }) });
    await h.controller.confirmEmail();
    expect(h.controller.state).toEqual({ phase: "blocked", busy: false, error: "request" });
    expect(h.navigations).toEqual([]);
    expect(JSON.stringify(h.states)).not.toContain("private-provider-detail");
  });
  test("signup uses the fixed confirmation destination and does not grant application access", async () => {
    const h = setup({ mode: "register" });
    await h.controller.register("operator@example.invalid", PASSWORD, PASSWORD);
    expect(h.operations[0].args).toEqual({ email: "operator@example.invalid", password: PASSWORD,
      options: { emailRedirectTo: ORIGIN+"/account/confirm" } });
    expect(h.controller.state.phase).toBe("sent");
    expect(h.navigations).toEqual([]);
    expect(JSON.stringify(h.states)).not.toContain(PASSWORD);
  });
  test("unexpected auto-confirmed signup is closed rather than accepted", async () => {
    const h = setup({ mode: "register", signUp: () => ok({ session: {} }) });
    await h.controller.register("operator@example.invalid", PASSWORD, PASSWORD);
    expect(h.controller.state.error).toBe("verification");
    expect(h.fake.count("signOut")).toBe(1);
    expect(h.navigations).toEqual([]);
  });
  test("matching password policy is checked before signup", async () => {
    const h = setup({ mode: "register" });
    await h.controller.register("operator@example.invalid", PASSWORD, "different");
    expect(h.operations).toEqual([]);
    expect(h.controller.state.error).toBe("password");
  });
  test("late confirmation after disposal cannot navigate", async () => {
    const gate = deferred(), h = setup({ mode: "confirm", verifyOtp: () => gate.promise });
    const pending = h.controller.confirmEmail(); h.controller.dispose(); gate.resolve(ok({})); await pending;
    expect(h.navigations).toEqual([]);
    expect(h.fake.count("getUser")).toBe(0);
  });
});

describe("initial authenticator enrollment", () => {
  test("password sign-in only offers setup; explicit action creates one owned pending factor", async () => {
    const h = setup();
    await h.controller.signIn("operator@example.invalid", PASSWORD);
    expect(h.controller.state.phase).toBe("offer");
    expect(h.operations).toEqual([]);
    await Promise.all([h.controller.beginEnrollment(), h.controller.beginEnrollment()]);
    expect(h.operations.filter((operation) => operation.name === "enroll")).toHaveLength(1);
    expect(h.controller.state.phase).toBe("enroll");
    expect(h.controller.enrollmentDisplay().secret).toBeNull();
    expect(h.controller.enrollmentDisplay().qr).toStartWith("data:image/svg+xml;charset=utf-8,%3Csvg");
    expect(JSON.stringify(h.controller)).not.toContain(SECRET);
    h.controller.toggleSetupKey(); expect(h.controller.enrollmentDisplay().secret).toBe(SECRET);
    expect(JSON.stringify(h.states)).not.toContain(SECRET);
  });
  test("existing verified authenticator is preserved and returns to fresh application sign-in", async () => {
    const h = setup({ factors: [factor()], nextLevel: "aal2" });
    await enroll(h);
    expect(h.operations).toEqual([]);
    expect(h.navigations).toEqual([SIGN_IN]);
    expect(h.fake.model.factors).toEqual([factor()]);
  });
  test("unverified email cannot reach enrollment", async () => {
    const h = setup(); h.fake.model.user.email_confirmed_at = null;
    await enroll(h);
    expect(h.operations).toEqual([]);
    expect(h.controller.state.phase).toBe("signin");
  });
  test("account change after password sign-in prevents a factor write", async () => {
    const h = setup(); await h.controller.signIn("operator@example.invalid", PASSWORD);
    h.fake.model.user.email = "different@example.invalid";
    await h.controller.beginEnrollment();
    expect(h.operations).toEqual([]);
    expect(h.controller.state.phase).toBe("blocked");
  });
  test("a provider response cannot substitute a remote QR image", async () => {
    const h = setup({ enroll: () => ok({ id: factor().id, type: "totp",
      totp: { secret: SECRET, qr_code: "https://attacker.invalid/image.svg" } }) });
    await enroll(h);
    expect(h.controller.state.phase).toBe("blocked");
    expect(h.controller.enrollmentDisplay()).toBeNull();
  });
  test("successful factor verification requires AAL2 and verified owned factor before logout/return", async () => {
    const h = setup(); await enroll(h);
    await h.controller.verifyEnrollment("123456");
    expect(h.fake.calls.find((call) => call.name === "verify").args).toEqual([{ factorId: factor().id, code: "123456" }]);
    expect(h.controller.enrollmentDisplay()).toBeNull();
    expect(h.controller.state.phase).toBe("complete");
    expect(h.navigations).toEqual([SIGN_IN]);
    expect(h.fake.count("signOut")).toBe(1);
  });
  test("explicit rejected OTP permits retry without exposing the manual key", async () => {
    const h = setup({ verify: () => ({ error: new Error("wrong OTP") }) }); await enroll(h);
    h.controller.toggleSetupKey(); await h.controller.verifyEnrollment("123456");
    expect(h.controller.state.phase).toBe("enroll");
    expect(h.controller.state.error).toBe("code");
    expect(h.controller.enrollmentDisplay().secret).toBeNull();
    expect(h.navigations).toEqual([]);
  });
  test.each(["no-aal2", "wrong-factor", "account-change", "network"])("uncertain or false success closes enrollment: %s", async (kind) => {
    const h = setup({ verify: () => {
      if (kind === "network") throw new Error("private-network-error");
      if (kind === "account-change") h.fake.model.user.email = "changed@example.invalid";
      if (kind !== "no-aal2") h.fake.model.currentLevel = "aal2";
      if (kind !== "wrong-factor") h.fake.model.factors[0].status = "verified";
      return ok({});
    } });
    await enroll(h); await h.controller.verifyEnrollment("123456");
    expect(h.controller.state.phase).toBe("blocked");
    expect(h.controller.enrollmentDisplay()).toBeNull();
    expect(h.navigations).toEqual([]);
  });
  test("cancel clears the seed and session but never removes a provider factor", async () => {
    const h = setup(); await enroll(h); await h.controller.cancel();
    expect(h.controller.enrollmentDisplay()).toBeNull();
    expect(h.fake.model.factors).toHaveLength(1);
    expect(h.fake.model.factors[0].status).toBe("unverified");
    expect(h.navigations).toEqual([SIGN_IN]);
  });
  test("failed cleanup reports completion honestly without navigating", async () => {
    const h = setup({ signOut: () => ({ error: new Error("unavailable") }) }); await enroll(h);
    await h.controller.verifyEnrollment("123456");
    expect(h.controller.state).toEqual({ phase: "complete", busy: false, error: "cleanup" });
    expect(h.navigations).toEqual([]);
    expect(h.controller.enrollmentDisplay()).toBeNull();
  });
});
