import { describe, expect, test } from "bun:test";
import { AUTHORIZATION_ID, callback, deferred, details, factor, fakeClient, flush, harness, ok, user } from "./fixtures.js";

const signIn = (controller) => controller.signIn("operator@example.invalid", "synthetic-password");

describe("verified sign-in and explicit consent", () => {
  test("login and details never approve; explicit approval verifies again and disables SDK navigation", async () => {
    const h = harness();
    const fake = h.clients[0];
    await signIn(h.controller);
    expect(h.controller.state.phase).toBe("consent");
    expect(fake.count("getUser")).toBe(1);
    expect(fake.count("approve")).toBe(0);
    expect(fake.count("deny")).toBe(0);
    expect(h.navigations).toEqual([]);
    expect(fake.calls.findIndex((call) => call.name === "getUser")).toBeLessThan(fake.calls.findIndex((call) => call.name === "details"));

    await h.controller.decide("approve");
    expect(fake.count("getUser")).toBe(2);
    expect(fake.calls.find((call) => call.name === "approve").args).toEqual([AUTHORIZATION_ID, { skipBrowserRedirect: true }]);
    expect(h.navigations).toEqual([callback()]);
    expect(h.signals[0].aborted).toBe(true);
    expect(fake.calls.find((call) => call.name === "signOut").args).toEqual([{ scope: "local" }]);
    expect(JSON.stringify(h.states)).not.toContain("synthetic-code");
    expect(JSON.stringify(h.states)).not.toContain("synthetic-state");
    expect(JSON.stringify(h.states)).not.toContain("synthetic-password");
  });

  test("deny uses the provider denial and exact validated error callback", async () => {
    const h = harness();
    await signIn(h.controller);
    await h.controller.decide("deny");
    expect(h.clients[0].count("approve")).toBe(0);
    expect(h.clients[0].calls.find((call) => call.name === "deny").args).toEqual([AUTHORIZATION_ID, { skipBrowserRedirect: true }]);
    expect(h.navigations).toEqual([callback("deny")]);
  });

  test("a success response from denial is never followed", async () => {
    const h = harness([fakeClient({ deny: () => ok({ redirect_url: callback() }) })]);
    await signIn(h.controller);
    await h.controller.decide("deny");
    expect(h.controller.state.error).toBe("redirect");
    expect(h.navigations).toEqual([]);
  });

  test("unverified accounts are stopped before MFA or authorization details", async () => {
    const h = harness([fakeClient({ user: { ...user(), email_confirmed_at: null, email_verified: true } })]);
    await signIn(h.controller);
    expect(h.controller.state.error).toBe("unverified");
    expect(h.clients[0].count("details")).toBe(0);
    expect(h.clients[0].count("listFactors")).toBe(0);
  });

  test("server getUser failure wins over a successful password response", async () => {
    const h = harness([fakeClient({ getUser: () => ({ data: { user: user() }, error: { message: "private-provider-body" } }) })]);
    await signIn(h.controller);
    expect(h.controller.state.error).toBe("session");
    expect(h.clients[0].count("details")).toBe(0);
    expect(JSON.stringify(h.states)).not.toContain("private-provider-body");
  });

  test("a changed or disabled account prevents an already-rendered consent action", async () => {
    const h = harness();
    await signIn(h.controller);
    h.clients[0].model.user = { ...user(), id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" };
    await h.controller.decide("approve");
    expect(h.controller.state.error).toBe("session_changed");
    expect(h.clients[0].count("approve")).toBe(0);
    expect(h.navigations).toEqual([]);
  });

  test("unknown client details and unsafe approval redirects fail closed", async () => {
    const unregistered = details();
    unregistered.client.id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    const h1 = harness([fakeClient({ details: unregistered })]);
    await signIn(h1.controller);
    expect(h1.controller.state.error).toBe("authorization");
    const h2 = harness([fakeClient({ approve: () => ok({ redirect_url: "https://attacker.example.invalid/callback?code=secret" }) })]);
    await signIn(h2.controller);
    await h2.controller.decide("approve");
    expect(h2.controller.state.error).toBe("redirect");
    expect(h2.navigations).toEqual([]);
    expect(JSON.stringify(h2.states)).not.toContain("attacker");
  });

  test("raw SDK exceptions and invalid credentials are not reflected or sent", async () => {
    const h = harness([fakeClient({ signIn: () => { throw new Error("password=secret&access_token=private"); } })]);
    await h.controller.signIn("bad-email", "");
    expect(h.created()).toBe(0);
    await signIn(h.controller);
    expect(h.controller.state.error).toBe("sign_in");
    expect(JSON.stringify(h.states)).not.toContain("private");
    expect(JSON.stringify(h.states)).not.toContain("secret");
  });
});

describe("enrolled TOTP enforcement", () => {
  test("cannot reach authorization details until TOTP completes and AAL2 is checked", async () => {
    const h = harness([fakeClient({ factors: [factor()], nextLevel: "aal2" })]);
    const fake = h.clients[0];
    await signIn(h.controller);
    expect(h.controller.state.phase).toBe("mfa");
    expect(fake.count("details")).toBe(0);
    await h.controller.decide("approve");
    expect(fake.count("approve")).toBe(0);
    await h.controller.verifyTotp(factor().id, "123456");
    expect(fake.calls.find((call) => call.name === "verify").args).toEqual([{ factorId: factor().id, code: "123456" }]);
    expect(h.controller.state.phase).toBe("consent");
    expect(fake.count("getUser")).toBe(2);
    expect(fake.count("approve")).toBe(0);
  });

  test("wrong factor, malformed code and provider verification failure cannot proceed", async () => {
    const h = harness([fakeClient({ factors: [factor()], nextLevel: "aal2", verify: () => ({ data: null, error: { message: "private-code-rejected" } }) })]);
    await signIn(h.controller);
    await h.controller.verifyTotp("unknown-factor-id", "123456");
    await h.controller.verifyTotp(factor().id, "12345");
    expect(h.clients[0].count("verify")).toBe(0);
    await h.controller.verifyTotp(factor().id, "123456");
    expect(h.controller.state.phase).toBe("mfa");
    expect(h.controller.state.error).toBe("mfa_failed");
    expect(h.clients[0].count("details")).toBe(0);
    expect(JSON.stringify(h.states)).not.toContain("private-code-rejected");
  });

  test("unmet phone or unknown MFA never falls back to password-only consent", async () => {
    for (const type of ["phone", "webauthn", "future-factor"]) {
      const h = harness([fakeClient({ factors: [factor(type)], nextLevel: "aal2" })]);
      await signIn(h.controller);
      expect(h.controller.state.error).toBe("mfa_unavailable");
      expect(h.clients[0].count("details")).toBe(0);
    }
  });

  test("an MFA success envelope without actual AAL2 cannot bypass verification", async () => {
    const fake = fakeClient({ factors: [factor()], nextLevel: "aal2" });
    fake.model.verify = () => { fake.model.factors = []; fake.model.nextLevel = "aal1"; return ok({}); };
    const h = harness([fake]);
    await signIn(h.controller);
    await h.controller.verifyTotp(factor().id, "123456");
    expect(h.controller.state.error).toBe("mfa_incomplete");
    expect(fake.count("details")).toBe(0);
  });

  test("losing AAL2 after TOTP invalidates the consent decision", async () => {
    const fake = fakeClient({ factors: [factor()], nextLevel: "aal2" });
    const h = harness([fake]);
    await signIn(h.controller);
    await h.controller.verifyTotp(factor().id, "123456");
    fake.model.currentLevel = "aal1";
    fake.model.nextLevel = "aal1";
    fake.model.factors = [];
    await h.controller.decide("approve");
    expect(h.controller.state.error).toBe("mfa_incomplete");
    expect(fake.count("approve")).toBe(0);
  });
});

describe("already-consented responses", () => {
  test("requires explicit Continue, validates destination and never calls approve again", async () => {
    const h = harness([fakeClient({ details: { redirect_url: callback() } })]);
    await signIn(h.controller);
    expect(h.controller.state.phase).toBe("return");
    expect(h.navigations).toEqual([]);
    expect(JSON.stringify(h.controller.state)).not.toContain("synthetic-code");
    await h.controller.decide("approve");
    expect(h.navigations).toEqual([]);
    await h.controller.continueToApp();
    expect(h.navigations).toEqual([callback()]);
    expect(h.clients[0].count("approve")).toBe(0);
    expect(h.clients[0].count("deny")).toBe(0);
    expect(h.clients[0].count("getUser")).toBe(2);
  });

  test("unsafe prior-consent callback is stopped before any Continue action", async () => {
    const h = harness([fakeClient({ details: { redirect_url: "https://attacker.example.invalid/?code=secret" } })]);
    await signIn(h.controller);
    expect(h.controller.state.error).toBe("redirect");
    await h.controller.continueToApp();
    expect(h.navigations).toEqual([]);
  });

  test("local cancellation does not pretend to revoke an existing grant", async () => {
    const h = harness([fakeClient({ details: { redirect_url: callback() } })]);
    await signIn(h.controller);
    h.controller.cancel();
    expect(h.controller.state.error).toBe("cancelled");
    expect(h.clients[0].count("deny")).toBe(0);
    expect(h.clients[0].count("approve")).toBe(0);
    expect(h.signals[0].aborted).toBe(true);
    expect(h.navigations).toEqual([]);
  });

  test("switching a provider-bound request requires a fresh authorization from the application", async () => {
    const h = harness([fakeClient(), fakeClient()]);
    await signIn(h.controller);
    h.controller.switchAccount();
    expect(h.controller.state.error).toBe("restart");
    expect(h.controller.state.restartRequired).toBe(true);
    await h.controller.signIn("another@example.invalid", "synthetic-password");
    expect(h.created()).toBe(1);
    expect(h.navigations).toEqual([]);
  });
});

describe("stale asynchronous work and duplicate actions", () => {
  test("a password response after account switch cannot replace the new account", async () => {
    const pending = deferred();
    const old = fakeClient({ signIn: () => pending.promise });
    const next = fakeClient();
    next.model.user = { ...user(), email: "second@example.invalid" };
    next.model.details.user.email = "second@example.invalid";
    const h = harness([old, next]);
    const firstSignIn = signIn(h.controller);
    h.controller.switchAccount();
    await h.controller.signIn("second@example.invalid", "another-synthetic-password");
    pending.resolve(ok({ session: {}, user: user() }));
    await firstSignIn;
    expect(h.controller.state.email).toBe("second@example.invalid");
    expect(h.created()).toBe(2);
    expect(old.count("getUser")).toBe(0);
    expect(old.count("signOut")).toBeGreaterThan(0);
    expect(h.signals[0].aborted).toBe(true);
    expect(h.signals[1].aborted).toBe(false);
  });

  test("a TOTP response after switching cannot load authorization details", async () => {
    const pending = deferred();
    const fake = fakeClient({ factors: [factor()], nextLevel: "aal2", verify: () => pending.promise });
    const h = harness([fake]);
    await signIn(h.controller);
    const verification = h.controller.verifyTotp(factor().id, "123456");
    h.controller.switchAccount();
    pending.resolve(ok({}));
    await verification;
    expect(h.controller.state.phase).toBe("signin");
    expect(fake.count("details")).toBe(0);
  });

  test("an authorization details result after disposal cannot render consent", async () => {
    const pending = deferred();
    const fake = fakeClient({ details: () => pending.promise });
    const h = harness([fake]);
    const signingIn = signIn(h.controller);
    await flush();
    expect(fake.count("details")).toBe(1);
    h.controller.dispose();
    pending.resolve(ok(details()));
    await signingIn;
    expect(h.states.some((state) => state.phase === "consent")).toBe(false);
    expect(h.navigations).toEqual([]);
  });

  test("switch during details retrieval cannot reuse an ID the provider may already have bound", async () => {
    const pending = deferred();
    const fake = fakeClient({ details: () => pending.promise });
    const h = harness([fake, fakeClient()]);
    const signingIn = signIn(h.controller);
    await flush();
    expect(fake.count("details")).toBe(1);
    h.controller.switchAccount();
    expect(h.controller.state.error).toBe("restart");
    pending.resolve(ok(details()));
    await signingIn;
    await signIn(h.controller);
    expect(h.created()).toBe(1);
    expect(h.states.some((state) => state.phase === "consent")).toBe(false);
  });

  test("double approval sends one request and a late response after switch never redirects", async () => {
    const pending = deferred();
    const fake = fakeClient({ approve: () => pending.promise });
    const h = harness([fake]);
    await signIn(h.controller);
    const deciding = h.controller.decide("approve");
    await h.controller.decide("approve");
    await flush();
    expect(fake.count("approve")).toBe(1);
    h.controller.switchAccount();
    pending.resolve(ok({ redirect_url: callback() }));
    await deciding;
    expect(h.controller.state.error).toBe("restart");
    expect(h.navigations).toEqual([]);
  });
});
