import example from "../public/config.example.json";
import { AuthController } from "../src/controller.js";

export const AUTHORIZATION_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
export const USER_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
export const FACTOR_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
export const publicConfig = () => structuredClone(example);
export const user = () => ({ id: USER_ID, email: "operator@example.invalid", email_confirmed_at: "2026-01-01T00:00:00Z", is_anonymous: false });
export const factor = (type = "totp") => ({ id: FACTOR_ID, factor_type: type, status: "verified", friendly_name: "Primary authenticator" });
export const details = () => ({
  authorization_id: AUTHORIZATION_ID,
  redirect_uri: example.clients[0].redirectUris[0],
  client: { id: example.clients[0].id, name: "ElevenID", uri: "https://ignored.example.invalid", logo_uri: "https://ignored.example.invalid/logo.png" },
  user: { id: USER_ID, email: "operator@example.invalid" },
  scope: "openid email profile",
});
export const callback = (outcome = "approve") => `${example.clients[0].redirectUris[0]}?${outcome === "approve" ? "code=synthetic-code" : "error=access_denied&error_description=User%20denied%20access"}&state=synthetic-state`;
export const ok = (data) => ({ data, error: null });
export const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
export const flush = async () => { for (let i = 0; i < 12; i += 1) await Promise.resolve(); };

export function fakeClient(options = {}) {
  const calls = [];
  const model = { user: user(), factors: [], currentLevel: "aal1", nextLevel: "aal1", details: details(), ...options };
  const method = (name, defaultResult) => async (...args) => {
    calls.push({ name, args });
    return typeof model[name] === "function" ? model[name](...args) : defaultResult(...args);
  };
  const client = { auth: {
    signInWithPassword: method("signIn", () => ok({ session: {}, user: model.user })),
    getUser: method("getUser", () => ok({ user: model.user })),
    signOut: method("signOut", () => ({ error: null })),
    stopAutoRefresh: method("stopAutoRefresh", () => undefined),
    mfa: {
      getAuthenticatorAssuranceLevel: method("assurance", () => ok({ currentLevel: model.currentLevel, nextLevel: model.nextLevel })),
      listFactors: method("listFactors", () => ok({ all: model.factors, totp: model.factors.filter((item) => item.factor_type === "totp") })),
      challengeAndVerify: method("verify", () => { model.currentLevel = "aal2"; return ok({}); }),
    },
    oauth: {
      getAuthorizationDetails: method("details", () => ok(model.details)),
      approveAuthorization: method("approve", () => ok({ redirect_url: callback() })),
      denyAuthorization: method("deny", () => ok({ redirect_url: callback("deny") })),
    },
  } };
  return { client, calls, model, count: (name) => calls.filter((call) => call.name === name).length };
}

export function harness(clients = [fakeClient()]) {
  const states = [];
  const navigations = [];
  const signals = [];
  let created = 0;
  const controller = new AuthController({
    config: publicConfig(),
    authorizationId: AUTHORIZATION_ID,
    createClient: (_config, signal) => { signals.push(signal); return clients[created++].client; },
    onChange: (state) => states.push(state),
    navigate: (url) => navigations.push(url),
  });
  return { controller, clients, states, navigations, signals, created: () => created };
}
