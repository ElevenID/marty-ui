// All values leaving this module are safe for text-only rendering. Provider
// errors, access tokens, authorization codes and state never enter UI state.
export const MESSAGES = Object.freeze({
  configuration: "This sign-in page is not configured correctly. Contact the operator.",
  request: "This sign-in link is missing, invalid or unsupported. Start again from your application.",
  restart: "This authorization request has already been associated with an account. Return to your application and start a new sign-in to choose another account.",
  credentials: "Enter your email address and password.",
  sign_in: "Sign-in failed. Check your details and try again. If this continues, contact the operator.",
  unverified: "This page requires an existing account with a verified email address. Contact the operator for account help.",
  session: "Your account could not be verified. Start again from your application.",
  session_changed: "The account changed during this request. Start again from your application.",
  mfa_unavailable: "This account requires a verification method this page cannot complete. Use an enrolled authenticator app or contact the operator.",
  mfa_code: "Enter the six-digit code from your selected authenticator app.",
  mfa_failed: "The verification code was not accepted. Try a new code from your authenticator app.",
  mfa_incomplete: "Additional verification was not completed. Start again or contact the operator.",
  authorization: "This authorization request could not be verified. Start again from your application.",
  redirect: "The application return address could not be verified. No redirect was made.",
  decision: "The authorization decision could not be completed. Start again from your application.",
  cancelled: "This sign-in was cancelled. You can close this page and return to your application.",
});

export class UiError extends Error {
  constructor(code) {
    super(MESSAGES[code] ?? MESSAGES.authorization);
    this.name = "UiError";
    this.code = Object.hasOwn(MESSAGES, code) ? code : "authorization";
  }
}

const fail = (code) => { throw new UiError(code); };
const record = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const identifier = (value) => typeof value === "string" && /^[A-Za-z0-9_-]{16,128}$/.test(value);
const noControls = (value) => !/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/u.test(value);
const text = (value, maximum) => typeof value === "string" && value.length > 0 && value.length <= maximum && value.trim() === value && noControls(value);

function closed(value, keys, code) {
  if (!record(value) || Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) fail(code);
}

function httpsUrl(value, code) {
  if (!text(value, 2048) || !value.startsWith("https://") || /\s/u.test(value)) fail(code);
  let parsed;
  try { parsed = new URL(value); } catch { fail(code); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.port || !parsed.hostname.includes(".")) fail(code);
  return parsed;
}

function callback(value, code) {
  const parsed = httpsUrl(value, code);
  // Deliberately narrow callback registrations: exact ordinary paths, no query,
  // fragment, wildcard, percent-encoded path or URL normalization ambiguity.
  if (value !== `${parsed.origin}${parsed.pathname}` || !/^\/[A-Za-z0-9/._~-]*$/.test(parsed.pathname)) fail(code);
  return value;
}

export function validateConfig(input) {
  closed(input, ["schema", "supabaseUrl", "publishableKey", "brand", "clients"], "configuration");
  if (!["elevenid.supabase-auth-ui/v1", "elevenid.supabase-auth-ui/v2"].includes(input.schema)) fail("configuration");
  const nativeModes = input.schema === "elevenid.supabase-auth-ui/v2";
  const project = httpsUrl(input.supabaseUrl, "configuration");
  if (input.supabaseUrl !== project.origin) fail("configuration");
  if (typeof input.publishableKey !== "string" || !/^sb_publishable_[A-Za-z0-9_-]{16,256}$/.test(input.publishableKey)) fail("configuration");
  if (!text(input.brand, 80) || !Array.isArray(input.clients) || input.clients.length < 1 || input.clients.length > 16) fail("configuration");
  const ids = new Set();
  const callbacks = new Set();
  const clients = input.clients.map((client) => {
    closed(client, nativeModes ? ["id", "label", "redirectUris", "callbackMode"] : ["id", "label", "redirectUris"], "configuration");
    if (nativeModes && !["redirect", "native_mfa_post"].includes(client.callbackMode)) fail("configuration");
    if (!identifier(client.id) || ids.has(client.id) || !text(client.label, 100) || !Array.isArray(client.redirectUris) || client.redirectUris.length < 1 || client.redirectUris.length > 8) fail("configuration");
    ids.add(client.id);
    const redirectUris = client.redirectUris.map((uri) => {
      callback(uri, "configuration");
      // An already-consented response carries no client ID. Each callback must
      // therefore identify exactly one locally registered client.
      if (callbacks.has(uri)) fail("configuration");
      callbacks.add(uri);
      return uri;
    });
    return Object.freeze({ id: client.id, label: client.label, redirectUris: Object.freeze(redirectUris), ...(nativeModes ? { callbackMode: client.callbackMode } : {}) });
  });
  return Object.freeze({ schema: input.schema, supabaseUrl: input.supabaseUrl, publishableKey: input.publishableKey, brand: input.brand, clients: Object.freeze(clients) });
}

function query(search, allowed, code, maxLength) {
  if (!search.startsWith("?") || search.length > maxLength || search.length < 2) fail(code);
  const result = new Map();
  for (const pair of search.slice(1).split("&")) {
    const equals = pair.indexOf("=");
    if (equals < 1) fail(code);
    let key;
    let value;
    try {
      key = decodeURIComponent(pair.slice(0, equals).replace(/\+/g, " "));
      value = decodeURIComponent(pair.slice(equals + 1).replace(/\+/g, " "));
    } catch { fail(code); }
    if (!allowed.includes(key) || result.has(key) || !text(value, 2048)) fail(code);
    result.set(key, value);
  }
  return result;
}

export function parseAuthorizationRequest(location) {
  let url;
  try { url = new URL(location); } catch { fail("request"); }
  if (url.href.includes("#")) fail("request");
  const values = query(url.search, ["authorization_id"], "request", 512);
  const id = values.get("authorization_id");
  if (!identifier(id)) fail("request");
  return id;
}

export function consumeAuthorizationRequest(location, replaceLocation) {
  const id = parseAuthorizationRequest(location);
  const clean = new URL(location);
  clean.search = "";
  clean.hash = "";
  // Keep the authorization ID only in this page's memory. Reload/back restores
  // must obtain a fresh request instead of retrying a provider-bound ID.
  replaceLocation(clean.href);
  return id;
}

export function validateCredentials(email, password) {
  if (typeof email !== "string" || !text(email.trim(), 254) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim()) || typeof password !== "string" || password.length < 1 || password.length > 1024) fail("credentials");
  return { email: email.trim(), password };
}

export function verifiedUser(user) {
  if (!record(user) || !identifier(user.id) || !text(user.email, 254) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(user.email) || user.is_anonymous === true) fail("session");
  if (typeof user.email_confirmed_at !== "string" || !Number.isFinite(Date.parse(user.email_confirmed_at))) fail("unverified");
  return Object.freeze({ id: user.id, email: user.email });
}

export function requiredMfa(assurance, factors) {
  if (!record(assurance) || !["aal1", "aal2"].includes(assurance.currentLevel) || !["aal1", "aal2"].includes(assurance.nextLevel) || !record(factors) || !Array.isArray(factors.all) || factors.all.length > 32) fail("mfa_unavailable");
  if (factors.all.some((factor) => !record(factor) || !identifier(factor.id) || !["verified", "unverified"].includes(factor.status) || !text(factor.factor_type, 80))) fail("mfa_unavailable");
  const verified = factors.all.filter((factor) => factor.status === "verified");
  if (assurance.currentLevel === "aal2") return Object.freeze([]);
  const needed = assurance.nextLevel === "aal2" || verified.length > 0;
  if (!needed) return Object.freeze([]);
  const totp = verified.filter((factor) => factor.factor_type === "totp");
  if (!totp.length || totp.some((factor) => !identifier(factor.id))) fail("mfa_unavailable");
  const ids = new Set();
  return Object.freeze(totp.map((factor, index) => {
    if (ids.has(factor.id)) fail("mfa_unavailable");
    ids.add(factor.id);
    return Object.freeze({ id: factor.id, label: text(factor.friendly_name, 80) ? factor.friendly_name : `Authenticator ${index + 1}` });
  }));
}

export function validateDetails(data, config, authorizationId, user) {
  if (!record(data) || Object.hasOwn(data, "redirect_url") || data.authorization_id !== authorizationId || !record(data.client) || !record(data.user) || data.user.id !== user.id || data.user.email !== user.email) fail("authorization");
  const client = config.clients.find((entry) => entry.id === data.client.id);
  if (!client || !text(data.client.name, 120) || !client.redirectUris.includes(data.redirect_uri)) fail("authorization");
  if (typeof data.scope !== "string" || data.scope.length > 2048) fail("authorization");
  const scopes = data.scope.split(" ");
  if (scopes.length < 1 || scopes.length > 32 || new Set(scopes).size !== scopes.length || scopes.some((scope) => !/^[\x21\x23-\x5b\x5d-\x7e]{1,128}$/.test(scope))) fail("authorization");
  return Object.freeze({ clientId: client.id, label: client.label, providerName: data.client.name, redirectUri: data.redirect_uri, callbackOrigin: new URL(data.redirect_uri).origin, scopes: Object.freeze(scopes) });
}

export function validateRedirect(value, config, outcome, expected = null) {
  if (!text(value, 8192)) fail("redirect");
  let parsed;
  try { parsed = new URL(value); } catch { fail("redirect"); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.port || value.includes("#")) fail("redirect");
  const base = value.split("?")[0];
  const client = config.clients.find((entry) => entry.redirectUris.includes(base));
  if (!client || `${parsed.origin}${parsed.pathname}` !== base || (expected && (expected.clientId !== client.id || expected.redirectUri !== base))) fail("redirect");
  const allowed = outcome === "deny" ? ["error", "error_description", "state", "iss"] : ["code", "state", "iss"];
  if (!["approve", "deny"].includes(outcome)) fail("redirect");
  const values = query(parsed.search, allowed, "redirect", 6144);
  if (outcome === "approve" && !/^[A-Za-z0-9._~-]{1,2048}$/.test(values.get("code") ?? "")) fail("redirect");
  if (outcome === "deny" && values.get("error") !== "access_denied") fail("redirect");
  if (values.has("iss") && values.get("iss") !== `${config.supabaseUrl}/auth/v1`) fail("redirect");
  return Object.freeze({ url: value, clientId: client.id, label: client.label, redirectUri: base, callbackOrigin: parsed.origin });
}

export function authorizationResponse(data, config, authorizationId, user) {
  if (!record(data)) fail("authorization");
  if (Object.hasOwn(data, "redirect_url")) {
    if (Object.keys(data).length !== 1) fail("authorization");
    return { kind: "return", redirect: validateRedirect(data.redirect_url, config, "approve") };
  }
  return { kind: "consent", details: validateDetails(data, config, authorizationId, user) };
}

export function safeError(error, fallback) {
  return error instanceof UiError ? error.code : fallback;
}

// This checks transport shape only. Auth must independently verify the native
// signature, issuer, audience, subject, actual MFA events and request freshness,
// alongside its normal OAuth code/state/nonce/PKCE and client checks.
export function nativeCallbackPost(redirect, config, accessToken) {
  const validated = validateRedirect(redirect.url, config, "approve", redirect);
  const client = config.clients.find((entry) => entry.id === validated.clientId);
  if (client?.callbackMode !== "native_mfa_post" || typeof accessToken !== "string" || accessToken.length > 16_384 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(accessToken)) fail("session");
  const values = new URL(validated.url).searchParams;
  const state = values.get("state");
  if (!text(state, 2048)) fail("redirect");
  return Object.freeze({ action: validated.redirectUri, fields: Object.freeze({ code: values.get("code"), state, native_access_token: accessToken }) });
}
