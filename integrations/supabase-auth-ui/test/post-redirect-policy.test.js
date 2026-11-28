import { expect, test } from "bun:test";
import example from "../public/config.split-origin.example.json";
import { nativeCallbackPost, validateConfig, validateRedirect } from "../src/protocol.js";

const config = () => structuredClone(example);
const TOKEN = "synthetic_header.synthetic_payload.synthetic_signature";

test("v4 explicitly pins final form-navigation origins and remains idempotently validated", () => {
  const validated = validateConfig(config());
  expect(validateConfig(validated)).toEqual(validated);
  expect(validated.postRedirectOrigins).toEqual(["https://console.example.invalid"]);
  expect(Object.isFrozen(validated.postRedirectOrigins)).toBe(true);
  expect(validated.accountLifecycle.signInUri).toBe("https://api.example.invalid/v1/auth/login");
});

test("older schemas cannot silently broaden form navigation", () => {
  for (const version of ["v1", "v2", "v3"]) {
    const legacy = config(); legacy.schema = `elevenid.supabase-auth-ui/${version}`;
    expect(() => validateConfig(legacy)).toThrow();
  }
  const missing = config(); delete missing.postRedirectOrigins;
  expect(() => validateConfig(missing)).toThrow();
});

test("final navigation accepts only bounded unique exact HTTPS origins", () => {
  for (const invalid of [null, [], "https://console.example.invalid", Array(17).fill("https://console.example.invalid"),
    ["https://console.example.invalid", "https://console.example.invalid"], ["*"], ["https:"],
    ["http://console.example.invalid"], ["https://*.example.invalid"], ["https://console.example.invalid/"],
    ["https://console.example.invalid/console"], ["https://console.example.invalid?next=evil"],
    ["https://console.example.invalid#fragment"], ["https://user:password@console.example.invalid"],
    ["https://console.example.invalid:8443"], ["https://console.example.invalid:443"],
    ["https://console.example.invalid; form-action *"], ["https://Console.example.invalid"], [{}]]) {
    const candidate = config(); candidate.postRedirectOrigins = invalid;
    expect(() => validateConfig(candidate)).toThrow();
  }
});

test("the final navigation origin never becomes a proof callback registration", () => {
  const validated = validateConfig(config());
  const callback = "https://api.example.invalid/v1/auth/callback?code=synthetic-code&state=synthetic-state";
  const redirect = validateRedirect(callback, validated, "approve");
  expect(nativeCallbackPost(redirect, validated, TOKEN)).toEqual({
    action: "https://api.example.invalid/v1/auth/callback",
    fields: { code: "synthetic-code", state: "synthetic-state", native_access_token: TOKEN },
  });
  const consoleCallback = callback.replace("https://api.example.invalid", "https://console.example.invalid");
  expect(() => validateRedirect(consoleCallback, validated, "approve")).toThrow();
  expect(() => nativeCallbackPost({ ...redirect, url: consoleCallback, redirectUri: "https://console.example.invalid/v1/auth/callback" }, validated, TOKEN)).toThrow();
});
