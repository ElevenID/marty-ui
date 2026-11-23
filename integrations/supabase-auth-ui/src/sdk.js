import { createClient } from "@supabase/supabase-js";

/** Kept injectable so tests can exercise the real pinned SDK without network. */
export function createProviderClient(config, signal, transport = globalThis.fetch) {
  const boundedFetch = (input, options = {}) => {
    const target = new URL(input instanceof Request ? input.url : String(input));
    if (target.origin !== config.supabaseUrl || !target.pathname.startsWith("/auth/v1/") || target.username || target.password) {
      return Promise.reject(new Error("Unsupported authentication endpoint"));
    }
    const signals = [signal, AbortSignal.timeout(15_000)];
    if (options.signal) signals.push(options.signal);
    const requestSignal = AbortSignal.any(signals);
    // In particular, cleanup's local signOut must not revoke a server session
    // before the OAuth application has exchanged its authorization code.
    if (requestSignal.aborted) return Promise.reject(new DOMException("Request cancelled", "AbortError"));
    return transport(input, { ...options, signal: requestSignal, redirect: "error", cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer" });
  };
  return createClient(config.supabaseUrl, config.publishableKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false,
      storageKey: `elevenid-consent-${crypto.randomUUID()}`,
      debug: false,
    },
    global: { fetch: boundedFetch },
  });
}
