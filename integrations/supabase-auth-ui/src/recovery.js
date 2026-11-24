import { requiredMfa, validateConfig, validateCredentials, verifiedUser } from "./protocol.js";

export const RECOVERY_MESSAGES = Object.freeze({
  configuration: "Account recovery is not configured on this site. Contact your operator.",
  request: "This recovery link is invalid or expired. Request a new email from the password recovery page.",
  email: "The email request could not be completed. Try again later.",
  credentials: "Enter a valid email address.",
  session: "Your recovery session could not be verified. Request a new recovery email.",
  mfa: "Account verification could not be completed. Use an enrolled authenticator or contact your operator.",
  code: "Enter the six-digit code from your authenticator app.",
  password: "Use matching passwords with at least 12 characters. Your provider may require additional password rules.",
  save: "The password could not be saved. Check your recovery session and your provider's password requirements.",
  cleanup: "Your password was saved, but we could not finish closing the recovery session. Start a new sign-in from the application.",
});

const STALE = Symbol("stale recovery action");

// Email one-time hashes live only in the fragment. Scrub even malformed links
// before configuration requests, provider requests, rendering or history reuse.
export function consumeRecoveryRequest(address, replaceLocation) {
  const url = new URL(address);
  const clean = new URL(url); clean.search = ""; clean.hash = "";
  replaceLocation(clean.href);
  if (url.search || url.href.split("#")[0].includes("?") || !["/account/recover", "/account/verify"].includes(url.pathname)) throw new Error("request");
  if (url.pathname === "/account/recover") {
    if (url.hash) throw new Error("request");
    return Object.freeze({ mode: "request" });
  }
  const fragment = url.hash.slice(1);
  if (fragment.length > 1024 || !fragment) throw new Error("request");
  const values = new URLSearchParams(fragment);
  if ([...values.keys()].length !== 2 || values.getAll("token_hash").length !== 1 || values.getAll("type").length !== 1
      || values.get("type") !== "recovery" || !/^[A-Za-z0-9_-]{16,512}$/.test(values.get("token_hash") ?? "")) throw new Error("request");
  return Object.freeze({ mode: "verify", tokenHash: values.get("token_hash") });
}

export class RecoveryController {
  #tokenHash = null;
  constructor({ config, mode, tokenHash, origin, createClient, onChange, navigate }) {
    this.config = validateConfig(config);
    if (!this.config.accountLifecycle || !["request", "verify"].includes(mode)
        || !/^https:\/\//.test(origin) || new URL(origin).origin !== origin) throw new Error("configuration");
    this.abort = new AbortController();
    this.client = createClient(this.config, this.abort.signal);
    this.onChange = onChange; this.navigate = navigate;
    this.origin = origin; this.user = null; this.factors = [];
    this.#tokenHash = tokenHash ?? null;
    this.verifiedFactors = null; this.disposed = false; this.verificationStarted = false;
    this.state = Object.freeze({ phase: mode === "request" ? "request" : "confirm", busy: false, error: null });
  }

  check() { if (this.disposed) throw STALE; }
  emit(value) { this.check(); this.state = Object.freeze(value); this.onChange(this.state); }
  async account() {
    const result = await this.client.auth.getUser(); this.check();
    if (result.error) throw new Error("session");
    const user = verifiedUser(result.data?.user);
    if (this.user && (this.user.id !== user.id || this.user.email !== user.email)) throw new Error("session");
    this.user = user;
    const [assurance, listed] = await Promise.all([
      this.client.auth.mfa.getAuthenticatorAssuranceLevel(), this.client.auth.mfa.listFactors(),
    ]); this.check();
    if (assurance.error || listed.error) throw new Error("mfa");
    const factors = requiredMfa(assurance.data, listed.data);
    const verified = listed.data.all.filter((factor) => factor.status === "verified").map((factor) => `${factor.id}:${factor.factor_type}`).sort();
    if (this.verifiedFactors && JSON.stringify(verified) !== JSON.stringify(this.verifiedFactors)) throw new Error("mfa");
    this.verifiedFactors = verified;
    return factors;
  }

  async requestEmail(email) {
    if (this.disposed || this.state.phase !== "request" || this.state.busy) return;
    let normalized;
    try { normalized = validateCredentials(email, "unused").email; }
    catch { this.emit({ phase: "request", busy: false, error: "credentials" }); return; }
    this.emit({ phase: "request", busy: true, error: null });
    try {
      const result = await this.client.auth.resetPasswordForEmail(normalized, { redirectTo: `${this.origin}/account/verify` }); this.check();
      if (result.error) throw new Error("email");
      this.emit({ phase: "sent", busy: false, error: null });
    } catch (error) { if (error !== STALE && !this.disposed) this.emit({ phase: "request", busy: false, error: "email" }); }
  }

  async confirmRecovery() {
    if (this.disposed || this.state.phase !== "confirm" || this.verificationStarted) return;
    this.verificationStarted = true;
    let tokenHash = this.#tokenHash; this.#tokenHash = null;
    if (typeof tokenHash !== "string" || !/^[A-Za-z0-9_-]{16,512}$/.test(tokenHash)) {
      this.emit({ phase: "blocked", busy: false, error: "request" }); return;
    }
    this.emit({ phase: "verifying", busy: true, error: null });
    try {
      const result = await this.client.auth.verifyOtp({ token_hash: tokenHash, type: "recovery" }); tokenHash = null; this.check();
      if (result.error) throw new Error("request");
      this.factors = await this.account();
      this.emit({ phase: this.factors.length ? "mfa" : "password", busy: false, error: null, factors: this.factors });
    } catch (error) { if (error !== STALE && !this.disposed) this.emit({ phase: "blocked", busy: false, error: "request" }); }
    finally { tokenHash = null; }
  }

  async verifyTotp(factorId, code) {
    if (this.disposed || this.state.phase !== "mfa" || this.state.busy) return;
    if (!this.factors.some((factor) => factor.id === factorId) || !/^[0-9]{6}$/.test(code)) {
      this.emit({ ...this.state, error: "code" }); return;
    }
    this.emit({ ...this.state, busy: true, error: null });
    try {
      const verified = await this.client.auth.mfa.challengeAndVerify({ factorId, code }); code = null; this.check();
      if (verified.error) throw new Error("code");
      if ((await this.account()).length) throw new Error("mfa");
      this.emit({ phase: "password", busy: false, error: null });
    } catch (error) { if (error !== STALE && !this.disposed) this.emit({ phase: "mfa", busy: false, error: "mfa", factors: this.factors }); }
    finally { code = null; }
  }

  async savePassword(password, confirmation) {
    if (this.disposed || this.state.phase !== "password" || this.state.busy) return;
    if (typeof password !== "string" || password.length < 12 || password.length > 1024 || password !== confirmation) {
      this.emit({ phase: "password", busy: false, error: "password" }); return;
    }
    this.emit({ phase: "password", busy: true, error: null });
    let saved = false;
    try {
      if ((await this.account()).length) throw new Error("mfa");
      const result = await this.client.auth.updateUser({ password }); password = confirmation = null; this.check();
      if (result.error) throw new Error("save");
      saved = true;
      await this.account();
      const closed = await this.client.auth.signOut({ scope: "local" }); this.check();
      if (closed.error) throw new Error("cleanup");
      this.emit({ phase: "saved", busy: true, error: null });
      this.navigate(this.config.accountLifecycle.signInUri);
    } catch (error) {
      if (error !== STALE && !this.disposed) this.emit({ phase: saved ? "saved" : "password", busy: false, error: saved ? "cleanup" : "save" });
    } finally { password = confirmation = null; }
  }

  dispose() {
    this.disposed = true;
    this.#tokenHash = null;
    this.abort.abort();
    try { Promise.resolve(this.client.auth.stopAutoRefresh()).catch(() => {}); } catch {}
    try { Promise.resolve(this.client.auth.signOut({ scope: "local" })).catch(() => {}); } catch {}
  }
}
