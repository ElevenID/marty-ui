import { requiredMfa, validateConfig, validateCredentials, verifiedUser } from "./protocol.js";

export const SETUP_MESSAGES = Object.freeze({
  configuration: "Account setup is not configured on this site. Contact your operator.",
  request: "This verification link is invalid or expired. Request a new verification email.",
  signup: "The account request could not be completed. Check your details and try again later.",
  password: "Use matching passwords with at least 12 characters. Your provider may require additional password rules.",
  verification: "Email verification must be enabled before this account can be used. Contact your operator.",
  email: "The verification email request could not be completed. Try again later.",
  signin: "Sign-in failed. Check your details and verify your email before setting up an authenticator.",
  setup: "Authenticator setup could not be completed. Start a new sign-in or contact your operator.",
  changed: "Your account verification changed. Start a new sign-in from the application.",
  code: "The verification code was not accepted. Use a new six-digit code from this authenticator.",
  cleanup: "Your account change is complete, but the setup session could not be closed. Start a new sign-in from the application.",
});

const STALE = Symbol("stale account setup");
const hash = (value) => typeof value === "string" && /^[A-Za-z0-9_-]{16,512}$/.test(value);
const uuid = (value) => typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);

export function consumeSetupRequest(address, replaceLocation) {
  const url = new URL(address), clean = new URL(url); clean.search = ""; clean.hash = "";
  replaceLocation(clean.href);
  if (url.href.split("#")[0].includes("?") || !["/account/register", "/account/confirm", "/account/security"].includes(url.pathname)) throw new Error("request");
  if (url.pathname !== "/account/confirm") {
    if (url.hash) throw new Error("request");
    return Object.freeze({ mode: url.pathname.endsWith("register") ? "register" : "security" });
  }
  if (!url.hash) return Object.freeze({ mode: "resend" });
  if (url.hash.length > 1024) throw new Error("request");
  const values = new URLSearchParams(url.hash.slice(1));
  if ([...values.keys()].length !== 2 || values.getAll("token_hash").length !== 1 || values.getAll("type").length !== 1
      || values.get("type") !== "email" || !hash(values.get("token_hash"))) throw new Error("request");
  return Object.freeze({ mode: "confirm", tokenHash: values.get("token_hash") });
}

export class AccountSetupController {
  #tokenHash = null;
  #enrollment = null;
  constructor({ config, mode, tokenHash, origin, createClient, onChange, navigate }) {
    this.config = validateConfig(config);
    if (!this.config.accountLifecycle || !["register", "resend", "confirm", "security"].includes(mode)
        || !origin.startsWith("https://") || new URL(origin).origin !== origin) throw new Error("configuration");
    this.origin = origin; this.onChange = onChange; this.navigate = navigate;
    this.abort = new AbortController(); this.client = createClient(this.config, this.abort.signal);
    this.#tokenHash = tokenHash ?? null; this.user = null; this.disposed = false; this.enrollStarted = false;
    this.state = Object.freeze({ phase: mode === "security" ? "signin" : mode, busy: false, error: null });
  }

  check() { if (this.disposed) throw STALE; }
  emit(state) { this.check(); this.state = Object.freeze(state); this.onChange(this.state); }
  async snapshot() {
    const response = await this.client.auth.getUser(); this.check();
    if (response.error) throw new Error("changed");
    const user = verifiedUser(response.data?.user);
    if (this.user && (this.user.id !== user.id || this.user.email !== user.email)) throw new Error("changed");
    this.user = user;
    const [assurance, listed] = await Promise.all([this.client.auth.mfa.getAuthenticatorAssuranceLevel(), this.client.auth.mfa.listFactors()]); this.check();
    if (assurance.error || listed.error) throw new Error("setup");
    requiredMfa(assurance.data, listed.data);
    return { all: listed.data.all, level: assurance.data.currentLevel };
  }

  async close(destination, phase) {
    this.#tokenHash = null; this.#enrollment = null;
    this.emit({ phase, busy: true, error: null });
    try {
      const result = await this.client.auth.signOut({ scope: "local" }); this.check();
      if (result.error) throw new Error("cleanup");
      this.navigate(destination);
    } catch (error) { if (error !== STALE && !this.disposed) this.emit({ phase, busy: false, error: "cleanup" }); }
  }

  async register(email, password, confirmation) {
    if (this.disposed || this.state.phase !== "register" || this.state.busy) return;
    let credentials;
    try {
      credentials = validateCredentials(email, password);
      if (password.length < 12 || password !== confirmation) throw new Error("password");
    } catch { this.emit({ phase: "register", busy: false, error: "password" }); return; }
    this.emit({ phase: "register", busy: true, error: null });
    try {
      const result = await this.client.auth.signUp({ ...credentials, options: { emailRedirectTo: this.origin+"/account/confirm" } });
      credentials = password = confirmation = null; this.check();
      if (result.error) throw new Error("signup");
      if (result.data?.session) {
        await this.client.auth.signOut({ scope: "local" }); this.check();
        this.emit({ phase: "blocked", busy: false, error: "verification" }); return;
      }
      this.emit({ phase: "sent", busy: false, error: null });
    } catch (error) { if (error !== STALE && !this.disposed) this.emit({ phase: "register", busy: false, error: "signup" }); }
    finally { credentials = password = confirmation = null; }
  }

  async resendEmail(email) {
    if (this.disposed || this.state.phase !== "resend" || this.state.busy) return;
    let normalized;
    try { normalized = validateCredentials(email, "unused").email; }
    catch { this.emit({ phase: "resend", busy: false, error: "email" }); return; }
    this.emit({ phase: "resend", busy: true, error: null });
    try {
      const result = await this.client.auth.resend({ type: "signup", email: normalized, options: { emailRedirectTo: this.origin+"/account/confirm" } }); this.check();
      if (result.error) throw new Error("email");
      this.emit({ phase: "sent", busy: false, error: null });
    } catch (error) { if (error !== STALE && !this.disposed) this.emit({ phase: "resend", busy: false, error: "email" }); }
  }

  async confirmEmail() {
    if (this.disposed || this.state.phase !== "confirm" || this.state.busy) return;
    let tokenHash = this.#tokenHash; this.#tokenHash = null;
    this.emit({ phase: "checking", busy: true, error: null });
    try {
      if (!hash(tokenHash)) throw new Error("request");
      const result = await this.client.auth.verifyOtp({ token_hash: tokenHash, type: "email" }); tokenHash = null; this.check();
      if (result.error) throw new Error("request");
      const account = await this.client.auth.getUser(); this.check();
      if (account.error) throw new Error("request");
      this.user = verifiedUser(account.data?.user);
      await this.close(this.origin+"/account/security", "confirmed");
    } catch (error) { if (error !== STALE && !this.disposed) this.emit({ phase: "blocked", busy: false, error: "request" }); }
    finally { tokenHash = null; }
  }

  async signIn(email, password) {
    if (this.disposed || this.state.phase !== "signin" || this.state.busy) return;
    let credentials;
    try { credentials = validateCredentials(email, password); }
    catch { this.emit({ phase: "signin", busy: false, error: "signin" }); return; }
    this.emit({ phase: "signin", busy: true, error: null });
    try {
      const result = await this.client.auth.signInWithPassword(credentials); credentials = password = null; this.check();
      if (result.error) throw new Error("signin");
      const account = await this.snapshot();
      const verified = account.all.filter((factor) => factor.status === "verified");
      if (verified.length) {
        if (!verified.some((factor) => factor.factor_type === "totp")) throw new Error("setup");
        await this.close(this.config.accountLifecycle.signInUri, "ready"); return;
      }
      this.emit({ phase: "offer", busy: false, error: null });
    } catch (error) { if (error !== STALE && !this.disposed) this.emit({ phase: "signin", busy: false, error: "signin" }); }
    finally { credentials = password = null; }
  }

  async beginEnrollment() {
    if (this.disposed || this.state.phase !== "offer" || this.state.busy || this.enrollStarted) return;
    this.enrollStarted = true;
    this.emit({ phase: "offer", busy: true, error: null });
    try {
      const before = await this.snapshot();
      if (before.all.some((factor) => factor.status === "verified")) throw new Error("changed");
      const result = await this.client.auth.mfa.enroll({ factorType: "totp", issuer: this.config.brand,
        friendlyName: this.config.brand.slice(0,40)+" authenticator "+crypto.randomUUID().slice(0,8) }); this.check();
      const data = result.data, prefix = "data:image/svg+xml;utf-8,";
      if (result.error || !uuid(data?.id) || data.type !== "totp" || !/^[A-Z2-7]{16,256}$/.test(data.totp?.secret ?? "")
          || typeof data.totp?.qr_code !== "string" || !data.totp.qr_code.startsWith(prefix) || data.totp.qr_code.length > 65_536) throw new Error("setup");
      this.#enrollment = { id: data.id, secret: data.totp.secret,
        qr: "data:image/svg+xml;charset=utf-8,"+encodeURIComponent(data.totp.qr_code.slice(prefix.length)) };
      this.emit({ phase: "enroll", busy: false, error: null, showKey: false });
    } catch (error) { if (error !== STALE && !this.disposed) this.emit({ phase: "blocked", busy: false, error: "setup" }); }
  }

  enrollmentDisplay() {
    return !this.disposed && this.state.phase === "enroll" && this.#enrollment
      ? Object.freeze({ qr: this.#enrollment.qr, secret: this.state.showKey ? this.#enrollment.secret : null }) : null;
  }
  toggleSetupKey() { if (!this.disposed && this.state.phase === "enroll" && !this.state.busy) this.emit({ ...this.state, showKey: !this.state.showKey }); }

  async verifyEnrollment(code) {
    if (this.disposed || this.state.phase !== "enroll" || this.state.busy || !this.#enrollment) return;
    if (typeof code !== "string" || !/^[0-9]{6}$/.test(code)) { this.emit({ ...this.state, error: "code" }); return; }
    this.emit({ ...this.state, busy: true, error: null });
    let retryAllowed = false;
    try {
      const before = await this.snapshot(), id = this.#enrollment.id;
      if (before.all.some((factor) => factor.status === "verified") || !before.all.some((factor) => factor.id === id && factor.factor_type === "totp" && factor.status === "unverified")) throw new Error("changed");
      const result = await this.client.auth.mfa.challengeAndVerify({ factorId: id, code }); code = null; this.check();
      if (result.error) {
        // Only an explicit provider OTP rejection establishes a safe retry.
        // A lost verification response may follow a committed enrollment.
        retryAllowed = result.error.name === "AuthApiError"
          && result.error.code === "mfa_verification_failed"
          && [400, 422].includes(result.error.status);
        throw new Error(retryAllowed ? "code" : "changed");
      }
      this.#enrollment = null;
      this.emit({ phase: "checking", busy: true, error: null });
      const after = await this.snapshot();
      if (after.level !== "aal2" || !after.all.some((factor) => factor.id === id && factor.factor_type === "totp" && factor.status === "verified")) throw new Error("changed");
      await this.close(this.config.accountLifecycle.signInUri, "complete");
    } catch (error) {
      if (error !== STALE && !this.disposed) {
        if (!retryAllowed) this.#enrollment = null;
        this.emit({ phase: retryAllowed ? "enroll" : "blocked", busy: false, error: retryAllowed ? "code" : "changed", showKey: false });
      }
    }
    finally { code = null; }
  }

  async cancel() {
    if (this.disposed || this.state.busy) return;
    // Never delete a factor: an interrupted verification may already have
    // committed. Clearing a setup page is not permission to remove MFA.
    await this.close(this.config.accountLifecycle.signInUri, "cancelled");
  }
  dispose() {
    this.disposed = true; this.#tokenHash = null; this.#enrollment = null;
    this.abort.abort();
    try { Promise.resolve(this.client.auth.stopAutoRefresh()).catch(() => {}); } catch {}
    try { Promise.resolve(this.client.auth.signOut({ scope: "local" })).catch(() => {}); } catch {}
  }
}
