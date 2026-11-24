import {
  UiError, authorizationResponse, requiredMfa, safeError,
  nativeCallbackPost, validateConfig, validateCredentials, validateRedirect, verifiedUser,
} from "./protocol.js";

const STALE = Symbol("stale authorization attempt");

/**
 * The controller is independent of the DOM and never exposes SDK sessions or
 * callback URLs through its public state. Each attempt gets a new memory-only
 * SDK client. The epoch check after every asynchronous boundary prevents an
 * old login/MFA/consent response from affecting a switched account.
 */
export class AuthController {
  constructor({ config, authorizationId, createClient, onChange, navigate, postCallback }) {
    this.config = validateConfig(config);
    this.authorizationId = authorizationId;
    this.createClient = createClient;
    this.onChange = onChange;
    this.navigate = navigate;
    this.postCallback = postCallback;
    this.epoch = 0;
    this.attempt = null;
    this.authorizationStarted = false;
    this.disposed = false;
    this.state = Object.freeze({ phase: "signin", busy: false, error: null });
  }

  emit(state) {
    this.state = Object.freeze(state);
    this.onChange(this.state);
  }

  check(attempt) {
    if (this.disposed || this.attempt !== attempt || attempt.epoch !== this.epoch) throw STALE;
  }

  cleanup(attempt) {
    if (!attempt) return;
    // Abort first: local SDK signOut clears its memory before its attempted
    // server logout. The aborted transport prevents revoking the parent auth
    // session while the OAuth client is about to exchange its code.
    attempt.abort.abort();
    try { Promise.resolve(attempt.client.auth.stopAutoRefresh()).catch(() => {}); } catch {}
    try { Promise.resolve(attempt.client.auth.signOut({ scope: "local" })).catch(() => {}); } catch {}
  }

  reset(phase = "signin", error = null) {
    this.epoch += 1;
    const previous = this.attempt;
    this.attempt = null;
    this.cleanup(previous);
    // Details retrieval can bind/consume the provider authorization even if
    // its response is cancelled. That ID cannot safely be reused by a newly
    // selected account; only the OAuth client can create a fresh request.
    if (phase === "signin" && this.authorizationStarted) {
      phase = "blocked";
      error = "restart";
    }
    this.emit({ phase, busy: false, error, restartRequired: this.authorizationStarted });
  }

  switchAccount() {
    if (!this.disposed) this.reset();
  }

  cancel() {
    if (!this.disposed) this.reset("blocked", "cancelled");
  }

  dispose() {
    this.disposed = true;
    this.epoch += 1;
    const previous = this.attempt;
    this.attempt = null;
    this.cleanup(previous);
  }

  fail(attempt, error, fallback) {
    if (error === STALE || this.disposed || this.attempt !== attempt) {
      // signInWithPassword may have completed after a switch. Clear that old
      // client's newly written session as well as ignoring its result.
      this.cleanup(attempt);
      return;
    }
    this.reset("blocked", safeError(error, fallback));
  }

  async signIn(email, password) {
    if (this.disposed || this.state.phase !== "signin" || this.state.busy) return;
    let credentials;
    try { credentials = validateCredentials(email, password); }
    catch (error) { this.emit({ phase: "signin", busy: false, error: safeError(error, "credentials") }); return; }
    const attempt = { epoch: ++this.epoch, abort: new AbortController(), client: null, user: null, factors: null, selectedFactorId: null, totpVerified: false, details: null, redirect: null };
    this.attempt = attempt;
    this.emit({ phase: "checking", busy: true, error: null });
    try {
      attempt.client = this.createClient(this.config, attempt.abort.signal);
      const result = await attempt.client.auth.signInWithPassword(credentials);
      credentials = null;
      this.check(attempt);
      if (result.error) {
        this.reset("signin", "sign_in");
        return;
      }
      const factors = await this.checkSession(attempt);
      this.check(attempt);
      if (factors.length) this.showMfa(attempt, factors);
      else await this.loadAuthorization(attempt);
    } catch (error) {
      if (error !== STALE && this.attempt === attempt && !attempt.user && !(error instanceof UiError)) this.reset("signin", "sign_in");
      else this.fail(attempt, error, "session");
    } finally {
      credentials = null;
      if (this.attempt !== attempt) this.cleanup(attempt);
    }
  }

  async checkSession(attempt, requireAal2 = false) {
    this.check(attempt);
    const result = await attempt.client.auth.getUser();
    this.check(attempt);
    if (result.error) throw new UiError("session");
    const user = verifiedUser(result.data?.user);
    if (attempt.user && (attempt.user.id !== user.id || attempt.user.email !== user.email)) throw new UiError("session_changed");
    attempt.user = user;
    const [assurance, factors] = await Promise.all([
      attempt.client.auth.mfa.getAuthenticatorAssuranceLevel(),
      attempt.client.auth.mfa.listFactors(),
    ]);
    this.check(attempt);
    if (assurance.error || factors.error) throw new UiError("mfa_unavailable");
    if (requireAal2 && assurance.data?.currentLevel !== "aal2") throw new UiError("mfa_incomplete");
    return requiredMfa(assurance.data, factors.data);
  }

  showMfa(attempt, factors, error = null, busy = false) {
    this.check(attempt);
    attempt.factors = factors;
    this.emit({ phase: "mfa", busy, error, email: attempt.user.email, factors, selectedFactorId: attempt.selectedFactorId ?? factors[0].id });
  }

  async verifyTotp(factorId, code) {
    if (this.disposed || this.state.phase !== "mfa" || this.state.busy) return;
    const attempt = this.attempt;
    if (attempt.factors.some((factor) => factor.id === factorId)) attempt.selectedFactorId = factorId;
    if (!attempt.factors.some((factor) => factor.id === factorId) || typeof code !== "string" || !/^\d{6}$/.test(code)) {
      this.showMfa(attempt, attempt.factors, "mfa_code");
      return;
    }
    this.showMfa(attempt, attempt.factors, null, true);
    try {
      const result = await attempt.client.auth.mfa.challengeAndVerify({ factorId, code });
      this.check(attempt);
      if (result.error) {
        this.showMfa(attempt, attempt.factors, "mfa_failed");
        return;
      }
      const factors = await this.checkSession(attempt, true);
      this.check(attempt);
      if (factors.length) throw new UiError("mfa_incomplete");
      attempt.totpVerified = true;
      await this.loadAuthorization(attempt);
    } catch (error) { this.fail(attempt, error, "mfa_failed"); }
  }

  async loadAuthorization(attempt) {
    this.check(attempt);
    this.authorizationStarted = true;
    const result = await attempt.client.auth.oauth.getAuthorizationDetails(this.authorizationId);
    this.check(attempt);
    if (result.error) throw new UiError("authorization");
    const response = authorizationResponse(result.data, this.config, this.authorizationId, attempt.user);
    const clientId = response.kind === "consent" ? response.details.clientId : response.redirect.clientId;
    if (this.config.clients.find((client) => client.id === clientId)?.callbackMode === "native_mfa_post" && !attempt.totpVerified) throw new UiError("mfa_incomplete");
    if (response.kind === "consent") {
      attempt.details = response.details;
      this.emit({ phase: "consent", busy: false, error: null, email: attempt.user.email, details: response.details });
    } else {
      attempt.redirect = response.redirect;
      this.emit({ phase: "return", busy: false, error: null, email: attempt.user.email, label: response.redirect.label, callbackOrigin: response.redirect.callbackOrigin });
    }
  }

  async decide(outcome) {
    if (this.disposed || this.state.phase !== "consent" || this.state.busy || !["approve", "deny"].includes(outcome)) return;
    const attempt = this.attempt;
    this.emit({ ...this.state, busy: true });
    try {
      const factors = await this.checkSession(attempt, attempt.totpVerified);
      this.check(attempt);
      if (factors.length) throw new UiError("mfa_incomplete");
      // Both SDK methods otherwise navigate automatically, before validation.
      const result = outcome === "approve"
        ? await attempt.client.auth.oauth.approveAuthorization(this.authorizationId, { skipBrowserRedirect: true })
        : await attempt.client.auth.oauth.denyAuthorization(this.authorizationId, { skipBrowserRedirect: true });
      this.check(attempt);
      if (result.error) throw new UiError("decision");
      const redirect = validateRedirect(result.data?.redirect_url, this.config, outcome, attempt.details);
      await this.leave(attempt, redirect, outcome);
    } catch (error) { this.fail(attempt, error, "decision"); }
  }

  async continueToApp() {
    if (this.disposed || this.state.phase !== "return" || this.state.busy) return;
    const attempt = this.attempt;
    this.emit({ ...this.state, busy: true });
    try {
      const factors = await this.checkSession(attempt, attempt.totpVerified);
      this.check(attempt);
      if (factors.length) throw new UiError("mfa_incomplete");
      const redirect = validateRedirect(attempt.redirect.url, this.config, "approve", attempt.redirect);
      await this.leave(attempt, redirect, "approve");
    } catch (error) { this.fail(attempt, error, "session"); }
  }

  async leave(attempt, redirect, outcome) {
    this.check(attempt);
    let handoff;
    if (outcome === "approve" && this.config.clients.find((client) => client.id === redirect.clientId)?.callbackMode === "native_mfa_post") {
      if (!attempt.totpVerified || typeof this.postCallback !== "function") throw new UiError("mfa_incomplete");
      const result = await attempt.client.auth.getSession();
      this.check(attempt);
      if (result.error || result.data?.session?.user?.id !== attempt.user.id) throw new UiError("session");
      handoff = nativeCallbackPost(redirect, this.config, result.data.session.access_token);
    }
    this.epoch += 1;
    this.attempt = null;
    this.cleanup(attempt);
    this.emit({ phase: "leaving", busy: true, error: null, label: redirect.label });
    try { if (handoff) this.postCallback(handoff); else this.navigate(redirect.url); }
    catch { this.emit({ phase: "blocked", busy: false, error: "redirect", restartRequired: true }); }
  }
}
