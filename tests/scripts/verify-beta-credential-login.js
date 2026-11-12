#!/usr/bin/env node
/* eslint-disable no-console */

const fs = require('fs');
const path = require('path');
const assert = require('node:assert/strict');
const { createDemoLiveEvidence, acknowledgeDemoInputs, applyLocalNativeReadiness } = require('./demo-live-evidence');
const { createOwnedMembership } = require('./demo-owned-membership');
const { requireJson } = require('./beta-demo-resource-helpers');
const { directPostRequestReference, directPostLoginBinding, loginInstanceOwnership, holderDeclineEvidence, freshDirectPostLogin } = require('./beta-membership-support-contract');
const { login, selectOrg } = require('./audit-beta-credential-lifecycle');
const { acquireWalletSession, openIsolatedWallet } = require('./demo-wallet-session');
const { chromium, request } = require('@playwright/test');
const { createCanvasCaptureCustody, createOriginalCookieSessionContext, retireCanvasBetaSession } = require('./run-canvas-oss-standard-contract');
const {
  collectBetaOffer,
  loadEnvFile,
  redact,
  waitFor,
} = require('./verify-beta-waltid-acceptance');
const {
  VIDEO_SIZE,
  createArtifactDir,
  finalizeVideo,
  maskProtocolField: maskRecordingProtocolField,
  showStep: showRecordingStep,
} = require('./demo-recording');
const {
  DEFAULT_LOGIN_BADGE_CONFIGURATION_ID,
  DEFAULT_LOGIN_BADGE_TEMPLATE_ID,
  DEFAULT_LOGIN_BADGE_APPLICATION_TEMPLATE_ID,
  DEFAULT_LOGIN_BADGE_FLOW_ID,
  DEFAULT_BETA_ORGANIZATION_ID,
  credentialInventoryEvidence,
  membershipLoginBehaviorAssertions,
  requireCompletedLoginNonce,
  loginNonceCompletionEvidence,
  isCredentialLoginDestinationUrl,
} = require('./beta-credential-contract');
const {observeCredentialLoginBrowser} = require('./credential-login-browser-observation');
const {
  installUiCandidateRoute,
  resolveUiCandidateDist,
} = require('./local-ui-candidate');

const ROOT = path.resolve(__dirname, '..', '..');
const BETA_ORIGIN = process.env.BETA_ORIGIN || 'https://beta.elevenidllc.com';
const TEST_WALLET_ORIGIN = process.env.MARTY_TEST_WALLET_ORIGIN || 'http://127.0.0.1:8787';
const MEMBERSHIP_BADGE_VCT = process.env.MARTY_LOGIN_BADGE_VCT
  || `${BETA_ORIGIN}/credentials/marty-verified-member-badge`;
const MEMBERSHIP_BADGE_CONFIGURATION_ID = process.env.EXPECTED_LOGIN_BADGE_CONFIGURATION_ID
  || DEFAULT_LOGIN_BADGE_CONFIGURATION_ID;
const HEADLESS = process.env.HEADED !== '1';
const RECORD_VIDEO = process.env.RECORD_VIDEO === '1';
const LOCAL_BETA_PROXY = process.env.BETA_LOCAL_PROXY === '1';
const CONTROL_IMPLEMENTATION = 'marty-core/marty-test-wallet';
const WALLET_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;

function controlCredentialReceived(badge) {
  return badge?.status === 201 && badge.accepted === true
    && badge.storedExpectedCredential === true && badge.nativeExpectedCredential === true
    && WALLET_ID.test(badge.credentialId || '')
    && ['jwt_vc_json', 'dc+sd-jwt'].includes(badge.credentialFormat);
}

function firstPartyControlAssertions(report) {
  const membership = membershipLoginBehaviorAssertions(report);
  const scope = report.controlScope?.classification === 'FIRST_PARTY_CONTROL'
    && report.controlScope?.implementation === CONTROL_IMPLEMENTATION
    && report.controlScope?.publicWalletProduct === false;
  const session = report.walletSession;
  const closed = report.closedWalletSession;
  return {
    governed_claim: scope && membership.governed_claim
      && WALLET_ID.test(report.ownedResources?.applicationId || '')
      && report.badge?.governedApplicationId === report.ownedResources.applicationId,
    expected_credential_received_and_stored: scope && controlCredentialReceived(report.badge),
    presentation_authenticated: scope && membership.same_device_passwordless_login
      && report.presentation?.status === 200 && report.completion?.authStatus === 200,
    closed_wallet_session_rejected: Boolean(scope
      && session?.implementation === CONTROL_IMPLEMENTATION
      && session?.protocol === 'isolated_sessions_v1' && session.closed === true
      && WALLET_ID.test(session.instanceId || '') && WALLET_ID.test(session.sessionId || '')
      && typeof session.runId === 'string' && session.runId.length > 0
      && closed?.scope === 'CLOSED_SESSION_REJECTION' && closed.status === 410
      && closed.instanceId === session.instanceId && closed.sessionId === session.sessionId
      && closed.runId === session.runId),
  };
}

async function closeControlSession(walletSession, context) {
  await walletSession.close();
  if (walletSession.evidence.closed !== true) throw new Error('Owned control wallet session closure is unconfirmed');
  // Rust rejects a closed run instead of selecting the legacy interactive
  // wallet. This is an API observation of closure, not a TTL-expiry claim.
  const url = `${walletSession.origin}/api/credentials`;
  const response = await context.request.get(url, {
    headers: { 'x-marty-wallet-run-id': walletSession.evidence.runId },
    timeout: 15000, maxRedirects: 0,
  });
  if (response.url() !== url || response.status() !== 410) {
    throw new Error('Closed control wallet session was not rejected with HTTP 410');
  }
  return { scope: 'CLOSED_SESSION_REJECTION', status: 410,
    instanceId: walletSession.evidence.instanceId, sessionId: walletSession.evidence.sessionId,
    runId: walletSession.evidence.runId, observedAt: new Date().toISOString() };
}

async function showStep(page, title, detail) {
  return showRecordingStep(page, title, detail, {
    enabled: RECORD_VIDEO,
    eyebrow: 'Membership badge issuance and credential login',
  });
}

async function maskProtocolField(page, label) {
  return maskRecordingProtocolField(page, label, RECORD_VIDEO);
}

async function receiveBadge(walletPage, offerUri, {
  retainSummary = false, configurationId = MEMBERSHIP_BADGE_CONFIGURATION_ID,
} = {}) {
  await openIsolatedWallet(walletPage, TEST_WALLET_ORIGIN);
  await maskProtocolField(walletPage, 'Credential offer URI');
  await walletPage.getByLabel('Credential offer URI').fill(offerUri);
  const responsePromise = walletPage.waitForResponse((response) => (
    response.url() === `${TEST_WALLET_ORIGIN}/api/receive`
    && response.request().method() === 'POST'
  ), { timeout: 60_000 });
  await walletPage.getByRole('button', { name: /^receive$/i }).click();
  const response = await responsePromise;
  const body = await response.json().catch(() => null);
  const inventory = await walletPage.locator('#credentials').innerText();
  const inventoryEvidence = credentialInventoryEvidence(inventory, {
    vct: MEMBERSHIP_BADGE_VCT,
    configurationId,
  });
  return {
    status: response.status(),
    accepted: response.ok(),
    ...inventoryEvidence,
    ...(retainSummary ? {
      credentialId: body?.id || null,
      credentialFormat: body?.format || null,
      credentialConfigurationId: body?.credential_configuration_id || null,
      credentialVct: body?.vct || null,
      nativeExpectedCredential: body?.credential_configuration_id === configurationId
        || body?.vct === MEMBERSHIP_BADGE_VCT,
    } : {}),
    error: response.ok() ? null : redact(body?.error || 'Credential receipt failed'),
  };
}

async function presentBadge(walletPage, requestUri, { holderDecision = null } = {}) {
  assert([null, 'Approve', 'Cancel'].includes(holderDecision));
  const endpoint = holderDecision === 'Cancel' ? '/api/presentation-decline' : '/api/present';
  const walletUrl = new URL(walletPage.url());
  assert(walletUrl.origin === TEST_WALLET_ORIGIN && walletUrl.pathname === '/', 'Owned wallet UI context changed');
  await maskProtocolField(walletPage, 'Presentation request URI');
  const requestInput = walletPage.getByLabel('Presentation request URI');
  await requestInput.fill(requestUri);
  assert(await requestInput.inputValue() === requestUri, 'Wallet request input changed');
  // Discriminate the actual embedded client before clicking. Never treat a
  // missing/late dialog after Present as permission to bypass consent.
  const consent = walletPage.locator('#presentation-consent');
  const dialogCount = await consent.count();
  assert([0, 1].includes(dialogCount), 'Ambiguous wallet consent UI');
  if (dialogCount === 1) {
    assert.equal(await consent.evaluate(element => element.tagName), 'DIALOG');
    for (const name of ['Approve', 'Cancel']) assert.equal(await consent.getByRole('button', { name, exact: true, includeHidden: true }).count(), 1);
  } else assert.equal(holderDecision, null, 'This holder decision requires the reviewed consent UI');
  const decision = dialogCount === 1 ? holderDecision || 'Approve' : null;
  const consentProtocol = dialogCount === 1 ? 'EXPLICIT_TEST_WALLET_DIALOG_V1' : 'LEGACY_PRESENT_UI';
  const responsePromise = walletPage.waitForResponse((response) => {
    if (response.url() !== `${TEST_WALLET_ORIGIN}${endpoint}` || response.request().method() !== 'POST') return false;
    try { return response.request().postDataJSON()?.request_uri === requestUri; } catch { return false; }
  }, { timeout: 60_000 });
  // An earlier UI failure still owns this waiter; do not leave an unhandled
  // rejection when cleanup closes its page. Awaiting it below still fails.
  responsePromise.catch(() => {});
  await walletPage.getByRole('button', { name: /^present$/i }).click();
  if (decision !== null) {
    await consent.waitFor({ state: 'visible', timeout: 15000 });
    await consent.getByRole('button', { name: decision, exact: true }).click({ timeout: 15000 });
    await consent.waitFor({ state: 'hidden', timeout: 15000 });
  }
  const response = await responsePromise;
  const body = await response.json().catch(() => null);
  if (holderDecision === 'Cancel') return { status: response.status(),
    acknowledged: response.ok() && body?.acknowledged === true,
    verifierHttpStatus: body?.submission?.verifier_http_status ?? null, holderDecision: decision, consentProtocol };
  return {
    status: response.status(),
    accepted: response.ok() && body?.ok === true,
    holderDecision: decision, consentProtocol,
    error: response.ok() ? null : redact(body?.error || 'Presentation failed'),
  };
}

async function bindMembershipLogin(loginPage, operator, details, organizationId, startedAt, acknowledgeOwned = async () => {}) {
  const reference = directPostRequestReference(details, BETA_ORIGIN);
  const instancePath = `/v1/flows/instances/${reference.instanceId}`;
  const before = await requireJson(operator, instancePath);
  const window = { afterMs: startedAt - 15000, beforeMs: Date.now() + 15000 };
  const ownership = loginInstanceOwnership({ ...details, dcApiRequestUrl: reference.url }, before,
    { login: { organizationId } }, BETA_ORIGIN, window);
  // Retain an independently owned identity before request emission/validation.
  // A later transport failure can still retire this exact Flow, never a scan.
  await acknowledgeOwned({ ...ownership, instancePath });
  const response = await loginPage.context().request.get(reference.url, { timeout: 15000, maxRedirects: 0 });
  assert.equal(response.status(), 200);
  assert.equal(response.url(), reference.url);
  const instance = await requireJson(operator, instancePath);
  const binding = directPostLoginBinding(details, instance, organizationId, BETA_ORIGIN, window, await response.text());
  for (const key of ['contextPolicyPresent', 'contextPolicyId', 'contextTrustProfilePresent', 'contextTrustProfileId']) {
    assert.equal(binding[key], ownership[key], 'Owned login scope changed during request emission');
  }
  return binding;
}

async function observeDeclinedLogin(context, nonce) {
  const auth = async () => {
    const response = await context.request.get(`${BETA_ORIGIN}/v1/auth/me`, { timeout: 15000, maxRedirects: 0 });
    assert.equal(response.status(), 200);
    assert.equal((await response.json()).authenticated, false);
    assert.equal((await context.cookies(BETA_ORIGIN)).some(cookie => cookie.name === 'sessionId'), false);
  };
  await auth();
  const finalized = await context.request.get(`${BETA_ORIGIN}/v1/auth/credential-login/finalize?nonce=${encodeURIComponent(nonce)}`,
    { timeout: 15000, maxRedirects: 0 });
  const finalizeSetCookie = Boolean(finalized.headers()['set-cookie']);
  assert.equal(finalizeSetCookie, false);
  assert([400, 302].includes(finalized.status()), 'Declined request finalized a login');
  if (finalized.status() === 302) {
    const destination = new URL(finalized.headers().location, BETA_ORIGIN);
    assert(destination.origin === BETA_ORIGIN && destination.pathname === '/' && !destination.hash
      && !destination.username && !destination.password && destination.searchParams.get('auth_error')?.trim(),
    'Declined request requires the actual Auth error destination');
  }
  await auth();
  return { authHttpStatus: 200, authenticated: false, sessionCookiePresent: false,
    finalizeStatus: finalized.status(), finalizeSetCookie };
}

function membershipSessionRetirement(runId) {
  const sessions = new Map();
  async function capture(role, context) {
    const cookies = await context.cookies(BETA_ORIGIN);
    const session = cookies.filter(cookie => cookie.name === 'sessionId');
    assert.equal(session.length, 1, 'Owned membership session requires its original cookie');
    if ([...sessions.values()].some(row => row.sessionId === session[0].value)) return;
    assert.ok(!sessions.has(role), 'Owned membership session role cannot be replaced');
    const custody = createCanvasCaptureCustody(`${runId}-${role}`);
    // Publish custody before the next owned API effect, not after logout clears the jar.
    sessions.set(role, { custody, sessionId: session[0].value, cookies: JSON.parse(JSON.stringify(cookies)) });
    custody.retain('betaAdminSession', JSON.stringify(cookies));
  }
  async function retire() {
    const results = [];
    for (const [role, row] of sessions) {
      let isolated;
      try {
        const cookies = row.cookies.map(cookie => ({ ...cookie }));
        const original = await createOriginalCookieSessionContext(request, cookies);
        isolated = original.isolated;
        const retirement = await retireCanvasBetaSession(original.session, row.custody);
        await isolated.dispose(); isolated = null;
        assert.equal(row.custody.retire(), true, 'Original session custody retirement unconfirmed');
        results.push({ role, ...retirement, originalCookieVerified: true, custodyRetired: true });
      } catch (error) {
        results.push({ role, originalCookieVerified: false, custodyRetired: false });
      } finally { if (isolated) await isolated.dispose().catch(() => {}); }
    }
    return { complete: sessions.size > 0 && results.every(row => row.originalCookieVerified && row.custodyRetired), sessions: results };
  }
  return { capture, retire };
}

async function runCredentialLogin({ retainedFirstParty = false, retainedMembership = false, evidence = null } = {}) {
  const ownedMembership = retainedFirstParty || retainedMembership;
  loadEnvFile(path.join(ROOT, '.env.tunnel.beta.local'));
  loadEnvFile(path.join(ROOT, '.env'));
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '');
  const artifactDir = createArtifactDir(ROOT, `beta-credential-login-${stamp}`);
  const uiCandidate = resolveUiCandidateDist(ROOT);
  if (ownedMembership && (!['0', '1'].includes(process.env.RECORD_VIDEO) || LOCAL_BETA_PROXY || uiCandidate
    || process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0' || new URL(BETA_ORIGIN).protocol !== 'https:')) {
    throw new Error('Retained first-party control requires explicit recording mode and authenticated deployed HTTPS');
  }
  const inputs = ownedMembership ? await acknowledgeDemoInputs(artifactDir, 'first-party-run-input.json', {
    runId: process.env.DEMO_EXECUTION_EVIDENCE_RUN_ID,
    organizationId: process.env.BETA_AUDIT_ORG_ID || DEFAULT_BETA_ORGANIZATION_ID,
    credentialTemplateId: process.env.LOGIN_BADGE_TEMPLATE_ID || DEFAULT_LOGIN_BADGE_TEMPLATE_ID,
    sourceApplicationTemplateId: process.env.LOGIN_BADGE_APPLICATION_TEMPLATE_ID || DEFAULT_LOGIN_BADGE_APPLICATION_TEMPLATE_ID,
    sourceFlowDefinitionId: DEFAULT_LOGIN_BADGE_FLOW_ID,
    configurationId: MEMBERSHIP_BADGE_CONFIGURATION_ID, vct: MEMBERSHIP_BADGE_VCT,
    email: process.env.TEST_APPLICANT_EMAIL, givenName: 'Jamie', familyName: 'Lee',
    identityBoundary: 'AUTHORIZED_EXISTING_BETA_TEST_ACCOUNT_WITH_SYNTHETIC_FORM_VALUES',
  }, evidence) : null;
  if (inputs) {
    assert.match(inputs.runId || '', /^[a-f0-9-]{36}$/i);
    assert.match(inputs.email || '', /^[^\s@]+@[^\s@]+\.[^\s@]+$/);
    assert.equal(inputs.email, process.env.DEMO_FIRST_PARTY_AUTHORIZED_APPLICANT,
      'Explicit authorization for the reserved beta test account is required');
  }
  const explain = ownedMembership
    ? (page, title, detail) => showRecordingStep(page, title, detail, {
      enabled: RECORD_VIDEO, eyebrow: 'First-party browser wallet control',
    }) : showStep;

  const browser = await chromium.launch({
    headless: HEADLESS,
    args: LOCAL_BETA_PROXY
      ? ['--host-resolver-rules=MAP beta.elevenidllc.com 127.0.0.1', '--no-proxy-server']
      : [],
  });
  const report = {
    startedAt: new Date().toISOString(),
    betaOrigin: BETA_ORIGIN,
    walletOrigin: TEST_WALLET_ORIGIN,
    artifactDir,
    pageErrors: [],
    badResponses: [],
    consoleErrors: [],
    ...(ownedMembership ? {
      scenario: retainedMembership ? 'membership-badge-login' : 'first-party-browser-wallet',
      controlScope: { classification: 'FIRST_PARTY_CONTROL', implementation: CONTROL_IMPLEMENTATION,
        productPath: 'GOVERNED_MEMBERSHIP_CLAIM_AND_CREDENTIAL_LOGIN', publicWalletProduct: false },
      limitations: [
        'This fresh run uses the governed membership product path with the internal Rust development/test wallet.',
        ...(retainedMembership ? ['Holder decline is observed through the first-party test wallet. This run does not qualify untrusted-issuer, expired-offer or independent-wallet behavior.'] : []),
        'Closed-session rejection is observed through the Rust wallet API; it does not qualify TTL expiry, public-device isolation or a public wallet product.',
        'A fresh owned application uses an authorized existing beta test account with synthetic form values. Its credential and application-template authority are retired after this run.',
      ],
    } : {}),
    uiCandidate: uiCandidate ? {
      mode: 'LOCAL_DIST_ENGINEERING_ONLY',
      sourceRevision: uiCandidate.sourceRevision,
      path: uiCandidate.relative,
      qualifiesAsDeployedEvidence: false,
    } : {
      mode: 'DEPLOYED_BETA',
      qualifiesAsDeployedEvidence: true,
    },
  };

  if (retainedMembership) report.membershipLoginFlows = [];
  const saveMembershipProgress = () => {
    if (retainedMembership) fs.writeFileSync(path.join(artifactDir, 'membership-consent-progress.json'),
      JSON.stringify({ flows: report.membershipLoginFlows, holderDecline: report.holderDecline || null }) + '\n', { mode: 0o600 });
  };
  let walletSession, walletContext, loginContext, holderContext, adminContext, adminPage;
  let control, loginVideo, walletVideo;
  const sessionRetirement = ownedMembership ? membershipSessionRetirement(inputs.runId) : null;
  try {
    if (ownedMembership) {
      adminContext = await browser.newContext({ viewport: VIDEO_SIZE });
      adminPage = await adminContext.newPage();
      evidence.bindPage(adminPage);
      await login(adminPage, process.env.TEST_ADMIN_EMAIL, process.env.TEST_ADMIN_PASSWORD);
      await sessionRetirement.capture('admin', adminContext);
      assert.equal((await selectOrg(adminPage)).ok, true);
      control = createOwnedMembership(adminPage, inputs);
      report.ownedResources = control.owned;
      report.demonstrationBoundary = { setup: 'AUTHENTICATED_PUBLIC_API', claim: 'REAL_APPLICANT_UI',
        receiptAndPresentation: 'REAL_RUST_WALLET_UI', cryptography: 'PRODUCTION_KMS_AND_VERIFIER', recording: RECORD_VIDEO };
    }
    walletContext = await browser.newContext({
      viewport: VIDEO_SIZE,
      ignoreHTTPSErrors: LOCAL_BETA_PROXY,
      ...(RECORD_VIDEO ? { recordVideo: { dir: artifactDir, size: VIDEO_SIZE } } : {}),
    });
    walletSession = await acquireWalletSession(walletContext, { origin: TEST_WALLET_ORIGIN });
    report.walletSession = walletSession.evidence;

    const offerResult = await collectBetaOffer(browser, {
      walletId: 'wr-default',
      logoutAfterOffer: true,
      keepContext: RECORD_VIDEO || ownedMembership,
      prepareApplication: control ? async (page) => {
        await sessionRetirement.capture('claim', page.context());
        return control.prepare(page);
      } : null,
      onPage: evidence ? (page) => evidence.bindPage(page) : null,
      contextOptions: RECORD_VIDEO ? { viewport: VIDEO_SIZE, recordVideo: { dir: artifactDir, size: VIDEO_SIZE } } : {},
      onStep: explain,
      setupContext: async (context) => {
        if (ownedMembership) holderContext = context;
        await installUiCandidateRoute(context, uiCandidate, BETA_ORIGIN);
      },
    });
    const { context: offerContext = null, page: holderPage = null, ...offer } = offerResult;
    holderContext = offerContext;
    report.badResponses.push(...(offer.badResponses || []));
    report.consoleErrors.push(...(offer.consoleErrors || []));
    const holderVideo = holderPage?.video() || null;
    await installUiCandidateRoute(walletContext, uiCandidate, BETA_ORIGIN);
    const walletPage = await walletContext.newPage();
    if (evidence) evidence.bindPage(walletPage);
    walletPage.on('pageerror', (error) => report.pageErrors.push(redact(error.message)));
    walletPage.on('console', (message) => {
      if (message.type() === 'error') report.consoleErrors.push(redact(message.text()).slice(0, 400));
    });
    walletVideo = walletPage.video();
    await explain(
      walletPage,
      'Browser wallet opened',
      'This local browser wallet exercises the same OpenID4VCI and OpenID4VP handoffs without exposing protocol secrets.',
    );
    report.badge = {
      offerSource: offer.offerSource,
      ...(control ? { governedApplicationId: control.owned.applicationId } : {}),
      loggedOut: offer.loggedOut === true,
      ...await receiveBadge(walletPage, offer.offerUri, { retainSummary: ownedMembership,
        ...(inputs ? { configurationId: inputs.configurationId } : {}) }),
    };
    if (ownedMembership && !controlCredentialReceived(report.badge)) {
      throw new Error('The control wallet did not receive and store the exact expected credential');
    }
    await explain(
      walletPage,
      'Membership badge received',
      'The wallet now contains the Marty Verified Member Open Badge issued by the canonical claim endpoint.',
    );
    await walletPage.screenshot({ path: path.join(artifactDir, '01-wallet-with-badge.png'), fullPage: true });

    loginContext = holderContext || await browser.newContext({
      viewport: VIDEO_SIZE,
      ignoreHTTPSErrors: LOCAL_BETA_PROXY,
      ...(RECORD_VIDEO ? { recordVideo: { dir: artifactDir, size: VIDEO_SIZE } } : {}),
    });
    if (!holderContext) await installUiCandidateRoute(loginContext, uiCandidate, BETA_ORIGIN);
    // This lane drives presentation through the deterministic local wallet.
    // Keep Chromium's platform-wallet prefetch from racing the same request URI.
    await loginContext.addInitScript(() => {
      Object.defineProperty(globalThis, 'DigitalCredential', {
        value: undefined,
        configurable: false,
      });
    });
    const loginPage = holderPage || await loginContext.newPage();
    loginVideo = holderVideo || loginPage.video();
    if (evidence && !holderPage) evidence.bindPage(loginPage);
    loginPage.on('pageerror', (error) => report.pageErrors.push(redact(error.message)));
    loginPage.on('console', (message) => {
      if (message.type() === 'error') report.consoleErrors.push(redact(message.text()).slice(0, 400));
    });
    loginPage.on('response', (response) => {
      if (response.url().startsWith(BETA_ORIGIN) && response.status() >= 400) {
        report.badResponses.push({
          status: response.status(),
          method: response.request().method(),
          url: redact(response.url()),
        });
      }
    });
    const openLoginRequest = async () => {
      const startedAt = Date.now();
      const entry = retainedMembership ? { createAttempted: true, retirementConfirmed: false, startedAt } : null;
      if (entry) { report.membershipLoginFlows.push(entry); saveMembershipProgress(); }
      await loginPage.goto(`${BETA_ORIGIN}/v1/auth/credential-login`, {
        waitUntil: 'domcontentloaded', timeout: 60_000,
      });
      const details = await loginPage.evaluate(() => ({
        nonce: document.body.dataset.nonce,
        href: document.querySelector('#wallet-link')?.href || null,
        walletOptions: Array.from(document.querySelectorAll('#wallet-select option'))
          .map((option) => option.textContent.trim()),
      }));
      if (!details.nonce || !details.href) throw new Error('Credential login did not provide a nonce and presentation link');
      const binding = retainedMembership ? await bindMembershipLogin(loginPage, adminPage, details, inputs.organizationId, startedAt,
        async ownership => { entry.binding = ownership; saveMembershipProgress(); }) : null;
      if (entry) { entry.binding = binding; saveMembershipProgress(); }
      return { details, binding };
    };
    let currentRequest = await openLoginRequest();
    if (retainedMembership) {
      const signedOut = await loginContext.request.get(`${BETA_ORIGIN}/v1/auth/me`, { timeout: 15000, maxRedirects: 0 });
      assert.equal(signedOut.status(), 200);
      assert.equal((await signedOut.json()).authenticated, false);
      assert.equal((await loginContext.cookies(BETA_ORIGIN)).some(cookie => cookie.name === 'sessionId'), false);
      await explain(walletPage, 'Choose not to share', 'The holder clicks Cancel in the test wallet. No presentation is signed or submitted.');
      const acknowledgement = await presentBadge(walletPage, currentRequest.details.href, { holderDecision: 'Cancel' });
      const cancelled = await requireJson(adminPage, currentRequest.binding.instancePath);
      const noSession = await observeDeclinedLogin(loginContext, currentRequest.details.nonce);
      report.holderDecline = holderDeclineEvidence(currentRequest.binding, cancelled, acknowledgement, noSession);
      saveMembershipProgress();
      const firstBinding = currentRequest.binding;
      currentRequest = await openLoginRequest();
      report.freshRequestDistinct = freshDirectPostLogin(firstBinding, currentRequest.binding);
      report.membershipRetryBinding = currentRequest.binding;
      await explain(loginPage, 'Start a fresh request', 'The new sign-in request has a different Auth nonce, Flow, presentation nonce and state. The holder now chooses Approve.');
    }
    const loginRequest = currentRequest.details;
    await explain(
      loginPage,
      'Credential login request ready',
      'The signed presentation request asks the wallet for the membership badge and required email disclosure.',
    );
    report.loginPage = {
      hasNonce: true,
      walletOptions: loginRequest.walletOptions,
    };
    // The browser owns the one-use finalize; bind its status and redirect before presentation.
    const loginObservation = observeCredentialLoginBrowser(loginPage, BETA_ORIGIN, loginRequest.nonce);
    report.presentation = await presentBadge(walletPage, loginRequest.href, { holderDecision: retainedMembership ? 'Approve' : null });
    if (!report.presentation.accepted || (ownedMembership && report.presentation.status !== 200)) {
      throw new Error(`Browser wallet presentation failed: ${report.presentation.error || 'unknown error'}`);
    }
    await explain(
      walletPage,
      'Membership badge presented',
      'The browser wallet submitted the selected badge to the signed credential-login callback.',
    );

    const {nonceEvidence, statusObservation: nonceStatusObservation,
      browserFinalize, terminalObserved} = await loginObservation.completion();
    report.completion = { ...nonceEvidence, authenticated: false,
      statusObservation: nonceStatusObservation,
      browserFinalizeVerified: browserFinalize?.verified === true,
      browserFinalize: browserFinalize || null };
    if (!terminalObserved && !browserFinalize) {
      let diagnosticTimer;
      const diagnostic = await Promise.race([
        loginPage.evaluate(async (nonce) => {
          const [status, auth] = await Promise.all([
            fetch(`/v1/auth/credential-login/status?nonce=${encodeURIComponent(nonce)}`,
              { credentials: 'same-origin', signal: AbortSignal.timeout(8_000) }).catch(() => null),
            fetch('/v1/auth/me',
              { credentials: 'same-origin', signal: AbortSignal.timeout(8_000) }).catch(() => null),
          ]);
          const body = status ? await status.json().catch(() => null) : null;
          const authBody = auth ? await auth.json().catch(() => null) : null;
          return { statusHttp: status?.status || null,
            statusBody: { status: body?.status, reason_code: body?.reason_code },
            authHttp: auth?.status || null, authenticated: authBody?.authenticated === true };
        }, loginRequest.nonce).catch(() => null),
        new Promise(resolve => { diagnosticTimer = setTimeout(() => resolve(null), 10_000); }),
      ]).finally(() => clearTimeout(diagnosticTimer));
      report.completion.timeoutDiagnostic = {
        statusHttp: diagnostic?.statusHttp || null,
        ...loginNonceCompletionEvidence(diagnostic?.statusBody),
        authHttp: diagnostic?.authHttp || null,
        authenticated: diagnostic?.authenticated === true,
      };
    }
    requireCompletedLoginNonce(nonceEvidence.status);
    if (!browserFinalize?.verified) throw new Error('Credential login browser finalize not verified');
    await loginPage.waitForURL((url) => isCredentialLoginDestinationUrl(url.href, BETA_ORIGIN),
    { timeout: 60_000 });
    report.completion.uiDestinationVerified = true;
    await waitFor(() => loginPage.evaluate(async () => {
      const response = await fetch('/v1/auth/me', { credentials: 'include' });
      const body = await response.json().catch(() => null);
      return body?.authenticated === true ? true : null;
    }), 60_000, 500);
    if (ownedMembership) await sessionRetirement.capture('credential-login', loginPage.context());
    const auth = await loginPage.evaluate(async () => {
      const response = await fetch('/v1/auth/me', { credentials: 'include' });
      return { status: response.status, body: await response.json().catch(() => null) };
    });
    await loginPage.screenshot({ path: path.join(artifactDir, '02-login-complete.png'), fullPage: true });

    report.completion = {
      ...nonceEvidence,
      statusObservation: nonceStatusObservation,
      browserFinalizeVerified: true,
      browserFinalize,
      uiDestinationVerified: true,
      authenticated: auth.body?.authenticated === true,
      authStatus: auth.status,
      authenticatedEmail: auth.body?.authenticated ? auth.body?.user?.email : null,
    };
    if (ownedMembership && report.completion.authenticatedEmail?.toLowerCase() !== inputs.email.toLowerCase()) {
      throw new Error('Credential login resolved a different account');
    }
    if (ownedMembership && !firstPartyControlAssertions(report).presentation_authenticated) {
      throw new Error('The control presentation did not establish an authenticated HTTP 200 session');
    }
    await explain(
      loginPage,
      'Credential login complete',
      'The badge presentation resolved the existing user and created a new authenticated ElevenID session.',
    );
    report.behaviorAssertions = membershipLoginBehaviorAssertions(report);
    if (retainedMembership) {
      report.holderConsentAssertions = {
        holder_cancel_no_session: report.holderDecline?.kind === 'ACTUAL_TEST_WALLET_UI_HOLDER_DECLINE'
          && report.holderDecline.terminalStatus === 'CANCELLED' && report.holderDecline.noSession.authenticated === false,
        fresh_request_approved_login: report.freshRequestDistinct === true && report.presentation.accepted === true
          && report.completion.authenticated === true && report.completion.browserFinalizeVerified === true,
      };
      assert(Object.values(report.holderConsentAssertions).every(value => value === true), 'Actual holder consent and recovery required');
      report.behaviorAssertions.holder_cancel_no_session = Object.values(report.holderConsentAssertions).every(value => value === true);
    }
    report.engineeringReady = (
      Object.values(report.behaviorAssertions).every((passed) => passed === true)
      && report.pageErrors.length === 0
      && report.badResponses.length === 0
      && report.consoleErrors.length === 0
    );
    report.releaseReady = report.engineeringReady && !uiCandidate;
    report.finishedAt = new Date().toISOString();
    if (ownedMembership) {
      report.closedWalletSession = await closeControlSession(walletSession, walletContext);
      if (retainedFirstParty) {
        report.firstPartyControlAssertions = firstPartyControlAssertions(report);
        if (!Object.values(report.firstPartyControlAssertions).every(value => value === true)) {
          throw new Error('The retained first-party control contract did not pass');
        }
      }
      await explain(walletPage, 'Run-owned wallet session closed',
        "The Rust control closed this run's session. A fresh credential-list API request for that run is rejected with HTTP 410.");
      report.finishedAt = new Date().toISOString();
    } else await walletSession.close();
  } catch (error) {
    report.finishedAt = new Date().toISOString();
    report.releaseReady = false;
    report.engineeringReady = false;
    report.error = redact(error.stack || error.message || String(error));
  } finally {
    if (retainedMembership) {
      const { retireLoginFlow } = require('./dev-test-wallet-contract');
      for (const entry of report.membershipLoginFlows) {
        try {
          assert(entry.binding, 'Unknown login creation outcome requires explicit reconciliation');
          const retired = await retireLoginFlow({ binding: entry.binding,
            readInstance: () => requireJson(adminPage, entry.binding.instancePath),
            beforeCancel: async () => { entry.cleanupCancelAttempted = true; saveMembershipProgress(); },
            cancel: () => requireJson(adminPage, entry.binding.instancePath + '/cancel', { method: 'POST' }).then(() => ({ ok: true })) });
          entry.retirementConfirmed = true; entry.terminalStatus = retired.status;
          saveMembershipProgress();
        } catch (error) {
          report.cleanupErrors ||= [];
          report.cleanupErrors.push({ operation: 'owned_membership_login_flow', error: redact(error.message) });
          report.engineeringReady = false;
        }
      }
    }
    if (control) {
      try { report.cleanup = await control.cleanup(); }
      catch (error) { report.cleanupError = redact(error.message); report.engineeringReady = false; }
    }
    if (ownedMembership) {
      // Also retain any session acquired immediately before a failed login/claim callback.
      try {
        for (const [index, context] of [...new Set([adminContext, holderContext, loginContext].filter(Boolean))].entries()) {
          if ((await context.cookies(BETA_ORIGIN)).some(cookie => cookie.name === 'sessionId')) {
            await sessionRetirement.capture(`remaining-${index}`, context);
          }
        }
      } catch (error) { report.cleanupErrors ||= []; report.cleanupErrors.push({operation:'beta_session_custody',error:redact(error.message)}); }
      report.originalSessionRetirement = await sessionRetirement.retire();
      report.authoringSessionsRetired = report.originalSessionRetirement.complete === true;
      if (!report.authoringSessionsRetired) report.engineeringReady = false;
    }
    for (const [operation, close] of [
      ['wallet', () => walletSession?.close()],
      ['holder_context', () => (loginContext || holderContext)?.close()],
      ['wallet_context', () => walletContext?.close()], ['admin_context', () => adminContext?.close()],
      ['browser', () => browser.close()],
    ]) {
      try { await close(); }
      catch (error) {
        report.cleanupErrors ||= [];
        report.cleanupErrors.push({ operation, error: redact(error.message || String(error)) });
        report.engineeringReady = false;
        report.releaseReady = false;
      }
    }
    if (ownedMembership) {
      const cleanupComplete = report.cleanup?.complete === true && report.authoringSessionsRetired === true
        && walletSession?.evidence.closed === true
        && (!retainedMembership || report.membershipLoginFlows.length === 2 && report.membershipLoginFlows.every(row => row.retirementConfirmed === true))
        && !report.cleanupError && !report.cleanupErrors?.length;
      report.engineeringReady = report.engineeringReady === true && cleanupComplete;
      report.releaseReady = report.engineeringReady && !uiCandidate;
      applyLocalNativeReadiness(report, evidence, { ready: report.engineeringReady, cleanupComplete });
    }
    if (RECORD_VIDEO && report.engineeringReady) {
      try { report.recordings = {
        holder: path.relative(ROOT, await finalizeVideo(loginVideo, artifactDir, 'open-badge-holder-and-login.webm')),
        wallet: path.relative(ROOT, await finalizeVideo(walletVideo, artifactDir, 'open-badge-browser-wallet.webm')),
      }; } catch (error) { report.engineeringReady = false; report.releaseReady = false; report.error = redact(error.message); }
    }
    if (evidence && report.engineeringReady) {
      try { await evidence.complete(); } catch (error) {
        report.engineeringReady = false; report.releaseReady = false; report.functionalReady = false;
        report.operations_verified = false; report.error = redact(error.message);
      }
    }
    report.finishedAt = new Date().toISOString();
    fs.writeFileSync(path.join(artifactDir, 'report.json'), JSON.stringify(report, null, 2));
    console.log(redact(JSON.stringify(report, null, 2)));
    if (!report.engineeringReady) process.exitCode = 1;
  }
}

async function main({ retainedFirstParty = false, retainedMembership = false } = {}) {
  assert.equal(typeof retainedFirstParty, 'boolean');
  assert.equal(typeof retainedMembership, 'boolean');
  assert.ok(!(retainedFirstParty && retainedMembership), 'Select one membership evidence contract');
  if (!retainedFirstParty && !retainedMembership) return runCredentialLogin();
  const evidence = await createDemoLiveEvidence();
  try { return await runCredentialLogin({ retainedFirstParty, retainedMembership, evidence }); }
  finally { evidence.close(); }
}

if (require.main === module) {
  assert.ok(process.argv.length === 2 || (process.argv.length === 3 && process.argv[2] === '--owned-membership'), 'Unknown credential-login mode');
  main({ retainedMembership: process.argv[2] === '--owned-membership' }).catch((error) => {
    console.log(JSON.stringify({ error: redact(error.stack || error.message || String(error)) }, null, 2));
    process.exitCode = 1;
  });
}

module.exports = { presentBadge, bindMembershipLogin, observeDeclinedLogin, membershipSessionRetirement, closeControlSession, controlCredentialReceived, firstPartyControlAssertions, main };
