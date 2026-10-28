#!/usr/bin/env node
/* eslint-disable no-console */

const fs = require('fs');
const path = require('path');
const assert = require('node:assert/strict');
const { createDemoLiveEvidence, acknowledgeDemoInputs, applyLocalNativeReadiness } = require('./demo-live-evidence');
const { createOwnedMembership } = require('./demo-owned-membership');
const { login, selectOrg } = require('./audit-beta-credential-lifecycle');
const { acquireWalletSession, openIsolatedWallet } = require('./demo-wallet-session');
const { chromium } = require('@playwright/test');
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

async function presentBadge(walletPage, requestUri) {
  await maskProtocolField(walletPage, 'Presentation request URI');
  await walletPage.getByLabel('Presentation request URI').fill(requestUri);
  const responsePromise = walletPage.waitForResponse((response) => (
    response.url() === `${TEST_WALLET_ORIGIN}/api/present`
    && response.request().method() === 'POST'
  ), { timeout: 60_000 });
  await walletPage.getByRole('button', { name: /^present$/i }).click();
  const response = await responsePromise;
  const body = await response.json().catch(() => null);
  return {
    status: response.status(),
    accepted: response.ok() && body?.ok === true,
    error: response.ok() ? null : redact(body?.error || 'Presentation failed'),
  };
}

async function runCredentialLogin({ retainedFirstParty = false, evidence = null } = {}) {
  loadEnvFile(path.join(ROOT, '.env.tunnel.beta.local'));
  loadEnvFile(path.join(ROOT, '.env'));
  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '');
  const artifactDir = createArtifactDir(ROOT, `beta-credential-login-${stamp}`);
  const uiCandidate = resolveUiCandidateDist(ROOT);
  if (retainedFirstParty && (!['0', '1'].includes(process.env.RECORD_VIDEO) || LOCAL_BETA_PROXY || uiCandidate
    || process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0' || new URL(BETA_ORIGIN).protocol !== 'https:')) {
    throw new Error('Retained first-party control requires explicit recording mode and authenticated deployed HTTPS');
  }
  const inputs = retainedFirstParty ? await acknowledgeDemoInputs(artifactDir, 'first-party-run-input.json', {
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
  const explain = retainedFirstParty
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
    ...(retainedFirstParty ? {
      scenario: 'first-party-browser-wallet',
      controlScope: { classification: 'FIRST_PARTY_CONTROL', implementation: CONTROL_IMPLEMENTATION,
        productPath: 'GOVERNED_MEMBERSHIP_CLAIM_AND_CREDENTIAL_LOGIN', publicWalletProduct: false },
      limitations: [
        'This fresh run reuses the governed membership product path with the internal Rust wallet control.',
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

  let walletSession, walletContext, loginContext, holderContext, adminContext, adminPage;
  let control, loginVideo, walletVideo;
  try {
    if (retainedFirstParty) {
      adminContext = await browser.newContext({ viewport: VIDEO_SIZE });
      adminPage = await adminContext.newPage();
      evidence.bindPage(adminPage);
      await login(adminPage, process.env.TEST_ADMIN_EMAIL, process.env.TEST_ADMIN_PASSWORD);
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
      keepContext: RECORD_VIDEO || retainedFirstParty,
      prepareApplication: control ? (page) => control.prepare(page) : null,
      onPage: evidence ? (page) => evidence.bindPage(page) : null,
      contextOptions: RECORD_VIDEO ? { viewport: VIDEO_SIZE, recordVideo: { dir: artifactDir, size: VIDEO_SIZE } } : {},
      onStep: explain,
      setupContext: async (context) => {
        if (retainedFirstParty) holderContext = context;
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
      ...await receiveBadge(walletPage, offer.offerUri, { retainSummary: retainedFirstParty,
        ...(inputs ? { configurationId: inputs.configurationId } : {}) }),
    };
    if (retainedFirstParty && !controlCredentialReceived(report.badge)) {
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
    await loginPage.goto(`${BETA_ORIGIN}/v1/auth/credential-login`, {
      waitUntil: 'domcontentloaded', timeout: 60_000,
    });
    const loginRequest = await loginPage.evaluate(() => ({
      nonce: document.body.dataset.nonce,
      href: document.querySelector('#wallet-link')?.href || null,
      walletOptions: Array.from(document.querySelectorAll('#wallet-select option'))
        .map((option) => option.textContent.trim()),
    }));
    if (!loginRequest.nonce || !loginRequest.href) {
      throw new Error('Credential login did not provide a nonce and signed presentation link');
    }
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
    report.presentation = await presentBadge(walletPage, loginRequest.href);
    if (!report.presentation.accepted || (retainedFirstParty && report.presentation.status !== 200)) {
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
    await loginPage.waitForURL((url) => url.origin === new URL(BETA_ORIGIN).origin
      && url.pathname === '/console/applicant/catalog'
      && url.searchParams.size === 1 && url.searchParams.get('auth_method') === 'credential',
    { timeout: 60_000 });
    report.completion.uiDestinationVerified = true;
    await waitFor(() => loginPage.evaluate(async () => {
      const response = await fetch('/v1/auth/me', { credentials: 'include' });
      const body = await response.json().catch(() => null);
      return body?.authenticated === true ? true : null;
    }), 60_000, 500);
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
    if (retainedFirstParty && report.completion.authenticatedEmail?.toLowerCase() !== inputs.email.toLowerCase()) {
      throw new Error('Credential login resolved a different account');
    }
    if (retainedFirstParty && !firstPartyControlAssertions(report).presentation_authenticated) {
      throw new Error('The control presentation did not establish an authenticated HTTP 200 session');
    }
    await explain(
      loginPage,
      'Credential login complete',
      'The badge presentation resolved the existing user and created a new authenticated ElevenID session.',
    );
    report.behaviorAssertions = membershipLoginBehaviorAssertions(report);
    report.engineeringReady = (
      Object.values(report.behaviorAssertions).every((passed) => passed === true)
      && report.pageErrors.length === 0
      && report.badResponses.length === 0
      && report.consoleErrors.length === 0
    );
    report.releaseReady = report.engineeringReady && !uiCandidate;
    report.finishedAt = new Date().toISOString();
    if (retainedFirstParty) {
      report.closedWalletSession = await closeControlSession(walletSession, walletContext);
      report.firstPartyControlAssertions = firstPartyControlAssertions(report);
      if (!Object.values(report.firstPartyControlAssertions).every(value => value === true)) {
        throw new Error('The retained first-party control contract did not pass');
      }
      await explain(walletPage, 'Run-owned wallet session closed',
        'The Rust control closed this run’s session. A fresh credential-list API request for that run is rejected with HTTP 410.');
      report.finishedAt = new Date().toISOString();
    } else await walletSession.close();
  } catch (error) {
    report.finishedAt = new Date().toISOString();
    report.releaseReady = false;
    report.engineeringReady = false;
    report.error = redact(error.stack || error.message || String(error));
  } finally {
    if (control) {
      try { report.cleanup = await control.cleanup(); }
      catch (error) { report.cleanupError = redact(error.message); report.engineeringReady = false; }
    }
    if (retainedFirstParty) {
      report.authoringSessionsRetired = true;
      for (const context of new Set([loginContext || holderContext, adminContext].filter(Boolean))) {
        try {
          const response = await context.request.post(`${BETA_ORIGIN}/v1/auth/logout`, { maxRedirects: 0 });
          assert.ok(response.ok() || [302, 303, 307].includes(response.status()));
          const me = await context.request.get(`${BETA_ORIGIN}/v1/auth/me`);
          assert.equal((await me.json()).authenticated, false);
        } catch (error) {
          report.authoringSessionsRetired = false; report.engineeringReady = false;
          report.cleanupErrors ||= [];
          report.cleanupErrors.push({ operation: 'beta_session_logout', error: redact(error.message) });
        }
      }
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
    if (retainedFirstParty) {
      const cleanupComplete = report.cleanup?.complete === true && report.authoringSessionsRetired === true
        && walletSession?.evidence.closed === true && !report.cleanupError && !report.cleanupErrors?.length;
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

async function main({ retainedFirstParty = false } = {}) {
  if (!retainedFirstParty) return runCredentialLogin();
  const evidence = await createDemoLiveEvidence();
  try { return await runCredentialLogin({ retainedFirstParty, evidence }); }
  finally { evidence.close(); }
}

if (require.main === module) {
  main().catch((error) => {
    console.log(JSON.stringify({ error: redact(error.stack || error.message || String(error)) }, null, 2));
    process.exitCode = 1;
  });
}

module.exports = { closeControlSession, controlCredentialReceived, firstPartyControlAssertions, main };
