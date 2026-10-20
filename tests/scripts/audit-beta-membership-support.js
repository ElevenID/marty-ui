#!/usr/bin/env node
'use strict';

// D05 supporting lanes: real public issuance/Auth APIs and actual Receive /
// Present UI actions in a run-owned Rust test wallet. No database access,
// synthetic signatures, trust-rule edits, or deployment revision shortcuts.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const {
  browserJson, cancelOwnedIssuanceTransaction, cleanupApplicationCredential,
  createOwnedApplication, findCurrentCredential, issueOwnedApplication, listResources,
  requireJson, requireNoConflictingApplications, requireOwnedApplication, requireOwnedTransaction,
  selectApplicationTransaction, selectCurrentCredential, submitOwnedApplication,
} = require('./beta-demo-resource-helpers');
const { acquireWalletSession, openIsolatedWallet, resetIsolatedWallet, walletOrigin } = require('./demo-wallet-session');
const { VIDEO_SIZE, createArtifactDir, finalizeVideo, maskProtocolField, showStep } = require('./demo-recording');
const {
  GRANT, assertions, awaitNaturalExpiry, credentialContract, expiryWindow, hash,
  loginInstanceBinding, nativeLoginResult, validateFixture, validateIssuerSetup, validateLoginSetup,
} = require('./beta-membership-support-contract');

const ROOT = path.resolve(__dirname, '../..');
const FIXTURE_FILE = 'd05-support-fixture.json';
const EVIDENCE_FILE = 'd05-support-evidence.json';
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const BLOCKED_ACTIONS = {
  preflight: 'Check explicit deployment, synthetic fixture, recording, credential and recorder IPC inputs in the recorder docs/d05-supporting-lanes.md.',
  fixture_schema: 'Supply the bounded preprovisioned fixture JSON with the declared synthetic applicant; expired-offer requires an isolated 60/120-second server TTL.',
  browser_authentication: 'Confirm the existing operator and synthetic applicant can sign in through the deployed ElevenID login UI.',
  fixture_bindings: 'Resolve the exact ACTIVE issuer, credential/application template, trust, policy and revocation bindings read-only; existing applications must be resolved explicitly.',
  wallet_isolation: 'Run the native Rust wallet with isolated_sessions v1 and acquire a fresh run-owned browser context.',
  actual_expiry: 'The returned admin transaction created_at/expires_at must match the declared short server TTL; cleanup retains its exact cancellation result.',
  natural_expiration: 'The real public offer must become HTTP 410 before the explicit maximum wait. No clock override is supported.',
  untrusted_login: 'Require the native Flow signature-valid trust denial plus Auth issuer_not_trusted and no session; an unauthenticated wallet error is insufficient.',
  trusted_login_recovery: 'A fresh trusted badge must complete actual native verification and sign in the existing synthetic account.',
};

function guards(env, lane) {
  assert.ok(['expired-offer', 'untrusted-issuer'].includes(lane), 'Choose expired-offer or untrusted-issuer');
  const origin = new URL(env.BETA_ORIGIN);
  assert.ok(origin.protocol === 'https:' && origin.origin === env.BETA_ORIGIN && !origin.username && !origin.password,
    'BETA_ORIGIN must be the explicit HTTPS deployment origin');
  walletOrigin(env.MARTY_TEST_WALLET_ORIGIN);
  assert.equal(env.D05_SYNTHETIC_FIXTURE, '1', 'D05_SYNTHETIC_FIXTURE=1 is required');
  assert.ok(env.DEMO_D05_FIXTURE_FILE, 'DEMO_D05_FIXTURE_FILE must select an authorized preprovisioned fixture');
  for (const field of ['TEST_ADMIN_EMAIL', 'TEST_ADMIN_PASSWORD', 'TEST_APPLICANT_EMAIL', 'TEST_APPLICANT_PASSWORD']) {
    assert.ok(typeof env[field] === 'string' && env[field], `${field} is required`);
  }
  assert.ok(env.RECORD_VIDEO === '0' || env.RECORD_VIDEO === '1', 'Set RECORD_VIDEO explicitly to 0 or 1');
  assert.ok(env.BETA_LOCAL_PROXY !== '1' && !env.MARTY_UI_CANDIDATE_DIST,
    'This capture requires the deployed UI and native services, without a local UI/proxy substitution');
  assert.ok(!env.NODE_TLS_REJECT_UNAUTHORIZED || env.NODE_TLS_REJECT_UNAUTHORIZED === '1',
    'TLS verification is required');
  assert.match(env.DEMO_EXECUTION_EVIDENCE_RUN_ID || '', /^[0-9a-f-]{36}$/i, 'Recorder-owned run ID is required');
  assert.ok(env.DEMO_EXECUTION_EVIDENCE_HELPER, 'Recorder-owned live IPC evidence helper is required');
  assert.match(env.DEMO_EXECUTION_EVIDENCE_HELPER_SHA256 || '', /^[0-9a-f]{64}$/);
  return { origin: origin.origin, wallet: walletOrigin(env.MARTY_TEST_WALLET_ORIGIN), record: env.RECORD_VIDEO === '1' };
}

async function prepareFixture(artifactDir, env, lane, evidence) {
  const filename = fs.realpathSync(env.DEMO_D05_FIXTURE_FILE);
  const stat = fs.statSync(filename);
  assert.ok(stat.isFile() && stat.size > 0 && stat.size <= 64 * 1024, 'A bounded regular fixture JSON file is required');
  const bytes = fs.readFileSync(filename);
  // Validate before copying; private/provider credentials are not fixture data.
  const proposed = validateFixture(JSON.parse(bytes.toString('utf8')), lane);
  assert.equal(proposed.applicant.email, env.TEST_APPLICANT_EMAIL, 'Fixture must name the existing synthetic applicant account');
  fs.writeFileSync(path.join(artifactDir, FIXTURE_FILE), bytes, { flag: 'wx', mode: 0o600 });
  const actualBytes = await evidence.readFixture(FIXTURE_FILE);
  assert.equal(sha256(actualBytes), sha256(bytes), 'Recorder fixture bytes changed before sealing');
  const fixture = validateFixture(JSON.parse(actualBytes.toString('utf8')), lane);
  await evidence.seal();
  return { fixture, sha256: sha256(actualBytes) };
}

function stableConfiguration(setup) {
  // Public source definitions are immutable inputs for this run. Exclude only
  // bookkeeping timestamps, not trust rules, issuer keys, or signing defaults.
  const stable = (value) => {
    if (Array.isArray(value)) return value.map(stable);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value)
      .filter(([key]) => !['created_at', 'updated_at', 'last_used_at', 'last_resolved_at'].includes(key))
      .map(([key, item]) => [key, stable(item)]));
    return value;
  };
  return stable(setup);
}

function createSupportController({ operator, applicantPage, fixture, lane, origin, runId,
  waitFor, onOwned = () => {} }) {
  const ownedApplications = [];
  let initialHash;

  async function issuerSetup(binding) {
    const org = encodeURIComponent(binding.organizationId);
    const credential = await requireJson(operator, `/v1/credential-templates/${encodeURIComponent(binding.credentialTemplateId)}`);
    assert.ok(credential.revocation_profile_id, 'Preprovisioned credential revocation binding is required');
    const [application, trust, identities, issuers, relationships, revocations] = await Promise.all([
      requireJson(operator, `/v1/application-templates/${encodeURIComponent(binding.applicationTemplateId)}`),
      requireJson(operator, `/v1/trust-profiles/${encodeURIComponent(binding.trustProfileId)}`),
      requireJson(operator, `/v1/signing-keys/issuer-identities?organization_id=${org}`),
      listResources(operator, '/v1/issuer-entities', binding.organizationId),
      requireJson(operator, `/v1/trust-profiles/${encodeURIComponent(binding.trustProfileId)}/issuers`),
      listResources(operator, '/v1/revocation-profiles', binding.organizationId),
    ]);
    const matching = revocations.filter((item) => item.id === credential.revocation_profile_id);
    assert.equal(matching.length, 1, 'Exact credential revocation profile is required');
    const observed = { credential, application, trust, identities, issuers, relationships, revocation: matching[0] };
    const proof = validateIssuerSetup(binding, observed, fixture.login.vct);
    return { ...observed, issuers: issuers.filter((item) => item.id === binding.issuerEntityId),
      identities: { identities: identities.identities.filter((item) => item.issuer_did === binding.issuerDid) }, proof };
  }

  async function configuration() {
    const trusted = await issuerSetup(fixture.trusted);
    const foreign = lane === 'untrusted-issuer' ? await issuerSetup(fixture.foreign) : null;
    if (foreign) assert.deepEqual(credentialContract(foreign.credential), credentialContract(trusted.credential),
      'Foreign fixture must preserve the exact membership claim/format contract');
    const login = {
      policy: await requireJson(operator, `/v1/presentation-policies/${encodeURIComponent(fixture.login.presentationPolicyId)}`),
      trust: await requireJson(operator, `/v1/trust-profiles/${encodeURIComponent(fixture.login.trustProfileId)}`),
      relationships: await requireJson(operator, `/v1/trust-profiles/${encodeURIComponent(fixture.login.trustProfileId)}/issuers`),
      issuers: await listResources(operator, '/v1/issuer-entities', fixture.login.organizationId),
    };
    const loginProof = validateLoginSetup(fixture, login, lane);
    const referenced = new Set(login.relationships.map((item) => item.issuer_id));
    login.issuers = login.issuers.filter((item) => referenced.has(item.id)
      || [fixture.trusted.issuerDid, fixture.foreign?.issuerDid].includes(item.issuer_id));
    const organizationIds = [...new Set([fixture.trusted.organizationId,
      ...(lane === 'untrusted-issuer' ? [fixture.foreign.organizationId] : [])])];
    const organizationState = [];
    for (const organizationId of organizationIds) {
      const signing = await requireJson(operator, `/v1/signing-keys/config?organization_id=${encodeURIComponent(organizationId)}`);
      const discovery = await requireJson(operator, `/.well-known/openid-credential-issuer/org/${encodeURIComponent(organizationId)}`);
      assert.equal(discovery.credential_issuer, `${origin}/org/${organizationId}`, 'Issuer discovery origin/tenant mismatch');
      organizationState.push({ organizationId, discovery, signingDefaults: Object.fromEntries(
        ['default_service_id', 'format_defaults', 'type_defaults'].map((key) => [key, signing[key] ?? null]),
      ) });
    }
    return { trusted, foreign, login, loginProof, organizationState };
  }

  async function preflight() {
    initialHash = null;
    const memberships = await requireJson(operator, '/v1/organizations/mine');
    assert.ok(Array.isArray(memberships), 'Organization membership lookup must be a collection');
    for (const binding of [fixture.trusted, ...(lane === 'untrusted-issuer' ? [fixture.foreign] : [])]) {
      assert.ok(memberships.some((item) => item.id === binding.organizationId && item.membership?.has_org_console_access),
        'Operator must have console access to each explicit fixture organization');
    }
    const profile = await requireJson(applicantPage, '/v1/me/applicant-profile');
    assert.equal(profile?.id, fixture.applicant.id, 'The signed-in applicant profile must match the fixture');
    assert.equal(profile.email, fixture.applicant.email);
    const observed = await configuration();
    for (const binding of [fixture.trusted, ...(lane === 'untrusted-issuer' ? [fixture.foreign] : [])]) {
      await requireNoConflictingApplications(applicantPage, binding);
    }
    initialHash = hash(stableConfiguration(observed));
    return { configurationSha256: initialHash, trusted: observed.trusted.proof,
      foreign: observed.foreign?.proof || null, login: observed.loginProof };
  }

  async function issue(binding, stage) {
    assert.ok(initialHash, 'Read-only fixture preflight must complete before issuance');
    await requireNoConflictingApplications(applicantPage, binding);
    const owned = { organizationId: binding.organizationId, credentialTemplateId: binding.credentialTemplateId,
      applicationTemplateId: binding.applicationTemplateId, applicantId: fixture.applicant.id,
      runId: `${runId}.${stage}`, applicationId: null, transactionId: null, credentialId: null, uncertainMutations: [] };
    ownedApplications.push(owned); onOwned(ownedApplications);
    await createOwnedApplication(applicantPage, owned, { formData: fixture.applicant.formData,
      integrationContext: { demo_scenario: 'D05', demo_stage: stage }, label: 'Create owned D05 application' });
    onOwned(ownedApplications);
    await submitOwnedApplication(applicantPage, owned, 'Submit owned D05 application');
    const approved = requireOwnedApplication(await requireJson(operator,
      `/v1/organizations/${encodeURIComponent(owned.organizationId)}/applicants/${encodeURIComponent(owned.applicationId)}/approve`,
      { method: 'POST', body: JSON.stringify({ notes: 'Authorized synthetic D05 supporting-lane fixture' }) }), owned);
    assert.equal(approved.status, 'APPROVED');
    const result = await issueOwnedApplication(operator, owned, 'Issue owned D05 membership credential');
    onOwned(ownedApplications);
    // The public list is a summary and omits expires_at. Read the exact scoped
    // detail for authoritative expiry and ownership, including expired offers.
    const transaction = requireOwnedTransaction(await requireJson(operator,
      `/v1/issuance/${encodeURIComponent(owned.transactionId)}?organization_id=${encodeURIComponent(owned.organizationId)}`), owned);
    assert.equal(typeof result.issued.credential_offer_uri, 'string', 'Application issuance must expose its real offer');
    const offerUri = result.issued.credential_offer_uri;
    const parsed = new URL(offerUri);
    assert.equal(parsed.protocol, 'openid-credential-offer:');
    const offer = JSON.parse(parsed.searchParams.get('credential_offer'));
    assert.equal(offer?.credential_issuer, `${origin}/org/${binding.organizationId}`);
    assert.deepEqual(offer.credential_configuration_ids, [binding.credentialConfigurationId]);
    assert.ok(typeof offer.grants?.[GRANT]?.['pre-authorized_code'] === 'string');
    return { owned, application: result.issued, transaction, offerUri, offer };
  }

  async function issuedCredential(issuance, binding) {
    const credential = await findCurrentCredential(operator, { ...issuance.owned,
      waitFor: (probe) => waitFor(probe, 30_000, 500) });
    assert.equal(credential.issuer_did, binding.issuerDid);
    assert.equal(credential.credential_format, binding.credentialFormat);
    assert.equal(credential.status, 'ACTIVE');
    issuance.owned.credentialId = credential.id; onOwned(ownedApplications);
    return { id: credential.id, transactionId: issuance.owned.transactionId, applicationId: issuance.owned.applicationId,
      organizationId: credential.organization_id, credentialTemplateId: credential.credential_template_id,
      issuerDid: credential.issuer_did, credentialHash: credential.credential_hash || null };
  }

  async function noIssuedCredential(owned) {
    return selectCurrentCredential(await listResources(operator, '/v1/issued-credentials', owned.organizationId), owned) === null;
  }

  async function cleanupOne(owned) {
    let cancellation = null;
    if (owned.applicationId) {
      requireOwnedApplication(await requireJson(operator,
        `/v1/organizations/${encodeURIComponent(owned.organizationId)}/applicants/${encodeURIComponent(owned.applicationId)}`), owned);
      const transaction = selectApplicationTransaction(await listResources(operator, '/v1/issuance', owned.organizationId), owned);
      if (transaction) {
        owned.transactionId = transaction.id;
        const credential = selectCurrentCredential(await listResources(operator, '/v1/issued-credentials', owned.organizationId), owned);
        if (credential) owned.credentialId = credential.id;
        else if (!owned.credentialId) {
          // Even failed/expired offers require exact public cancellation. The
          // shared helper also confirms an already-revoked transaction and
          // resolves any previous lost-response uncertainty by readback.
          cancellation = await cancelOwnedIssuanceTransaction(operator, owned, 'D05 owned unused offer cleanup');
        }
      }
    }
    const result = await cleanupApplicationCredential(operator, owned, 'D05 owned synthetic fixture cleanup');
    onOwned(ownedApplications);
    return { applicationId: owned.applicationId, transactionId: owned.transactionId, cancellation, ...result };
  }

  async function cleanup() {
    const results = [];
    for (const owned of ownedApplications) {
      try { results.push(await cleanupOne(owned)); }
      catch (error) { results.push({ ok: false, applicationId: owned.applicationId, transactionId: owned.transactionId,
        credentialId: owned.credentialId, errorType: error.name, uncertainMutations: owned.uncertainMutations }); }
    }
    return { ok: results.every((item) => item.ok === true), applications: results };
  }

  async function invariantReadback() {
    if (!initialHash) return { ok: false, beforeSha256: null, afterSha256: null };
    const afterHash = hash(stableConfiguration(await configuration()));
    return { ok: afterHash === initialHash, beforeSha256: initialHash, afterSha256: afterHash };
  }
  return { preflight, issue, issuedCredential, noIssuedCredential, cleanupOne, cleanup, invariantReadback, ownedApplications };
}

async function walletInventory(context, session) {
  await session.assertOwned();
  const response = await context.request.get(`${session.origin}/api/credentials`, {
    timeout: 15_000, headers: { 'x-marty-wallet-run-id': session.evidence.runId },
  });
  assert.equal(response.status(), 200);
  const body = await response.json();
  assert.ok(Array.isArray(body), 'Wallet credential inventory must be a collection');
  return body;
}

async function receive(page, wallet, offerUri, record) {
  await openIsolatedWallet(page, wallet);
  await maskProtocolField(page, 'Credential offer URI', record);
  await page.getByLabel('Credential offer URI').fill(offerUri);
  const pending = page.waitForResponse((response) => response.url() === `${wallet}/api/receive`
    && response.request().method() === 'POST', { timeout: 60_000 });
  await page.getByRole('button', { name: /^receive$/i }).click();
  const response = await pending;
  const body = await response.json().catch(() => null);
  if (response.ok()) await page.getByRole('status').filter({ hasText: 'Credential received' }).waitFor({ timeout: 10_000 });
  else await page.locator('#status.error').waitFor({ timeout: 10_000 });
  return { httpStatus: response.status(), ok: response.ok(),
    visibleMessage: Boolean((await page.locator('#status').innerText()).trim()),
    // No provider error string or bearer protocol value is written to reports.
    responseHasError: typeof body?.error === 'string' };
}

async function authMe(context, origin) {
  const response = await context.request.get(`${origin}/v1/auth/me`, { timeout: 15_000 });
  assert.equal(response.status(), 200);
  return response.json();
}

async function present({ authPage, walletPage, authContext, operator, fixture, origin, wallet, record, waitFor, issuerDid, allowed, step }) {
  await authPage.goto(`${origin}/v1/auth/credential-login`, { waitUntil: 'domcontentloaded', timeout: 60_000 });
  const details = await authPage.evaluate(() => ({ nonce: document.body.dataset.nonce,
    href: document.querySelector('#wallet-link')?.href, dcApiRequestUrl: document.body.dataset.dcApiRequestUrl }));
  const requestUrl = new URL(details.dcApiRequestUrl, origin);
  const match = requestUrl.pathname.match(/^\/v1\/flows\/instances\/([0-9a-f-]{36})\/request$/i);
  assert.ok(requestUrl.origin === origin && match, 'Native login Flow request binding is required');
  const instancePath = `/v1/flows/instances/${match[1]}`;
  const binding = loginInstanceBinding(details, await requireJson(operator, instancePath), fixture, origin);
  await step(authPage, allowed ? '4. Sign in with the trusted badge' : '2. Try the foreign issuer badge',
    'The real credential sign-in page has created a signed request. The separate wallet is the first-party Rust test client.');
  await maskProtocolField(walletPage, 'Presentation request URI', record);
  await walletPage.getByLabel('Presentation request URI').fill(details.href);
  const pending = walletPage.waitForResponse((response) => response.url() === `${wallet}/api/present`
    && response.request().method() === 'POST', { timeout: 60_000 });
  await walletPage.getByRole('button', { name: /^present$/i }).click();
  const response = await pending;
  const outcome = await waitFor(async () => {
    const polled = await authContext.request.get(`${origin}/v1/auth/credential-login/status?nonce=${encodeURIComponent(details.nonce)}`, { timeout: 15_000 });
    assert.equal(polled.status(), 200);
    const body = await polled.json();
    return ['completed', 'failed', 'expired'].includes(body?.status) ? body : null;
  }, 60_000, 500);
  // Re-bind after the response. A terminal result from an unrelated instance
  // or changed policy cannot qualify either the positive or negative lane.
  loginInstanceBinding(details, await requireJson(operator, instancePath), fixture, origin);
  const result = nativeLoginResult(await requireJson(operator, `${instancePath}/result`), binding, fixture, issuerDid, allowed);
  if (allowed) {
    assert.ok(response.ok(), 'Wallet must complete the actual trusted presentation');
    assert.equal(outcome.status, 'completed');
    await waitFor(async () => (await authMe(authContext, origin)).authenticated === true, 60_000, 500);
    await authPage.waitForURL((url) => url.origin === origin && !url.pathname.includes('credential-login'), { timeout: 60_000 });
    const user = await authMe(authContext, origin);
    assert.equal(user.authenticated, true);
    assert.equal(user.user?.email || user.email, fixture.applicant.email, 'Recovered login must be the existing synthetic account');
    return { binding, result, status: outcome.status, walletHttpStatus: response.status(), authenticated: true };
  }
  assert.equal(outcome.status, 'failed');
  assert.equal(outcome.reason_code, 'issuer_not_trusted');
  await authPage.locator('#status .err').waitFor({ timeout: 10_000 });
  const failureVisible = /does not trust for sign-in/i.test(await authPage.locator('#status').innerText())
    && await authPage.locator('#status').getByRole('link', { name: 'Try again' }).isVisible();
  assert.ok(failureVisible, 'Actual credential-login trust error and retry link must be visible');
  assert.equal((await authMe(authContext, origin)).authenticated, false);
  const finalized = await authContext.request.get(`${origin}/v1/auth/credential-login/finalize?nonce=${encodeURIComponent(details.nonce)}`, {
    maxRedirects: 0, timeout: 15_000,
  });
  assert.ok(!finalized.headers()['set-cookie'], 'Rejected credential must not create a login session cookie');
  assert.equal((await authMe(authContext, origin)).authenticated, false);
  return { binding, result, status: outcome.status, reasonCode: outcome.reason_code,
    walletHttpStatus: response.status(), authFailureVisible: failureVisible, authenticated: false, finalizeSetCookie: false };
}

async function main(lane = process.argv[2], env = process.env) {
  const dir = createArtifactDir(ROOT, `d05-${lane || 'blocked'}-${Date.now()}`, env);
  assert.ok(!fs.existsSync(path.join(dir, 'report.json')), 'Refuse to overwrite an existing attempt');
  const report = { schemaVersion: 2, scenario: `D05 support: ${lane}`, lane, classification: 'FIRST_PARTY_CONTROL',
    independentWalletQualification: false, startedAt: new Date().toISOString(), checks: {}, stage: 'preflight',
    releaseReady: false, status: 'BLOCKED', runId: env.DEMO_EXECUTION_EVIDENCE_RUN_ID || null,
    source: { entrypoint: 'tests/scripts/audit-beta-membership-support.js', sha256: sha256(fs.readFileSync(__filename)) },
    observed: {}, cleanup: { ok: false }, finalizationFailures: [], recording: env.RECORD_VIDEO === '1' };
  let browser, evidence, controller, walletSession, walletContext, authContext;
  let walletVideo, authVideo, fixture, settings;
  let walletAcquisitionAttempted = false;
  const contexts = [];
  try {
    settings = guards(env, lane);
    assert.ok(process.connected, 'Run this driver through the recorder-owned Node IPC capture');
    assert.equal(sha256(fs.readFileSync(env.DEMO_EXECUTION_EVIDENCE_HELPER)), env.DEMO_EXECUTION_EVIDENCE_HELPER_SHA256,
      'Recorder evidence helper digest mismatch');
    evidence = await require(env.DEMO_EXECUTION_EVIDENCE_HELPER).createLiveEvidenceClient();
    report.stage = 'fixture_schema';
    const input = await prepareFixture(dir, env, lane, evidence);
    fixture = input.fixture; report.fixtureSha256 = input.sha256;
    const { chromium } = require('@playwright/test');
    const { login, waitFor } = require('./audit-beta-credential-lifecycle');
    browser = await chromium.launch({ headless: env.HEADED !== '1' });
    const adminContext = await browser.newContext(); contexts.push(adminContext);
    const applicantContext = await browser.newContext(); contexts.push(applicantContext);
    const operator = await adminContext.newPage(); evidence.bindPage(operator);
    const applicantPage = await applicantContext.newPage(); evidence.bindPage(applicantPage);
    report.stage = 'browser_authentication';
    await login(operator, env.TEST_ADMIN_EMAIL, env.TEST_ADMIN_PASSWORD);
    await login(applicantPage, env.TEST_APPLICANT_EMAIL, env.TEST_APPLICANT_PASSWORD);
    controller = createSupportController({ operator, applicantPage, fixture, lane, origin: settings.origin,
      runId: report.runId, waitFor, onOwned: (owned) => { report.ownedApplications = JSON.parse(JSON.stringify(owned)); } });
    report.stage = 'fixture_bindings';
    report.observed.preflight = await controller.preflight();
    report.checks.login_trust_excludes_foreign = lane === 'untrusted-issuer';
    report.stage = 'wallet_isolation';
    walletContext = await browser.newContext({ viewport: VIDEO_SIZE,
      ...(settings.record ? { recordVideo: { dir, size: VIDEO_SIZE } } : {}) });
    contexts.push(walletContext);
    walletAcquisitionAttempted = true;
    walletSession = await acquireWalletSession(walletContext, { origin: settings.wallet, runId: report.runId });
    report.walletSession = walletSession.evidence;
    authContext = await browser.newContext({ viewport: VIDEO_SIZE,
      ...(settings.record ? { recordVideo: { dir, size: VIDEO_SIZE } } : {}) });
    contexts.push(authContext);
    // Redact only the transient QR carrier; never replace an authentication or
    // verification response. No Playwright trace spans protocol secret input.
    await authContext.route('https://api.qrserver.com/**', (route) => route.fulfill({ contentType: 'image/svg+xml',
      body: '<svg xmlns="http://www.w3.org/2000/svg" width="220" height="220"><rect width="220" height="220" fill="#e5e7eb"/><text x="110" y="110" text-anchor="middle" font-family="Arial" font-size="16">QR token redacted</text></svg>' }));
    await authContext.addInitScript(() => Object.defineProperty(globalThis, 'DigitalCredential', { value: undefined, configurable: false }));
    report.captureRedactions = ['Protocol fields masked for recordings', 'Transient QR carrier replaced by labeled redaction'];
    const walletPage = await walletContext.newPage(); evidence.bindPage(walletPage); walletVideo = walletPage.video();
    const authPage = await authContext.newPage(); evidence.bindPage(authPage); authVideo = authPage.video();
    const step = (page, title, detail) => showStep(page, title, detail, { enabled: settings.record,
      eyebrow: 'D05 supporting evidence · First-party Rust test wallet' });
    const inventory = () => walletInventory(walletContext, walletSession);
    assert.equal((await inventory()).length, 0);
    assert.equal((await authMe(authContext, settings.origin)).authenticated, false);
    let recovery;
    if (lane === 'expired-offer') {
      report.stage = 'issue_expiring_offer';
      const expired = await controller.issue(fixture.trusted, 'expired-offer');
      report.stage = 'actual_expiry';
      const window = expiryWindow(expired.transaction, expired.application, fixture.expiry);
      report.observed.expiryWindow = { ...window, transactionId: expired.owned.transactionId };
      const offerUrl = `${settings.origin}/v1/issuance/offers/${encodeURIComponent(expired.owned.transactionId)}`;
      const before = await operator.request.get(offerUrl, { timeout: 15_000 });
      assert.equal(before.status(), 200);
      const publicOffer = await before.json();
      assert.equal(publicOffer.credential_issuer, expired.offer.credential_issuer);
      assert.equal(publicOffer.grants?.[GRANT]?.['pre-authorized_code'], expired.offer.grants[GRANT]['pre-authorized_code']);
      const metadata = await requireJson(operator, `/.well-known/oauth-authorization-server/org/${fixture.trusted.organizationId}`);
      const tokenEndpoint = new URL(metadata.token_endpoint);
      assert.equal(tokenEndpoint.origin, settings.origin, 'Native token endpoint must be on the deployment origin');
      assert.ok(!tokenEndpoint.username && !tokenEndpoint.password && !tokenEndpoint.search && !tokenEndpoint.hash);
      await openIsolatedWallet(walletPage, settings.wallet);
      await step(walletPage, '1. Let this offer expire',
        'This isolated demo deployment uses a short server offer lifetime. We wait for its actual expires_at; no clock or database state is changed.');
      report.stage = 'natural_expiration';
      report.observed.expiration = await awaitNaturalExpiry({ window,
        readOffer: async () => ({ status: (await operator.request.get(offerUrl, { timeout: 15_000 })).status() }) });
      report.checks.expired_offer_gone = true;
      const token = await operator.request.post(tokenEndpoint.href, { timeout: 15_000,
        form: { grant_type: GRANT, 'pre-authorized_code': expired.offer.grants[GRANT]['pre-authorized_code'] } });
      const tokenBody = await token.json().catch(() => null);
      assert.equal(token.status(), 400); assert.equal(tokenBody?.error, 'invalid_grant');
      report.observed.cachedCode = { httpStatus: token.status(), error: tokenBody.error };
      report.checks.cached_code_denied = true;
      const denial = await receive(walletPage, settings.wallet, expired.offerUri, settings.record);
      assert.ok(!denial.ok && denial.visibleMessage && denial.responseHasError);
      report.observed.expiredReceipt = denial; report.checks.wallet_error_visible = true;
      report.checks.no_credential_on_denial = (await inventory()).length === 0
        && await controller.noIssuedCredential(expired.owned);
      assert.equal(report.checks.no_credential_on_denial, true);
      await step(walletPage, '2. Expired receipt is rejected',
        'The real wallet displays a receipt error. The server and this owned wallet session contain no credential from the expired offer.');
      report.observed.expiredOfferCleanup = await controller.cleanupOne(expired.owned);
      assert.equal(report.observed.expiredOfferCleanup.ok, true, 'Expired offer must be cancelled and its owned application withdrawn before reissue');
      report.stage = 'fresh_reissue';
      recovery = await controller.issue(fixture.trusted, 'fresh-reissue');
      assert.notEqual(recovery.owned.transactionId, expired.owned.transactionId);
    } else {
      report.stage = 'foreign_issuance';
      const foreign = await controller.issue(fixture.foreign, 'foreign-issuer');
      const received = await receive(walletPage, settings.wallet, foreign.offerUri, settings.record);
      assert.ok(received.ok);
      report.observed.foreignCredential = await controller.issuedCredential(foreign, fixture.foreign);
      const inventoryBefore = await inventory();
      assert.equal(inventoryBefore.length, 1);
      assert.equal(inventoryBefore[0].credential_configuration_id, fixture.foreign.credentialConfigurationId);
      await step(walletPage, '1. Receive the foreign issuer badge',
        'The authorized fixture uses a real signing service. Receipt alone is not signature or login-trust proof; the native verifier checks both next.');
      report.stage = 'untrusted_login';
      const denied = await present({ authPage, walletPage, authContext, operator, fixture, ...settings,
        waitFor, issuerDid: fixture.foreign.issuerDid, allowed: false, step });
      report.observed.denial = denied;
      report.checks.foreign_signature_valid = denied.result.signatureValid === true;
      report.checks.issuer_not_trusted = denied.reasonCode === 'issuer_not_trusted';
      report.checks.auth_failure_visible = denied.authFailureVisible === true;
      report.checks.no_session_on_denial = denied.authenticated === false && denied.finalizeSetCookie === false;
      await step(authPage, '3. Sign-in denied without a session',
        'The native verifier authenticated the issuer signature and rejected its login trust. The actual sign-in page shows the denial and retry option.');
      await resetIsolatedWallet(walletPage, settings.wallet);
      assert.equal((await inventory()).length, 0);
      report.stage = 'trusted_reissue';
      recovery = await controller.issue(fixture.trusted, 'trusted-recovery');
    }
    const received = await receive(walletPage, settings.wallet, recovery.offerUri, settings.record);
    assert.ok(received.ok);
    const credentials = await inventory();
    assert.equal(credentials.length, 1);
    assert.equal(credentials[0].credential_configuration_id, fixture.trusted.credentialConfigurationId);
    report.observed.recoveryCredential = await controller.issuedCredential(recovery, fixture.trusted);
    report.observed.recoveryReceipt = received;
    report.checks.fresh_reissue_received = true;
    report.checks.receipt_has_no_session = (await authMe(authContext, settings.origin)).authenticated === false;
    assert.equal(report.checks.receipt_has_no_session, true);
    await step(walletPage, '3. Receive a fresh trusted badge',
      'A new offer succeeds. Receiving the badge does not create an ElevenID login session.');
    report.stage = 'trusted_login_recovery';
    report.observed.recovery = await present({ authPage, walletPage, authContext, operator, fixture, ...settings,
      waitFor, issuerDid: fixture.trusted.issuerDid, allowed: true, step });
    report.checks.trusted_login_recovery = report.observed.recovery.authenticated === true;
    await step(authPage, '5. Trusted sign-in opens the portal',
      'The real credential login completed with the trusted issuer and the existing synthetic account.');
    report.stage = 'cleanup';
  } catch (error) {
    // Exceptions can contain bearer offers, callback nonces or filled values.
    // Retain stage/type only; actionable static prerequisites are documented.
    report.failure = { type: error.name, stage: report.stage,
      action: BLOCKED_ACTIONS[report.stage] || 'Inspect the exact owned resource and public native response for this stage; do not replace it with saved or synthetic evidence.' };
  } finally {
    if (controller) {
      report.cleanup = await controller.cleanup().catch((error) => ({ ok: false, errorType: error.name }));
      try {
        report.observed.configurationReadback = await controller.invariantReadback();
        report.checks.configuration_unchanged = report.observed.configurationReadback.ok;
      } catch (error) { report.finalizationFailures.push({ operation: 'configuration_readback', type: error.name }); }
    }
    let authClosed = !authContext;
    if (authContext) {
      try {
        if ((await authMe(authContext, settings.origin)).authenticated) {
          const response = await authContext.request.post(`${settings.origin}/v1/auth/logout`, { maxRedirects: 0, timeout: 15_000 });
          assert.ok(response.status() >= 200 && response.status() < 400, 'Synthetic login logout failed');
        }
        authClosed = (await authMe(authContext, settings.origin)).authenticated === false;
      } catch (error) { report.finalizationFailures.push({ operation: 'auth_logout', type: error.name }); }
    }
    let walletClosed = !walletAcquisitionAttempted;
    if (walletSession) {
      try { await walletSession.close(); walletClosed = walletSession.evidence.closed === true; }
      catch (error) { report.finalizationFailures.push({ operation: 'wallet_session_close', type: error.name }); }
    } else if (walletAcquisitionAttempted) report.finalizationFailures.push({ operation: 'wallet_session_acquisition', outcome: 'UNCONFIRMED' });
    report.checks.fixture_cleanup = report.cleanup.ok === true && authClosed && walletClosed;
    for (const context of contexts.reverse()) {
      try { await context.close(); }
      catch (error) { report.finalizationFailures.push({ operation: 'browser_context_close', type: error.name }); }
    }
    if (settings?.record) {
      for (const [video, name] of [
        [walletVideo, lane === 'expired-offer' ? 'd05-expired-offer.webm' : 'd05-untrusted-issuer-wallet.webm'],
        [authVideo, lane === 'expired-offer' ? 'd05-expired-offer-login.webm' : 'd05-untrusted-issuer.webm'],
      ]) {
        try { assert.ok(video, 'Required recorded page video missing'); await finalizeVideo(video, dir, name); }
        catch (error) { report.finalizationFailures.push({ operation: 'video_finalization', file: name, type: error.name }); }
      }
    }
    if (browser) {
      try { await browser.close(); }
      catch (error) { report.finalizationFailures.push({ operation: 'browser_close', type: error.name }); }
    }
    report.behaviorAssertions = assertions(lane, report.checks);
    report.releaseReady = !report.failure && report.finalizationFailures.length === 0
      && Object.values(report.behaviorAssertions).every(Boolean);
    report.status = report.releaseReady ? 'PASS' : 'BLOCKED';
    report.finishedAt = new Date().toISOString();
    const save = () => {
      fs.writeFileSync(path.join(dir, EVIDENCE_FILE), `${JSON.stringify({ schemaVersion: 1, kind: 'd05-support-evidence',
        runId: report.runId, lane, fixtureSha256: report.fixtureSha256 || null, source: report.source,
        status: report.status, observed: report.observed, ownedApplications: report.ownedApplications || [],
        cleanup: report.cleanup, checks: report.checks, failure: report.failure || null,
        scope: 'FIRST_PARTY_PUBLIC_API_AND_BROWSER_CONTROL_ONLY' }, null, 2)}\n`, { mode: 0o600 });
      fs.writeFileSync(path.join(dir, 'report.json'), `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600 });
    };
    try {
      save();
      if (report.releaseReady) await evidence.complete();
    } catch (error) {
      report.releaseReady = false; report.status = 'BLOCKED';
      report.finalizationFailures.push({ operation: 'evidence_finalization', type: error.name });
      save();
    } finally { evidence?.close(); }
    console.log(JSON.stringify({ lane, status: report.status, releaseReady: report.releaseReady,
      stage: report.stage, failure: report.failure || null, behaviorAssertions: report.behaviorAssertions }));
    if (!report.releaseReady) process.exitCode = 1;
  }
  return report;
}

if (require.main === module) main().catch((error) => {
  console.error(JSON.stringify({ failed: true, type: error.name })); process.exitCode = 1;
});
module.exports = { EVIDENCE_FILE, FIXTURE_FILE, createSupportController, guards, main,
  prepareFixture, present, receive, stableConfiguration, walletInventory };
