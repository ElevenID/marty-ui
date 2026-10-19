#!/usr/bin/env node
'use strict';
// D05 supporting lanes only. First-party protocol/browser evidence is not independent-wallet qualification.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { chromium } = require('@playwright/test');
const { login, waitFor } = require('./audit-beta-credential-lifecycle');
const { requireJson, ensureGovernedIssuer } = require('./beta-demo-resource-helpers');
const { VIDEO_SIZE, createArtifactDir, finalizeVideo, maskProtocolField, showStep } = require('./demo-recording');
const BASE = 'https://beta.elevenidllc.com';
const WALLET = 'http://127.0.0.1:8787';
const ORG = '00000000-0000-0000-0000-000000000001';
const TEMPLATE = '50000000-0000-0000-0000-000000000040';
const TRUST = '60000000-0000-0000-0000-000000000001';
const ROOT = path.resolve(__dirname, '../..');
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(k => [k, canonical(value[k])]));
  return value;
}
const hash = value => crypto.createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
function guards(env, lane) {
  assert.ok(['expired-offer', 'untrusted-issuer'].includes(lane), 'Explicit D05 supporting lane required');
  assert.equal(env.BETA_ORIGIN, BASE, 'Exact beta origin required');
  assert.equal(env.MARTY_TEST_WALLET_ORIGIN, WALLET, 'Exact local first-party wallet required');
  assert.equal(env.D05_SYNTHETIC_FIXTURE, '1', 'Synthetic fixture acknowledgement required');
  assert.equal(env.BETA_AUDIT_ORG_ID || ORG, ORG);
  assert.ok(env.MARTY_TEST_WALLET_HOLDER_KID?.startsWith('did:'), 'Synthetic wallet holder required');
  assert.ok(env.TEST_ADMIN_EMAIL && env.TEST_ADMIN_PASSWORD, 'Operator fixture credentials required');
  assert.ok(env.D05_EXPECTED_RELEASE_MARKER && env.D05_EXPECTED_UI_REVISION && env.D05_EXPECTED_AUTH_REVISION && env.D05_EXPECTED_POLICY_REVISION, 'Pinned current beta release and components required');
}
function credentialPath(id) {
  assert.match(id.replace(/^urn:uuid:/, ''), UUID);
  return `/v1/issued-credentials/${encodeURIComponent(id)}/revoke`;
}
function expirySql(id) {
  assert.match(id, UUID);
  return `UPDATE issuance_service.issuance_transactions SET expires_at=now()-interval '1 minute' WHERE id='${id}' AND organization_id='${ORG}' AND status='pending' RETURNING id;`;
}
function sql(statement) {
  const result = spawnSync('docker', ['exec', '-i', 'elevenid-beta-postgres-1', 'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'marty'], { input: statement, encoding: 'utf8', windowsHide: true });
  assert.equal(result.status, 0, 'Scoped beta fixture SQL failed');
  return result.stdout.trim();
}
function verifyForeignSignature(raw, document, did) {
  const [header, payload, signature, extra] = raw.split('.');
  assert.equal(extra, undefined);
  const head = JSON.parse(Buffer.from(header, 'base64url'));
  const claims = JSON.parse(Buffer.from(payload, 'base64url'));
  assert.equal(head.alg, 'ES256'); assert.equal(claims.iss, did); assert.equal(document.id, did);
  const methods = document.verificationMethod.filter(method => method.id === head.kid);
  assert.equal(methods.length, 1); const method = methods[0];
  assert.equal(method.controller, did);
  assert.ok(document.assertionMethod.some(item => (typeof item === 'string' ? item : item.id) === head.kid));
  assert.ok(!Object.hasOwn(method.publicKeyJwk, 'd'));
  const key = crypto.createPublicKey({ key: method.publicKeyJwk, format: 'jwk' });
  assert.ok(crypto.verify('sha256', Buffer.from(`${header}.${payload}`), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(signature, 'base64url')));
  return crypto.createHash('sha256').update(raw).digest('hex');
}
function assertions(lane, checks) {
  const required = lane === 'expired-offer'
    ? ['expired_offer_gone', 'cached_code_denied', 'wallet_error_visible', 'no_credential_on_denial', 'fresh_reissue_received', 'receipt_has_no_session']
    : ['foreign_signature_valid', 'login_trust_excludes_foreign', 'issuer_not_trusted', 'auth_failure_visible', 'no_session_on_denial', 'trusted_login_recovery'];
  const result = Object.fromEntries([...required, 'login_trust_unchanged', 'signing_defaults_unchanged', 'discovery_restored', 'fixture_cleanup'].map(k => [k, checks[k] === true]));
  result[lane === 'expired-offer' ? 'expired_offer_reissue' : 'issuer_not_trusted_no_session'] = Object.values(result).every(Boolean);
  return result;
}
async function main(lane = process.argv[2], env = process.env) {
  guards(env, lane);
  const record = env.RECORD_VIDEO === '1';
  const dir = createArtifactDir(ROOT, `d05-${lane}-${Date.now()}`);
  assert.ok(!fs.existsSync(path.join(dir, 'report.json')), 'Refuse to overwrite an existing attempt');
  const report = { scenario: `D05 support: ${lane}`, classification: 'FIRST_PARTY_CONTROL', independentWalletQualification: false, startedAt: new Date().toISOString(), checks: {}, stage: 'setup', releaseReady: false };
  const browser = await chromium.launch({ headless: env.HEADED !== '1' });
  let adminContext, walletContext, authContext, operator, walletPage, authPage, clone;
  let initial, walletVideo, authVideo;
  const transactions = [];
  const step = (page, title, detail) => showStep(page, title, detail, { enabled: record, eyebrow: 'D05 supporting evidence · First-party test wallet' });
  const get = async url => { const response = await fetch(url); assert.ok(response.ok, 'Public fixture lookup failed'); return response.json(); };
  const request = (route, method = 'GET', body) => requireJson(operator, route, { method, ...(body ? { body: JSON.stringify(body) } : {}) });
  const state = async () => ({ trust: { profile: await request(`/v1/trust-profiles/${TRUST}`), issuers: await request(`/v1/trust-profiles/${TRUST}/issuers`) }, signing: await request(`/v1/signing-keys/config?organization_id=${ORG}`), discovery: await get(`${BASE}/.well-known/openid-credential-issuer/org/${ORG}`) });
  const defaults = signing => Object.fromEntries(['default_service_id', 'format_defaults', 'type_defaults'].map(k => [k, signing[k] ?? null]));
  const resetWallet = async () => { const r = await walletContext.request.post(`${WALLET}/api/reset`); assert.ok(r.ok()); };
  const inventory = async () => { const r = await walletContext.request.get(`${WALLET}/api/credentials`); assert.ok(r.ok()); return r.json(); };
  const issue = async template => {
    const result = await request('/v1/issuance', 'POST', { organization_id: ORG, credential_template_id: template, subject_did: env.MARTY_TEST_WALLET_HOLDER_KID, claims: { email: 'demo.member@example.test', organization_id: ORG, role: 'applicant', achievement_name: 'Verified Member', achievement_description: 'Synthetic D05 denial and recovery', issued_at: new Date().toISOString() } });
    assert.match(result.id, UUID); transactions.push(result.id); return result;
  };
  const receive = async offer => {
    await walletPage.goto(WALLET); await maskProtocolField(walletPage, 'Credential offer URI', true);
    await walletPage.getByLabel('Credential offer URI').fill(offer);
    const pending = walletPage.waitForResponse(r => r.url() === `${WALLET}/api/receive` && r.request().method() === 'POST');
    await walletPage.getByRole('button', { name: /^receive$/i }).click(); return pending;
  };
  const authMe = async () => { const r = await authContext.request.get(`${BASE}/v1/auth/me`); assert.ok(r.ok()); return r.json(); };
  const present = async () => {
    await authPage.goto(`${BASE}/v1/auth/credential-login`);
    const details = await authPage.evaluate(() => ({ nonce: document.body.dataset.nonce, href: document.querySelector('#wallet-link')?.href }));
    assert.ok(details.nonce && details.href);
    await step(authPage, 'Present a membership badge', 'This is the ElevenID credential sign-in page. The separate browser wallet is a first-party test client.');
    await maskProtocolField(walletPage, 'Presentation request URI', true);
    await walletPage.getByLabel('Presentation request URI').fill(details.href);
    const pending = walletPage.waitForResponse(r => r.url() === `${WALLET}/api/present` && r.request().method() === 'POST');
    await walletPage.getByRole('button', { name: /^present$/i }).click(); const response = await pending;
    const outcome = await waitFor(async () => {
      const r = await authContext.request.get(`${BASE}/v1/auth/credential-login/status?nonce=${encodeURIComponent(details.nonce)}`);
      const body = await r.json(); return body.status !== 'pending' ? body : null;
    }, 60000, 500);
    return { ...details, outcome, responseStatus: response.status() };
  };
  try {
    const live = await get(`${BASE}/.well-known/marty-release`);
    assert.equal(live.deployment_release_marker, env.D05_EXPECTED_RELEASE_MARKER);
    assert.equal(live.component_revisions['marty-ui'], env.D05_EXPECTED_UI_REVISION);
    assert.equal(live.component_revisions['marty-ui-auth'], env.D05_EXPECTED_AUTH_REVISION);
    assert.equal(live.component_revisions['marty-ui-presentation-policy'], env.D05_EXPECTED_POLICY_REVISION);
    report.deployment = live;
    adminContext = await browser.newContext(); operator = await adminContext.newPage();
    await login(operator, env.TEST_ADMIN_EMAIL, env.TEST_ADMIN_PASSWORD);
    initial = await state(); report.loginTrustBeforeSha256 = hash(initial.trust); report.signingDefaultsBeforeSha256 = hash(defaults(initial.signing)); report.discoveryBeforeSha256 = hash(initial.discovery);
    walletContext = await browser.newContext({ viewport: VIDEO_SIZE, ...(record ? { recordVideo: { dir, size: VIDEO_SIZE } } : {}) });
    authContext = await browser.newContext({ viewport: VIDEO_SIZE, ...(record && lane === 'untrusted-issuer' ? { recordVideo: { dir, size: VIDEO_SIZE } } : {}) });
    // Redact transient QR request tokens without substituting any authentication outcome.
    await authContext.route('https://api.qrserver.com/**', route => route.fulfill({ contentType: 'image/svg+xml', body: '<svg xmlns="http://www.w3.org/2000/svg" width="220" height="220"><rect width="220" height="220" fill="#e5e7eb"/><text x="110" y="110" text-anchor="middle" font-family="Arial" font-size="16">QR token redacted</text></svg>' }));
    report.captureRedactions = ['protocol input fields masked', 'QR token replaced by labeled redaction'];
    await authContext.addInitScript(() => Object.defineProperty(globalThis, 'DigitalCredential', { value: undefined, configurable: false }));
    walletPage = await walletContext.newPage(); walletVideo = walletPage.video(); authPage = await authContext.newPage(); authVideo = authPage.video();
    await resetWallet(); assert.equal((await inventory()).length, 0); assert.equal((await authMe()).authenticated, false);
    if (lane === 'expired-offer') {
      report.stage = 'expired_offer'; const issued = await issue(TEMPLATE); report.expiredTransactionId = issued.id;
      const url = new URL(issued.credential_offer_uri).searchParams.get('credential_offer_uri') || `${BASE}/v1/issuance/offers/${issued.id}`;
      assert.equal(new URL(url).origin, BASE); const offer = await get(url);
      assert.equal(sql(expirySql(issued.id)), issued.id);
      report.checks.expired_offer_gone = (await fetch(url)).status === 410;
      const metadata = await get(`${BASE}/.well-known/oauth-authorization-server${new URL(offer.credential_issuer).pathname}`);
      assert.equal(new URL(metadata.token_endpoint).origin, BASE);
      const grant = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
      const token = await fetch(metadata.token_endpoint, { method: 'POST', body: new URLSearchParams({ grant_type: grant, 'pre-authorized_code': offer.grants[grant]['pre-authorized_code'] }) });
      report.checks.cached_code_denied = token.status === 400 && (await token.json()).error === 'invalid_grant';
      const denied = await receive(issued.credential_offer_uri); assert.ok(!denied.ok());
      await walletPage.locator('#status.error').waitFor();
      assert.ok((await walletPage.locator('#status').innerText()).trim());
      report.checks.wallet_error_visible = true;
      report.checks.no_credential_on_denial = (await inventory()).length === 0 && sql(`SELECT count(*) FROM issuance_service.issued_credentials WHERE transaction_id='${issued.id}';`) === '0';
      await step(walletPage, 'Expired offer rejected', 'The test wallet shows the real receipt error. The server issued no credential and the wallet remains empty.');
      await walletPage.screenshot({ path: path.join(dir, '01-expired-offer-denied.png') });
      report.stage = 'fresh_reissue'; const replacement = await issue(TEMPLATE); assert.notEqual(replacement.id, issued.id); report.replacementTransactionId = replacement.id;
      assert.ok((await receive(replacement.credential_offer_uri)).ok());
      await walletPage.getByRole('status').filter({ hasText: 'Credential received' }).waitFor();
      const credentials = await inventory(); report.checks.fresh_reissue_received = credentials.length === 1 && credentials[0].credential_configuration_id === 'open_badge';
      report.checks.receipt_has_no_session = (await authMe()).authenticated === false;
      await step(walletPage, 'Fresh offer received', 'A new offer succeeds. Receiving a credential does not itself sign the holder into ElevenID.');
      await walletPage.screenshot({ path: path.join(dir, '02-fresh-offer-received.png') });
    } else {
      report.stage = 'foreign_fixture'; const stamp = Date.now(); const did = `did:web:beta.elevenidllc.com:orgs:d05-support-${stamp}`;
      await request('/v1/signing-keys/issuer-identities', 'POST', { organization_id: ORG, issuer_did: did, key_purpose: 'vc_jwt_issuer', credential_format: 'VC_JWT', algorithm: 'ES256' });
      const document = await get(`${BASE}/orgs/d05-support-${stamp}/did.json`);
      const trust = await request('/v1/trust-profiles', 'POST', { organization_id: ORG, name: `D05 support issuer ${stamp}`, profile_type: 'CUSTOM', trust_sources: [], allowed_algorithms: ['ES256'], supported_formats: ['VC_JWT'], allowed_issuers: [did], denied_issuers: [] });
      assert.notEqual(trust.id, TRUST); await ensureGovernedIssuer(operator, { organizationId: ORG, trustProfileId: trust.id, issuerDid: did, displayName: `D05 support issuer ${stamp}`, idempotencyKey: `d05-${stamp}` });
      await request(`/v1/trust-profiles/${trust.id}/activate`, 'POST');
      clone = await request(`/v1/credential-templates/${TEMPLATE}/new-version`, 'POST');
      await request(`/v1/credential-templates/${clone.id}`, 'PATCH', { name: `D05 support badge ${stamp}`, issuer_did: did, trust_profile_id: trust.id });
      await request(`/v1/credential-templates/${clone.id}/activate`, 'POST');
      report.checks.login_trust_excludes_foreign = hash((await state()).trust) === hash(initial.trust) && !JSON.stringify(initial.trust).includes(did);
      const issued = await issue(clone.id); assert.ok((await receive(issued.credential_offer_uri)).ok());
      const raw = sql(`SELECT credential_jwt FROM issuance_service.issued_credentials WHERE transaction_id='${issued.id}';`);
      report.credentialSha256 = verifyForeignSignature(raw, document, did); report.checks.foreign_signature_valid = true;
      report.stage = 'untrusted_denial'; const denied = await present();
      report.denial = { status: denied.outcome.status, reasonCode: denied.outcome.reason_code, walletHttpStatus: denied.responseStatus };
      report.checks.issuer_not_trusted = denied.outcome.status === 'failed' && denied.outcome.reason_code === 'issuer_not_trusted';
      await authPage.locator('#status .err').waitFor();
      report.checks.auth_failure_visible = /does not trust for sign-in/i.test(await authPage.locator('#status').innerText()) && await authPage.locator('#status').getByRole('link', { name: 'Try again' }).isVisible();
      assert.equal((await authMe()).authenticated, false);
      const finalize = await authContext.request.get(`${BASE}/v1/auth/credential-login/finalize?nonce=${encodeURIComponent(denied.nonce)}`, { maxRedirects: 0 });
      report.checks.no_session_on_denial = !finalize.headers()['set-cookie'] && (await authMe()).authenticated === false;
      await step(authPage, 'Issuer is not trusted for sign-in', 'The real sign-in page reports verification failure. This valid badge belongs to an issuer outside the login trust policy; no login session was created.');
      await authPage.screenshot({ path: path.join(dir, '01-auth-issuer-denied.png') });
      await request(`/v1/credential-templates/${clone.id}/deprecate`, 'POST');
      report.stage = 'trusted_recovery'; await resetWallet(); const trusted = await issue(TEMPLATE); assert.ok((await receive(trusted.credential_offer_uri)).ok());
      const recovered = await present(); assert.equal(recovered.outcome.status, 'completed');
      await waitFor(async () => (await authMe()).authenticated === true, 60000, 500);
      report.checks.trusted_login_recovery = true;
      await authPage.waitForURL(url => !url.pathname.includes('credential-login'), { timeout: 60000 });
      await step(authPage, 'Trusted badge signs in', 'A fresh badge from the configured trusted issuer completes sign-in and opens the ElevenID portal.');
      await authPage.screenshot({ path: path.join(dir, '02-auth-trusted-recovery.png') });
    }
  } catch (error) {
    report.failure = { type: error.name, stage: report.stage }; // Do not serialize request/credential-bearing exceptions.
  } finally {
    try {
      if (operator && initial) {
        if (clone) {
          const current = await request(`/v1/credential-templates/${clone.id}`);
          if (current.status.toUpperCase() !== 'DEPRECATED') await request(`/v1/credential-templates/${clone.id}/deprecate`, 'POST');
        }
        for (const id of transactions) {
          const credentialIds = sql(`SELECT id FROM issuance_service.issued_credentials WHERE transaction_id='${id}';`).split(/\r?\n/).filter(Boolean);
          for (const credentialId of credentialIds) { await request(credentialPath(credentialId), 'POST', { reason: 'D05 synthetic supporting lane cleanup' }); }
        }
        if (walletContext) await resetWallet();
        report.checks.fixture_cleanup = true;
        const after = await state(); report.loginTrustAfterSha256 = hash(after.trust); report.signingDefaultsAfterSha256 = hash(defaults(after.signing)); report.discoveryAfterSha256 = hash(after.discovery);
        report.checks.login_trust_unchanged = report.loginTrustBeforeSha256 === report.loginTrustAfterSha256;
        report.checks.signing_defaults_unchanged = report.signingDefaultsBeforeSha256 === report.signingDefaultsAfterSha256;
        report.checks.discovery_restored = report.discoveryBeforeSha256 === report.discoveryAfterSha256;
      }
    } catch (error) { report.cleanupFailure = { type: error.name }; }
    for (const context of [authContext, walletContext, adminContext]) if (context) await context.close().catch(() => {});
    if (record) {
      if (walletVideo) await finalizeVideo(walletVideo, dir, lane === 'expired-offer' ? 'd05-expired-offer.webm' : 'd05-untrusted-issuer-wallet.webm');
      if (authVideo) await finalizeVideo(authVideo, dir, 'd05-untrusted-issuer.webm');
    }
    await browser.close();
    report.behaviorAssertions = assertions(lane, report.checks);
    report.releaseReady = !report.failure && !report.cleanupFailure && Object.values(report.behaviorAssertions).every(Boolean);
    report.finishedAt = new Date().toISOString();
    fs.writeFileSync(path.join(dir, 'report.json'), JSON.stringify(report, null, 2)+'\n');
    console.log(JSON.stringify({ scenario: report.scenario, stage: report.stage, releaseReady: report.releaseReady, failure: report.failure, cleanupFailure: report.cleanupFailure, behaviorAssertions: report.behaviorAssertions }));
    if (!report.releaseReady) process.exitCode = 1;
  }
}
if (require.main === module) main().catch(error => { console.error(JSON.stringify({ failed: true, type: error.name })); process.exitCode = 1; });
module.exports = { guards, credentialPath, expirySql, verifyForeignSignature, assertions };
