#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { randomUUID, createHash } = require('node:crypto');
const { chromium } = require('@playwright/test');
const stock = require('./run-canvas-oss-standard-contract');
const { runCanvasCapture, requireCaptureMutationReconciliation } = require('./canvas-capture-sequence');
const { acquireWalletSession } = require('./demo-wallet-session');
const { login, selectOrg } = require('./audit-beta-credential-lifecycle');
const { VIDEO_SIZE, finalizeVideo, showStep, showVerificationResult } = require('./demo-recording');

async function main() {
  const scenario = process.argv[2];
  assert.ok(['canvas-learning-achievement', 'external-evidence-to-credential'].includes(scenario));
  assert.equal(process.env.BETA_ORIGIN, 'https://beta.elevenidllc.com');
  assert.equal(process.env.BETA_AUDIT_ORG_ID, process.env.CANVAS_OSS_ORGANIZATION_ID,
    'Browser admin and Canvas service actor must select the same organization');
  assert.ok(!process.env.NODE_TLS_REJECT_UNAUTHORIZED || process.env.NODE_TLS_REJECT_UNAUTHORIZED === '1');
  assert.ok(!process.env.MARTY_UI_CANDIDATE_DIST && process.env.BETA_LOCAL_PROXY !== '1');
  const executionBoundary = stock.requireComposeExecutionBoundary();
  for (const key of ['CANVAS_OSS_ADMIN_EMAIL', 'CANVAS_OSS_LEARNER_EMAIL', 'CANVAS_CAPTURE_ADMIN_EMAIL']) {
    assert.match(stock.requireSecretFile(key), /^[a-z0-9._+-]+@(?:marty\.demo|[a-z0-9.-]+\.test)$/i,
      'Canvas recording requires explicitly synthetic identities');
  }
  assert.ok(process.connected, 'Canvas capture requires recorder-owned live IPC');
  const helper = process.env.DEMO_EXECUTION_EVIDENCE_HELPER;
  assert.equal(createHash('sha256').update(fs.readFileSync(helper)).digest('hex'),
    process.env.DEMO_EXECUTION_EVIDENCE_HELPER_SHA256);
  const evidence = await require(helper).createLiveEvidenceClient();
  const dir = path.resolve(process.env.DEMO_ARTIFACT_DIR);
  const recording = process.env.RECORD_VIDEO === '1';
  const report = { scenario, startedAt: new Date().toISOString(), status: 'FAIL',
    executionBoundary,
    releaseReady: false, captureClassification: 'FIRST_PARTY_BROWSER_RUST_WALLET',
    editorialReview: 'NOT_REVIEWED', productionDemoReady: false,
    nativeIndependentWalletCapture: false, operations: [], behaviorAssertions: {}, failures: [] };
  const setupState = {};
  const contexts = [], videos = new Map();
  let browser, setup, session, adminPage, complete = false, applicationId;
  const save = (file, value) => fs.writeFileSync(path.join(dir, file), JSON.stringify(value, null, 2) + '\n', { flag: 'wx' });
  async function recordContext() {
    const context = await browser.newContext({ viewport: VIDEO_SIZE,
      ...(recording ? { recordVideo: { dir, size: VIDEO_SIZE } } : {}) });
    contexts.push(context);
    return context;
  }
  async function deployment() {
    const response = await fetch('https://beta.elevenidllc.com/.well-known/marty-release',
      { redirect: 'error', signal: AbortSignal.timeout(15000) });
    assert.equal(response.status, 200);
    const value = await response.json();
    assert.match(value.marty_ui_sha || '', /^[a-f0-9]{40}$/);
    assert.ok(value.deployment_release_marker);
    return { source: value.marty_ui_sha, marker: value.deployment_release_marker,
      componentRevisions: value.component_revisions, images: value.image_digests };
  }
  try {
    report.deployment = await deployment();
    // This exact recorder checkout is already bound by the parent and helper
    // handshake. The imported report remains a prerequisite, never an assertion.
    const { loadCanvasPortabilityAttestation } = require(path.join(path.dirname(helper), 'canvasPortabilityAttestation.js'));
    const prerequisite = loadCanvasPortabilityAttestation(process.env.CANVAS_PORTABILITY_ATTESTATION_PATH);
    assert.equal(prerequisite.summary.marty_release_version, report.deployment.marker);
    assert.equal(prerequisite.summary.marty_source_id, report.deployment.source);
    report.prerequisite = prerequisite.summary;
    const input = { schemaVersion: 1, scenario, runId: randomUUID(),
      grades: [95, 40, 95], organizationId: process.env.CANVAS_OSS_ORGANIZATION_ID };
    save('canvas-run-input.json', input);
    const actual = JSON.parse((await evidence.readFixture('canvas-run-input.json')).toString('utf8'));
    assert.deepEqual(actual, input);
    browser = await chromium.launch({ headless: process.env.HEADED !== '1' });
    const ledger = new stock.ObservationLedger(report.startedAt, { scope: 'CURRENT_RUN_SETUP_PREREQUISITES_ONLY' });
    setup = await stock.prepareCanvasCaptureFixtures({ browser, ledger, state: setupState,
      runSuffix: actual.runId, ownershipDirectory: dir, pass: (id, detail) => ledger.pass(id, detail),
      prerequisiteDirectory: path.dirname(path.resolve(process.env.CANVAS_PORTABILITY_ATTESTATION_PATH)) });
    assert.equal(setup.organizationId, actual.organizationId);
    const policyId = process.env.CANVAS_CAPTURE_PRESENTATION_POLICY_ID;
    assert.match(policyId || '', /^[a-f0-9-]{36}$/i);
    const policy = await setup.marty.get(`/v1/presentation-policies/${encodeURIComponent(policyId)}`);
    assert.equal(policy.organization_id, setup.organizationId);
    assert.equal(String(policy.status).toLowerCase(), 'active');
    assert.ok(policy.credential_requirements?.some(r => r.credential_template_id === setup.templates.credential.id),
      'Select an active canonical verification policy for the actual badge template');
    setup.templates.policy = policy;
    const fixture = { schemaVersion: 1, runId: actual.runId, scenario,
      organizationId: setup.organizationId, platformId: setup.platformId, bindingId: setup.binding.id,
      courseId: setup.fixtures.course.id, assignmentId: setup.fixtures.assignment.id,
      learnerId: setup.fixtures.learner.id, externalAssignmentId: setup.externalAssignment.id,
      credentialTemplateId: setup.templates.credential.id, policyId };
    save('canvas-owned-fixtures.json', fixture);
    const bound = JSON.parse((await evidence.readFixture('canvas-owned-fixtures.json')).toString('utf8'));
    assert.deepEqual(bound, fixture);
    await evidence.seal();
    report.fixtures = bound;

    const learner = await recordContext();
    await learner.addCookies(await setup.learnerContext.cookies());
    const canvasPage = await learner.newPage();
    evidence.bindPage(canvasPage);
    if (recording) videos.set(`${scenario}-canvas.webm`, canvasPage.video());
    const popups = [];
    // This context records every page. A real assignment popup is retained;
    // unexpected additional pages fail instead of silently escaping capture.
    learner.on('page', page => {
      popups.push(page);
      if (popups.length === 1) {
        evidence.bindPage(page);
        if (recording) videos.set(`${scenario}.webm`, page.video());
      }
    });
    const admin = await recordContext();
    adminPage = await admin.newPage();
    evidence.bindPage(adminPage);
    if (recording) videos.set(`${scenario}-admin.webm`, adminPage.video());
    await login(adminPage, stock.requireSecretFile('CANVAS_CAPTURE_ADMIN_EMAIL'),
      stock.requireSecretFile('CANVAS_CAPTURE_ADMIN_PASSWORD'));
    await selectOrg(adminPage);
    const walletContext = await recordContext();
    session = await acquireWalletSession(walletContext, { origin: 'http://127.0.0.1:8787', runId: actual.runId });
    report.walletSession = session.evidence;
    const walletPage = await walletContext.newPage();
    evidence.bindPage(walletPage);
    if (recording) videos.set(`${scenario}-wallet.webm`, walletPage.video());
    const checkpoint = async (page, phase, facts) => {
      assert.equal(popups.length, 1, 'Uncaptured or unexpected Canvas launch window');
      report.landmarks ||= [];
      report.landmarks.push({ phase, observedAt: new Date().toISOString(), facts,
        alignment: 'DRIVER_LANDMARK_ONLY_REQUIRES_MEASURED_SOURCE_FRAMES' });
      await showStep(page, phase.replaceAll('-', ' '), 'Canvas learning achievement',
        { enabled: recording, eyebrow: 'ElevenID learning credentials' });
      if (phase === 'wallet-receipt-and-verification') {
        await showVerificationResult(adminPage, report.verification.result, { enabled: recording,
          actor: 'Canvas credential verifier', testId: 'CANVAS-PRES-01' });
      }
      if (phase === 'correction-review-open' || phase === 'correction-review-resolved') {
        // Render the existing product review queue, never a success-only overlay.
        const loaded = adminPage.waitForResponse(r => new URL(r.url()).origin === setup.martyOrigin
          && new URL(r.url()).pathname === '/v1/integrations/canvas/evidence-policy-reviews'
          && r.request().method() === 'GET' && r.ok());
        await adminPage.goto(`${setup.martyOrigin}/console/org/deploy/canvas`, { waitUntil: 'domcontentloaded' });
        await loaded;
        const card = adminPage.getByTestId('canvas-correction-review').filter({ hasText: facts.credentialId });
        if (phase === 'correction-review-open') {
          await card.waitFor({ state: 'visible' });
          assert.equal(await card.getAttribute('data-review-id'), facts.id);
          assert.equal(await card.getAttribute('data-application-id'), facts.applicationId);
        } else { assert.equal(await card.count(), 0, 'Resolved review remains open in the actual queue'); }
      }
    };
    await runCanvasCapture({ setup, page: canvasPage, adminPage, walletPage, scenario,
      checkpoint, report, onApplication: id => { applicationId = id; } });
    assert.equal(popups.length, 1, 'Canvas opened an unexpected additional capture page');
    assert.deepEqual(await deployment(), report.deployment, 'Beta deployment changed during Canvas capture');
    complete = true;
  } catch (error) {
    // Do not put response bodies, bearer offers or credentials in reports.
    report.failures.push({ stage: 'execution', type: error.name, code: error.code || 'CANVAS_CAPTURE_FAILED' });
  } finally {
    async function cleanup(operation, fn) {
      try { await fn(); return true; } catch (error) {
        complete = false;
        report.failures.push({ stage: 'cleanup', operation, type: error.name });
        return false;
      }
    }
    if (session) await cleanup('wallet-session', () => session.close());
    const state = setup || setupState;
    let retired = true;
    if (state.marty && applicationId) retired = await cleanup('owned-issuance-retirement', async () => {
      const records = await state.marty.get(`/v1/issued-credentials?organization_id=${encodeURIComponent(state.organizationId || process.env.CANVAS_OSS_ORGANIZATION_ID)}`);
      const owned = records.filter(r => r.application_id === applicationId);
      assert.ok(owned.length <= 1);
      for (const record of owned) {
        assert.equal(record.organization_id, state.organizationId);
        assert.equal(record.credential_template_id, state.templates.credential.id);
        assert.equal(record.flow_execution_id, report.transactionId);
        const id = record.credential_id || record.id;
        await state.marty.post(`/v1/issued-credentials/${encodeURIComponent(id)}/revoke`, { reason: 'Run-owned Canvas capture cleanup' }, [200]);
        const current = await state.marty.get(`/v1/issued-credentials/${encodeURIComponent(id)}`);
        assert.equal(String(current.status).toUpperCase(), 'REVOKED');
      }
      // Retain application history. An unused reserved offer needs explicit
      // transaction revocation; never treat withdrawal as retirement.
      if (!owned.length && report.transactionId) {
        const transactionPath = `/v1/issuance/${encodeURIComponent(report.transactionId)}`;
        const scoped = `${transactionPath}?organization_id=${encodeURIComponent(state.organizationId)}`;
        const exact = transaction => {
          assert.equal(transaction.id, report.transactionId);
          assert.equal(transaction.application_id, applicationId);
          assert.equal(transaction.organization_id, state.organizationId);
          assert.equal(transaction.credential_template_id, state.templates.credential.id);
          assert.ok(!transaction.issued_at, 'Transaction already issued');
        };
        exact(await state.marty.get(scoped));
        await state.marty.post(`${transactionPath}/revoke`, { reason: 'Run-owned Canvas capture cleanup' }, [200]);
        const retired = await state.marty.get(scoped);
        exact(retired);
        assert.equal(String(retired.status).toLowerCase(), 'revoked');
      }
      requireCaptureMutationReconciliation(report);
    });
    report.resourceRetirementConfirmed = retired;
    let disconnected = retired;
    if (retired && state.marty && state.platformId && state.oauthConnected) disconnected = await cleanup('oauth-disconnect', async () => {
      const result = await state.marty.delete(`/v1/integrations/canvas/platforms/${encodeURIComponent(state.platformId)}/oauth`, [200]);
      assert.equal(result.status, 'disconnected');
      assert.equal(result.scopes.length, 0);
    });
    if (disconnected && state.marty && state.platformId) await cleanup('platform', () =>
      state.marty.delete(`/v1/integrations/canvas/platforms/${encodeURIComponent(state.platformId)}`, [204]));
    if (disconnected && state.marty && state.integrationSecretId) await cleanup('oauth-secret', () =>
      state.marty.delete(`/v1/integrations/canvas/integration-secrets/${encodeURIComponent(state.integrationSecretId)}`, [204]));
    for (const context of contexts) await cleanup('recording-context', () => context.close());
    for (const [file, video] of videos) await cleanup('recording-finalization', () => finalizeVideo(video, dir, file));
    if (browser) await cleanup('browser', () => browser.close());
    report.completedAt = new Date().toISOString();
    report.status = complete ? 'PASS' : 'FAIL';
    report.releaseReady = complete;
    save('report.json', report);
    try { if (complete) await evidence.complete(); } finally { evidence.close(); }
  }
  if (!complete) process.exitCode = 1;
}
if (require.main === module) main().catch(error => {
  const code = /^[A-Za-z0-9_]{1,80}$/.test(error.code || '') ? error.code : 'INITIALIZATION_FAILED';
  process.stderr.write(`Canvas capture initialization failed (${code}).\n`);
  process.exitCode = 1;
});
module.exports = { main };
