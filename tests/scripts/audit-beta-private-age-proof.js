#!/usr/bin/env node
/* D03: actual native mDL issuance + independent Android wallet presentation.
 * This adapter owns browser/device control. Rust owns API/claim/ownership checks.
 * No saved PASS report, local test wallet or synthetic presentation is accepted.
 */
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { browserJson, cancelOwnedIssuanceTransaction, selectOrganization } = require('./beta-demo-resource-helpers');
const { createActionRecording, createArtifactDir, finalizeVideo, VIDEO_SIZE } = require('./demo-recording');

const ROOT = path.resolve(__dirname, '../..');
const idPattern = /^[A-Za-z0-9_-]{1,128}$/;
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const REQUIRED_LANES = ['eudi-age-proof-interoperability', 'spruceid-age-proof-interoperability'];

function sourceBinding(repository, expectedRevision) {
  const revision = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: repository, encoding: 'utf8' });
  const status = spawnSync('git', ['status', '--porcelain', '--untracked-files=all'], { cwd: repository, encoding: 'utf8' });
  if (revision.status !== 0 || status.status !== 0 || status.stdout.trim()
    || !/^[a-f0-9]{40}$/.test(expectedRevision || '') || revision.stdout.trim() !== expectedRevision) {
    throw Error('D03 requires the exact frozen, clean source worktree');
  }
  return { revision: revision.stdout.trim() };
}

function rustCheck(operation, expected, observed) {
  const result = spawnSync('cargo', ['run', '--quiet', '--locked', '--manifest-path', 'rust/Cargo.toml',
    '-p', 'marty-release-evidence', '--bin', 'validate-age-proof-demo', '--', operation], {
    cwd: ROOT, encoding: 'utf8', input: JSON.stringify({ expected, observed }),
    maxBuffer: 3 * 1024 * 1024, timeout: 180000,
  });
  if (result.status !== 0) throw Error(`D03 Rust ${operation} check rejected the run: ${String(result.stderr || result.error?.message || '').slice(-2000)}`);
  const receipt = JSON.parse(result.stdout);
  if (receipt.schema !== 'marty-age-proof-demo/v1' || receipt.operation !== operation || receipt.run_id !== expected.run_id) {
    throw Error('D03 Rust receipt binding is invalid');
  }
  return receipt.evidence;
}

function successful(reply, label) {
  if (!reply || reply.status < 200 || reply.status >= 300 || reply.body === null || reply.body === undefined) {
    throw Error(`${label} failed (HTTP ${reply?.status ?? 'unknown'})`);
  }
  return reply.body;
}

function createAgeProofController({ page, expected, syntheticClaims, recording,
  check = rustCheck, api = browserJson, readRequest, onState = () => {} }) {
  const owned = { issuance: [], instances: [], uncertainMutations: [] };
  let plan;
  const laneResults = [];
  const attemptedLanes = new Set();
  const dispatch = action => api(page, action.path, { method: action.method, body: JSON.stringify(action.body) });
  const get = route => api(page, route);
  const notify = () => onState({ ownedResources: JSON.parse(JSON.stringify(owned)), laneResults });

  async function create(action, label, idKey, retain) {
    const pending = { operation: label, outcome: 'UNKNOWN' };
    owned.uncertainMutations.push(pending);
    notify();
    const reply = await dispatch(action);
    const id = reply?.body?.[idKey];
    if (reply.status >= 200 && reply.status < 300 && typeof id === 'string' && idPattern.test(id)) {
      // Save exact returned ownership before any follow-up GET, evidence check
      // or recording action can fail. Never recover it by listing newest items.
      retain(id);
      owned.uncertainMutations.splice(owned.uncertainMutations.indexOf(pending), 1);
    } else if ([400, 401, 403, 404, 409, 422].includes(reply.status)) {
      owned.uncertainMutations.splice(owned.uncertainMutations.indexOf(pending), 1);
    }
    notify();
    successful(reply, label);
    if (typeof id !== 'string' || !idPattern.test(id)) throw Error(`${label} returned no exact resource ID; cleanup remains incomplete`);
    return reply;
  }

  async function preflight() {
    // These are read-only. A missing dependency never marks a mutation uncertain.
    check('inputs', expected, {});
    const trusted = successful(await get(`/v1/credential-templates/${expected.trusted_template_id}`), 'Trusted mDL template');
    const rejected = successful(await get(`/v1/credential-templates/${expected.rejected_template_id}`), 'Rejected-issuer mDL template');
    const policy = successful(await get(`/v1/presentation-policies/${expected.policy_id}`), 'Age presentation policy');
    const trust = successful(await get(`/v1/trust-profiles/${expected.trust_profile_id}`), 'Age issuer trust profile');
    plan = check('prepare', expected, { trusted_template: trusted, rejected_template: rejected,
      policy, trust_profile: trust, synthetic_claims: syntheticClaims });
    return { setupSha256: plan.setup_sha256, trustedTemplateName: trusted.name, rejectedTemplateName: rejected.name };
  }

  async function prepareLane(laneId) {
    if (!plan || !REQUIRED_LANES.includes(laneId) || attemptedLanes.has(laneId)) throw Error('D03 lane is not prepared or is duplicated');
    attemptedLanes.add(laneId);
    const binding = { serviceOrigin: expected.service_origin };
    for (const kind of ['trusted', 'rejected']) {
      const templateId = expected[`${kind}_template_id`];
      const issuanceReply = await create(plan[`${kind}_issuance`], `${laneId}-${kind}-issuance`, 'id', id => {
        owned.issuance.push({ id, template_id: templateId, laneId, kind });
      });
      const issuance = successful(issuanceReply, 'mDL issuance');
      if (issuance.organization_id !== expected.organization_id || issuance.credential_template_id !== templateId) {
        throw Error('Issuance response crossed its organization or template boundary');
      }
      const externalReference = `D03-${expected.run_id}-${laneId}-${kind}`;
      const action = { ...plan.verification, body: { ...plan.verification.body, external_reference: externalReference } };
      const startReply = await create(action, `${laneId}-${kind}-verification`, 'instance_id', id => {
        owned.instances.push({ id, externalReference, laneId, kind });
      });
      const instanceId = startReply.body.instance_id;
      const instanceReply = await get(`/v1/flows/instances/${instanceId}`);
      const requestJwt = await readRequest(`/v1/flows/instances/${instanceId}/request`);
      const requestBinding = check('request', expected, { start_reply: startReply, instance_reply: instanceReply,
        request_jwt: requestJwt, external_reference: externalReference });
      binding[kind] = { templateId, instanceId, externalReference, issuanceReply, requestBinding,
        offerUri: issuance.credential_offer_uri, requestUri: startReply.body.request_uri };
    }
    if (recording) await recording.explain(page, 'issue', 'Fresh mDL offers and age-only verification requests now belong to this run. The independent wallet must receive and present them.', { title: '1. Issue an mDL / 2. Request only age' });
    return binding;
  }

  async function completeLane(laneId, binding, device) {
    const inventory = successful(await get(`/v1/issued-credentials?organization_id=${expected.organization_id}`), 'Issued mDL inventory');
    const issuedBindings = {};
    for (const kind of ['trusted', 'rejected']) {
      issuedBindings[kind] = check('issued', expected, { template_id: binding[kind].templateId,
        issuance_reply: binding[kind].issuanceReply, issued_credentials: inventory });
    }
    const allowed = check('allowed', expected, { request_binding: binding.trusted.requestBinding,
      result_reply: await get(`/v1/flows/instances/${binding.trusted.instanceId}/result`) });
    const denied = check('denied', expected, { request_binding: binding.rejected.requestBinding,
      issued_binding: issuedBindings.rejected, instance_reply: await get(`/v1/flows/instances/${binding.rejected.instanceId}`),
      wallet_report: device.report, denial_action_index: device.denialActionIndex,
      rejection_text: device.rejectionText, scenario_sha256: device.scenarioSha256 });
    if (denied.issuer_trust_denial_observed !== true) throw Error('BLOCKED: generic wallet rejection is not issuer-trust denial evidence');
    const result = { laneId, trustedIssuance: issuedBindings.trusted, rejectedIssuance: issuedBindings.rejected,
      allowed, denied, deviceReportSha256: device.report.reportSha256, scenarioSha256: device.scenarioSha256,
      controlSource: device.controlSource };
    laneResults.push(result);
    notify();
    return result;
  }

  async function cleanup() {
    const summary = { ok: false, actions: [], pendingOffers: [], uncertainMutations: [...owned.uncertainMutations], errors: [] };
    try {
      if (!owned.issuance.length && !owned.instances.length) {
        summary.ok = summary.uncertainMutations.length === 0;
        return summary;
      }
      const inventory = successful(await get(`/v1/issued-credentials?organization_id=${expected.organization_id}`), 'Cleanup inventory');
      const instances = [];
      for (const instance of owned.instances) instances.push(successful(await get(`/v1/flows/instances/${instance.id}`), 'Owned verification cleanup lookup'));
      const cleanupPlan = check('cleanup', expected, { owned_issuance: owned.issuance,
        issued_credentials: inventory, owned_instances: instances });
      summary.pendingOffers = [...cleanupPlan.pending_offers];
      for (const transactionId of cleanupPlan.pending_offers) {
        const entry = { resource: 'issuance', id: transactionId, ok: false };
        summary.actions.push(entry);
        const matchesCancellation = mutation => mutation.operation === 'transaction_cancellation'
          && mutation.transactionId === transactionId;
        let cancellation;
        try {
          const captured = owned.issuance.filter(item => item.id === transactionId);
          if (captured.length !== 1) throw Error('D03 pending cleanup requires one exact captured transaction');
          cancellation = { organizationId: expected.organization_id, credentialTemplateId: captured[0].template_id,
            transactionId, applicationId: null, uncertainMutations: owned.uncertainMutations.filter(matchesCancellation) };
          // The shared transport rechecks the authenticated transaction and
          // inventory, then requires exact revoked readback, including expiry.
          entry.cancellation = await cancelOwnedIssuanceTransaction(page, cancellation, 'D03 current-run cleanup');
          entry.ok = entry.cancellation.ok === true;
          if (entry.ok) summary.pendingOffers = summary.pendingOffers.filter(id => id !== transactionId);
          else entry.error = 'D03 pending transaction cancellation was not confirmed';
        } catch (error) { entry.error = error.message; }
        finally {
          if (cancellation) {
            // Keep uncertainty scoped to this transaction: reconciling one
            // offer must never clear another offer or a lost creation ID.
            owned.uncertainMutations = [
              ...owned.uncertainMutations.filter(mutation => !matchesCancellation(mutation)),
              ...cancellation.uncertainMutations.map(mutation => ({ ...mutation, transactionId })),
            ];
          }
          summary.uncertainMutations = [...owned.uncertainMutations];
          notify();
        }
      }
      for (const action of cleanupPlan.actions) {
        const entry = { resource: action.resource, id: action.id, ok: false };
        summary.actions.push(entry);
        try {
          successful(await dispatch(action), 'Owned D03 cleanup');
          const route = action.resource === 'credential' ? `/v1/issued-credentials/${action.id}` : `/v1/flows/instances/${action.id}`;
          const after = successful(await get(route), 'Confirm owned D03 cleanup');
          if (after.id !== action.id || after.organization_id !== expected.organization_id || after.status !== action.expected_status) {
            throw Error('D03 cleanup response did not confirm the exact owned resource state');
          }
          entry.ok = true;
        } catch (error) { entry.error = error.message; }
      }
      summary.ok = !summary.pendingOffers.length && !summary.uncertainMutations.length && summary.actions.every(action => action.ok);
    } catch (error) { summary.errors.push(error.message); }
    return summary;
  }
  return { preflight, prepareLane, completeLane, cleanup, owned, laneResults };
}

async function login(page, origin, email, password) {
  await page.goto(`${origin}/v1/auth/login?redirect_uri=${encodeURIComponent('/console/org')}`, { waitUntil: 'domcontentloaded', timeout: 60000 });
  await page.locator('#username, input[name="username"], input[type="email"]').first().fill(email);
  await page.locator('#password, input[name="password"], input[type="password"]').first().fill(password);
  await Promise.all([
    page.waitForURL(url => url.origin === origin && url.pathname.startsWith('/console'), { timeout: 60000 }),
    page.locator('#kc-login, button[type="submit"], input[type="submit"]').first().click(),
  ]);
  if (successful(await browserJson(page, '/v1/auth/me'), 'D03 authentication').authenticated !== true) throw Error('D03 did not authenticate');
}

async function main() {
  const artifactDir = createArtifactDir(ROOT, 'private-online-age-proof');
  const report = { schemaVersion: 1, releaseReady: false, scenario: 'private-online-age-proof',
    startedAt: new Date().toISOString(), behaviorAssertions: {}, errors: [], limitations: [
      'Native API receipts do not replace EUDI and SpruceID Android recordings.',
      'API fixture issuance and native deep-link handoff are explicit; this does not claim a governed applicant claim UI or camera QR scanning.',
      'Issuer-trust denial requires an explicit issuer-untrusted message observed in the pinned wallet. Generic presentation rejection cannot pass. A typed backend issuer_not_trusted reason remains unavailable.',
      'Android emulator evidence does not establish physical-device security.',
    ] };
  let browser, context, video, controller;
  try {
    if (process.env.RECORD_VIDEO !== '1') throw Error('D03 requires fresh independent-wallet recordings; functional-only or saved-report qualification is unsupported');
    if (process.env.NODE_TLS_REJECT_UNAUTHORIZED === '0' || process.env.BETA_LOCAL_PROXY === '1' || process.env.MARTY_UI_CANDIDATE_DIST) throw Error('D03 production capture requires authenticated HTTPS and the deployed UI');
    const fixturePath = process.env.D03_FIXTURE_PATH;
    if (!fixturePath) throw Error('D03_FIXTURE_PATH must identify the frozen non-secret release fixture');
    const bytes = fs.readFileSync(fixturePath);
    if (bytes.length > 1024 * 1024) throw Error('D03 release fixture exceeds its size bound');
    const fixture = JSON.parse(bytes);
    if (fixture.schemaVersion !== 1 || fixture.syntheticIdentity !== true) throw Error('D03 requires its reviewed synthetic-identity fixture');
    if (fixture.expected.service_origin !== process.env.BETA_ORIGIN) throw Error('D03 fixture service origin must match the recorder release probe');
    report.source = sourceBinding(ROOT, fixture.expected.source_revision);
    const recorderRepository = path.resolve(path.dirname(fixturePath), fixture.recorderRepository);
    report.recorderSource = sourceBinding(recorderRepository, fixture.recorderRevision);
    report.fixtureSha256 = sha256(bytes);
    const expected = { ...fixture.expected, run_id: randomUUID(), started_at: report.startedAt };
    rustCheck('inputs', expected, {});
    report.runId = expected.run_id;
    const gatewayConfigPath = path.resolve(path.dirname(fixturePath), fixture.androidGatewayConfig);
    const { runPrivateAgeProofGateway } = require(path.join(recorderRepository, 'src/privateAgeProofGateway.js'));
    const email = process.env.DEMO_SECRET_D03_ADMIN_EMAIL;
    const password = process.env.DEMO_SECRET_D03_ADMIN_PASSWORD;
    if (!email || !password) throw Error('D03 requires the dedicated synthetic administrator runtime credentials');
    const { chromium } = require('@playwright/test');
    browser = await chromium.launch({ headless: process.env.HEADED !== '1' });
    context = await browser.newContext({ viewport: VIDEO_SIZE, recordVideo: { dir: artifactDir, size: VIDEO_SIZE } });
    const page = await context.newPage();
    video = page.video();
    const recording = createActionRecording({ enabled: true, scenario: 'private-online-age-proof',
      eyebrow: 'Private online age proof - Synthetic mDL holder', onEvent: evidence => { report.presentationRecording = evidence; } });
    await login(page, expected.service_origin, email, password);
    const selection = await selectOrganization(page, { organizationId: expected.organization_id, consoleOrigin: expected.service_origin });
    if (!selection.ok) throw Error('D03 administrator does not own the selected organization');
    controller = createAgeProofController({ page, expected, syntheticClaims: fixture.syntheticClaims, recording,
      onState: state => { report.ownedResources = state.ownedResources; report.lanes = state.laneResults; },
      readRequest: async route => {
        const reply = await page.evaluate(async requestPath => {
          const response = await fetch(requestPath, { credentials: 'include', redirect: 'error' });
          return { status: response.status, contentType: response.headers.get('content-type'), body: await response.text() };
        }, route);
        if (reply.status !== 200 || !reply.contentType?.startsWith('application/oauth-authz-req+jwt') || reply.body.length > 100000) throw Error('Native signed request object unavailable');
        return reply.body;
      } });
    report.preflight = await controller.preflight();
    await page.goto(`${expected.service_origin}/console/org/operate/verify`, { waitUntil: 'domcontentloaded' });
    await recording.explain(page, 'purpose', 'An online service needs one answer: is this holder over 21? Their name and date of birth are unnecessary.', { title: 'Private online age proof' });
    process.env.DEMO_RELEASE_OUTPUT_DIR = path.join(artifactDir, 'android');
    const gateway = await runPrivateAgeProofGateway(gatewayConfigPath, {
      prepareLane: controller.prepareLane,
      completeLane: async (lane, binding, device) => {
        const evidence = await controller.completeLane(lane, binding, device);
        await page.goto(`${expected.service_origin}/console/org/operate/verify`, { waitUntil: 'domcontentloaded' });
        await page.getByRole('tab', { name: /^History \(/ }).click();
        const row = page.locator(`tr[data-flow-instance-id="${binding.trusted.instanceId}"]`);
        await recording.click(page, row.getByRole('button', { name: 'View session details' }), { action: 'inspect-minimal-result' });
        const summary = page.getByTestId('verification-result-summary');
        await recording.hold(page, summary, 3200, { action: 'inspect-minimal-result' });
        if (await summary.getAttribute('data-verification-instance-id') !== binding.trusted.instanceId
          || await summary.getAttribute('data-disclosed-claim-names') !== '["age_over_21"]'
          || await summary.getAttribute('data-issuer-trusted') !== 'true') throw Error('Recorded product result does not match the native D03 evidence');
        await recording.explain(page, 'allowed', 'The trusted mDL passed. Authenticated disclosures contain only age_over_21.', { title: '3. Trusted issuer / Minimal response' });
        await recording.explain(page, 'denied', 'The wallet explicitly reports that this issuer is not trusted. The observed message is retained; the API does not provide a typed backend reason.', { title: '4. Issuer trust rejection' });
        return evidence;
      },
    });
    report.androidGate = gateway.report;
    report.lanes = controller.laneResults;
    if (gateway.report.result !== 'PASS' || REQUIRED_LANES.some(id => !gateway.receipts.some(result => result.laneId === id))) throw Error('Both EUDI and SpruceID live age-proof lanes must pass');
    report.behaviorAssertions = { trusted_mdl_issuance: true, request_only_age_over_21: true,
      verify_issuer_trust_and_minimum_response: true, untrusted_issuer_denied: true, independent_wallets_pass: true };
  } catch (error) { report.errors.push(String(error.message).slice(0, 2000)); }
  finally {
    try { report.cleanup = controller ? await controller.cleanup() : { ok: true, actions: [], pendingOffers: [], uncertainMutations: [] }; }
    catch (error) { report.cleanup = { ok: false, error: error.message }; }
    if (context) {
      try {
        await context.close();
        if (video) {
          const videoPath = await finalizeVideo(video, artifactDir, 'private-online-age-proof-application.webm');
          report.applicationVideo = { path: path.basename(videoPath), sha256: sha256(fs.readFileSync(videoPath)) };
        }
      } catch (error) { report.errors.push(error.message); }
    }
    if (browser) await browser.close().catch(error => report.errors.push(error.message));
    report.releaseReady = report.errors.length === 0 && report.cleanup?.ok === true
      && report.androidGate?.result === 'PASS' && !!report.applicationVideo
      && report.behaviorAssertions.independent_wallets_pass === true;
    report.result = report.releaseReady ? 'PASS' : report.lanes?.length ? 'FAIL' : 'BLOCKED';
    report.completedAt = new Date().toISOString();
    fs.writeFileSync(path.join(artifactDir, 'report.json'), `${JSON.stringify(report, null, 2)}\n`);
  }
  if (!report.releaseReady) throw Error(`D03 ${report.result}: ${report.errors.join('; ') || 'cleanup or evidence incomplete'}`);
  return report;
}

if (require.main === module) main().catch(error => { console.error(error.message); process.exitCode = 1; });
module.exports = { createAgeProofController, rustCheck, sourceBinding, successful };
