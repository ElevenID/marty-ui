'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createHash, createHmac } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const { verifyNegativeMedia, readPrivatePlan, validatePreliminary, validateLiveInstance,
  hideRecordedPage, revealRedactedPage, requireDirectBetaTransport } = require('./audit-beta-physical-passport-flow');
const routes = require('../../contracts/issuance-physical-passport-native.json').routes;
const steps = [
  'accept_application', 'validate_evidence', 'approval_decision',
  'generate_data_groups', 'sign_sod', 'submit_to_personalization',
  'track_production', 'quality_verify', 'activate_credential',
];

const digest = (value) => createHash('sha256').update(value).digest('hex');
const API_KEY = 'synthetic-beta-api-key-32-characters-minimum';
const commitment = (label, value) => createHmac('sha256', API_KEY).update(`${label}:${value}`).digest('hex');
const sha = (character) => character.repeat(64);
const privacyScan = (video) => `${JSON.stringify({
  schemaVersion: 1, passed: true, findings: [],
  videoSha256: digest(video), frameSamplingFps: 2,
})}\n`;

function fixture() {
  const artifactDir = fs.mkdtempSync(path.join(os.tmpdir(), 'passport-demo-audit-test-'));
  const stack = '{}\n';
  fs.writeFileSync(path.join(artifactDir, 'stack-manifest.json'), stack);
  const services = ['gateway', 'flow', 'issuance-native', 'signing-keys',
    'passport-callback-signer', 'passport-beta-bureau', 'postgres'];
  const plan = {
    schema: 'marty.passport-beta-aggregate-compose-plan/v1',
    beta_origin: 'https://beta.elevenidllc.com',
    source_commit: 'a'.repeat(40), stack_manifest_sha256: digest(stack),
    target_services: services.filter((name) => name !== 'postgres'),
  };
  const planWire = `${JSON.stringify(plan)}\n`;
  fs.writeFileSync(path.join(artifactDir, 'aggregate-deployment.json.plan.json'), planWire);
  const deployment = {
    schema: 'marty.passport-beta-aggregate-deployment/v1',
    beta_origin: 'https://beta.elevenidllc.com',
    source_commit: plan.source_commit, plan_sha256: digest(planWire),
    beta_services: services,
    beta_runtime: Object.fromEntries(services.map((name) => [name, {}])),
    acceptance_pending: true,
  };
  fs.writeFileSync(path.join(artifactDir, 'aggregate-deployment.json'), `${JSON.stringify(deployment)}\n`);
  const privatePlan = {
    schema: 'marty.passport-beta-demo-private/v1',
    source_commit: deployment.source_commit,
    stack_manifest_sha256: digest(stack),
    organization_id: 'synthetic-org', flow_definition_id: 'synthetic-definition',
    flow_instance_id: 'synthetic-flow', application_id: 'synthetic-app',
    source_job_id: 'synthetic-job',
    bureau_job_id: '76a7baef-368a-4722-95a4-df70ea1dfefa',
  };
  const flow = {
    routes,
    gateway_owner: 'rust', flow_owner: 'rust', completed_steps: 9,
    ordered_steps: steps,
    organization_commitment: commitment('organization', privatePlan.organization_id),
    flow_definition_commitment: commitment('flow-definition', privatePlan.flow_definition_id),
    flow_instance_commitment: commitment('flow-instance', privatePlan.flow_instance_id),
    application_commitment: commitment('application', privatePlan.application_id),
    source_job_commitment: commitment('source-job', privatePlan.source_job_id),
    bureau_job_commitment: commitment('bureau-job', privatePlan.bureau_job_id),
  };
  const probe = (evidence) => ({ verified: true, evidence });
  const report = {
    schema: 'marty.passport-beta-preliminary/v1',
    status: 'qualified_for_recording',
    beta_origin: deployment.beta_origin,
    physical_claim: 'not_claimed',
    synthetic_identities_only: true,
    negative_runs: {
      unsigned: {
        http_status: 422, webhook_owner: 'issuance-native',
        request_kind: 'missing_signature_header',
        response_projection: { missing_signature_header: true },
        organization_commitment: flow.organization_commitment,
        source_job_commitment: flow.source_job_commitment,
        bureau_job_commitment: flow.bureau_job_commitment,
        video_sha256: digest('unsigned video'),
        privacy_scan_report_sha256: digest(privacyScan('unsigned video')),
        job_state_before_commitment: sha('6'), job_state_after_commitment: sha('6'),
      },
      foreign: {
        http_status: 404, webhook_owner: 'issuance-native',
        request_kind: 'signed_foreign_organization',
        signature_valid: true, foreign_organization: true,
        organization_commitment: commitment('organization', 'synthetic-foreign-org'),
        source_job_commitment: flow.source_job_commitment,
        bureau_job_commitment: flow.bureau_job_commitment,
        response_projection: { webhook_job_not_found: true },
        video_sha256: digest('foreign video'),
        privacy_scan_report_sha256: digest(privacyScan('foreign video')),
        job_state_before_commitment: sha('6'), job_state_after_commitment: sha('6'),
      },
    },
    release: {
      source_commit: deployment.source_commit,
      stack_manifest_sha256: digest(stack),
      signed_manifest_verified: true,
    },
    deployment: {
      provider_mode: 'simulator',
      aggregate_deployment_receipt_sha256: digest(fs.readFileSync(path.join(artifactDir, 'aggregate-deployment.json'))),
      aggregate_plan_sha256: digest(planWire),
    },
    probes: {
      managed_csca_dsc_chain: probe({
        csca_issuer_profile_commitment: commitment('issuer-profile', 'csca'),
        dsc_issuer_profile_commitment: commitment('issuer-profile', 'dsc'),
        managed_kms_custody_verified: true,
        chain_verified: true, sod_dsc_binding_verified: true,
        organization_commitment: flow.organization_commitment,
        application_commitment: flow.application_commitment,
        source_job_commitment: flow.source_job_commitment,
        sod_dsc_certificate_sha256: sha('4'),
      }),
      sod_signature: probe({ sod_sha256: sha('1'), dsc_certificate_sha256: sha('4'),
        source_job_commitment: flow.source_job_commitment }),
      simulator_material_receipt: probe({
        tenant_and_job_binding: true,
        first_accepted_sod_der_matches_native: true,
        first_accepted_dsc_der_matches_selected_chain: true,
        first_accepted_dsc_pem_wire_matches_selected_chain: true,
        source_job_id_commitment: flow.source_job_commitment,
        bureau_job_id_commitment: flow.bureau_job_commitment,
      }),
      nine_route_gateway_flow: probe(flow),
      physical_bureau_submission: probe({
        provider_kind: 'simulator', physical_claim: 'not_claimed',
        selected_source_job_commitment: flow.source_job_commitment,
        selected_bureau_job_commitment: flow.bureau_job_commitment,
        organization_commitment: flow.organization_commitment,
        application_commitment: flow.application_commitment,
        flow_instance_commitment: flow.flow_instance_commitment,
      }),
      physical_bureau_batch: probe({
        provider_kind: 'simulator', physical_claim: 'not_claimed',
        native_binding_verified: true, selected_flow_in_two_job_batch: true,
        native_completed_jobs: 2, first_accepted_material_verified: true,
        selected_flow_callback_verified: true, http_status: 202, batch_status: 'QUEUED',
        request_commitment: sha('a'), response_commitment: sha('b'),
        selected_callback_receipt_sha256: sha('c'),
        selected_source_job_commitment: flow.source_job_commitment,
        selected_bureau_job_commitment: flow.bureau_job_commitment,
        submitted_job_commitments: [flow.source_job_commitment, sha('3')],
        returned_jobs: [
          { source_job_commitment: sha('3'), bureau_job_commitment: sha('9') },
          { source_job_commitment: flow.source_job_commitment,
            bureau_job_commitment: flow.bureau_job_commitment },
        ],
      }),
      signed_bureau_callback: probe({
        provider_kind: 'simulator', physical_claim: 'not_claimed',
        signature_verified: true, organization_bound: true,
        organization_commitment: flow.organization_commitment,
        application_commitment: flow.application_commitment,
        flow_instance_commitment: flow.flow_instance_commitment,
        source_job_commitment: flow.source_job_commitment,
        bureau_job_commitment: flow.bureau_job_commitment,
        callback_receipt_sha256: sha('c'),
      }),
      physical_claim_boundary: probe({ physical_claim: 'not_claimed', booklet_verified: false }),
      unsigned_or_foreign_callback_denied: probe({
        unsigned_denied: true, foreign_organization_denied: true,
        job_unchanged: true, source_job_commitment: flow.source_job_commitment,
        bureau_job_commitment: flow.bureau_job_commitment,
        unsigned_uncut_video_sha256: digest('unsigned video'),
        foreign_uncut_video_sha256: digest('foreign video'),
      }),
    },
  };
  return { artifactDir, deployment, report, flow, privatePlan };
}

test('D-12 rejects the localhost beta proxy before recording', () => {
  assert.throws(() => requireDirectBetaTransport({ BETA_LOCAL_PROXY: '1' }),
    /direct beta TLS and DNS/);
  requireDirectBetaTransport({});
});

test('D-12 preliminary report requires exact simulator lineage and job proof', () => {
  const { artifactDir, deployment, report, flow, privatePlan } = fixture();
  try {
    assert.equal(validatePreliminary(report, deployment, artifactDir, privatePlan, API_KEY).publicFlow, flow);
    const mutations = [
      (value) => { value.status = 'accepted'; },
      (value) => { value.release.source_commit = 'b'.repeat(40); },
      (value) => { value.deployment.provider_mode = 'physical'; },
      (value) => { value.deployment.aggregate_deployment_receipt_sha256 = sha('9'); },
      (value) => { value.deployment.aggregate_plan_sha256 = sha('9'); },
      (value) => { value.provider_ingress_runtime_image = {}; },
      (value) => { value.probes.physical_claim_boundary.evidence.booklet_verified = true; },
      (value) => { value.probes.managed_csca_dsc_chain.evidence.dsc_issuer_profile_commitment = value.probes.managed_csca_dsc_chain.evidence.csca_issuer_profile_commitment; },
      (value) => { value.probes.sod_signature.evidence.sod_sha256 = 'bad'; },
      (value) => { value.probes.managed_csca_dsc_chain.evidence.source_job_commitment = sha('5'); },
      (value) => { value.probes.sod_signature.evidence.dsc_certificate_sha256 = sha('5'); },
      (value) => { value.probes.simulator_material_receipt.evidence.first_accepted_sod_der_matches_native = false; },
      (value) => { value.probes.simulator_material_receipt.evidence.source_job_id_commitment = sha('9'); },
      (value) => { value.probes.simulator_material_receipt.evidence.bureau_job_id_commitment = sha('9'); },
      (value) => { value.probes.nine_route_gateway_flow.evidence.routes.pop(); },
      (value) => { value.probes.nine_route_gateway_flow.evidence.completed_steps = 8; },
      (value) => { value.probes.nine_route_gateway_flow.evidence.ordered_steps.reverse(); },
      (value) => { value.probes.physical_bureau_batch.evidence.selected_source_job_commitment = sha('4'); },
      (value) => { value.probes.physical_bureau_batch.evidence.request_commitment = 'bad'; },
      (value) => { value.probes.physical_bureau_batch.evidence.selected_flow_in_two_job_batch = false; },
      (value) => { value.probes.physical_bureau_batch.evidence.submitted_job_commitments.pop(); value.probes.physical_bureau_batch.evidence.returned_jobs.shift(); },
      (value) => { value.probes.physical_bureau_batch.evidence.returned_jobs[0].source_job_commitment = sha('2'); },
      (value) => { value.probes.physical_bureau_submission.evidence.application_commitment = sha('5'); },
      (value) => { value.probes.signed_bureau_callback.evidence.source_job_commitment = sha('5'); },
      (value) => { value.probes.signed_bureau_callback.evidence.callback_receipt_sha256 = sha('5'); },
      (value) => { value.probes.unsigned_or_foreign_callback_denied.evidence.job_unchanged = false; },
      (value) => { value.negative_runs.unsigned.job_state_after_commitment = sha('8'); },
      (value) => { value.negative_runs.foreign.http_status = 200; },
      (value) => { value.negative_runs.unsigned.response_projection.missing_signature_header = false; },
      (value) => { value.negative_runs.foreign.request_kind = 'unsigned'; },
      (value) => { value.negative_runs.foreign.signature_valid = false; },
      (value) => { value.negative_runs.foreign.source_job_commitment = sha('9'); },
      (value) => { value.negative_runs.foreign.organization_commitment = flow.organization_commitment; },
      (value) => { value.negative_runs.foreign.bureau_job_commitment = sha('9'); },
      (value) => { value.negative_runs.unsigned.source_job_commitment = sha('8'); },
      (value) => { value.probes.nine_route_gateway_flow.evidence.job_id = 'raw-private-job'; },
      (value) => { value.probes.physical_bureau_batch.evidence.selected_bureau_job_commitment = sha('9'); },
      (value) => { value.probes.unsigned_or_foreign_callback_denied.evidence.foreign_uncut_video_sha256 = sha('9'); },
      (value) => { value.synthetic_identities_only = false; },
    ];
    for (const mutate of mutations) {
      const changed = structuredClone(report);
      mutate(changed);
      assert.throws(() => validatePreliminary(changed, deployment, artifactDir, privatePlan, API_KEY));
    }
    const planPath = path.join(artifactDir, 'aggregate-deployment.json.plan.json');
    const originalPlan = fs.readFileSync(planPath);
    fs.appendFileSync(planPath, ' ');
    assert.throws(() => validatePreliminary(report, deployment, artifactDir, privatePlan, API_KEY));
    fs.writeFileSync(planPath, originalPlan);
    const receiptPath = path.join(artifactDir, 'aggregate-deployment.json');
    const originalReceipt = fs.readFileSync(receiptPath);
    fs.appendFileSync(receiptPath, ' ');
    assert.throws(() => validatePreliminary(report, deployment, artifactDir, privatePlan, API_KEY));
    fs.writeFileSync(receiptPath, originalReceipt);
    assert.throws(() => validatePreliminary(report, deployment, artifactDir,
      { ...privatePlan, source_job_id: 'other-job' }, API_KEY));
    assert.throws(() => validatePreliminary(report, deployment, artifactDir,
      privatePlan, 'different-key-32-characters-minimum'));
    for (const key of ['mrz', 'data_groups', 'DG1', 'applicant',
      'issuer_profile_id', 'kms_key_id', 'kms_key_arn',
      'sod_der_base64', 'dsc_cert_pem',
      'kms_key_reference', 'callback_body', 'callback_signature', 'private_receipt',
      'batch_request', 'operator_token', 'wire_hmac_key',
      'source_job_sha256', 'flow_instance_sha256', 'selected_bureau_job_sha256',
      'organization_sha256']) {
      const changed = structuredClone(report);
      changed.probes.physical_bureau_batch.evidence[key] = 'private material';
      assert.throws(() => validatePreliminary(changed, deployment, artifactDir,
        privatePlan, API_KEY), `Public ${key} must be rejected`);
    }
    const escapedKey = 'synthetic-"quote\\backslash-api-key-32-characters';
    const leakedKey = structuredClone(report);
    leakedKey.probes.physical_bureau_batch.evidence.provider_kind = `simulator${escapedKey}`;
    assert.throws(() => validatePreliminary(leakedKey, deployment, artifactDir,
      privatePlan, escapedKey), /private identifier or key/);
    const keyedLeak = structuredClone(report);
    keyedLeak.probes.physical_bureau_batch.evidence.receipts = {
      [privatePlan.bureau_job_id]: true,
    };
    assert.throws(() => validatePreliminary(keyedLeak, deployment, artifactDir,
      privatePlan, API_KEY), /private identifier or key/);
  } finally {
    fs.rmSync(artifactDir, { recursive: true, force: true });
  }
});

test('D-12 retains two distinct uncut protected negative recordings', () => {
  const { artifactDir, report } = fixture();
  try {
    fs.writeFileSync(path.join(artifactDir, 'unsigned-callback-uncut.webm'), 'unsigned video');
    fs.writeFileSync(path.join(artifactDir, 'foreign-callback-uncut.webm'), 'foreign video');
    fs.writeFileSync(path.join(artifactDir, 'unsigned-callback-privacy-scan.json'), privacyScan('unsigned video'));
    fs.writeFileSync(path.join(artifactDir, 'foreign-callback-privacy-scan.json'), privacyScan('foreign video'));
    assert.deepEqual(Object.keys(verifyNegativeMedia(report, artifactDir)), ['unsigned', 'foreign']);
    const failedScan = JSON.parse(privacyScan('foreign video'));
    failedScan.passed = false;
    fs.writeFileSync(path.join(artifactDir, 'foreign-callback-privacy-scan.json'), `${JSON.stringify(failedScan)}\n`);
    assert.throws(() => verifyNegativeMedia(report, artifactDir));
    fs.writeFileSync(path.join(artifactDir, 'foreign-callback-privacy-scan.json'), privacyScan('foreign video'));
    fs.writeFileSync(path.join(artifactDir, 'foreign-callback-uncut.webm'), 'swapped video');
    assert.throws(() => verifyNegativeMedia(report, artifactDir));
    fs.writeFileSync(path.join(artifactDir, 'foreign-callback-uncut.webm'), 'foreign video');
    const leakedScan = { ...JSON.parse(privacyScan('foreign video')), mrz: 'P<PRIVATE' };
    const leakedBytes = `${JSON.stringify(leakedScan)}\n`;
    fs.writeFileSync(path.join(artifactDir, 'foreign-callback-privacy-scan.json'), leakedBytes);
    report.negative_runs.foreign.privacy_scan_report_sha256 = digest(leakedBytes);
    assert.throws(() => verifyNegativeMedia(report, artifactDir));
  } finally {
    fs.rmSync(artifactDir, { recursive: true, force: true });
  }
});

test('D-12 failure log does not echo private selector paths', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'passport-demo-log-'));
  const sentinel = 'SENTINEL-PRIVATE-FLOW-ID';
  try {
    const result = spawnSync(process.execPath,
      [path.join(__dirname, 'audit-beta-physical-passport-flow.js')], {
        encoding: 'utf8',
        env: {
          ...process.env,
          DEMO_ARTIFACT_DIR: directory,
          PASSPORT_BETA_ARTIFACT_DIR: path.join(directory, sentinel),
          PASSPORT_BETA_PRELIMINARY_RUN_ID: '1',
          PASSPORT_BETA_PRELIMINARY_SHA256: sha('1'),
          PASSPORT_BETA_PRIVATE_PLAN_FILE: path.join(directory, `${sentinel}.json`),
          PASSPORT_BETA_API_KEY: API_KEY,
          TEST_VENDOR_EMAIL: 'synthetic@example.invalid',
          TEST_VENDOR_PASSWORD: 'synthetic-password',
          RECORD_VIDEO: '1',
        },
      });
    assert.notEqual(result.status, 0);
    assert.equal(result.stderr.includes(sentinel), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('D-12 reads a private exact-identity handoff outside public artifacts', () => {
  const { artifactDir, privatePlan } = fixture();
  const privateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'passport-demo-private-'));
  const file = path.join(privateDir, 'selected.json');
  try {
    fs.writeFileSync(file, `${JSON.stringify(privatePlan)}\n`, { mode: 0o600 });
    assert.deepEqual(readPrivatePlan(file, artifactDir), privatePlan);
    const changed = { ...privatePlan, bureau_job_id: 'not-a-uuid' };
    fs.writeFileSync(file, `${JSON.stringify(changed)}\n`, { mode: 0o600 });
    assert.throws(() => readPrivatePlan(file, artifactDir));
    fs.writeFileSync(file, '{"source_job_id":"SENTINEL-PRIVATE-JOB",', { mode: 0o600 });
    assert.throws(() => readPrivatePlan(file, artifactDir), (error) =>
      !error.message.includes('SENTINEL-PRIVATE-JOB'));
    assert.throws(() => readPrivatePlan(path.join(artifactDir, 'selected.json'), artifactDir));
  } finally {
    fs.rmSync(privateDir, { recursive: true, force: true });
    fs.rmSync(artifactDir, { recursive: true, force: true });
  }
});

test('D-12 live instance must match the protected nine-step job', () => {
  const { artifactDir, privatePlan: flow } = fixture();
  try {
    const definition = {
      id: flow.flow_definition_id, organization_id: flow.organization_id,
      flow_type: 'physical_document_issuance', resolved_steps: steps,
    };
    const instance = {
      id: flow.flow_instance_id, flow_id: flow.flow_definition_id,
      organization_id: flow.organization_id,
      flow_type: 'physical_document_issuance', status: 'COMPLETED',
      context_data: {
        application_id: flow.application_id,
        physical_document_job: { id: flow.source_job_id,
          application_id: flow.application_id, status: 'ACTIVE', sod_sha256: sha('1'),
          bureau_job_id: flow.bureau_job_id,
          flow_execution_id: flow.flow_instance_id,
          organization_id: flow.organization_id },
      },
      step_results: Object.fromEntries(steps.map((step) => [step, { status: 'COMPLETED' }])),
    };
    assert.doesNotThrow(() => validateLiveInstance(instance, definition, flow, sha('1')));
    instance.context_data.physical_document_job.id = 'foreign-job';
    assert.throws(() => validateLiveInstance(instance, definition, flow, sha('1')));
    instance.context_data.physical_document_job.id = flow.source_job_id;
    instance.context_data.physical_document_job.application_id = 'foreign-app';
    assert.throws(() => validateLiveInstance(instance, definition, flow, sha('1')));
    instance.context_data.physical_document_job.application_id = flow.application_id;
    instance.context_data.physical_document_job.sod_sha256 = sha('2');
    assert.throws(() => validateLiveInstance(instance, definition, flow, sha('1')));
    instance.context_data.physical_document_job.sod_sha256 = sha('1');
    instance.context_data.physical_document_job.status = 'SUBMITTED';
    assert.throws(() => validateLiveInstance(instance, definition, flow, sha('1')));
    instance.context_data.physical_document_job.status = 'ACTIVE';
    instance.organization_id = 'foreign-org';
    assert.throws(() => validateLiveInstance(instance, definition, flow, sha('1')));
    instance.organization_id = flow.organization_id;
    instance.step_results = { ...instance.step_results, unrelated: { status: 'COMPLETED' } };
    delete instance.step_results.activate_credential;
    assert.throws(() => validateLiveInstance(instance, definition, flow, sha('1')));
    instance.step_results.activate_credential = { status: 'COMPLETED' };
    delete instance.step_results.unrelated;
    definition.resolved_steps = [...steps].reverse();
    assert.throws(() => validateLiveInstance(instance, definition, flow, sha('1')));
  } finally {
    fs.rmSync(artifactDir, { recursive: true, force: true });
  }
});

test('D-12 recorded page stays hidden until identifiers are masked', async (t) => {
  let chromium;
  try {
    ({ chromium } = require('@playwright/test'));
  } catch {
    t.skip('Playwright is unavailable in this checkout');
    return;
  }
  const { artifactDir, privatePlan } = fixture();
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext();
    await hideRecordedPage(context);
    const page = await context.newPage();
    await page.goto(`data:text/html,<h1 style="visibility:visible">Flow Instance ${privatePlan.flow_instance_id}</h1>`
      + `<p>${privatePlan.source_job_id}</p>`);
    assert.equal(await page.evaluate(() => getComputedStyle(document.documentElement).opacity), '0');
    assert.equal(await page.locator('h1').evaluate((element) => getComputedStyle(element).visibility), 'visible');
    await revealRedactedPage(page, privatePlan);
    assert.equal(await page.evaluate(() => getComputedStyle(document.documentElement).opacity), '1');
    assert.equal((await page.locator('body').innerText()).includes(privatePlan.flow_instance_id), false);
    await page.evaluate((id) => document.body.appendChild(document.createTextNode(id)),
      privatePlan.bureau_job_id);
    await page.waitForFunction((id) => !document.body.innerText.includes(id),
      privatePlan.bureau_job_id);
    await context.close();
  } finally {
    await browser.close();
    fs.rmSync(artifactDir, { recursive: true, force: true });
  }
});
