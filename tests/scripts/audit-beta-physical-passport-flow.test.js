'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createHash } = require('node:crypto');
const test = require('node:test');

const { verifyNegativeMedia, validatePreliminary, validateLiveInstance } = require('./audit-beta-physical-passport-flow');
const routes = require('../../contracts/issuance-physical-passport-native.json').routes;
const steps = [
  'accept_application', 'validate_evidence', 'approval_decision',
  'generate_data_groups', 'sign_sod', 'submit_to_personalization',
  'track_production', 'quality_verify', 'activate_credential',
];

const digest = (value) => createHash('sha256').update(value).digest('hex');
const sha = (character) => character.repeat(64);
const privacyScan = (video) => `${JSON.stringify({
  schemaVersion: 1, passed: true, findings: [],
  videoSha256: digest(video), frameSamplingFps: 2,
})}\n`;

function fixture() {
  const artifactDir = fs.mkdtempSync(path.join(os.tmpdir(), 'passport-demo-audit-test-'));
  const stack = '{}\n';
  const source = '{}\n';
  fs.writeFileSync(path.join(artifactDir, 'stack-manifest.json'), stack);
  fs.writeFileSync(path.join(artifactDir, 'source-manifest.json'), source);
  const deployment = {
    beta_origin: 'https://beta.elevenidllc.com',
    source_kind: 'official-stack-release',
    passport_provider_mode: 'simulator',
    marty_ui_sha: 'a'.repeat(40),
    official_stack_manifest_sha256: digest(stack),
  };
  fs.writeFileSync(path.join(artifactDir, 'local-deployment-manifest.json'), `${JSON.stringify(deployment)}\n`);
  const flow = {
    routes,
    gateway_owner: 'rust', flow_owner: 'rust', completed_steps: 9,
    ordered_steps: steps, flow_id: 'synthetic-definition',
    organization_id: 'synthetic-org', flow_instance_id: 'synthetic-flow',
    application_id: 'synthetic-app', job_id: 'synthetic-job',
    source_job_commitment: sha('2'),
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
        organization_id: flow.organization_id, job_id: flow.job_id,
        source_job_commitment: sha('2'), bureau_job_commitment: sha('8'),
        video_sha256: digest('unsigned video'),
        privacy_scan_report_sha256: digest(privacyScan('unsigned video')),
        job_state_before_sha256: sha('6'), job_state_after_sha256: sha('6'),
      },
      foreign: {
        http_status: 404, webhook_owner: 'issuance-native',
        request_kind: 'signed_foreign_organization',
        signature_valid: true, foreign_organization: true,
        organization_id: 'synthetic-foreign-org', job_id: flow.job_id,
        source_job_commitment: sha('2'),
        bureau_job_commitment: sha('8'),
        response_projection: { webhook_job_not_found: true },
        video_sha256: digest('foreign video'),
        privacy_scan_report_sha256: digest(privacyScan('foreign video')),
        job_state_before_sha256: sha('6'), job_state_after_sha256: sha('6'),
      },
    },
    release: {
      source_commit: deployment.marty_ui_sha,
      stack_manifest_sha256: digest(stack),
      signed_manifest_verified: true,
    },
    deployment: {
      provider_mode: 'simulator',
      local_deployment_manifest_sha256: digest(fs.readFileSync(path.join(artifactDir, 'local-deployment-manifest.json'))),
      source_manifest_sha256: digest(source),
    },
    probes: {
      managed_csca_dsc_chain: probe({
        csca_issuer_profile_id: 'csca', dsc_issuer_profile_id: 'dsc',
        chain_verified: true, sod_dsc_binding_verified: true,
        organization_id: flow.organization_id, application_id: flow.application_id,
        job_id: flow.job_id, sod_dsc_certificate_sha256: sha('4'),
      }),
      sod_signature: probe({ sod_sha256: sha('1'), dsc_certificate_sha256: sha('4'), job_id: flow.job_id }),
      simulator_material_receipt: probe({
        tenant_and_job_binding: true,
        first_accepted_sod_der_matches_native: true,
        first_accepted_dsc_der_matches_selected_chain: true,
        first_accepted_dsc_pem_wire_matches_selected_chain: true,
        source_job_id_commitment: sha('2'), bureau_job_id_commitment: sha('8'),
      }),
      nine_route_gateway_flow: probe(flow),
      physical_bureau_submission: probe({
        provider_kind: 'simulator', physical_claim: 'not_claimed',
        selected_source_job_commitment: sha('2'),
        selected_bureau_job_commitment: sha('8'),
        organization_id: flow.organization_id, application_id: flow.application_id,
        job_id: flow.job_id,
      }),
      physical_bureau_batch: probe({
        provider_kind: 'simulator', physical_claim: 'not_claimed',
        native_binding_verified: true, selected_source_job_commitment: sha('2'),
        selected_bureau_job_commitment: sha('8'),
        submitted_job_commitments: [sha('2'), sha('3')],
        returned_jobs: [
          { source_job_commitment: sha('3'), bureau_job_commitment: sha('9') },
          { source_job_commitment: sha('2'), bureau_job_commitment: sha('8') },
        ],
      }),
      signed_bureau_callback: probe({
        provider_kind: 'simulator', physical_claim: 'not_claimed',
        signature_verified: true, organization_bound: true,
        organization_id: flow.organization_id, application_id: flow.application_id,
        job_id: flow.job_id, source_job_commitment: sha('2'),
        bureau_job_commitment: sha('8'),
      }),
      physical_claim_boundary: probe({ physical_claim: 'not_claimed', booklet_verified: false }),
      unsigned_or_foreign_callback_denied: probe({
        unsigned_denied: true, foreign_organization_denied: true,
        job_unchanged: true, job_id: flow.job_id,
        unsigned_uncut_video_sha256: digest('unsigned video'),
        foreign_uncut_video_sha256: digest('foreign video'),
      }),
    },
  };
  return { artifactDir, deployment, report, flow };
}

test('D-12 preliminary report requires exact simulator lineage and job proof', () => {
  const { artifactDir, deployment, report, flow } = fixture();
  try {
    assert.equal(validatePreliminary(report, deployment, artifactDir).flow, flow);
    const mutations = [
      (value) => { value.status = 'accepted'; },
      (value) => { value.release.source_commit = 'b'.repeat(40); },
      (value) => { value.deployment.provider_mode = 'physical'; },
      (value) => { value.provider_ingress_runtime_image = {}; },
      (value) => { value.probes.physical_claim_boundary.evidence.booklet_verified = true; },
      (value) => { value.probes.managed_csca_dsc_chain.evidence.dsc_issuer_profile_id = 'csca'; },
      (value) => { value.probes.sod_signature.evidence.sod_sha256 = 'bad'; },
      (value) => { value.probes.managed_csca_dsc_chain.evidence.job_id = 'other-job'; },
      (value) => { value.probes.sod_signature.evidence.dsc_certificate_sha256 = sha('5'); },
      (value) => { value.probes.simulator_material_receipt.evidence.first_accepted_sod_der_matches_native = false; },
      (value) => { value.probes.simulator_material_receipt.evidence.source_job_id_commitment = sha('9'); },
      (value) => { value.probes.simulator_material_receipt.evidence.bureau_job_id_commitment = sha('9'); },
      (value) => { value.probes.nine_route_gateway_flow.evidence.routes.pop(); },
      (value) => { value.probes.nine_route_gateway_flow.evidence.completed_steps = 8; },
      (value) => { value.probes.nine_route_gateway_flow.evidence.ordered_steps.reverse(); },
      (value) => { value.probes.physical_bureau_batch.evidence.selected_source_job_commitment = sha('4'); },
      (value) => { value.probes.physical_bureau_batch.evidence.submitted_job_commitments.pop(); value.probes.physical_bureau_batch.evidence.returned_jobs.shift(); },
      (value) => { value.probes.physical_bureau_batch.evidence.returned_jobs[0].source_job_commitment = sha('2'); },
      (value) => { value.probes.physical_bureau_submission.evidence.application_id = 'other-app'; },
      (value) => { value.probes.signed_bureau_callback.evidence.job_id = 'other-job'; },
      (value) => { value.probes.unsigned_or_foreign_callback_denied.evidence.job_unchanged = false; },
      (value) => { value.negative_runs.unsigned.job_state_after_sha256 = sha('8'); },
      (value) => { value.negative_runs.foreign.http_status = 200; },
      (value) => { value.negative_runs.unsigned.response_projection.missing_signature_header = false; },
      (value) => { value.negative_runs.foreign.request_kind = 'unsigned'; },
      (value) => { value.negative_runs.foreign.signature_valid = false; },
      (value) => { value.negative_runs.foreign.source_job_commitment = sha('9'); },
      (value) => { value.negative_runs.foreign.organization_id = flow.organization_id; },
      (value) => { value.negative_runs.foreign.bureau_job_commitment = sha('9'); },
      (value) => { value.negative_runs.unsigned.job_id = 'unrelated-job'; },
      (value) => { value.probes.physical_bureau_batch.evidence.selected_bureau_job_commitment = sha('9'); },
      (value) => { value.probes.unsigned_or_foreign_callback_denied.evidence.foreign_uncut_video_sha256 = sha('9'); },
      (value) => { value.synthetic_identities_only = false; },
    ];
    for (const mutate of mutations) {
      const changed = structuredClone(report);
      mutate(changed);
      assert.throws(() => validatePreliminary(changed, deployment, artifactDir));
    }
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
  } finally {
    fs.rmSync(artifactDir, { recursive: true, force: true });
  }
});

test('D-12 live instance must match the protected nine-step job', () => {
  const { artifactDir, flow } = fixture();
  try {
    const definition = {
      id: flow.flow_id, organization_id: flow.organization_id,
      flow_type: 'physical_document_issuance', resolved_steps: steps,
    };
    const instance = {
      id: flow.flow_instance_id, flow_id: flow.flow_id,
      organization_id: flow.organization_id,
      flow_type: 'physical_document_issuance', status: 'COMPLETED',
      context_data: {
        application_id: flow.application_id,
        physical_document_job: { id: flow.job_id },
      },
      step_results: Object.fromEntries(steps.map((step) => [step, { status: 'COMPLETED' }])),
    };
    assert.doesNotThrow(() => validateLiveInstance(instance, definition, flow));
    instance.context_data.physical_document_job.id = 'foreign-job';
    assert.throws(() => validateLiveInstance(instance, definition, flow));
    instance.context_data.physical_document_job.id = flow.job_id;
    instance.organization_id = 'foreign-org';
    assert.throws(() => validateLiveInstance(instance, definition, flow));
    instance.organization_id = flow.organization_id;
    instance.step_results = { ...instance.step_results, unrelated: { status: 'COMPLETED' } };
    delete instance.step_results.activate_credential;
    assert.throws(() => validateLiveInstance(instance, definition, flow));
    instance.step_results.activate_credential = { status: 'COMPLETED' };
    delete instance.step_results.unrelated;
    definition.resolved_steps = [...steps].reverse();
    assert.throws(() => validateLiveInstance(instance, definition, flow));
  } finally {
    fs.rmSync(artifactDir, { recursive: true, force: true });
  }
});
