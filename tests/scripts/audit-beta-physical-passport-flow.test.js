'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const {
  ASSERTIONS, STEPS, deriveBehaviorAssertions, validateProtectedReceipt,
} = require('./audit-beta-physical-passport-flow');

const SOURCE = 'a'.repeat(40);
const IMAGE = `sha256:${'b'.repeat(64)}`;
const IDENTITY = Object.freeze({
  organization_id: 'org-synthetic', instance_id: 'instance-synthetic',
  application_id: 'application-synthetic', job_id: 'job-synthetic',
});

function fixture() {
  const identity = { ...IDENTITY };
  const bound = () => ({ ...identity, source_commit: SOURCE,
    stack_manifest_sha256: 'c'.repeat(64), proof_sha256: 'f'.repeat(64) });
  const receipt = {
    schema: 'marty.passport-beta-acceptance/v1', status: 'accepted',
    beta_origin: 'https://beta.elevenidllc.com',
    release: { source_commit: SOURCE, signed_manifest_verified: true,
      stack_manifest_sha256: 'c'.repeat(64),
      oci_digests: {
        'ghcr.io/elevenid/marty-ui-oss/ui': `sha256:${'d'.repeat(64)}`,
        'ghcr.io/elevenid/marty-ui-oss/services': IMAGE,
        'ghcr.io/elevenid/marty-ui-oss/migrations': `sha256:${'e'.repeat(64)}`,
      } },
    deployment: { provider_mode: 'physical' },
    runtime_images: Object.fromEntries([
      'gateway', 'flow', 'issuance-native', 'signing-keys',
      'passport-callback-signer-supported', 'passport-provider-ingress',
    ].map((service) => [service, {
      oci_reference: `ghcr.io/elevenid/marty-ui-oss/services@${IMAGE}`,
      oci_digest: IMAGE,
    }])),
    probes: {
      nine_route_gateway_flow: { verified: true, evidence: {
        identity, synthetic_test_data_verified: true,
        steps: STEPS.map((step) => ({ ...bound(), step, status: 'completed' })),
      } },
      managed_csca_dsc_chain: { verified: true, evidence: {
        organization_id: identity.organization_id, source_commit: SOURCE,
        stack_manifest_sha256: 'c'.repeat(64), proof_sha256: 'f'.repeat(64),
        signer_mode: 'MANAGED_ISSUER_PROFILE', csca_issuer_profile_id: 'csca-profile',
        dsc_issuer_profile_id: 'dsc-profile', csca_kms_backed: true, dsc_kms_backed: true,
        csca_certificate_sha256: '1'.repeat(64), dsc_certificate_sha256: '2'.repeat(64),
        chain_verified_by: 'openssl-x509-strict',
      } },
      sod_signature: { verified: true, evidence: {
        ...bound(), sod_signature_verified: true, dsc_signature_verified: true,
        sod_sha256: '3'.repeat(64), dsc_certificate_sha256: '2'.repeat(64),
      } },
      physical_bureau_submission: { verified: true, evidence: bound() },
      physical_bureau_batch: { verified: true, evidence: { ...bound(), provider_mode: 'physical' } },
      signed_bureau_callback: { verified: true, evidence: { ...bound(), signature_verified: true } },
      physical_booklet_verified: { verified: true, evidence: {
        ...bound(), booklet_verified: true, sod_sha256: '3'.repeat(64),
      } },
      unauthenticated_denial: { verified: true, evidence: {
        ...bound(), unsigned_rejected: true, foreign_rejected: true,
      } },
    },
  };
  const bytes = Buffer.from(JSON.stringify(receipt));
  const archiveBytes = Buffer.from('synthetic-immutable-artifact-archive');
  const run = { id: 12345, repository: { full_name: 'ElevenID/marty-ui' },
    head_repository: { full_name: 'ElevenID/marty-ui' },
    path: '.github/workflows/passport-beta-acceptance.yml',
    event: 'workflow_dispatch', head_branch: 'main', head_sha: SOURCE,
    status: 'completed', conclusion: 'success' };
  const artifact = { name: 'passport-beta-acceptance-12345', workflow_run: { id: 12345 },
    expired: false, digest: `sha256:${crypto.createHash('sha256').update(archiveBytes).digest('hex')}` };
  return { receipt, run, artifact, bytes, archiveBytes };
}

test('D-12 derives all six assertions from one protected physical job', () => {
  const { receipt, run, artifact, bytes, archiveBytes } = fixture();
  assert.deepEqual(validateProtectedReceipt(run, artifact, bytes, archiveBytes), receipt);
  const result = deriveBehaviorAssertions(receipt);
  assert.deepEqual(Object.keys(result.behaviorAssertions), ASSERTIONS);
  assert.ok(Object.values(result.behaviorAssertions).every((value) => value === true));
  assert.deepEqual(result.identity, IDENTITY);
  assert.deepEqual(result.issuerProfileIds, ['csca-profile', 'dsc-profile']);
});

test('D-12 rejects blocked, unsigned, simulator, foreign and altered artifacts', () => {
  for (const mutate of [
    (item) => { item.receipt.status = 'blocked'; },
    (item) => { item.receipt.release.signed_manifest_verified = false; },
    (item) => { item.receipt.deployment.provider_mode = 'simulator'; },
    (item) => { item.run.head_branch = 'feature'; },
    (item) => { item.run.conclusion = 'failure'; },
    (item) => { item.run.repository.full_name = 'attacker/fork'; },
  ]) {
    const item = fixture(); mutate(item);
    item.bytes = Buffer.from(JSON.stringify(item.receipt));
    assert.throws(() => validateProtectedReceipt(item.run, item.artifact, item.bytes, item.archiveBytes));
  }
  const altered = fixture();
  altered.artifact.digest = `sha256:${'f'.repeat(64)}`;
  assert.throws(() => validateProtectedReceipt(altered.run, altered.artifact, altered.bytes,
    altered.archiveBytes));
});

test('D-12 rejects cross-job and cross-tenant joins and absent physical proofs', () => {
  for (const mutate of [
    (receipt) => { receipt.probes.nine_route_gateway_flow.evidence.steps[7].job_id = 'other'; },
    (receipt) => { receipt.probes.physical_booklet_verified.evidence.organization_id = 'foreign'; },
    (receipt) => { receipt.probes.signed_bureau_callback.verified = false; },
    (receipt) => { receipt.probes.unauthenticated_denial.evidence.foreign_rejected = false; },
    (receipt) => { receipt.probes.managed_csca_dsc_chain.evidence.csca_kms_backed = false; },
    (receipt) => { receipt.probes.managed_csca_dsc_chain.evidence.dsc_issuer_profile_id = ''; },
    (receipt) => { receipt.probes.managed_csca_dsc_chain.evidence.dsc_issuer_profile_id = 'csca-profile'; },
    (receipt) => { receipt.probes.sod_signature.evidence.dsc_certificate_sha256 = '4'.repeat(64); },
    (receipt) => { receipt.probes.sod_signature.evidence.job_id = 'other-job'; },
    (receipt) => { receipt.probes.physical_bureau_batch.evidence.provider_mode = 'simulator'; },
    (receipt) => { receipt.probes.signed_bureau_callback.evidence.proof_sha256 = ''; },
    (receipt) => { receipt.probes.physical_booklet_verified.evidence.source_commit = 'e'.repeat(40); },
    (receipt) => { receipt.probes.nine_route_gateway_flow.evidence.synthetic_test_data_verified = false; },
  ]) {
    const { receipt } = fixture(); mutate(receipt);
    assert.throws(() => deriveBehaviorAssertions(receipt));
  }
});

test('D-12 emits no report or video without a protected run', () => {
  const output = fs.mkdtempSync(path.join(os.tmpdir(), 'marty-d12-no-provider-'));
  try {
    const result = spawnSync(process.execPath, [path.join(__dirname, 'audit-beta-physical-passport-flow.js')], {
      encoding: 'utf8',
      env: { ...process.env, PASSPORT_D12_ACCEPTANCE_RUN_ID: '',
        DEMO_ARTIFACT_DIR: output, RECORD_VIDEO: '1' },
    });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /protected workflow run ID is required/);
    assert.deepEqual(fs.readdirSync(output), []);
  } finally { fs.rmSync(output, { recursive: true, force: true }); }
});
