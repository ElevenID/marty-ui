#!/usr/bin/env node
/* eslint-disable no-console */
'use strict';

// D-12 is a recorder, never a source of passport acceptance. Its only input is
// the artifact of a successful protected-main acceptance workflow run.
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const REPO = 'ElevenID/marty-ui';
const WORKFLOW = '.github/workflows/passport-beta-acceptance.yml';
const BETA_ORIGIN = 'https://beta.elevenidllc.com';
const SHA = /^[a-f0-9]{40}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const ID = /^[A-Za-z0-9_-]{1,255}$/;
const STEPS = Object.freeze([
  'accept_application', 'validate_evidence', 'approval_decision',
  'generate_data_groups', 'sign_sod', 'submit_to_personalization',
  'track_production', 'quality_verify', 'activate_credential',
]);
const ASSERTIONS = Object.freeze([
  'managed_csca_dsc_issuer_profiles', 'nine_step_physical_issuance_flow',
  'physical_bureau_job_correlated', 'signed_provider_callback_verified',
  'physical_booklet_evidence_verified', 'unsigned_or_foreign_callback_denied',
]);
const PHYSICAL_SERVICES = Object.freeze([
  'gateway', 'flow', 'issuance-native', 'signing-keys',
  'passport-callback-signer-supported', 'passport-provider-ingress',
]);
const OCI_ROLES = Object.freeze(['ui', 'services', 'migrations']);

function fail(message) { throw new Error(`D-12 evidence: ${message}`); }
function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function sameIdentity(item, identity) {
  return item && typeof item === 'object'
    && ['organization_id', 'instance_id', 'application_id', 'job_id']
      .every((key) => item[key] === identity[key]);
}

function validateProtectedReceipt(run, artifact, bytes, archiveBytes) {
  if (run?.repository?.full_name !== REPO || run?.head_repository?.full_name !== REPO
      || run?.path?.split('@')[0] !== WORKFLOW || run?.event !== 'workflow_dispatch'
      || run?.head_branch !== 'main' || run?.status !== 'completed'
      || run?.conclusion !== 'success' || !SHA.test(run?.head_sha || '')) {
    fail('protected main workflow did not complete successfully');
  }
  const expectedName = `passport-beta-acceptance-${run.id}`;
  if (artifact?.name !== expectedName || artifact?.workflow_run?.id !== run.id
      || artifact?.expired !== false || !Buffer.isBuffer(archiveBytes)
      || artifact?.digest !== `sha256:${sha256(archiveBytes)}`) {
    fail('workflow artifact identity or digest differs');
  }
  let receipt;
  try { receipt = JSON.parse(bytes.toString('utf8')); } catch { fail('invalid receipt JSON'); }
  if (receipt?.schema !== 'marty.passport-beta-acceptance/v1'
      || receipt?.status !== 'accepted' || receipt?.beta_origin !== BETA_ORIGIN
      || receipt?.release?.source_commit !== run.head_sha
      || receipt?.release?.signed_manifest_verified !== true
      || !DIGEST.test(receipt?.release?.stack_manifest_sha256 || '')
      || receipt?.deployment?.provider_mode !== 'physical') {
    fail('accepted physical release lineage is absent');
  }
  const images = receipt.release.oci_digests;
  const servicesDigest = images?.['ghcr.io/elevenid/marty-ui-oss/services'];
  if (!images || Object.keys(images).length !== OCI_ROLES.length
      || OCI_ROLES.some((role) => !/^sha256:[a-f0-9]{64}$/.test(
        images[`ghcr.io/elevenid/marty-ui-oss/${role}`] || ''))
      || !receipt.runtime_images
      || Object.keys(receipt.runtime_images).length !== PHYSICAL_SERVICES.length
      || PHYSICAL_SERVICES.some((service) => !receipt.runtime_images[service])
      || !Object.values(receipt.runtime_images || {}).every((entry) => (
        entry?.oci_reference === `ghcr.io/elevenid/marty-ui-oss/services@${servicesDigest}`
        && entry?.oci_digest === servicesDigest
      ))
      || receipt.runtime_images?.['passport-beta-bureau']) {
    fail('physical runtime is not bound to the signed services image');
  }
  return receipt;
}

function deriveBehaviorAssertions(receipt) {
  const probes = receipt.probes || {};
  const required = [
    'managed_csca_dsc_chain', 'nine_route_gateway_flow', 'physical_bureau_submission',
    'physical_bureau_batch', 'signed_bureau_callback', 'physical_booklet_verified',
    'unauthenticated_denial',
  ];
  if (required.some((name) => probes[name]?.verified !== true || !probes[name]?.evidence)) {
    fail('physical provider, callback, booklet, or denial proof is missing');
  }
  const execution = probes.nine_route_gateway_flow.evidence;
  const identity = execution.identity;
  if (!identity || ['organization_id', 'instance_id', 'application_id', 'job_id']
    .some((key) => !ID.test(identity[key] || ''))
      || !Array.isArray(execution.steps) || execution.steps.length !== STEPS.length
      || execution.steps.some((item, index) => item?.step !== STEPS[index]
        || !sameIdentity(item, identity) || item?.status !== 'completed')) {
    fail('nine steps do not share one completed tenant, instance, application, and job');
  }
  const bound = [
    probes.managed_csca_dsc_chain.evidence,
    probes.physical_bureau_submission.evidence,
    probes.physical_bureau_batch.evidence,
    probes.signed_bureau_callback.evidence,
    probes.physical_booklet_verified.evidence,
    probes.unauthenticated_denial.evidence,
  ];
  if (!bound.every((item) => sameIdentity(item, identity)
      && item.source_commit === receipt.release.source_commit
      && item.stack_manifest_sha256 === receipt.release.stack_manifest_sha256
      && DIGEST.test(item.proof_sha256 || ''))
      || probes.managed_csca_dsc_chain.evidence.signer_mode !== 'MANAGED_ISSUER_PROFILE'
      || !ID.test(probes.managed_csca_dsc_chain.evidence.issuer_profile_id || '')
      || probes.managed_csca_dsc_chain.evidence.kms_backed !== true
      || probes.physical_bureau_batch.evidence.provider_mode !== 'physical'
      || probes.signed_bureau_callback.evidence.signature_verified !== true
      || probes.physical_booklet_verified.evidence.booklet_verified !== true
      || probes.unauthenticated_denial.evidence.unsigned_rejected !== true
      || probes.unauthenticated_denial.evidence.foreign_rejected !== true
      || execution.synthetic_test_data_verified !== true) {
    fail('governed profile, physical booklet, callback, denial, or synthetic privacy binding is absent');
  }
  return {
    identity,
    issuerProfileId: probes.managed_csca_dsc_chain.evidence.issuer_profile_id,
    behaviorAssertions: Object.fromEntries(ASSERTIONS.map((name) => [name, true])),
  };
}

function loadProtectedReceipt(runId, command = execFileSync) {
  if (!/^[1-9][0-9]{0,17}$/.test(String(runId || ''))) fail('a protected workflow run ID is required');
  const api = (endpoint) => JSON.parse(command('gh', ['api', endpoint], { encoding: 'utf8' }));
  const run = api(`repos/${REPO}/actions/runs/${runId}`);
  const listing = api(`repos/${REPO}/actions/runs/${runId}/artifacts?per_page=100`);
  const matches = (listing.artifacts || []).filter((item) => item.name === `passport-beta-acceptance-${runId}`);
  if (matches.length !== 1) fail('exactly one protected acceptance artifact is required');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'marty-d12-'));
  try {
    const archive = command('gh', ['api', `repos/${REPO}/actions/artifacts/${matches[0].id}/zip`],
      { maxBuffer: 16 * 1024 * 1024 });
    command('gh', ['run', 'download', String(runId), '--repo', REPO,
      '--name', matches[0].name, '--dir', tmp], { encoding: 'utf8' });
    const files = fs.readdirSync(tmp);
    if (files.length !== 1 || files[0] !== `${matches[0].name}.json`) fail('unexpected artifact files');
    const bytes = fs.readFileSync(path.join(tmp, files[0]));
    return { receipt: validateProtectedReceipt(run, matches[0], bytes, archive),
      receiptSha256: sha256(bytes) };
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
}

async function record(receipt, proof, options = {}) {
  if (options.recordVideo !== true) fail('fresh primary recording is required');
  const { chromium } = require('@playwright/test');
  const { login, selectOrg } = require('./audit-beta-credential-lifecycle');
  const { DEFAULT_BETA_ORGANIZATION_ID } = require('./beta-credential-contract');
  const { loadEnvFile, redact } = require('./verify-beta-waltid-acceptance');
  const { VIDEO_SIZE, createArtifactDir, finalizeVideo, showStep } = require('./demo-recording');
  const root = path.resolve(__dirname, '..', '..');
  loadEnvFile(path.join(root, '.env.tunnel.beta.local'));
  loadEnvFile(path.join(root, '.env'));
  const email = process.env.TEST_VENDOR_EMAIL || process.env.TEST_ADMIN_EMAIL;
  const password = process.env.TEST_VENDOR_PASSWORD || process.env.TEST_ADMIN_PASSWORD;
  if (!email || !password
      || (process.env.BETA_AUDIT_ORG_ID || DEFAULT_BETA_ORGANIZATION_ID)
        !== proof.identity.organization_id) {
    fail('beta operator credentials or selected tenant do not match protected evidence');
  }
  const browser = await chromium.launch({ headless: process.env.HEADED !== '1' });
  let context;
  try {
    const verifyPage = async (page, pageErrors) => {
      page.on('pageerror', (error) => pageErrors.push(redact(error.message)));
      const target = `${BETA_ORIGIN}/console/org/operate/flow-instances/${encodeURIComponent(proof.identity.instance_id)}`;
      await page.goto(target, { waitUntil: 'domcontentloaded', timeout: 60_000 });
      await page.getByText(`Flow Instance ${proof.identity.instance_id}`, { exact: true })
        .waitFor({ state: 'visible', timeout: 30_000 });
      const instance = await page.evaluate(async (instanceId) => {
        const response = await fetch(`/v1/flows/instances/${encodeURIComponent(instanceId)}`, {
          credentials: 'include', headers: { Accept: 'application/json' },
        });
        return response.ok ? response.json() : null;
      }, proof.identity.instance_id);
      const job = instance?.context_data?.physical_document_job;
      if (instance?.id !== proof.identity.instance_id
          || instance?.organization_id !== proof.identity.organization_id
          || instance?.status !== 'COMPLETED'
          || instance?.flow_type !== 'physical_document_issuance'
          || instance?.current_step !== STEPS[STEPS.length - 1]
          || !instance?.step_results || Object.keys(instance.step_results).length !== STEPS.length
          || STEPS.some((step) => instance.step_results[step]?.result !== 'success')
          || job?.id !== proof.identity.job_id
          || job?.application_id !== proof.identity.application_id
          || !Array.isArray(receipt.probes.nine_route_gateway_flow.evidence.steps)) {
        fail('visible Flow instance differs from protected acceptance identity');
      }
      await page.getByText(proof.identity.job_id, { exact: false }).first()
        .waitFor({ state: 'visible', timeout: 30_000 });
      if (pageErrors.length) fail('Flow Instances page raised a browser error');
    };
    // Credentials and the first live identity check never enter the recording.
    context = await browser.newContext({ viewport: VIDEO_SIZE });
    const loginPage = await context.newPage();
    await login(loginPage, email, password);
    const selection = await selectOrg(loginPage);
    if (!selection.ok) fail('protected evidence tenant is not selectable');
    await verifyPage(loginPage, []);
    const storageState = await context.storageState();
    await context.close(); context = null;

    const artifactDir = createArtifactDir(root, `beta-physical-passport-${Date.now()}`);
    if (fs.existsSync(path.join(artifactDir, 'report.json'))
        || fs.existsSync(path.join(artifactDir, 'physical-passport-issuance-evidence.webm'))) {
      fail('recording output contains stale D-12 evidence');
    }
    context = await browser.newContext({ viewport: VIDEO_SIZE, storageState,
      ...(options.recordVideo ? { recordVideo: { dir: artifactDir, size: VIDEO_SIZE } } : {}) });
    const page = await context.newPage();
    const video = page.video();
    const pageErrors = [];
    await verifyPage(page, pageErrors);
    await showStep(page, 'Physical passport Flow completed',
      'The authenticated acceptance run binds all nine steps to one synthetic job.',
      { enabled: options.recordVideo, eyebrow: 'D-12 | protected beta evidence' });
    await showStep(page, 'Provider and booklet evidence verified',
      'A KMS issuer profile, signed callback, physical booklet, and denial probes share this job.',
      { enabled: options.recordVideo, eyebrow: 'D-12 | protected beta evidence' });
    if (pageErrors.length) fail('Flow Instances page raised a browser error');
    await context.close(); context = null;
    const recording = await finalizeVideo(video, artifactDir, 'physical-passport-issuance-evidence.webm');
    if (!recording || !fs.statSync(recording).size) fail('fresh D-12 video was not captured');
    const report = {
      demoId: 'D-12', status: 'passed', releaseReady: true,
      sourceCommit: receipt.release.source_commit,
      stackManifestSha256: receipt.release.stack_manifest_sha256,
      evidenceRunId: options.runId, evidenceReceiptSha256: options.receiptSha256,
      behaviorAssertions: proof.behaviorAssertions,
      syntheticTestDataVerified: true,
      recording: path.relative(root, recording),
    };
    fs.writeFileSync(path.join(artifactDir, 'report.json'), `${JSON.stringify(report, null, 2)}\n`);
    return report;
  } finally {
    if (context) await context.close().catch(() => {});
    await browser.close();
  }
}

async function main() {
  if (process.env.RECORD_VIDEO !== '1') fail('D-12 requires RECORD_VIDEO=1');
  const runId = process.env.PASSPORT_D12_ACCEPTANCE_RUN_ID;
  const { receipt, receiptSha256 } = loadProtectedReceipt(runId);
  const proof = deriveBehaviorAssertions(receipt);
  const report = await record(receipt, proof, { runId, receiptSha256, recordVideo: true });
  console.log(JSON.stringify(report, null, 2));
}

if (require.main === module) main().catch((error) => {
  console.error(`D-12 recording blocked: ${error.message}`);
  process.exitCode = 1;
});

module.exports = { ASSERTIONS, STEPS, deriveBehaviorAssertions, loadProtectedReceipt, validateProtectedReceipt };
