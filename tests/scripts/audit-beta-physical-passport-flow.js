#!/usr/bin/env node
/* eslint-disable no-console */
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { execFileSync } = require('node:child_process');

const { VIDEO_SIZE, createArtifactDir, finalizeVideo, showStep } = require('./demo-recording');

const ROOT = path.resolve(__dirname, '..', '..');
const BETA_ORIGIN = 'https://beta.elevenidllc.com';
const SHA256 = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const REQUIRED_PROBES = [
  'managed_csca_dsc_chain', 'sod_signature', 'nine_route_gateway_flow',
  'physical_bureau_submission', 'physical_bureau_batch',
  'signed_bureau_callback', 'physical_claim_boundary',
  'unsigned_or_foreign_callback_denied',
];
const FROZEN_ROUTES = new Set(
  require('../../contracts/issuance-physical-passport-native.json').routes
    .map(({ method, path: routePath }) => `${method} ${routePath}`),
);
const FROZEN_STEPS = [
  'accept_application', 'validate_evidence', 'approval_decision',
  'generate_data_groups', 'sign_sod', 'submit_to_personalization',
  'track_production', 'quality_verify', 'activate_credential',
];
const NEGATIVE_MEDIA = {
  unsigned: 'unsigned-callback-uncut.webm',
  foreign: 'foreign-callback-uncut.webm',
};

function requireProof(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(filePath) {
  return createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function readJson(filePath) {
  const value = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  requireProof(value && typeof value === 'object' && !Array.isArray(value), 'Evidence must be an object');
  return value;
}

function verifyNegativeMedia(report, directory) {
  const output = {};
  for (const [name, filename] of Object.entries(NEGATIVE_MEDIA)) {
    const declared = report.negative_runs?.[name];
    requireProof(SHA256.test(declared?.video_sha256), `Protected ${name} callback video digest is missing`);
    const videoPath = path.join(directory, filename);
    const video = fs.lstatSync(videoPath);
    requireProof(video.isFile() && video.size > 0 && video.size <= 128 * 1024 * 1024,
      `Protected ${name} callback video is missing or oversized`);
    requireProof(sha256(videoPath) === declared.video_sha256,
      `Protected ${name} callback video digest mismatch`);
    output[name] = fs.readFileSync(videoPath);
  }
  return output;
}

function protectedReceipt(runId, expectedSha256, sourceCommit) {
  requireProof(Number.isSafeInteger(runId) && runId > 0, 'Preliminary workflow run ID is invalid');
  requireProof(SHA256.test(expectedSha256), 'Preliminary artifact digest is invalid');
  const run = JSON.parse(execFileSync('gh', [
    'api', `repos/ElevenID/marty-ui/actions/runs/${runId}`,
  ], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }));
  requireProof(
    run.status === 'completed' && run.conclusion === 'success'
    && run.head_sha === sourceCommit && run.head_branch === 'main'
    && run.path === '.github/workflows/passport-beta-preliminary.yml'
    && run.repository?.full_name === 'ElevenID/marty-ui'
    && run.head_repository?.full_name === 'ElevenID/marty-ui',
    'Preliminary receipt is not from the protected passport beta workflow',
  );
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'passport-demo-preliminary-'));
  try {
    execFileSync('gh', [
      'run', 'download', String(runId), '--repo', 'ElevenID/marty-ui',
      '--name', `passport-beta-preliminary-${runId}`, '--dir', directory,
    ], { stdio: ['ignore', 'pipe', 'pipe'] });
    const reportPath = path.join(directory, `passport-beta-preliminary-${runId}.json`);
    const artifact = fs.lstatSync(reportPath);
    requireProof(artifact.isFile() && artifact.size <= 1024 * 1024,
      'Preliminary artifact is missing or oversized');
    requireProof(sha256(reportPath) === expectedSha256, 'Preliminary artifact digest mismatch');
    const report = readJson(reportPath);
    return { report, negativeMedia: verifyNegativeMedia(report, directory) };
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

function validatePreliminary(report, deployment, artifactDir) {
  const stackDigest = sha256(path.join(artifactDir, 'stack-manifest.json'));
  const deploymentDigest = sha256(path.join(artifactDir, 'local-deployment-manifest.json'));
  const sourceDigest = sha256(path.join(artifactDir, 'source-manifest.json'));
  const sourceCommit = deployment.marty_ui_sha;
  requireProof(COMMIT.test(sourceCommit), 'Deployed source commit is invalid');
  requireProof(
    report.schema === 'marty.passport-beta-preliminary/v1'
    && report.status === 'qualified_for_recording'
    && report.beta_origin === BETA_ORIGIN
    && report.physical_claim === 'not_claimed'
    && report.release?.source_commit === sourceCommit
    && report.release?.stack_manifest_sha256 === stackDigest
    && report.release?.signed_manifest_verified === true
    && report.deployment?.provider_mode === 'simulator'
    && report.deployment?.local_deployment_manifest_sha256 === deploymentDigest
    && report.deployment?.source_manifest_sha256 === sourceDigest
    && !Object.hasOwn(report, 'provider_ingress_runtime_image'),
    'Preliminary flow receipt does not match the signed simulator deployment',
  );
  requireProof(
    deployment.beta_origin === BETA_ORIGIN
    && deployment.source_kind === 'official-stack-release'
    && deployment.passport_provider_mode === 'simulator'
    && typeof deployment.official_stack_manifest_sha256 === 'string'
    && deployment.official_stack_manifest_sha256.replace(/^sha256:/, '') === stackDigest,
    'Deployment is not the signed beta simulator',
  );
  for (const name of REQUIRED_PROBES) {
    requireProof(report.probes?.[name]?.verified === true
      && report.probes[name].evidence && typeof report.probes[name].evidence === 'object',
    `Preliminary passport proof is incomplete: ${name}`);
  }
  const boundary = report.probes.physical_claim_boundary.evidence;
  requireProof(boundary.physical_claim === 'not_claimed' && boundary.booklet_verified === false,
    'Preliminary receipt claims a physical booklet');
  const chain = report.probes.managed_csca_dsc_chain.evidence;
  requireProof(
    typeof chain.csca_issuer_profile_id === 'string'
    && typeof chain.dsc_issuer_profile_id === 'string'
    && chain.csca_issuer_profile_id !== chain.dsc_issuer_profile_id
    && chain.chain_verified === true && chain.sod_dsc_binding_verified === true,
    'Distinct managed issuer profiles and same-job SOD binding are unproven',
  );
  const sod = report.probes.sod_signature.evidence;
  requireProof(SHA256.test(sod.sod_sha256) && SHA256.test(sod.dsc_certificate_sha256),
    'Same-job SOD digest is missing');
  const route = report.probes.nine_route_gateway_flow.evidence;
  const keys = Array.isArray(route.routes) ? route.routes.map(({ method, path: routePath }) => `${method} ${routePath}`) : [];
  requireProof(
    keys.length === FROZEN_ROUTES.size
    && new Set(keys).size === FROZEN_ROUTES.size
    && keys.every((key) => FROZEN_ROUTES.has(key))
    && route.gateway_owner === 'rust' && route.flow_owner === 'rust'
    && route.completed_steps === 9
    && JSON.stringify(route.ordered_steps) === JSON.stringify(FROZEN_STEPS)
    && typeof route.organization_id === 'string' && route.organization_id
    && typeof route.flow_id === 'string' && route.flow_id
    && typeof route.flow_instance_id === 'string' && route.flow_instance_id
    && typeof route.application_id === 'string' && route.application_id
    && typeof route.job_id === 'string' && route.job_id
    && SHA256.test(route.source_job_commitment),
    'Nine-route Rust flow or exact instance correlation is unproven',
  );
  requireProof(
    chain.organization_id === route.organization_id
    && chain.application_id === route.application_id
    && chain.job_id === route.job_id
    && SHA256.test(chain.sod_dsc_certificate_sha256)
    && chain.sod_dsc_certificate_sha256 === sod.dsc_certificate_sha256
    && sod.job_id === route.job_id,
    'Managed issuer chain and SOD do not match the recorded passport job',
  );
  const batch = report.probes.physical_bureau_batch.evidence;
  const submission = report.probes.physical_bureau_submission.evidence;
  const callback = report.probes.signed_bureau_callback.evidence;
  const selectedBureauJobs = Array.isArray(batch.returned_jobs)
    ? batch.returned_jobs.filter((job) =>
      job?.source_job_commitment === route.source_job_commitment)
    : [];
  requireProof(
    batch.provider_kind === 'simulator' && batch.physical_claim === 'not_claimed'
    && batch.native_binding_verified === true
    && SHA256.test(batch.selected_source_job_commitment)
    && Array.isArray(batch.submitted_job_commitments)
    && batch.submitted_job_commitments.includes(batch.selected_source_job_commitment)
    && batch.selected_source_job_commitment === route.source_job_commitment
    && selectedBureauJobs.length === 1
    && SHA256.test(selectedBureauJobs[0].bureau_job_commitment)
    && batch.selected_bureau_job_commitment === selectedBureauJobs[0].bureau_job_commitment
    && submission.provider_kind === 'simulator' && submission.physical_claim === 'not_claimed'
    && submission.selected_source_job_commitment === batch.selected_source_job_commitment
    && submission.selected_bureau_job_commitment === batch.selected_bureau_job_commitment
    && submission.organization_id === route.organization_id
    && submission.application_id === route.application_id
    && submission.job_id === route.job_id
    && callback.provider_kind === 'simulator' && callback.physical_claim === 'not_claimed'
    && callback.signature_verified === true && callback.organization_bound === true
    && callback.source_job_commitment === batch.selected_source_job_commitment
    && callback.bureau_job_commitment === batch.selected_bureau_job_commitment
    && callback.organization_id === route.organization_id
    && callback.application_id === route.application_id
    && callback.job_id === route.job_id,
    'Simulator batch and signed native callback do not match the recorded job',
  );
  const denial = report.probes.unsigned_or_foreign_callback_denied.evidence;
  const unsigned = report.negative_runs?.unsigned;
  const foreign = report.negative_runs?.foreign;
  requireProof(
    denial.unsigned_denied === true
    && denial.foreign_organization_denied === true
    && denial.job_unchanged === true
    && denial.job_id === route.job_id
    && unsigned?.http_status === 422
    && unsigned.webhook_owner === 'issuance-native'
    && unsigned.request_kind === 'missing_signature_header'
    && unsigned.response_projection?.missing_signature_header === true
    && unsigned.organization_id === route.organization_id
    && unsigned.job_id === route.job_id
    && unsigned.source_job_commitment === route.source_job_commitment
    && unsigned.bureau_job_commitment === batch.selected_bureau_job_commitment
    && foreign?.http_status === 404
    && foreign.webhook_owner === 'issuance-native'
    && foreign.request_kind === 'signed_foreign_organization'
    && foreign.signature_valid === true
    && foreign.foreign_organization === true
    && typeof foreign.organization_id === 'string'
    && foreign.organization_id !== route.organization_id
    && foreign.job_id === route.job_id
    && foreign.source_job_commitment === route.source_job_commitment
    && foreign.bureau_job_commitment === batch.selected_bureau_job_commitment
    && foreign.response_projection?.webhook_job_not_found === true
    && SHA256.test(unsigned?.video_sha256)
    && SHA256.test(foreign?.video_sha256)
    && unsigned.video_sha256 !== foreign.video_sha256
    && SHA256.test(unsigned?.privacy_scan_report_sha256)
    && SHA256.test(foreign?.privacy_scan_report_sha256)
    && SHA256.test(unsigned?.job_state_before_sha256)
    && unsigned.job_state_before_sha256 === unsigned.job_state_after_sha256
    && foreign?.job_state_before_sha256 === unsigned.job_state_before_sha256
    && foreign.job_state_after_sha256 === unsigned.job_state_before_sha256
    && denial.unsigned_uncut_video_sha256 === unsigned.video_sha256
    && denial.foreign_uncut_video_sha256 === foreign.video_sha256,
    'Unsigned and foreign simulator callback denials are unproven',
  );
  requireProof(report.synthetic_identities_only === true,
    'Preliminary receipt does not attest synthetic identity inputs');
  return { sourceCommit, stackDigest, flow: route };
}

function validateLiveInstance(instance, definition, flow) {
  const context = instance?.context_data;
  const job = context?.physical_document_job;
  const results = instance?.step_results;
  const observedSteps = results && typeof results === 'object' ? Object.keys(results) : [];
  requireProof(
    instance?.id === flow.flow_instance_id
    && instance?.flow_id === flow.flow_id
    && instance?.organization_id === flow.organization_id
    && instance?.flow_type === 'physical_document_issuance'
    && String(instance?.status).toUpperCase() === 'COMPLETED'
    && definition?.id === flow.flow_id
    && definition?.organization_id === flow.organization_id
    && definition?.flow_type === 'physical_document_issuance'
    && JSON.stringify(definition?.resolved_steps) === JSON.stringify(FROZEN_STEPS)
    && context?.application_id === flow.application_id
    && job && (job.id || job.job_id) === flow.job_id
    && observedSteps.length === FROZEN_STEPS.length
    && FROZEN_STEPS.every((step) => observedSteps.includes(step))
    && Object.values(results).every((step) =>
      ['COMPLETED', 'SUCCESS'].includes(String(step?.status || step?.result).toUpperCase())),
    'Live beta Flow Instance differs from the protected nine-step receipt',
  );
}

async function main() {
  const artifactDir = createArtifactDir(ROOT, 'beta-passport-simulator-demo');
  const deploymentDir = process.env.PASSPORT_BETA_ARTIFACT_DIR;
  const runId = Number(process.env.PASSPORT_BETA_PRELIMINARY_RUN_ID);
  const expectedSha256 = process.env.PASSPORT_BETA_PRELIMINARY_SHA256 || '';
  const email = process.env.TEST_VENDOR_EMAIL || process.env.TEST_ADMIN_EMAIL;
  const password = process.env.TEST_VENDOR_PASSWORD || process.env.TEST_ADMIN_PASSWORD;
  requireProof(deploymentDir && email && password && process.env.RECORD_VIDEO === '1',
    'Beta deployment, operator session, and recorder inputs are required');
  const deployment = readJson(path.join(deploymentDir, 'local-deployment-manifest.json'));
  const { report: receipt, negativeMedia } = protectedReceipt(
    runId, expectedSha256, deployment.marty_ui_sha,
  );
  const proof = validatePreliminary(receipt, deployment, deploymentDir);
  for (const [name, filename] of Object.entries(NEGATIVE_MEDIA)) {
    fs.writeFileSync(path.join(artifactDir, filename), negativeMedia[name], { flag: 'wx' });
  }
  const { chromium } = require('@playwright/test');
  const { login } = require('./audit-beta-credential-lifecycle');
  const { selectOrganization } = require('./beta-demo-resource-helpers');
  const localProxy = process.env.BETA_LOCAL_PROXY === '1';
  const browser = await chromium.launch({
    headless: process.env.HEADED !== '1',
    args: localProxy
      ? ['--host-resolver-rules=MAP beta.elevenidllc.com 127.0.0.1', '--no-proxy-server']
      : [],
  });
  let context;
  try {
    const loginContext = await browser.newContext({ ignoreHTTPSErrors: localProxy });
    const loginPage = await loginContext.newPage();
    await login(loginPage, email, password);
    const organization = await selectOrganization(loginPage, {
      organizationId: proof.flow.organization_id, consoleOrigin: BETA_ORIGIN,
    });
    requireProof(organization.ok === true, 'Demo operator cannot select the beta organization');
    const storageState = await loginContext.storageState();
    await loginContext.close();
    context = await browser.newContext({
      storageState, viewport: VIDEO_SIZE,
      ignoreHTTPSErrors: localProxy,
      recordVideo: { dir: artifactDir, size: VIDEO_SIZE },
    });
    const page = await context.newPage();
    const video = page.video();
    const pageErrors = [];
    const unexpectedResponses = [];
    page.on('pageerror', (error) => pageErrors.push(error.message));
    page.on('response', (response) => {
      if (response.url().startsWith(BETA_ORIGIN)
        && response.status() >= 400
        && !response.url().includes('/cdn-cgi/rum')) {
        unexpectedResponses.push(response.status());
      }
    });
    const instanceId = proof.flow.flow_instance_id;
    await page.goto(`${BETA_ORIGIN}/console/org/operate/flow-instances/${encodeURIComponent(instanceId)}`,
      { waitUntil: 'domcontentloaded', timeout: 60_000 });
    await page.getByText(`Flow Instance ${instanceId}`, { exact: true }).waitFor({ timeout: 30_000 });
    await page.getByText(proof.flow.job_id, { exact: false }).first().waitFor({ timeout: 30_000 });
    const instance = await page.evaluate(async (id) => {
      const response = await fetch(`/v1/flows/instances/${encodeURIComponent(id)}`, { credentials: 'include' });
      return response.ok ? response.json() : null;
    }, instanceId);
    const definition = await page.evaluate(async (id) => {
      const response = await fetch(`/v1/flows/definitions/${encodeURIComponent(id)}`, { credentials: 'include' });
      return response.ok ? response.json() : null;
    }, proof.flow.flow_id);
    validateLiveInstance(instance, definition, proof.flow);
    await showStep(page, 'Managed CSCA and DSC issuer profiles',
      'Distinct KMS-backed profiles sign and verify the same synthetic passport job.',
      { enabled: true, eyebrow: 'Marty beta passport simulator' });
    await showStep(page, 'Nine-step Rust passport Flow',
      'The live Flow Instance and Marty simulator job match the protected preliminary receipt.',
      { enabled: true, eyebrow: 'Marty beta passport simulator' });
    await showStep(page, 'Signed simulator callback',
      'Native issuance accepts the signed callback; unsigned and foreign-organization callbacks are denied.',
      { enabled: true, eyebrow: 'Marty beta passport simulator' });
    await showStep(page, 'No physical booklet claim',
      'Physical claim: not claimed. No booklet has been verified.',
      { enabled: true, eyebrow: 'Marty beta passport simulator' });
    requireProof(pageErrors.length === 0 && unexpectedResponses.length === 0,
      'Live passport demo had browser or HTTP errors');
    await context.close();
    context = null;
    await finalizeVideo(video, artifactDir, 'physical-passport-issuance-evidence.webm');
    const report = {
      releaseReady: true,
      betaOrigin: BETA_ORIGIN,
      sourceCommit: proof.sourceCommit,
      stackManifestSha256: proof.stackDigest,
      preliminaryRunId: runId,
      preliminaryArtifactSha256: expectedSha256,
      negativeCallbackMediaSha256: {
        unsigned: receipt.negative_runs.unsigned.video_sha256,
        foreign: receipt.negative_runs.foreign.video_sha256,
      },
      flowInstanceSha256: createHash('sha256').update(instanceId).digest('hex'),
      behaviorAssertions: {
        managed_csca_dsc_issuer_profiles: true,
        nine_step_passport_issuance_flow: true,
        simulator_bureau_job_correlated: true,
        signed_simulator_callback_verified: true,
        physical_claim: 'not_claimed',
        booklet_verified: false,
        unsigned_or_foreign_callback_denied: true,
      },
    };
    fs.writeFileSync(path.join(artifactDir, 'report.json'), `${JSON.stringify(report, null, 2)}\n`);
    console.log(JSON.stringify({ releaseReady: true, report: path.join(artifactDir, 'report.json') }));
  } finally {
    if (context) await context.close().catch(() => {});
    await browser.close();
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`Passport simulator demo blocked: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { protectedReceipt, verifyNegativeMedia, validatePreliminary, validateLiveInstance };
