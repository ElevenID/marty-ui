#!/usr/bin/env node
/* eslint-disable no-console */
'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createHash, createHmac } = require('node:crypto');
const { execFileSync } = require('node:child_process');

const { VIDEO_SIZE, createArtifactDir, finalizeVideo, showStep } = require('./demo-recording');

const ROOT = path.resolve(__dirname, '..', '..');
const BETA_ORIGIN = 'https://beta.elevenidllc.com';
const SHA256 = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const IDENTIFIER = /^[A-Za-z0-9._:-]{1,255}$/;
const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PRIVATE_HANDOFF = require('../../contracts/passport-beta-demo-private-handoff.json');
const PROHIBITED_PUBLIC_KEYS = new Set([
  'organization_id', 'flow_id', 'flow_definition_id', 'flow_instance_id',
  'application_id', 'job_id', 'source_job_id', 'bureau_job_id', 'batch_id',
  'csca_issuer_profile_id', 'dsc_issuer_profile_id', 'issuer_profile_id',
  'csca_certificate_id', 'kms_key_id', 'kms_key_arn',
  'application_input_sha256', 'job_id_sha256', 'application_id_sha256',
  'bureau_job_id_sha256', 'flowInstanceSha256', 'job_state_before_sha256',
  'job_state_after_sha256', 'mrz', 'data_groups', 'sod_der_base64',
  'dsc_cert_pem', 'dsc_certificate_pem', 'certificate_bytes',
  'kms_key_reference', 'callback_body', 'callback_signature',
  'private_receipt', 'batch_request', 'batch_response',
  'request_body', 'response_body', 'applicant', 'passport_document',
  'document_data', 'personalization_payload', 'portrait', 'photo',
]);
const ALLOWED_PUBLIC_SHA256_KEYS = new Set([
  'stack_manifest_sha256', 'local_deployment_manifest_sha256',
  'source_manifest_sha256', 'official_stack_manifest_sha256',
  'csca_certificate_sha256', 'dsc_certificate_sha256',
  'sod_dsc_certificate_sha256', 'sod_sha256',
  'callback_receipt_sha256', 'selected_callback_receipt_sha256',
  'companion_callback_receipt_sha256', 'video_sha256',
  'privacy_scan_report_sha256', 'unsigned_uncut_video_sha256',
  'foreign_uncut_video_sha256',
]);

function prohibitedPublicKey(key) {
  const normalized = key.replace(/([a-z])([A-Z])/g, '$1_$2').toLowerCase();
  if (/(?:_sha256|_hash)$/.test(normalized)
      && !ALLOWED_PUBLIC_SHA256_KEYS.has(normalized)) return true;
  return PROHIBITED_PUBLIC_KEYS.has(key) || PROHIBITED_PUBLIC_KEYS.has(normalized)
    || /(?:^|_)(?:api_key|password|token|secret|cookie|wire_key|hmac_key|private_key|mrz|data_groups?)(?:_|$)/.test(normalized)
    || /(?:^|_)(?:raw|private)(?:_|$)/.test(normalized)
    || /^dg[0-9]+$/.test(normalized)
    || /(?:^|_)issuer_profile_id$/.test(normalized)
    || /(?:^|_)kms_key_(?:id|arn|reference)$/.test(normalized)
    || /(?:^|_)(?:certificate_pem|certificate_bytes|kms_key_reference|callback_body|callback_signature|batch_request|batch_response|request_body|response_body)(?:_|$)/.test(normalized)
    || /^(?:raw_)?(?:sod_der|dsc_pem|dsc_pem_wire)(?:_base64|_bytes|_hex)?$/.test(normalized)
    || /(?:^|_)(?:job|application|organization|flow|bureau|batch)_id_(?:sha256|hash)$/.test(normalized);
}
const REQUIRED_PROBES = [
  'managed_csca_dsc_chain', 'sod_signature', 'simulator_material_receipt',
  'nine_route_gateway_flow',
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
const NEGATIVE_SCANS = {
  unsigned: 'unsigned-callback-privacy-scan.json',
  foreign: 'foreign-callback-privacy-scan.json',
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

function commitment(key, label, value) {
  requireProof(typeof key === 'string' && key.length >= 32 && !/[\r\n\0]/.test(key)
    && typeof value === 'string' && IDENTIFIER.test(value),
  'Private passport commitment input is invalid');
  return createHmac('sha256', key).update(`${label}:${value}`, 'utf8').digest('hex');
}

function assertPublicPrivacy(report, privatePlan, apiKey) {
  const privateIds = ['organization_id', 'flow_definition_id', 'flow_instance_id',
    'application_id', 'source_job_id', 'bureau_job_id'].map((field) => privatePlan[field]);
  function visit(value) {
    if (Array.isArray(value)) return value.forEach(visit);
    if (value && typeof value === 'object') {
      for (const [key, nested] of Object.entries(value)) {
        requireProof(!prohibitedPublicKey(key),
          'Preliminary receipt contains a raw or unkeyed identifier field');
        requireProof(!key.includes(apiKey)
          && privateIds.every((identifier) => !key.includes(identifier)),
        'Preliminary receipt contains a private identifier or key');
        visit(nested);
      }
    } else if (typeof value === 'string') {
      requireProof(!value.includes('-----BEGIN ') && !/P<[A-Z0-9<]{15,}/.test(value),
        'Preliminary receipt contains raw passport material');
      requireProof(!value.includes(apiKey)
        && privateIds.every((identifier) => !value.includes(identifier)),
      'Preliminary receipt contains a private identifier or key');
    }
  }
  visit(report);
}

function readPrivatePlan(filePath, artifactDir) {
  try {
    requireProof(typeof filePath === 'string' && path.isAbsolute(filePath),
      'Private passport demo handoff path is invalid');
    const resolved = path.resolve(filePath);
    const real = fs.realpathSync(resolved);
    const checkout = path.resolve(ROOT);
    const artifacts = path.resolve(artifactDir);
    requireProof(real !== checkout && !real.startsWith(`${checkout}${path.sep}`)
      && real !== artifacts && !real.startsWith(`${artifacts}${path.sep}`),
    'Private passport demo handoff must be outside checkout and artifacts');
    const stat = fs.lstatSync(resolved);
    requireProof(stat.isFile() && !stat.isSymbolicLink() && stat.size > 0 && stat.size <= 16 * 1024
      && (process.platform === 'win32' || (stat.mode & 0o077) === 0),
    'Private passport demo handoff file is not protected');
    const plan = readJson(resolved);
    const keys = PRIVATE_HANDOFF.private_plan_fields;
    requireProof(Object.keys(plan).length === keys.length
      && Object.keys(plan).every((key) => keys.includes(key))
      && plan.schema === PRIVATE_HANDOFF.private_plan_schema
      && COMMIT.test(plan.source_commit) && SHA256.test(plan.stack_manifest_sha256)
      && ['organization_id', 'flow_definition_id', 'flow_instance_id',
        'application_id', 'source_job_id', 'bureau_job_id']
        .every((key) => typeof plan[key] === 'string' && IDENTIFIER.test(plan[key]))
      && CANONICAL_UUID.test(plan.bureau_job_id),
    'Private passport demo handoff is incomplete');
    return plan;
  } catch {
    throw new Error('Private passport demo handoff is invalid');
  }
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
    const scanPath = path.join(directory, NEGATIVE_SCANS[name]);
    const scanFile = fs.lstatSync(scanPath);
    requireProof(scanFile.isFile() && scanFile.size > 0 && scanFile.size <= 1024 * 1024,
      `Protected ${name} callback privacy scan is missing or oversized`);
    requireProof(sha256(scanPath) === declared.privacy_scan_report_sha256,
      `Protected ${name} callback privacy scan digest mismatch`);
    const scan = readJson(scanPath);
    requireProof(Object.keys(scan).length === 5
      && ['schemaVersion', 'passed', 'findings', 'videoSha256', 'frameSamplingFps']
        .every((key) => Object.hasOwn(scan, key))
      && scan.schemaVersion === 1 && scan.passed === true
      && Array.isArray(scan.findings) && scan.findings.length === 0
      && scan.videoSha256 === declared.video_sha256
      && Number(scan.frameSamplingFps) >= 2,
    `Protected ${name} callback privacy scan did not pass for its exact video`);
    output[name] = {
      video: fs.readFileSync(videoPath),
      privacyScan: fs.readFileSync(scanPath),
    };
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

function validatePreliminary(report, deployment, artifactDir, privatePlan, apiKey) {
  const stackDigest = sha256(path.join(artifactDir, 'stack-manifest.json'));
  const deploymentDigest = sha256(path.join(artifactDir, 'local-deployment-manifest.json'));
  const sourceDigest = sha256(path.join(artifactDir, 'source-manifest.json'));
  const sourceCommit = deployment.marty_ui_sha;
  requireProof(COMMIT.test(sourceCommit), 'Deployed source commit is invalid');
  requireProof(privatePlan?.schema === PRIVATE_HANDOFF.private_plan_schema
    && privatePlan.source_commit === sourceCommit
    && privatePlan.stack_manifest_sha256 === stackDigest,
  'Private passport demo handoff differs from the deployed release');
  assertPublicPrivacy(report, privatePlan, apiKey);
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
    SHA256.test(chain.csca_issuer_profile_commitment)
    && SHA256.test(chain.dsc_issuer_profile_commitment)
    && chain.csca_issuer_profile_commitment !== chain.dsc_issuer_profile_commitment
    && chain.managed_kms_custody_verified === true
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
    && SHA256.test(route.organization_commitment)
    && SHA256.test(route.flow_definition_commitment)
    && SHA256.test(route.flow_instance_commitment)
    && SHA256.test(route.application_commitment)
    && SHA256.test(route.source_job_commitment)
    && SHA256.test(route.bureau_job_commitment),
    'Nine-route Rust flow or exact instance correlation is unproven',
  );
  for (const [field, label] of Object.entries(PRIVATE_HANDOFF.labels)) {
    const privateField = {
      organization_commitment: 'organization_id',
      flow_definition_commitment: 'flow_definition_id',
      flow_instance_commitment: 'flow_instance_id',
      application_commitment: 'application_id',
      source_job_commitment: 'source_job_id',
      bureau_job_commitment: 'bureau_job_id',
    }[field];
    requireProof(route[field] === commitment(apiKey, label, privatePlan[privateField]),
      'Private passport identities do not match the protected preliminary receipt');
  }
  requireProof(
    chain.organization_commitment === route.organization_commitment
    && chain.application_commitment === route.application_commitment
    && chain.source_job_commitment === route.source_job_commitment
    && SHA256.test(chain.sod_dsc_certificate_sha256)
    && chain.sod_dsc_certificate_sha256 === sod.dsc_certificate_sha256
    && sod.source_job_commitment === route.source_job_commitment,
    'Managed issuer chain and SOD do not match the recorded passport job',
  );
  const batch = report.probes.physical_bureau_batch.evidence;
  const submission = report.probes.physical_bureau_submission.evidence;
  const callback = report.probes.signed_bureau_callback.evidence;
  const material = report.probes.simulator_material_receipt.evidence;
  const selectedBureauJobs = Array.isArray(batch.returned_jobs)
    ? batch.returned_jobs.filter((job) =>
      job?.source_job_commitment === route.source_job_commitment)
    : [];
  requireProof(
    material.tenant_and_job_binding === true
    && material.first_accepted_sod_der_matches_native === true
    && material.first_accepted_dsc_der_matches_selected_chain === true
    && material.first_accepted_dsc_pem_wire_matches_selected_chain === true
    && SHA256.test(material.source_job_id_commitment)
    && SHA256.test(material.bureau_job_id_commitment)
    && material.source_job_id_commitment === route.source_job_commitment
    && material.bureau_job_id_commitment === batch.selected_bureau_job_commitment,
    'First accepted simulator SOD and DSC do not match the selected passport job',
  );
  requireProof(
    batch.provider_kind === 'simulator' && batch.physical_claim === 'not_claimed'
    && batch.native_binding_verified === true
    && batch.selected_flow_in_two_job_batch === true
    && batch.native_completed_jobs === 2
    && batch.first_accepted_material_verified === true
    && batch.selected_flow_callback_verified === true
    && batch.http_status === 202 && batch.batch_status === 'QUEUED'
    && SHA256.test(batch.request_commitment)
    && SHA256.test(batch.response_commitment)
    && SHA256.test(batch.selected_source_job_commitment)
    && Array.isArray(batch.submitted_job_commitments)
    && batch.submitted_job_commitments.length === 2
    && new Set(batch.submitted_job_commitments).size === 2
    && batch.submitted_job_commitments.every((commitment) => SHA256.test(commitment))
    && Array.isArray(batch.returned_jobs)
    && batch.returned_jobs.length === 2
    && batch.returned_jobs.every((job) =>
      SHA256.test(job?.source_job_commitment) && SHA256.test(job?.bureau_job_commitment))
    && new Set(batch.returned_jobs.map((job) => job.source_job_commitment)).size === 2
    && new Set(batch.returned_jobs.map((job) => job.bureau_job_commitment)).size === 2
    && batch.returned_jobs.every((job) =>
      batch.submitted_job_commitments.includes(job.source_job_commitment))
    && batch.submitted_job_commitments.includes(batch.selected_source_job_commitment)
    && batch.selected_source_job_commitment === route.source_job_commitment
    && batch.selected_bureau_job_commitment === route.bureau_job_commitment
    && selectedBureauJobs.length === 1
    && SHA256.test(selectedBureauJobs[0].bureau_job_commitment)
    && batch.selected_bureau_job_commitment === selectedBureauJobs[0].bureau_job_commitment
    && submission.provider_kind === 'simulator' && submission.physical_claim === 'not_claimed'
    && submission.selected_source_job_commitment === batch.selected_source_job_commitment
    && submission.selected_bureau_job_commitment === batch.selected_bureau_job_commitment
    && submission.organization_commitment === route.organization_commitment
    && submission.application_commitment === route.application_commitment
    && submission.flow_instance_commitment === route.flow_instance_commitment
    && callback.provider_kind === 'simulator' && callback.physical_claim === 'not_claimed'
    && callback.signature_verified === true && callback.organization_bound === true
    && callback.source_job_commitment === batch.selected_source_job_commitment
    && callback.bureau_job_commitment === batch.selected_bureau_job_commitment
    && callback.organization_commitment === route.organization_commitment
    && callback.application_commitment === route.application_commitment
    && callback.flow_instance_commitment === route.flow_instance_commitment
    && callback.callback_receipt_sha256 === batch.selected_callback_receipt_sha256
    && SHA256.test(callback.callback_receipt_sha256),
    'Simulator batch and signed native callback do not match the recorded job',
  );
  const denial = report.probes.unsigned_or_foreign_callback_denied.evidence;
  const unsigned = report.negative_runs?.unsigned;
  const foreign = report.negative_runs?.foreign;
  requireProof(
    denial.unsigned_denied === true
    && denial.foreign_organization_denied === true
    && denial.job_unchanged === true
    && denial.source_job_commitment === route.source_job_commitment
    && denial.bureau_job_commitment === route.bureau_job_commitment
    && unsigned?.http_status === 422
    && unsigned.webhook_owner === 'issuance-native'
    && unsigned.request_kind === 'missing_signature_header'
    && unsigned.response_projection?.missing_signature_header === true
    && unsigned.organization_commitment === route.organization_commitment
    && unsigned.source_job_commitment === route.source_job_commitment
    && unsigned.bureau_job_commitment === batch.selected_bureau_job_commitment
    && foreign?.http_status === 404
    && foreign.webhook_owner === 'issuance-native'
    && foreign.request_kind === 'signed_foreign_organization'
    && foreign.signature_valid === true
    && foreign.foreign_organization === true
    && SHA256.test(foreign.organization_commitment)
    && foreign.organization_commitment !== route.organization_commitment
    && foreign.source_job_commitment === route.source_job_commitment
    && foreign.bureau_job_commitment === batch.selected_bureau_job_commitment
    && foreign.response_projection?.webhook_job_not_found === true
    && SHA256.test(unsigned?.video_sha256)
    && SHA256.test(foreign?.video_sha256)
    && unsigned.video_sha256 !== foreign.video_sha256
    && SHA256.test(unsigned?.privacy_scan_report_sha256)
    && SHA256.test(foreign?.privacy_scan_report_sha256)
    && SHA256.test(unsigned?.job_state_before_commitment)
    && unsigned.job_state_before_commitment === unsigned.job_state_after_commitment
    && foreign?.job_state_before_commitment === unsigned.job_state_before_commitment
    && foreign.job_state_after_commitment === unsigned.job_state_before_commitment
    && denial.unsigned_uncut_video_sha256 === unsigned.video_sha256
    && denial.foreign_uncut_video_sha256 === foreign.video_sha256,
    'Unsigned and foreign simulator callback denials are unproven',
  );
  requireProof(report.synthetic_identities_only === true,
    'Preliminary receipt does not attest synthetic identity inputs');
  return { sourceCommit, stackDigest, flow: privatePlan, publicFlow: route };
}

function validateLiveInstance(instance, definition, flow, expectedSodSha256) {
  const context = instance?.context_data;
  const job = context?.physical_document_job;
  const results = instance?.step_results;
  const observedSteps = results && typeof results === 'object' ? Object.keys(results) : [];
  requireProof(
    instance?.id === flow.flow_instance_id
    && instance?.flow_id === flow.flow_definition_id
    && instance?.organization_id === flow.organization_id
    && instance?.flow_type === 'physical_document_issuance'
    && String(instance?.status).toUpperCase() === 'COMPLETED'
    && definition?.id === flow.flow_definition_id
    && definition?.organization_id === flow.organization_id
    && definition?.flow_type === 'physical_document_issuance'
    && JSON.stringify(definition?.resolved_steps) === JSON.stringify(FROZEN_STEPS)
    && context?.application_id === flow.application_id
    && job && (job.id || job.job_id) === flow.source_job_id
    && job.application_id === flow.application_id
    && job.bureau_job_id === flow.bureau_job_id
    && job.flow_execution_id === flow.flow_instance_id
    && job.organization_id === flow.organization_id
    && job.status === 'ACTIVE'
    && SHA256.test(expectedSodSha256)
    && job.sod_sha256 === expectedSodSha256
    && observedSteps.length === FROZEN_STEPS.length
    && FROZEN_STEPS.every((step) => observedSteps.includes(step))
    && Object.values(results).every((step) =>
      ['COMPLETED', 'SUCCESS'].includes(String(step?.status || step?.result).toUpperCase())),
    'Live beta Flow Instance differs from the protected nine-step receipt',
  );
}

async function hideRecordedPage(context) {
  await context.addInitScript(() => {
    const sheet = new CSSStyleSheet();
    sheet.replaceSync('html { opacity: 0 !important; }');
    document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
    window.__passportRecordingPrivacySheet = sheet;
  });
}

async function revealRedactedPage(page, privatePlan) {
  const privateIds = ['organization_id', 'flow_definition_id', 'flow_instance_id',
    'application_id', 'source_job_id', 'bureau_job_id']
    .map((field) => privatePlan[field]).sort((left, right) => right.length - left.length);
  const safe = await page.evaluate((identifiers) => {
    if (!document.body) return false;
    const replace = (value) => identifiers.reduce(
      (text, identifier) => text.replaceAll(identifier, '[protected id]'), value);
    const scrub = (root) => {
      if (root.nodeType === Node.TEXT_NODE) {
        const value = root.nodeValue || '';
        const sanitized = replace(value);
        if (sanitized !== value) root.nodeValue = sanitized;
      } else if (root.nodeType === Node.ELEMENT_NODE) {
        const element = root;
        if (element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement) {
          const sanitized = replace(element.value);
          if (sanitized !== element.value) element.value = sanitized;
        }
        for (const child of element.childNodes) scrub(child);
      }
    };
    const observer = new MutationObserver((records) => {
      for (const record of records) {
        if (record.type === 'characterData') scrub(record.target);
        else for (const node of record.addedNodes) scrub(node);
      }
    });
    observer.observe(document.body, { subtree: true, childList: true, characterData: true });
    scrub(document.body);
    const visible = document.body.innerText
      + Array.from(document.querySelectorAll('input,textarea')).map((input) => input.value).join(' ');
    if (identifiers.some((identifier) => visible.includes(identifier))) return false;
    document.adoptedStyleSheets = document.adoptedStyleSheets.filter(
      (sheet) => sheet !== window.__passportRecordingPrivacySheet);
    return true;
  }, privateIds);
  requireProof(safe === true, 'Recorded beta page could not redact protected identifiers');
}

async function main() {
  const artifactDir = createArtifactDir(ROOT, 'beta-passport-simulator-demo');
  const deploymentDir = process.env.PASSPORT_BETA_ARTIFACT_DIR;
  const runId = Number(process.env.PASSPORT_BETA_PRELIMINARY_RUN_ID);
  const expectedSha256 = process.env.PASSPORT_BETA_PRELIMINARY_SHA256 || '';
  const privatePlanFile = process.env.PASSPORT_BETA_PRIVATE_PLAN_FILE;
  const apiKey = process.env.PASSPORT_BETA_API_KEY;
  const email = process.env.TEST_VENDOR_EMAIL || process.env.TEST_ADMIN_EMAIL;
  const password = process.env.TEST_VENDOR_PASSWORD || process.env.TEST_ADMIN_PASSWORD;
  requireProof(deploymentDir && email && password && privatePlanFile
    && apiKey && process.env.RECORD_VIDEO === '1',
  'Beta deployment, private handoff, operator session, and recorder inputs are required');
  const deployment = readJson(path.join(deploymentDir, 'local-deployment-manifest.json'));
  const privatePlan = readPrivatePlan(privatePlanFile, artifactDir);
  const { report: receipt, negativeMedia } = protectedReceipt(
    runId, expectedSha256, deployment.marty_ui_sha,
  );
  const proof = validatePreliminary(receipt, deployment, deploymentDir, privatePlan, apiKey);
  for (const [name, filename] of Object.entries(NEGATIVE_MEDIA)) {
    fs.writeFileSync(path.join(artifactDir, filename), negativeMedia[name].video, { flag: 'wx' });
    fs.writeFileSync(path.join(artifactDir, NEGATIVE_SCANS[name]),
      negativeMedia[name].privacyScan, { flag: 'wx' });
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
    await hideRecordedPage(context);
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
    await page.getByText(`Flow Instance ${instanceId}`, { exact: true })
      .waitFor({ state: 'attached', timeout: 30_000 });
    await page.getByText(proof.flow.source_job_id, { exact: false }).first()
      .waitFor({ state: 'attached', timeout: 30_000 });
    const instance = await page.evaluate(async (id) => {
      const response = await fetch(`/v1/flows/instances/${encodeURIComponent(id)}`, { credentials: 'include' });
      return response.ok ? response.json() : null;
    }, instanceId);
    const definition = await page.evaluate(async (id) => {
      const response = await fetch(`/v1/flows/definitions/${encodeURIComponent(id)}`, { credentials: 'include' });
      return response.ok ? response.json() : null;
    }, proof.flow.flow_definition_id);
    validateLiveInstance(instance, definition, proof.flow,
      receipt.probes.sod_signature.evidence.sod_sha256);
    await revealRedactedPage(page, proof.flow);
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
      selectedSourceJobCommitment: proof.publicFlow.source_job_commitment,
      selectedBureauJobCommitment: proof.publicFlow.bureau_job_commitment,
      flowInstanceCommitment: proof.publicFlow.flow_instance_commitment,
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
  main().catch(() => {
    console.error('Passport simulator demo blocked; inspect protected run state');
    process.exitCode = 1;
  });
}

module.exports = { protectedReceipt, verifyNegativeMedia, readPrivatePlan,
  validatePreliminary, validateLiveInstance, hideRecordedPage, revealRedactedPage };
