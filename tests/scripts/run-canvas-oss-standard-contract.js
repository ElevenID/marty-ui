#!/usr/bin/env node

'use strict';

/**
 * Honest Canvas OSS portability contract.
 *
 * This runner deliberately uses only:
 *   - stock Canvas browser screens for login, personal access tokens, and
 *     Developer Keys;
 *   - documented Canvas REST APIs;
 *   - standard LTI 1.3, Deep Linking, AGS, and NRPS launches emitted by Canvas;
 *   - ElevenID's public/management APIs and OID4VCI credential endpoint.
 *
 * It must never use Rails runner/console, direct database access, patched
 * Canvas source, a Canvas plugin, custom event ingestion, or persisted browser
 * state. Runtime credentials remain in memory and are never written to the
 * observation or video artifacts.
 */

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('@playwright/test');

const SCHEMA_VERSION = 1;
const DEFAULT_CANVAS_ORIGIN = 'https://canvas-test.elevenidllc.com';
const DEFAULT_MARTY_ORIGIN = 'https://beta.elevenidllc.com';
const RUN_NAME_PREFIX = 'ElevenID OSS portability';
const DEFAULT_TIMEOUT_MS = 60_000;
const JOB_TIMEOUT_MS = 180_000;
const READINESS_TIMEOUT_MS = 120_000;

const CASE_IDS = [
  'upstream_source_and_image_provenance',
  'stock_lifecycle_bootstrap_only',
  'beta_release_bound_and_healthy',
  'canvas_public_https_reachable',
  'standard_lti_13_install',
  'instructor_deep_linking',
  'learner_resource_launch',
  'marty_bound_ags_result',
  'nrps_roster',
  'canvas_oauth_authorization',
  'existing_assignment_submission',
  'classic_quiz_submission',
  'authoritative_evidence_sync',
  'module_completion',
  'course_completion',
  'background_pending_claim_unsigned',
  'kms_open_badge_claim_and_verify',
  'pre_issuance_grade_correction',
  'post_issuance_correction_review_only',
  'legacy_event_ingest_unavailable',
  'new_quizzes_authoritative_submission',
  'canvas_credentials_projection',
];

const OAUTH_CAPABILITIES = [
  'catalog',
  'native_activity_scores',
  'course_completion',
  'module_completion',
  'background_roster',
];

const CANVAS_OAUTH_SCOPES = [
  'url:GET|/api/v1/courses',
  'url:GET|/api/v1/courses/:course_id/assignments',
  'url:GET|/api/v1/courses/:course_id/modules',
  'url:GET|/api/v1/courses/:course_id/assignments/:assignment_id/submissions/:user_id',
  'url:GET|/api/v1/courses/:course_id/users/:user_id/progress',
  'url:GET|/api/v1/courses/:course_id/modules/:id',
  'url:GET|/api/v1/courses/:course_id/users',
  'url:GET|/api/v1/courses/:course_id/enrollments',
  'url:GET|/api/v1/courses/:course_id/bulk_user_progress',
];

const CANVAS_FEATURE_FLAGS = {
  enable_canvas_evidence: true,
  enable_canvas_lti: true,
  enable_canvas_deep_linking: true,
  enable_canvas_ags: true,
  enable_canvas_nrps: true,
  enable_background_awards: true,
};

// This list mirrors the production binding-readiness contract.  The driver
// intentionally requires every blocking check to be present and ready so a
// newly-added fail-closed check cannot be hidden behind a top-level boolean.
const BLOCKING_READINESS_CHECK_CODES = [
  'rollout_allowlist',
  'tenant_ownership',
  'platform_active',
  'lti_installation',
  'lti_metadata',
  'lti_tool_sign_verify_challenge',
  'typed_evidence_requirements',
  'ags_result_capability',
  'nrps_roster_capability',
  'oauth_capability_mapping',
  'oauth_connection',
  'oauth_least_privilege_grant',
  'worker_heartbeat',
  'application_template',
  'open_badge_template',
  'credential_template_snapshot',
  'credential_status_profile',
  'kms_issuer_configuration',
  'kms_did_sign_verify_challenge',
];

class ContractFailure extends Error {
  constructor(code, summary, options = {}) {
    super(summary, options);
    this.name = 'ContractFailure';
    this.code = code;
  }
}

function fail(code, summary) {
  throw new ContractFailure(code, summary);
}

function requireCondition(condition, code, summary) {
  if (!condition) fail(code, summary);
}

function sanitizeEvidence(value) {
  let text = String(value || '')
    .replace(/[\r\n\t]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  text = text
    .replace(/Bearer\s+[A-Za-z0-9._~-]{8,}/gi, 'Bearer [redacted]')
    .replace(/eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, '[redacted-jwt]')
    .replace(/([?&](?:code|state|credential_offer|credential_offer_uri)=)[^&\s]+/gi, '$1[redacted]')
    .replace(/(?:access|refresh|session|id)[_-]?token\s*[:=]\s*[^\s,;]+/gi, 'credential-material=[redacted]')
    .replace(/(?:client[_-]?secret|api[_-]?key|password)\s*[:=]\s*[^\s,;]+/gi, 'credential-material=[redacted]');
  return text.slice(0, 240);
}

class ObservationLedger {
  constructor(startedAt = new Date().toISOString(), execution = null) {
    this.startedAt = startedAt;
    this.execution = execution;
    this.entries = new Map(
      CASE_IDS.map((id) => [id, {
        id,
        status: id === 'new_quizzes_authoritative_submission'
          ? 'hosted_required'
          : id === 'canvas_credentials_projection'
            ? 'outside_gate'
            : 'not_run',
        evidence: id === 'new_quizzes_authoritative_submission'
          ? 'New Quizzes remains a hosted-Canvas contract case.'
          : id === 'canvas_credentials_projection'
            ? 'Canvas Credentials projection remains outside the production gate.'
            : 'The standard contract did not reach this case.',
      }]),
    );
  }

  set(id, status, evidence) {
    requireCondition(this.entries.has(id), 'observation_unknown_case', `Unknown observation case: ${id}`);
    this.entries.set(id, { id, status, evidence: sanitizeEvidence(evidence) });
  }

  pass(id, evidence) {
    this.set(id, 'passed', evidence);
  }

  fail(id, evidence) {
    this.set(id, 'failed', evidence);
  }

  toJSON() {
    const output = {
      schema_version: SCHEMA_VERSION,
      started_at: this.startedAt,
      cases: CASE_IDS.map((id) => this.entries.get(id)),
    };
    if (this.execution) output.execution = this.execution;
    return output;
  }

  write(filePath) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, `${JSON.stringify(this.toJSON(), null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  }

  allOssRequiredPassed() {
    return CASE_IDS
      .filter((id) => !['new_quizzes_authoritative_submission', 'canvas_credentials_projection'].includes(id))
      .every((id) => this.entries.get(id)?.status === 'passed');
  }
}

function parseArgs(argv) {
  const result = { observations: '', video: '' };
  for (let index = 2; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--observations') result.observations = argv[++index] || '';
    else if (arg === '--video') result.video = argv[++index] || '';
    else fail('invalid_argument', `Unsupported argument: ${arg}`);
  }
  requireCondition(result.observations, 'observations_path_missing', '--observations is required.');
  requireCondition(result.video, 'video_path_missing', '--video is required.');
  return {
    observations: path.resolve(result.observations),
    video: path.resolve(result.video),
  };
}

function requireEnv(name) {
  const value = String(process.env[name] || '').trim();
  requireCondition(value, 'environment_incomplete', `Required environment variable ${name} is missing.`);
  return value;
}

function requireSecretFile(name) {
  requireCondition(!process.env[name], 'secret_transport_invalid', `${name} must not be supplied through the process environment.`);
  const filePath = String(process.env[`${name}_FILE`] || '').trim();
  requireCondition(
    filePath.startsWith('/run/secrets/') && !filePath.includes('/../'),
    'secret_file_missing',
    `${name} must be supplied through a Compose secret file.`,
  );
  let value = '';
  try {
    requireCondition(fs.lstatSync(filePath).isFile(), 'secret_file_invalid', `${name} secret path is not a file.`);
    value = fs.readFileSync(filePath, 'utf8').replace(/\r?\n$/, '');
  } catch (error) {
    if (error instanceof ContractFailure) throw error;
    fail('secret_file_unreadable', `${name} Compose secret is unreadable.`);
  }
  requireCondition(value.length > 0, 'secret_file_empty', `${name} Compose secret is empty.`);
  return value;
}

function requireComposeExecutionBoundary() {
  requireCondition(fs.existsSync('/.dockerenv'), 'container_boundary_missing', 'The standard contract must run inside its Compose container.');
  const composeService = requireEnv('CANVAS_OSS_CONTRACT_SERVICE');
  const boundary = requireEnv('CANVAS_OSS_EXECUTION_BOUNDARY');
  const secretTransport = requireEnv('CANVAS_OSS_SECRET_TRANSPORT');
  const imageId = requireEnv('CANVAS_OSS_CONTRACT_IMAGE_ID');
  const sourceSha = requireEnv('CANVAS_OSS_DRIVER_SOURCE_SHA');
  const baseImage = requireEnv('CANVAS_OSS_PLAYWRIGHT_IMAGE');
  requireCondition(composeService === 'canvas-contract', 'compose_service_invalid', 'Unexpected contract Compose service identity.');
  requireCondition(boundary === 'docker_compose_one_shot', 'execution_boundary_invalid', 'Browser contract execution is not Compose-bound.');
  requireCondition(secretTransport === 'compose_secret_files', 'secret_transport_invalid', 'Browser contract secrets are not file-mounted.');
  requireCondition(/^sha256:[0-9a-f]{64}$/.test(imageId), 'contract_image_id_invalid', 'Contract image ID is not immutable.');
  requireCondition(/^[0-9a-f]{40}$/.test(sourceSha), 'contract_source_invalid', 'Contract driver source SHA is invalid.');
  requireCondition(
    /^mcr\.microsoft\.com\/playwright:v1\.56\.0-jammy@sha256:[0-9a-f]{64}$/.test(baseImage),
    'playwright_base_unpinned',
    'Playwright base image is not the locked immutable reference.',
  );
  return {
    boundary,
    compose_service: composeService,
    containerized: true,
    host_browser_processes: false,
    secret_transport: secretTransport,
    image_id: imageId,
    source_sha: sourceSha,
    base_image: baseImage,
  };
}

function normalizePinnedOrigin(value, expected, label) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail('origin_invalid', `${label} is not a valid URL.`);
  }
  requireCondition(
    parsed.protocol === 'https:'
      && !parsed.username
      && !parsed.password
      && !parsed.search
      && !parsed.hash
      && parsed.pathname === '/',
    'origin_invalid',
    `${label} must be a bare public HTTPS origin.`,
  );
  requireCondition(parsed.origin === expected, 'origin_changed', `${label} does not match the reviewed portability topology.`);
  return parsed.origin;
}

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function waitFor(check, timeoutMs = DEFAULT_TIMEOUT_MS, intervalMs = 1_000, code = 'condition_timeout') {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const value = await check();
      if (value) return value;
    } catch (error) {
      lastError = error;
    }
    await sleep(intervalMs);
  }
  if (lastError instanceof ContractFailure) throw lastError;
  fail(code, 'Timed out waiting for the standard contract condition.');
}

function readJsonFile(filePath, code) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    fail(code, 'A required sanitized pipeline JSON artifact could not be read.');
  }
}

async function fetchWithTimeout(url, options = {}, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal, redirect: options.redirect || 'manual' });
  } catch {
    fail('http_transport_failed', 'A required HTTPS request failed.');
  } finally {
    clearTimeout(timer);
  }
}

async function responseJson(response, code, summary, expectedStatuses = [200]) {
  const status = typeof response.status === 'function' ? response.status() : response.status;
  requireCondition(expectedStatuses.includes(status), code, `${summary} HTTP ${status}.`);
  if (status === 204) return null;
  try {
    return await response.json();
  } catch {
    fail(code, `${summary} did not return JSON.`);
  }
}

class MartyClient {
  constructor(origin, apiKey) {
    this.origin = origin;
    this.apiKey = apiKey;
  }

  async request(method, requestPath, { json = undefined, expected = [200] } = {}) {
    requireCondition(requestPath.startsWith('/v1/'), 'marty_path_rejected', 'Marty request path is outside the reviewed API surface.');
    const url = new URL(requestPath, this.origin);
    requireCondition(url.origin === this.origin, 'marty_origin_rejected', 'Marty request escaped the pinned origin.');
    const headers = {
      Accept: 'application/json',
      'X-API-Key': this.apiKey,
    };
    let body;
    if (json !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(json);
    }
    const response = await fetchWithTimeout(url, { method, headers, body, redirect: 'manual' });
    return responseJson(response, 'marty_request_failed', 'Marty API request failed', expected);
  }

  get(requestPath, expected = [200]) {
    return this.request('GET', requestPath, { expected });
  }

  post(requestPath, json = {}, expected = [200]) {
    return this.request('POST', requestPath, { json, expected });
  }

  put(requestPath, json = {}, expected = [200]) {
    return this.request('PUT', requestPath, { json, expected });
  }

  delete(requestPath, expected = [204]) {
    return this.request('DELETE', requestPath, { expected });
  }
}

class CanvasClient {
  constructor(origin, bearer) {
    this.origin = origin;
    this.bearer = bearer;
  }

  async request(method, requestPath, { form = undefined, json = undefined, expected = [200] } = {}) {
    requireCondition(requestPath.startsWith('/api/v1/'), 'canvas_api_path_rejected', 'Canvas request path is outside the documented REST API surface.');
    const url = new URL(requestPath, this.origin);
    requireCondition(url.origin === this.origin, 'canvas_api_origin_rejected', 'Canvas API request escaped the pinned origin.');
    const headers = {
      Accept: 'application/json',
      Authorization: `Bearer ${this.bearer}`,
    };
    let body;
    if (form !== undefined) {
      headers['Content-Type'] = 'application/x-www-form-urlencoded;charset=UTF-8';
      body = new URLSearchParams(Object.entries(form).map(([key, value]) => [key, String(value)])).toString();
    } else if (json !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(json);
    }
    const response = await fetchWithTimeout(url, { method, headers, body, redirect: 'manual' });
    return responseJson(response, 'canvas_api_request_failed', 'Canvas documented REST request failed', expected);
  }

  get(requestPath, expected = [200]) {
    return this.request('GET', requestPath, { expected });
  }

  postForm(requestPath, form = {}, expected = [200]) {
    return this.request('POST', requestPath, { form, expected });
  }

  putForm(requestPath, form = {}, expected = [200]) {
    return this.request('PUT', requestPath, { form, expected });
  }

  postJson(requestPath, json = {}, expected = [200]) {
    return this.request('POST', requestPath, { json, expected });
  }
}

function extractDeveloperKeyRecord(payload, expectedName) {
  const candidates = [];
  const visit = (value) => {
    if (!value || typeof value !== 'object') return;
    if (!Array.isArray(value)) {
      if (value.id && (value.name === expectedName || value.api_key || value.tool_configuration)) {
        candidates.push(value);
      }
      for (const nested of Object.values(value)) visit(nested);
    } else {
      for (const nested of value) visit(nested);
    }
  };
  visit(payload);
  return candidates.find((item) => item.name === expectedName)
    || candidates.find((item) => item.api_key)
    || candidates[0]
    || null;
}

async function loginCanvas(page, origin, email, password) {
  await page.goto(`${origin}/login/canvas`, { waitUntil: 'domcontentloaded', timeout: DEFAULT_TIMEOUT_MS });
  const identifier = page.locator('#pseudonym_session_unique_id, input[name="pseudonym_session[unique_id]"]').first();
  const passwordInput = page.locator('#pseudonym_session_password, input[name="pseudonym_session[password]"]').first();
  await identifier.fill(email);
  await passwordInput.fill(password);
  await Promise.all([
    page.waitForURL((url) => url.origin === origin && !url.pathname.startsWith('/login'), { timeout: DEFAULT_TIMEOUT_MS }),
    page.locator('button[type="submit"], input[type="submit"]').first().click(),
  ]);
  const accepted = page.getByRole('button', { name: /accept|agree|continue/i }).first();
  if (await accepted.isVisible().catch(() => false)) await accepted.click();
}

async function createPersonalAccessToken(page, origin, purpose) {
  await page.goto(`${origin}/profile/settings`, { waitUntil: 'domcontentloaded', timeout: DEFAULT_TIMEOUT_MS });
  const add = page.locator('.add_access_token_link').first();
  await add.waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
  await add.click();
  const dialog = page.getByRole('dialog', { name: /new access token/i });
  await dialog.waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
  await dialog.getByLabel(/^purpose/i).fill(purpose);
  const responsePromise = page.waitForResponse((response) => (
    response.request().method() === 'POST'
      && new URL(response.url()).pathname === '/api/v1/users/self/tokens'
  ), { timeout: DEFAULT_TIMEOUT_MS });
  await dialog.getByRole('button', { name: /^generate token$/i }).click();
  const response = await responsePromise;
  const payload = await responseJson(response, 'canvas_personal_token_failed', 'Canvas personal token creation failed', [200, 201]);
  const visible = String(payload?.visible_token || '').trim();
  requireCondition(visible.length >= 20, 'canvas_personal_token_missing', 'Canvas did not return a one-time personal token.');
  const details = page.getByRole('dialog', { name: /access token details/i });
  if (await details.isVisible().catch(() => false)) {
    await details.getByRole('button', { name: /close/i }).click().catch(() => {});
  }
  return visible;
}

async function openDeveloperKeyModal(page, origin, accountId, kind) {
  await page.goto(`${origin}/accounts/${encodeURIComponent(accountId)}/developer_keys`, {
    waitUntil: 'domcontentloaded',
    timeout: DEFAULT_TIMEOUT_MS,
  });
  const trigger = page.locator('#add-developer-key-button').or(page.getByRole('button', { name: /create.*developer key|developer key/i })).first();
  await trigger.waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
  await trigger.click();
  const menuName = kind === 'lti' ? /^LTI Key$/i : /^API Key$/i;
  await page.getByRole('menuitem', { name: menuName }).click();
  // Canvas labels the dialog "Create Developer Key"; "Key Settings" is its
  // visible heading, not the dialog's accessible name.
  const modal = page.getByRole('dialog', { name: /create developer key/i });
  await modal.waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
  await modal.getByRole('heading', { name: /^key settings$/i }).waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
  return modal;
}

async function saveDeveloperKey(page, modal, expectedName) {
  const responsePromise = page.waitForResponse((response) => {
    const parsed = new URL(response.url());
    return response.request().method() === 'POST' && parsed.pathname.includes('developer_keys');
  }, { timeout: DEFAULT_TIMEOUT_MS });
  await modal.getByRole('button', { name: /^save$/i }).click();
  const response = await responsePromise;
  const payload = await responseJson(response, 'canvas_developer_key_save_failed', 'Canvas Developer Key save failed', [200, 201]);
  await modal.waitFor({ state: 'hidden', timeout: DEFAULT_TIMEOUT_MS });
  const record = extractDeveloperKeyRecord(payload, expectedName);
  requireCondition(record?.id, 'canvas_developer_key_id_missing', 'Canvas Developer Key response omitted its client ID.');
  return record;
}

async function enableDeveloperKey(page, keyName) {
  const row = page.getByRole('row').filter({ hasText: keyName }).first();
  await row.waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
  const toggle = row.getByRole('checkbox', { name: new RegExp(`(?:off|on).*${escapeRegExp(keyName)}`, 'i') }).first();
  const checked = await toggle.isChecked().catch(() => false);
  if (!checked) {
    await toggle.click();
    const confirm = page.getByRole('button', { name: /switch to on|turn on|enable/i }).first();
    if (await confirm.isVisible().catch(() => false)) await confirm.click();
  }
  await waitFor(async () => toggle.isChecked().catch(() => false), DEFAULT_TIMEOUT_MS, 500, 'canvas_developer_key_enable_timeout');
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function createLtiDeveloperKey(page, config) {
  const modal = await openDeveloperKeyModal(page, config.canvasOrigin, config.accountId, 'lti');
  await modal.getByTestId('key-name-input').fill(config.name);
  await modal.getByTestId('owner-email-input').fill(config.ownerEmail);
  const method = modal.getByLabel(/^method$/i);
  await method.click();
  await page.getByRole('option', { name: /^enter url$/i }).click();
  await modal.getByLabel(/^json url$/i).fill(config.registrationConfigUrl);
  const record = await saveDeveloperKey(page, modal, config.name);
  await enableDeveloperKey(page, config.name);
  return { clientId: String(record.id) };
}

async function selectCanvasOauthScopes(modal, scopes) {
  await waitFor(async () => modal.locator('input').evaluateAll(
    (inputs, values) => values.every((value) => inputs.some((input) => input.value === value)),
    scopes,
  ), DEFAULT_TIMEOUT_MS, 500, 'canvas_oauth_scope_controls_missing');
  const selected = await modal.locator('input').evaluateAll((inputs, values) => {
    let count = 0;
    for (const input of inputs) {
      if (values.includes(input.value)) {
        if (!input.checked) input.click();
        if (input.checked) count += 1;
      }
    }
    return count;
  }, scopes);
  requireCondition(selected === scopes.length, 'canvas_oauth_scope_selection_failed', 'Canvas did not select the fixed OAuth scope allowlist.');
}

async function createOauthDeveloperKey(page, config) {
  const modal = await openDeveloperKeyModal(page, config.canvasOrigin, config.accountId, 'api');
  await modal.getByTestId('key-name-input').fill(config.name);
  await modal.getByTestId('owner-email-input').fill(config.ownerEmail);
  await modal.getByTestId('redirect-uris-input').fill(config.redirectUri);
  await selectCanvasOauthScopes(modal, CANVAS_OAUTH_SCOPES);
  const record = await saveDeveloperKey(page, modal, config.name);
  await enableDeveloperKey(page, config.name);
  const secret = String(record.api_key || record.client_secret || '').trim();
  requireCondition(secret.length >= 20, 'canvas_oauth_secret_missing', 'Canvas did not return the OAuth client secret from the stock Developer Key flow.');
  return { clientId: String(record.id), clientSecret: secret };
}

function formAnswers(answerTexts) {
  const result = {};
  answerTexts.forEach((answer, index) => {
    result[`question[answers][${index}][answer_text]`] = answer.text;
    result[`question[answers][${index}][weight]`] = answer.weight;
  });
  return result;
}

function safeList(value) {
  if (Array.isArray(value)) return value;
  if (Array.isArray(value?.items)) return value.items;
  return [];
}

async function selectProductionBadgeTemplates(marty, organizationId) {
  const explicitApplicationId = String(process.env.CANVAS_OSS_APPLICATION_TEMPLATE_ID || '').trim();
  const explicitCredentialId = String(process.env.CANVAS_OSS_CREDENTIAL_TEMPLATE_ID || '').trim();
  const applications = safeList(await marty.get(`/v1/application-templates?organization_id=${encodeURIComponent(organizationId)}`));
  const credentials = safeList(await marty.get(`/v1/credential-templates?organization_id=${encodeURIComponent(organizationId)}`));
  const credentialById = new Map(credentials.map((item) => [String(item.id), item]));
  const candidates = applications.filter((application) => {
    if (String(application.status || '').toUpperCase() !== 'ACTIVE') return false;
    if (explicitApplicationId && String(application.id) !== explicitApplicationId) return false;
    const credential = credentialById.get(String(application.credential_template_id || ''));
    if (!credential || String(credential.status || '').toUpperCase() !== 'ACTIVE') return false;
    if (explicitCredentialId && String(credential.id) !== explicitCredentialId) return false;
    const descriptor = [credential.name, credential.credential_type, credential.vct]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();
    return /open.?badge|badge|achievement/.test(descriptor);
  });
  requireCondition(candidates.length === 1, 'badge_template_selection_ambiguous', 'Exactly one active Open Badge application/template pair must be selected for the portability lane.');
  const application = candidates[0];
  const credential = credentialById.get(String(application.credential_template_id));
  return { application, credential };
}

async function observePipelinePrerequisites(ledger, martyOrigin, canvasOrigin, markActive = () => {}) {
  markActive('upstream_source_and_image_provenance');
  const artifactRoot = path.resolve('tests/artifacts/canvas-oss-portability');
  const image = readJsonFile(path.join(artifactRoot, 'image', 'canvas-oss-image-manifest.json'), 'image_manifest_unavailable');
  requireCondition(
    image.source_repository === 'https://github.com/instructure/canvas-lms.git'
      && image.source_modified === false
      && /^[0-9a-f]{40}$/.test(String(image.source_commit || ''))
      && /^sha256:[0-9a-f]{64}$/.test(String(image.image_digest || '')),
    'image_provenance_invalid',
    'Canvas image provenance does not prove an unmodified pinned upstream source.',
  );
  ledger.pass('upstream_source_and_image_provenance', 'Pinned upstream Canvas source and immutable image digest were verified by the pipeline artifact.');

  markActive('stock_lifecycle_bootstrap_only');
  const bootstrap = readJsonFile(path.join(artifactRoot, 'bootstrap-audit.json'), 'bootstrap_audit_unavailable');
  const counters = bootstrap.forbidden_operation_counts || {};
  requireCondition(
    bootstrap.phase === 'pre_start_only'
      && bootstrap.web_started_after_bootstrap === true
      && Object.values(counters).every((value) => value === 0),
    'bootstrap_audit_invalid',
    'Canvas bootstrap audit did not prove a stock pre-start-only lifecycle.',
  );
  ledger.pass('stock_lifecycle_bootstrap_only', 'Only the reviewed stock Canvas lifecycle commands ran before web startup; forbidden counters are zero.');

  markActive('beta_release_bound_and_healthy');
  const runtime = readJsonFile(path.join(artifactRoot, 'runtime-context.json'), 'runtime_context_unavailable');
  requireCondition(runtime.origin === martyOrigin && /^[0-9a-f]{40}$/.test(String(runtime.source_id || '')), 'runtime_context_invalid', 'The beta runtime is not bound to a reviewed source snapshot.');
  const releaseResponse = await fetchWithTimeout(`${martyOrigin}/.well-known/marty-release`, { headers: { Accept: 'application/json' } });
  const release = await responseJson(releaseResponse, 'beta_health_failed', 'Beta release marker request failed');
  requireCondition(release.marty_ui_sha === runtime.source_id, 'beta_release_drift', 'Beta release marker drifted from the captured runtime context.');
  ledger.pass('beta_release_bound_and_healthy', 'The healthy beta release marker matches the reviewed runtime source snapshot.');

  markActive('canvas_public_https_reachable');
  const canvasResponse = await fetchWithTimeout(`${canvasOrigin}/login/canvas`, { headers: { Accept: 'text/html' } });
  requireCondition(canvasResponse.status === 200, 'canvas_public_unreachable', `Public Canvas login returned HTTP ${canvasResponse.status}.`);
  ledger.pass('canvas_public_https_reachable', 'The stock Canvas HTTPS login surface returned HTTP 200 from the reviewed public origin.');
}

async function createCanvasFixtures(adminCanvas, accountId, adminUserId, learnerEmail, learnerPassword, runSuffix) {
  const learner = await adminCanvas.postForm(`/api/v1/accounts/${encodeURIComponent(accountId)}/users`, {
    'user[name]': `Portable Learner ${runSuffix}`,
    'user[short_name]': `Portable Learner ${runSuffix}`,
    'pseudonym[unique_id]': learnerEmail,
    'pseudonym[password]': learnerPassword,
    'pseudonym[send_confirmation]': false,
    'communication_channel[type]': 'email',
    'communication_channel[address]': learnerEmail,
    'communication_channel[skip_confirmation]': true,
  }, [200, 201]);
  requireCondition(learner?.id, 'canvas_learner_create_failed', 'Canvas did not create the learner through its Users API.');

  const course = await adminCanvas.postForm(`/api/v1/accounts/${encodeURIComponent(accountId)}/courses`, {
    'course[name]': `${RUN_NAME_PREFIX} ${runSuffix}`,
    'course[course_code]': `OSS-${runSuffix}`,
    'course[is_public]': false,
  }, [200, 201]);
  requireCondition(course?.id, 'canvas_course_create_failed', 'Canvas did not create the portability course.');

  await adminCanvas.postForm(`/api/v1/courses/${course.id}/enrollments`, {
    'enrollment[user_id]': learner.id,
    'enrollment[type]': 'StudentEnrollment',
    'enrollment[enrollment_state]': 'active',
    'enrollment[notify]': false,
  }, [200, 201]);
  await adminCanvas.postForm(`/api/v1/courses/${course.id}/enrollments`, {
    'enrollment[user_id]': adminUserId,
    'enrollment[type]': 'TeacherEnrollment',
    'enrollment[enrollment_state]': 'active',
    'enrollment[notify]': false,
  }, [200, 201, 409]);

  const assignment = await adminCanvas.postForm(`/api/v1/courses/${course.id}/assignments`, {
    'assignment[name]': `Portable evidence assignment ${runSuffix}`,
    'assignment[description]': 'Submit a short standards portability statement.',
    'assignment[points_possible]': 100,
    'assignment[grading_type]': 'points',
    'assignment[submission_types][]': 'online_text_entry',
    'assignment[published]': true,
  }, [200, 201]);

  const quiz = await adminCanvas.postForm(`/api/v1/courses/${course.id}/quizzes`, {
    'quiz[title]': `Portable Classic Quiz ${runSuffix}`,
    'quiz[description]': 'A stock Classic Quiz used by the portable evidence contract.',
    'quiz[quiz_type]': 'assignment',
    'quiz[points_possible]': 100,
    'quiz[allowed_attempts]': 1,
    'quiz[show_correct_answers]': true,
    'quiz[published]': false,
  }, [200, 201]);
  const question = await adminCanvas.postForm(`/api/v1/courses/${course.id}/quizzes/${quiz.id}/questions`, {
    'question[question_name]': 'Portable standard',
    'question[question_type]': 'multiple_choice_question',
    'question[question_text]': 'Which integration mechanism is portable across unmodified Canvas deployments?',
    'question[points_possible]': 100,
    ...formAnswers([
      { text: 'Standard LTI 1.3 and documented Canvas APIs', weight: 100 },
      { text: 'A private Canvas plugin and database patch', weight: 0 },
    ]),
  }, [200, 201]);
  const correctAnswer = safeList(question?.answers).find((answer) => Number(answer.weight) === 100);
  requireCondition(assignment?.id && quiz?.id && quiz?.assignment_id && question?.id && correctAnswer?.id, 'canvas_activity_create_failed', 'Canvas did not create the stock assignment and Classic Quiz fixtures.');
  await adminCanvas.putForm(`/api/v1/courses/${course.id}/quizzes/${quiz.id}`, {
    'quiz[published]': true,
  }, [200]);

  const module = await adminCanvas.postForm(`/api/v1/courses/${course.id}/modules`, {
    'module[name]': `Portable completion module ${runSuffix}`,
    'module[require_sequential_progress]': false,
    'module[published]': false,
  }, [200, 201]);
  await adminCanvas.postForm(`/api/v1/courses/${course.id}/modules/${module.id}/items`, {
    'module_item[type]': 'Assignment',
    'module_item[content_id]': assignment.id,
    'module_item[completion_requirement][type]': 'must_submit',
  }, [200, 201]);
  await adminCanvas.postForm(`/api/v1/courses/${course.id}/modules/${module.id}/items`, {
    'module_item[type]': 'Quiz',
    'module_item[content_id]': quiz.id,
    'module_item[completion_requirement][type]': 'must_submit',
  }, [200, 201]);
  await adminCanvas.putForm(`/api/v1/courses/${course.id}/modules/${module.id}`, {
    'module[published]': true,
  }, [200]);
  await adminCanvas.putForm(`/api/v1/courses/${course.id}`, { event: 'offer' }, [200]);
  return { learner, course, assignment, quiz, question, correctAnswer, module };
}

async function completeLearnerCanvasWork(learnerCanvas, adminCanvas, fixtures, markActive = () => {}) {
  const { learner, course, assignment, quiz, question, correctAnswer } = fixtures;
  markActive('existing_assignment_submission');
  await learnerCanvas.postForm(`/api/v1/courses/${course.id}/assignments/${assignment.id}/submissions`, {
    'submission[submission_type]': 'online_text_entry',
    'submission[body]': 'Portable standards, documented APIs, and external key management.',
  }, [200, 201]);
  await adminCanvas.putForm(`/api/v1/courses/${course.id}/assignments/${assignment.id}/submissions/${learner.id}`, {
    'submission[posted_grade]': 95,
  }, [200]);

  markActive('classic_quiz_submission');
  const started = await learnerCanvas.postJson(`/api/v1/courses/${course.id}/quizzes/${quiz.id}/submissions`, {}, [200]);
  const quizSubmission = safeList(started?.quiz_submissions)[0] || started?.quiz_submission || started;
  requireCondition(quizSubmission?.id && quizSubmission?.validation_token && quizSubmission?.attempt, 'classic_quiz_start_failed', 'Canvas did not start the Classic Quiz submission.');
  await learnerCanvas.postJson(`/api/v1/quiz_submissions/${quizSubmission.id}/questions`, {
    attempt: quizSubmission.attempt,
    validation_token: quizSubmission.validation_token,
    quiz_questions: [{ id: String(question.id), answer: Number(correctAnswer.id) }],
  }, [200]);
  await learnerCanvas.postJson(`/api/v1/courses/${course.id}/quizzes/${quiz.id}/submissions/${quizSubmission.id}/complete`, {
    attempt: quizSubmission.attempt,
    validation_token: quizSubmission.validation_token,
  }, [200]);

  const nativeSubmission = await waitFor(async () => {
    const current = await adminCanvas.get(`/api/v1/courses/${course.id}/assignments/${assignment.id}/submissions/${learner.id}`);
    return Number(current.score) === 95 && current.submitted_at ? current : null;
  }, DEFAULT_TIMEOUT_MS, 1_000, 'native_assignment_not_authoritative');
  const quizSubmissionRecord = await waitFor(async () => {
    const current = await adminCanvas.get(`/api/v1/courses/${course.id}/assignments/${quiz.assignment_id}/submissions/${learner.id}`);
    return Number(current.score) >= 99 && current.submitted_at ? current : null;
  }, DEFAULT_TIMEOUT_MS, 1_000, 'classic_quiz_not_authoritative');
  return { nativeSubmission, quizSubmissionRecord };
}

async function createProgramBinding(marty, platformId, templates, fixtures, runSuffix) {
  const courseId = String(fixtures.course.id);
  return marty.post(`/v1/integrations/canvas/platforms/${encodeURIComponent(platformId)}/program-bindings`, {
    application_template_id: String(templates.application.id),
    credential_template_id: String(templates.credential.id),
    display_name: `Portable Canvas badge ${runSuffix}`,
    auto_approve_on_evidence: false,
    delivery_mode: 'wallet_only',
    canvas_scope: { course_id: courseId },
    feature_flags: CANVAS_FEATURE_FLAGS,
    evidence_requirements: [
      {
        requirement_id: `ags-${runSuffix}`,
        source: 'ags_result',
        fact_type: 'canvas.assignment_score',
        scope: { course_id: courseId, resource_id: `portable-ags-${runSuffix}` },
        pass_rule: { min_score_percent: 80 },
        required: true,
      },
      {
        requirement_id: `assignment-${runSuffix}`,
        source: 'canvas_rest',
        fact_type: 'canvas.assignment_score',
        scope: { course_id: courseId, activity_id: String(fixtures.assignment.id) },
        pass_rule: { min_score_percent: 80 },
        required: true,
      },
      {
        requirement_id: `quiz-${runSuffix}`,
        source: 'canvas_rest',
        fact_type: 'canvas.quiz_score',
        scope: { course_id: courseId, activity_id: String(fixtures.quiz.assignment_id) },
        pass_rule: { min_score_percent: 80 },
        required: true,
      },
      {
        requirement_id: `module-${runSuffix}`,
        source: 'canvas_rest',
        fact_type: 'canvas.module_completion',
        scope: { course_id: courseId, module_id: String(fixtures.module.id) },
        pass_rule: { completed: true },
        required: true,
      },
      {
        requirement_id: `course-${runSuffix}`,
        source: 'canvas_rest',
        fact_type: 'canvas.course_completion',
        scope: { course_id: courseId },
        pass_rule: { completed: true },
        required: true,
      },
    ],
  }, [200]);
}

async function findNewExternalAssignment(adminCanvas, courseId, previousIds) {
  const assignments = safeList(await adminCanvas.get(`/api/v1/courses/${courseId}/assignments?per_page=100`));
  return assignments.find((assignment) => (
    !previousIds.has(String(assignment.id))
      && safeList(assignment.submission_types).includes('external_tool')
  )) || null;
}

async function runDeepLinkingViaAssignmentUi(page, fixtures, toolName, adminCanvas, previousIds, martyOrigin) {
  await page.goto(`${adminCanvas.origin}/courses/${fixtures.course.id}/assignments/new`, {
    waitUntil: 'domcontentloaded',
    timeout: DEFAULT_TIMEOUT_MS,
  });
  const name = page.locator('#assignment_name').or(page.getByLabel(/assignment name/i)).first();
  await name.fill(`Portable Marty activity ${Date.now().toString(36)}`);
  const submissionSelect = page.locator('#assignment_submission_type').or(page.getByLabel(/submission type/i)).first();
  await submissionSelect.selectOption({ value: 'external_tool' });
  await page.getByRole('button', { name: /^find$/i }).click();
  const chooser = page.getByRole('dialog').filter({ hasText: /external tools/i }).first();
  await chooser.waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
  await chooser.getByText(toolName, { exact: false }).first().click();
  const ltiFrame = await waitFor(() => page.frames().find((frame) => {
    try { return new URL(frame.url()).origin === martyOrigin; } catch { return false; }
  }), DEFAULT_TIMEOUT_MS, 500, 'deep_link_iframe_missing');
  await ltiFrame.getByRole('button', { name: /add marty activity to canvas/i }).click();
  await page.waitForTimeout(1_000);
  await page.getByRole('button', { name: /save\s*&\s*publish|save and publish/i }).click();
  return waitFor(
    () => findNewExternalAssignment(adminCanvas, fixtures.course.id, previousIds),
    DEFAULT_TIMEOUT_MS,
    1_000,
    'deep_link_assignment_missing',
  );
}

async function performInstructorDeepLinking(page, adminCanvas, fixtures, toolName, martyOrigin) {
  const before = safeList(await adminCanvas.get(`/api/v1/courses/${fixtures.course.id}/assignments?per_page=100`));
  const previousIds = new Set(before.map((item) => String(item.id)));
  // The portability claim must exercise the installed stock Canvas chooser and
  // assignment UI. An API-generated launch cannot substitute for instructor
  // adoption behavior in the full gate.
  const assignment = await runDeepLinkingViaAssignmentUi(
    page,
    fixtures,
    toolName,
    adminCanvas,
    previousIds,
    martyOrigin,
  );
  if (assignment?.id) {
    await adminCanvas.putForm(`/api/v1/courses/${fixtures.course.id}/assignments/${assignment.id}`, {
      'assignment[published]': true,
      'assignment[points_possible]': 100,
    }, [200]);
  }
  return assignment;
}

async function launchStaffResource(page, adminCanvas, fixtures, externalAssignment, martyOrigin) {
  await page.goto(`${adminCanvas.origin}/courses/${fixtures.course.id}/assignments`, {
    waitUntil: 'domcontentloaded',
    timeout: DEFAULT_TIMEOUT_MS,
  });
  const assignmentName = String(externalAssignment?.name || externalAssignment?.title || '').trim();
  requireCondition(assignmentName, 'canvas_staff_assignment_name_missing', 'The Deep Linked Canvas assignment has no instructor-visible name.');
  await page.getByRole('link', { name: assignmentName, exact: true }).first().click();
  await page.waitForURL(
    (url) => url.origin === adminCanvas.origin && url.pathname.includes(`/assignments/${externalAssignment.id}`),
    { timeout: DEFAULT_TIMEOUT_MS },
  );
  const launchControl = page
    .getByRole('link', { name: /load .* in a new window|open .* in a new window|launch external tool/i })
    .or(page.getByRole('button', { name: /load .* in a new window|open .* in a new window|launch external tool/i }))
    .first();
  await launchControl.waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
  const popupPromise = page.context().waitForEvent('page', { timeout: DEFAULT_TIMEOUT_MS });
  await launchControl.click();
  const launchedPage = await popupPromise;
  await launchedPage.waitForURL((url) => url.origin === martyOrigin, { timeout: DEFAULT_TIMEOUT_MS });
  await launchedPage.waitForLoadState('domcontentloaded', { timeout: DEFAULT_TIMEOUT_MS });
  await launchedPage.getByTestId('canvas-lti-login-page').waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
  await launchedPage.getByText(/Canvas launch verified/i).waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
  await launchedPage.close();
}

function validateReadinessSnapshot(snapshot, { requireActive = false } = {}) {
  requireCondition(snapshot?.ready === true && snapshot?.valid === true, 'binding_readiness_blocked', 'Canvas binding did not report a valid ready snapshot.');
  requireCondition(Number.isInteger(snapshot?.config_version) && snapshot.config_version >= 1, 'binding_readiness_version_invalid', 'Canvas binding readiness omitted its configuration version.');
  requireCondition(Number.isFinite(Date.parse(snapshot?.evaluated_at || '')), 'binding_readiness_timestamp_invalid', 'Canvas binding readiness omitted its evaluation timestamp.');
  if (requireActive) {
    requireCondition(snapshot?.active === true, 'binding_activation_not_active', 'Canvas binding activation did not return active=true.');
  }

  const checks = safeList(snapshot?.checks);
  const byCode = new Map();
  for (const check of checks) {
    const code = String(check?.code || '');
    requireCondition(code && !byCode.has(code), 'binding_readiness_check_duplicate', 'Canvas binding readiness returned a missing or duplicate check code.');
    byCode.set(code, check);
    if (check?.blocking === true) {
      requireCondition(check.status === 'ready', 'binding_readiness_check_failed', `Blocking Canvas readiness check ${code} is not ready.`);
    }
  }
  for (const code of BLOCKING_READINESS_CHECK_CODES) {
    const check = byCode.get(code);
    requireCondition(check?.blocking === true, 'binding_readiness_check_missing', `Blocking Canvas readiness check ${code} is missing.`);
    requireCondition(check.status === 'ready', 'binding_readiness_check_failed', `Blocking Canvas readiness check ${code} is not ready.`);
    requireCondition(String(check.component || '').trim(), 'binding_readiness_check_invalid', `Blocking Canvas readiness check ${code} omitted its component.`);
    requireCondition(Number.isFinite(Date.parse(check.timestamp || '')), 'binding_readiness_check_invalid', `Blocking Canvas readiness check ${code} omitted its timestamp.`);
  }
  return snapshot;
}

function validateAuthoritativeEvidenceHeads(facts, requirements) {
  const canvasFacts = safeList(facts).filter((fact) => fact?.provider === 'canvas');
  const supersededIds = new Set(
    canvasFacts.map((fact) => String(fact?.superseded_fact_id || '')).filter(Boolean),
  );
  const heads = canvasFacts.filter((fact) => !supersededIds.has(String(fact?.id || '')));
  const expected = safeList(requirements);
  requireCondition(heads.length === expected.length, 'authoritative_evidence_head_count', 'The current Canvas evidence-head count does not match the typed requirements.');

  for (const requirement of expected) {
    const matches = heads.filter((fact) => fact?.requirement_id === requirement?.requirement_id);
    requireCondition(matches.length === 1, 'authoritative_evidence_head_ambiguous', 'A typed Canvas requirement does not have exactly one current evidence head.');
    const fact = matches[0];
    requireCondition(fact.fact_type === requirement.fact_type, 'authoritative_evidence_fact_type_mismatch', 'A current Canvas evidence head has the wrong fact type.');
    requireCondition(fact.source?.source === requirement.source, 'authoritative_evidence_source_mismatch', 'A current Canvas evidence head has the wrong authoritative source.');
    requireCondition(fact.verification?.status === 'VERIFIED', 'authoritative_evidence_unverified', 'A current Canvas evidence head is not VERIFIED.');
    for (const field of ['logical_key', 'source_revision', 'payload_hash']) {
      requireCondition(/^[0-9a-f]{64}$/.test(String(fact[field] || '')), 'authoritative_evidence_revision_invalid', `A current Canvas evidence head has an invalid ${field}.`);
    }
    requireCondition(Number.isFinite(Date.parse(fact.observed_at || '')), 'authoritative_evidence_timestamp_invalid', 'A current Canvas evidence head omitted observed_at.');
    requireCondition(Number.isFinite(Date.parse(fact.effective_at || '')), 'authoritative_evidence_timestamp_invalid', 'A current Canvas evidence head omitted effective_at.');
    if (requirement.source === 'ags_result') {
      requireCondition(
        fact.scope?.line_item_url === requirement.scope?.line_item_url,
        'authoritative_ags_line_item_mismatch',
        'The AGS evidence head is not bound to the exact verified line item.',
      );
    }
  }
  return heads;
}

async function validateAndActivateBinding(marty, bindingId) {
  const deadline = Date.now() + READINESS_TIMEOUT_MS;
  let validation = null;
  while (Date.now() < deadline) {
    validation = await marty.post(`/v1/integrations/canvas/program-bindings/${encodeURIComponent(bindingId)}/validate`, {}, [200]);
    if (validation?.ready === true) break;
    await sleep(2_000);
  }
  if (!validation?.ready) {
    const codes = safeList(validation?.checks)
      .filter((check) => check.blocking && !['ready', 'not_applicable'].includes(check.status))
      .map((check) => String(check.code || 'unknown'))
      .slice(0, 8)
      .join(',');
    fail('binding_readiness_blocked', `Canvas binding readiness is blocked by: ${codes || 'unknown'}.`);
  }
  validateReadinessSnapshot(validation);
  const activation = await marty.post(`/v1/integrations/canvas/program-bindings/${encodeURIComponent(bindingId)}/activate`, {}, [200]);
  validateReadinessSnapshot(activation, { requireActive: true });
  requireCondition(activation.config_version === validation.config_version, 'binding_readiness_version_changed', 'Canvas binding configuration changed between validation and activation.');
  return { validation, activation };
}

async function waitForJob(marty, jobId) {
  return waitFor(async () => {
    const job = await marty.get(`/v1/integrations/canvas/canvas-sync-jobs/${encodeURIComponent(jobId)}`);
    if (job.status === 'succeeded') return job;
    if (['failed', 'cancelled', 'dead_letter'].includes(String(job.status))) {
      fail('canvas_sync_job_failed', `Canvas synchronization ended in ${job.status}.`);
    }
    return null;
  }, JOB_TIMEOUT_MS, 1_500, 'canvas_sync_job_timeout');
}

async function waitForLatestRosterJob(marty, organizationId, bindingId, afterIso) {
  return waitFor(async () => {
    const jobs = safeList(await marty.get(
      `/v1/integrations/canvas/canvas-sync-jobs?organization_id=${encodeURIComponent(organizationId)}&binding_id=${encodeURIComponent(bindingId)}&limit=100`,
    ));
    const job = jobs.find((item) => (
      item.target_type === 'background_roster'
        && Date.parse(item.created_at || 0) >= Date.parse(afterIso || 0)
    ));
    if (!job) return null;
    return waitForJob(marty, job.id);
  }, JOB_TIMEOUT_MS, 1_500, 'canvas_roster_job_timeout');
}

async function showVideoStep(page, title, detail) {
  await page.evaluate(({ titleText, detailText }) => {
    let overlay = document.getElementById('canvas-oss-contract-step');
    if (!overlay) {
      overlay = document.createElement('section');
      overlay.id = 'canvas-oss-contract-step';
      overlay.setAttribute('aria-label', 'Portability demonstration step');
      document.body.appendChild(overlay);
    }
    overlay.replaceChildren();
    const eyebrow = document.createElement('div');
    eyebrow.textContent = 'Unmodified Canvas portability';
    const titleNode = document.createElement('div');
    titleNode.textContent = titleText;
    const detailNode = document.createElement('div');
    detailNode.textContent = detailText;
    Object.assign(eyebrow.style, { fontSize: '12px', fontWeight: '800', letterSpacing: '0.08em', textTransform: 'uppercase', color: '#bfdbfe' });
    Object.assign(titleNode.style, { marginTop: '6px', fontSize: '25px', fontWeight: '800', lineHeight: '1.15' });
    Object.assign(detailNode.style, { marginTop: '8px', fontSize: '15px', lineHeight: '1.35', color: '#e0f2fe' });
    overlay.append(eyebrow, titleNode, detailNode);
    Object.assign(overlay.style, {
      position: 'fixed', zIndex: '2147483647', left: '22px', bottom: '22px', maxWidth: '600px',
      padding: '17px 21px', borderRadius: '12px', background: 'rgba(7, 35, 64, 0.94)', color: 'white',
      boxShadow: '0 16px 42px rgba(0,0,0,0.3)', fontFamily: 'Arial, sans-serif', pointerEvents: 'none',
    });
  }, { titleText: title, detailText: detail });
  await page.waitForTimeout(1_200);
}

async function copyCookies(sourceContext, destinationContext) {
  const cookies = await sourceContext.cookies();
  await destinationContext.addCookies(cookies);
}

async function launchLearnerResource(page, learnerCanvas, fixtures, externalAssignment, martyOrigin) {
  // Require the learner-visible stock Canvas assignment path. The external
  // tool launch APIs cannot satisfy the portability/adoption case.
  await page.goto(`${learnerCanvas.origin}/courses/${fixtures.course.id}/assignments`, {
    waitUntil: 'domcontentloaded',
    timeout: DEFAULT_TIMEOUT_MS,
  });
  const assignmentName = String(externalAssignment?.name || externalAssignment?.title || '').trim();
  requireCondition(assignmentName, 'canvas_assignment_name_missing', 'The Deep Linked Canvas assignment has no learner-visible name.');
  await page.getByRole('link', { name: assignmentName, exact: true }).first().click();
  await page.waitForURL(
    (url) => url.origin === learnerCanvas.origin && url.pathname.includes(`/assignments/${externalAssignment.id}`),
    { timeout: DEFAULT_TIMEOUT_MS },
  );

  const launchControl = page
    .getByRole('link', { name: /load .* in a new window|open .* in a new window|launch external tool/i })
    .or(page.getByRole('button', { name: /load .* in a new window|open .* in a new window|launch external tool/i }))
    .first();
  await launchControl.waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
  const popupPromise = page.context().waitForEvent('page', { timeout: DEFAULT_TIMEOUT_MS });
  await launchControl.click();
  const launchedPage = await popupPromise;
  await launchedPage.waitForURL((url) => url.origin === martyOrigin, { timeout: DEFAULT_TIMEOUT_MS });
  await launchedPage.waitForLoadState('domcontentloaded', { timeout: DEFAULT_TIMEOUT_MS });
  requireCondition(new URL(launchedPage.url()).origin === martyOrigin, 'learner_canvas_ui_launch_untrusted', 'The stock Canvas assignment launched outside Marty.');
  await launchedPage.getByTestId('canvas-lti-login-page').waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
  const bootstrapPromise = launchedPage.waitForResponse((response) => (
    response.request().method() === 'POST'
      && new URL(response.url()).pathname.endsWith('/lti/experience-sessions/current/bootstrap')
  ), { timeout: DEFAULT_TIMEOUT_MS });
  await launchedPage.getByTestId('canvas-lti-continue').click();
  const bootstrapResponse = await bootstrapPromise;
  const bootstrap = await responseJson(bootstrapResponse, 'canvas_application_bootstrap_failed', 'Canvas learner application bootstrap failed', [200]);
  await launchedPage.getByTestId('canvas-evidence-sync-panel').waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
  requireCondition(bootstrap?.application_id, 'canvas_application_id_missing', 'Canvas learner bootstrap omitted the application ID.');
  return { bootstrap, page: launchedPage };
}

async function reloadLearnerExperience(page) {
  await page.reload({ waitUntil: 'domcontentloaded', timeout: DEFAULT_TIMEOUT_MS });
  await page.getByTestId('canvas-evidence-sync-panel').waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
}

async function triggerLearnerSync(page, marty) {
  const responsePromise = page.waitForResponse((response) => (
    response.request().method() === 'POST'
      && new URL(response.url()).pathname.endsWith('/lti/experience-sessions/current/evidence-sync')
  ), { timeout: DEFAULT_TIMEOUT_MS });
  await page.getByTestId('canvas-evidence-sync-action').click();
  const response = await responsePromise;
  const body = await responseJson(response, 'learner_evidence_sync_failed', 'Learner Canvas evidence sync request failed', [202]);
  const jobId = body?.sync?.job_id;
  requireCondition(jobId, 'learner_evidence_job_missing', 'Learner Canvas evidence sync omitted its job ID.');
  const job = await waitForJob(marty, jobId);
  await page.waitForTimeout(2_500);
  return { body, job };
}

async function waitForCandidate(marty, organizationId, bindingId, status) {
  return waitFor(async () => {
    const candidates = safeList(await marty.get(
      `/v1/integrations/canvas/canvas-award-candidates?organization_id=${encodeURIComponent(organizationId)}&binding_id=${encodeURIComponent(bindingId)}&status=${encodeURIComponent(status)}&limit=100`,
    ));
    return candidates.find((item) => item.status === status) || null;
  }, JOB_TIMEOUT_MS, 1_500, 'canvas_award_candidate_timeout');
}

function parseCredentialOfferUri(uri) {
  const normalized = String(uri || '').trim();
  requireCondition(normalized, 'credential_offer_missing', 'The claim response omitted its OID4VCI offer.');
  let url;
  try {
    url = new URL(normalized);
  } catch {
    fail('credential_offer_invalid', 'The claim response returned an invalid OID4VCI offer URI.');
  }
  requireCondition(url.protocol === 'openid-credential-offer:', 'credential_offer_invalid', 'The claim response did not use the OID4VCI offer scheme.');
  const inline = url.searchParams.get('credential_offer');
  requireCondition(inline, 'credential_offer_reference_unsupported', 'The contract requires an inline OID4VCI offer for deterministic verification.');
  let offer;
  try {
    offer = JSON.parse(inline);
  } catch {
    fail('credential_offer_invalid', 'The inline OID4VCI offer is not valid JSON.');
  }
  const grant = offer?.grants?.['urn:ietf:params:oauth:grant-type:pre-authorized_code'];
  requireCondition(offer?.credential_issuer && safeList(offer?.credential_configuration_ids).length === 1 && grant?.['pre-authorized_code'], 'credential_offer_incomplete', 'The OID4VCI offer is missing required pre-authorized flow fields.');
  return {
    issuer: String(offer.credential_issuer),
    configurationId: String(offer.credential_configuration_ids[0]),
    preAuthorizedCode: String(grant['pre-authorized_code']),
  };
}

function base64urlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function decodeJwtPart(part) {
  try {
    return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
  } catch {
    fail('jwt_decode_failed', 'A signed JWT component could not be decoded.');
  }
}

function publicHolderJwk(publicKey) {
  const jwk = publicKey.export({ format: 'jwk' });
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
}

function createHolderProof(privateKey, publicJwk, issuer, nonce) {
  const did = `did:jwk:${Buffer.from(JSON.stringify(publicJwk)).toString('base64url')}`;
  const header = { typ: 'openid4vci-proof+jwt', alg: 'ES256', jwk: publicJwk };
  const payload = {
    iss: did,
    sub: did,
    aud: issuer,
    iat: Math.floor(Date.now() / 1000),
    nonce,
    jti: crypto.randomUUID(),
  };
  const input = `${base64urlJson(header)}.${base64urlJson(payload)}`;
  const signature = crypto.sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  return { did, jwt: `${input}.${signature.toString('base64url')}` };
}

function didWebResolutionUrl(did) {
  const prefix = 'did:web:';
  requireCondition(String(did).startsWith(prefix), 'issuer_did_method_unsupported', 'The contract verifier currently requires a published did:web issuer.');
  const segments = String(did).slice(prefix.length).split(':').map((segment) => decodeURIComponent(segment));
  requireCondition(segments.length >= 1 && segments.every(Boolean), 'issuer_did_invalid', 'The issued credential contains an invalid did:web issuer.');
  const authority = segments[0];
  const pathName = segments.length === 1
    ? '/.well-known/did.json'
    : `/${segments.slice(1).map(encodeURIComponent).join('/')}/did.json`;
  return `https://${authority}${pathName}`;
}

function verificationMethodFromDidDocument(document, kid) {
  const methods = safeList(document?.verificationMethod);
  const assertionIds = new Set(safeList(document?.assertionMethod).map((entry) => (
    typeof entry === 'string' ? entry : entry?.id
  )).filter(Boolean));
  const method = methods.find((entry) => entry?.id === kid)
    || safeList(document?.assertionMethod).find((entry) => typeof entry === 'object' && entry?.id === kid);
  requireCondition(method?.publicKeyJwk && (assertionIds.has(kid) || safeList(document?.assertionMethod).some((entry) => entry?.id === kid)), 'issuer_verification_method_missing', 'The credential signing key is not a published DID assertion method.');
  return method;
}

function verifyCompactJws(compact, publicJwk) {
  const parts = String(compact).split('.');
  requireCondition(parts.length === 3, 'credential_jws_invalid', 'The issued SD-JWT issuer-signed component is not a compact JWS.');
  const header = decodeJwtPart(parts[0]);
  const payload = decodeJwtPart(parts[1]);
  const key = crypto.createPublicKey({ key: publicJwk, format: 'jwk' });
  const data = Buffer.from(`${parts[0]}.${parts[1]}`);
  const signature = Buffer.from(parts[2], 'base64url');
  let verified = false;
  if (header.alg === 'ES256') {
    verified = crypto.verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, signature);
  } else if (header.alg === 'RS256') {
    verified = crypto.verify('RSA-SHA256', data, key, signature);
  } else {
    fail('credential_algorithm_unsupported', `Unsupported credential JWS algorithm ${String(header.alg || 'missing')}.`);
  }
  requireCondition(verified, 'credential_signature_invalid', 'The issued credential signature did not verify against the published DID key.');
  return { header, payload };
}

async function receiveAndVerifyCredential(offerUri, expectedTemplate, expectedIssuerOrigin = DEFAULT_MARTY_ORIGIN) {
  const offer = parseCredentialOfferUri(offerUri);
  const issuerUrl = new URL(offer.issuer);
  requireCondition(issuerUrl.protocol === 'https:' && issuerUrl.origin === expectedIssuerOrigin, 'credential_issuer_unpinned', 'The OID4VCI issuer is outside the reviewed beta origin.');
  const metadataUrl = `${issuerUrl.origin}/.well-known/openid-credential-issuer${issuerUrl.pathname}`;
  const metadataResponse = await fetchWithTimeout(metadataUrl, { headers: { Accept: 'application/json' } });
  const metadata = await responseJson(metadataResponse, 'credential_metadata_failed', 'OID4VCI issuer metadata request failed');
  const tokenEndpoint = new URL(String(metadata.token_endpoint || ''));
  const credentialEndpoint = new URL(String(metadata.credential_endpoint || ''));
  requireCondition(tokenEndpoint.origin === issuerUrl.origin && credentialEndpoint.origin === issuerUrl.origin, 'credential_endpoint_unpinned', 'OID4VCI metadata returned an endpoint outside the issuer origin.');

  const tokenResponse = await fetchWithTimeout(tokenEndpoint, {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      'pre-authorized_code': offer.preAuthorizedCode,
    }).toString(),
  });
  const token = await responseJson(tokenResponse, 'credential_token_exchange_failed', 'OID4VCI token exchange failed');
  requireCondition(token?.access_token && (token?.c_nonce || token?.nonce), 'credential_token_response_incomplete', 'OID4VCI token response omitted proof binding fields.');

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const holderJwk = publicHolderJwk(publicKey);
  const proof = createHolderProof(privateKey, holderJwk, offer.issuer, token.c_nonce || token.nonce);
  const credentialResponse = await fetchWithTimeout(credentialEndpoint, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token.access_token}`,
    },
    body: JSON.stringify({
      credential_configuration_id: offer.configurationId,
      proofs: { jwt: [proof.jwt] },
    }),
  }, JOB_TIMEOUT_MS);
  const issued = await responseJson(credentialResponse, 'credential_issue_failed', 'OID4VCI credential request failed');
  const credential = String(issued?.credential || issued?.credentials?.[0]?.credential || issued?.credentials?.[0] || '');
  requireCondition(credential, 'credential_payload_missing', 'OID4VCI credential response omitted the signed credential.');

  const issuerJws = credential.split('~')[0];
  const predecoded = verifyCompactJwsStructure(issuerJws);
  const didUrl = didWebResolutionUrl(predecoded.payload.iss);
  const didResponse = await fetchWithTimeout(didUrl, { headers: { Accept: 'application/did+json, application/json' } });
  const didDocument = await responseJson(didResponse, 'issuer_did_resolution_failed', 'Issuer DID document request failed');
  requireCondition(didDocument?.id === predecoded.payload.iss, 'issuer_did_document_mismatch', 'The resolved DID document does not match the credential issuer.');
  const method = verificationMethodFromDidDocument(didDocument, predecoded.header.kid);
  const verified = verifyCompactJws(issuerJws, method.publicKeyJwk);
  requireCondition(
    verified.payload.vct === expectedTemplate.vct
      || String(verified.payload.vct || '').includes(String(expectedTemplate.credential_type || '')),
    'open_badge_type_mismatch',
    'The KMS-signed credential does not match the selected Open Badge template.',
  );
  const cnf = verified.payload.cnf?.jwk || {};
  const holderJwkMatches = ['kty', 'crv', 'x', 'y'].every((key) => cnf[key] === holderJwk[key]);
  const holderBound = verified.payload.sub === proof.did || holderJwkMatches;
  requireCondition(holderBound, 'holder_binding_missing', 'The issued Open Badge is not bound to the wallet proof key.');
  return { credential, header: verified.header, payload: verified.payload, holderDid: proof.did };
}

function verifyCompactJwsStructure(compact) {
  const parts = String(compact).split('.');
  requireCondition(parts.length === 3, 'credential_jws_invalid', 'The issued credential is not a compact JWS.');
  return { header: decodeJwtPart(parts[0]), payload: decodeJwtPart(parts[1]) };
}

async function createFallbackVideo(browser, destination, message) {
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    recordVideo: { dir: path.dirname(destination), size: { width: 1440, height: 900 } },
  });
  const page = await context.newPage();
  await page.setContent(`<!doctype html><html><body style="margin:0;display:grid;place-items:center;min-height:100vh;background:#071f35;color:white;font-family:Arial,sans-serif"><main style="max-width:850px;padding:48px"><p style="text-transform:uppercase;letter-spacing:.12em;color:#93c5fd;font-weight:700">Canvas OSS portability</p><h1 style="font-size:42px">Standard contract did not complete</h1><p style="font-size:22px;line-height:1.5">${escapeHtml(sanitizeEvidence(message))}</p></main></body></html>`);
  await page.waitForTimeout(1_500);
  const video = page.video();
  await context.close();
  const source = await video.path();
  fs.copyFileSync(source, destination);
  if (path.resolve(source) !== path.resolve(destination)) fs.unlinkSync(source);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[character]);
}

async function finishRecordedVideo(context, page, destination) {
  const video = page.video();
  await context.close();
  const source = await video.path();
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.copyFileSync(source, destination);
  if (path.resolve(source) !== path.resolve(destination)) fs.unlinkSync(source);
}

async function main() {
  let args;
  try {
    args = parseArgs(process.argv);
  } catch (error) {
    process.stderr.write(`Canvas OSS contract arguments failed: ${sanitizeEvidence(error.code || error.message)}\n`);
    return 2;
  }

  let execution;
  try {
    execution = requireComposeExecutionBoundary();
  } catch (error) {
    process.stderr.write(`Canvas OSS contract boundary failed: ${sanitizeEvidence(error.code || error.message)}\n`);
    return 2;
  }

  const ledger = new ObservationLedger(new Date().toISOString(), execution);
  let activeCase = 'upstream_source_and_image_provenance';
  let browser = null;
  let adminContext = null;
  let learnerContext = null;
  let recordedContext = null;
  let recordedPage = null;
  let marty = null;
  let platformId = null;
  let integrationSecretId = null;
  let videoWritten = false;
  let failure = null;

  const markActive = (id) => { activeCase = id; };
  const pass = (id, evidence) => { ledger.pass(id, evidence); };

  try {
    const canvasOrigin = normalizePinnedOrigin(
      process.env.CANVAS_OSS_ORIGIN || DEFAULT_CANVAS_ORIGIN,
      DEFAULT_CANVAS_ORIGIN,
      'Canvas origin',
    );
    const martyOrigin = normalizePinnedOrigin(
      process.env.CANVAS_OSS_MARTY_ORIGIN || DEFAULT_MARTY_ORIGIN,
      DEFAULT_MARTY_ORIGIN,
      'Marty origin',
    );
    const adminEmail = requireSecretFile('CANVAS_OSS_ADMIN_EMAIL');
    const adminPassword = requireSecretFile('CANVAS_OSS_ADMIN_PASSWORD');
    const learnerEmail = requireSecretFile('CANVAS_OSS_LEARNER_EMAIL');
    const learnerPassword = requireSecretFile('CANVAS_OSS_LEARNER_PASSWORD');
    const organizationId = requireEnv('CANVAS_OSS_ORGANIZATION_ID');
    const martyApiKey = requireSecretFile('CANVAS_OSS_MARTY_API_KEY');
    marty = new MartyClient(martyOrigin, martyApiKey);
    const runSuffix = `${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`;

    await observePipelinePrerequisites(ledger, martyOrigin, canvasOrigin, markActive);

    browser = await chromium.launch({ headless: true });
    adminContext = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const adminPage = await adminContext.newPage();
    await loginCanvas(adminPage, canvasOrigin, adminEmail, adminPassword);
    const adminBearer = await createPersonalAccessToken(adminPage, canvasOrigin, `OSS contract admin ${runSuffix}`);
    const adminCanvas = new CanvasClient(canvasOrigin, adminBearer);
    const accounts = safeList(await adminCanvas.get('/api/v1/accounts?per_page=100'));
    const rootAccount = accounts.find((account) => !account.parent_account_id) || accounts[0];
    requireCondition(rootAccount?.id, 'canvas_root_account_missing', 'Canvas Accounts API did not return a root account.');
    const adminProfile = await adminCanvas.get('/api/v1/users/self/profile');
    requireCondition(adminProfile?.id, 'canvas_admin_profile_missing', 'Canvas Users API did not return the root administrator profile.');

    const templates = await selectProductionBadgeTemplates(marty, organizationId);

    markActive('standard_lti_13_install');
    const platform = await marty.post('/v1/integrations/canvas/platforms', {
      display_name: `${RUN_NAME_PREFIX} ${runSuffix}`,
      canvas_base_url: canvasOrigin,
      enabled: true,
    }, [200]);
    platformId = String(platform?.id || '');
    requireCondition(platformId, 'marty_canvas_platform_missing', 'Marty did not create the organization-owned Canvas draft.');
    requireCondition(String(platform.organization_id) === organizationId, 'marty_canvas_platform_tenant_mismatch', 'Marty created the Canvas draft outside the API key organization.');
    const registration = await marty.get(`/v1/integrations/canvas/platforms/${encodeURIComponent(platformId)}/registration-config`);
    const registrationConfigUrl = String(registration?.installation?.config_url || '');
    requireCondition(registrationConfigUrl.startsWith(`${martyOrigin}/v1/integrations/canvas/lti/config/`), 'lti_registration_url_invalid', 'Marty returned an invalid revocable LTI registration URL.');

    const ltiKeyName = `Marty LTI ${runSuffix}`;
    const ltiKey = await createLtiDeveloperKey(adminPage, {
      canvasOrigin,
      accountId: rootAccount.id,
      ownerEmail: adminEmail,
      name: ltiKeyName,
      registrationConfigUrl,
    });
    const tool = await adminCanvas.postForm(`/api/v1/accounts/${rootAccount.id}/external_tools`, {
      client_id: ltiKey.clientId,
    }, [200, 201]);
    requireCondition(tool?.id && tool?.deployment_id, 'lti_tool_install_failed', 'Canvas External Tools API did not install the LTI 1.3 deployment.');
    await marty.put(`/v1/integrations/canvas/platforms/${encodeURIComponent(platformId)}/lti-installation`, {
      lti_client_id: ltiKey.clientId,
      lti_deployment_id: String(tool.deployment_id),
      revoke_config_token: true,
    }, [200]);
    pass('standard_lti_13_install', 'Stock Canvas Developer Key UI and External Tools API installed the generated LTI 1.3 configuration.');

    markActive('existing_assignment_submission');
    const fixtures = await createCanvasFixtures(
      adminCanvas,
      rootAccount.id,
      adminProfile.id,
      learnerEmail,
      learnerPassword,
      runSuffix,
    );

    learnerContext = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    const learnerSetupPage = await learnerContext.newPage();
    await loginCanvas(learnerSetupPage, canvasOrigin, learnerEmail, learnerPassword);
    const learnerBearer = await createPersonalAccessToken(learnerSetupPage, canvasOrigin, `OSS contract learner ${runSuffix}`);
    const learnerCanvas = new CanvasClient(canvasOrigin, learnerBearer);
    const activityResults = await completeLearnerCanvasWork(learnerCanvas, adminCanvas, fixtures, markActive);
    pass('existing_assignment_submission', 'A learner submission and 95% score are authoritative through the documented Assignment Submissions API.');
    pass('classic_quiz_submission', 'A stock Classic Quiz was answered and its autograded score is authoritative through Assignment Submissions.');

    markActive('canvas_oauth_authorization');
    const oauthKey = await createOauthDeveloperKey(adminPage, {
      canvasOrigin,
      accountId: rootAccount.id,
      ownerEmail: adminEmail,
      name: `Marty OAuth ${runSuffix}`,
      redirectUri: `${martyOrigin}/v1/integrations/canvas/oauth/callback`,
    });
    integrationSecretId = String((await marty.post('/v1/integrations/canvas/integration-secrets', {
      organization_id: organizationId,
      name: `Canvas OAuth ${runSuffix}`,
      provider: 'canvas',
      purpose: 'oauth_client_secret',
      secret_value: oauthKey.clientSecret,
      metadata: { contract: 'canvas_oss_portability' },
      enabled: true,
    }, [200, 201]))?.id || '');
    requireCondition(integrationSecretId, 'marty_oauth_secret_reference_missing', 'Marty did not store the encrypted Canvas OAuth secret reference.');
    const oauthStart = await marty.post(`/v1/integrations/canvas/platforms/${encodeURIComponent(platformId)}/oauth/authorizations`, {
      client_id: oauthKey.clientId,
      client_secret_secret_id: integrationSecretId,
      capabilities: OAUTH_CAPABILITIES,
    }, [200]);
    const oauthUrl = new URL(String(oauthStart?.authorization_url || ''));
    requireCondition(oauthUrl.origin === canvasOrigin, 'canvas_oauth_url_unpinned', 'Marty returned an OAuth authorization URL outside Canvas.');
    await adminPage.goto(oauthUrl.href, { waitUntil: 'domcontentloaded', timeout: DEFAULT_TIMEOUT_MS });
    const authorize = adminPage.getByRole('button', { name: /^authorize$/i }).or(adminPage.locator('button[type="submit"], input[type="submit"]')).first();
    await authorize.click();
    await adminPage.waitForURL((url) => url.origin === martyOrigin && url.searchParams.get('outcome') === 'success', { timeout: DEFAULT_TIMEOUT_MS });
    const connectedPlatform = await marty.get(`/v1/integrations/canvas/platforms/${encodeURIComponent(platformId)}`);
    requireCondition(connectedPlatform?.connection_config?.oauth_status === 'connected', 'canvas_oauth_not_connected', 'Canvas OAuth callback did not publish a connected organization-scoped connection.');
    pass('canvas_oauth_authorization', 'A stock scoped Canvas API Developer Key completed the capability-derived OAuth flow.');

    const binding = await createProgramBinding(marty, platformId, templates, fixtures, runSuffix);
    requireCondition(binding?.id, 'canvas_binding_create_failed', 'Marty did not create the typed Canvas program binding.');

    markActive('instructor_deep_linking');
    const externalAssignment = await performInstructorDeepLinking(adminPage, adminCanvas, fixtures, ltiKeyName, martyOrigin);
    requireCondition(externalAssignment?.id, 'canvas_deep_link_assignment_missing', 'Canvas did not create an external-tool assignment from the standard Deep Linking response.');
    pass('instructor_deep_linking', 'An instructor Deep Linking launch created a Marty-bound Canvas assignment without Canvas customization.');

    markActive('marty_bound_ags_result');
    await launchStaffResource(adminPage, adminCanvas, fixtures, externalAssignment, martyOrigin);
    const pinnedBinding = await marty.get(`/v1/integrations/canvas/program-bindings/${encodeURIComponent(binding.id)}`);
    const agsRequirement = safeList(pinnedBinding?.evidence_requirements).find((item) => item.source === 'ags_result');
    requireCondition(agsRequirement?.scope?.line_item_url, 'ags_line_item_not_pinned', 'The verified Canvas resource launch did not pin its AGS line item.');
    await adminCanvas.putForm(`/api/v1/courses/${fixtures.course.id}/assignments/${externalAssignment.id}/submissions/${fixtures.learner.id}`, {
      'submission[posted_grade]': 95,
    }, [200]);

    markActive('standard_lti_13_install');
    const activationStartedAt = new Date().toISOString();
    await validateAndActivateBinding(marty, binding.id);
    pass('standard_lti_13_install', `Stock Canvas installed LTI 1.3 and all ${BLOCKING_READINESS_CHECK_CODES.length} production blocking readiness checks passed.`);

    markActive('nrps_roster');
    await waitForLatestRosterJob(marty, organizationId, binding.id, activationStartedAt);

    markActive('module_completion');
    await waitFor(async () => {
      const moduleState = await adminCanvas.get(`/api/v1/courses/${fixtures.course.id}/modules/${fixtures.module.id}?student_id=${fixtures.learner.id}`);
      return moduleState?.state === 'completed' ? moduleState : null;
    }, DEFAULT_TIMEOUT_MS, 1_000, 'module_completion_not_observed');
    pass('module_completion', 'Canvas module lookup with student_id reported the required module completed.');

    markActive('course_completion');
    await waitFor(async () => {
      const progress = await adminCanvas.get(`/api/v1/courses/${fixtures.course.id}/users/${fixtures.learner.id}/progress`);
      const complete = progress?.completed_at
        || (Number(progress?.requirement_count) > 0
          && Number(progress?.requirement_completed_count) === Number(progress?.requirement_count));
      return complete ? progress : null;
    }, DEFAULT_TIMEOUT_MS, 1_000, 'course_completion_not_observed');
    pass('course_completion', 'Canvas CourseProgress reported all non-empty module requirements completed.');

    recordedContext = await browser.newContext({
      viewport: { width: 1440, height: 900 },
      recordVideo: { dir: path.dirname(args.video), size: { width: 1440, height: 900 } },
    });
    await copyCookies(learnerContext, recordedContext);
    recordedPage = await recordedContext.newPage();
    await recordedPage.goto(`${canvasOrigin}/courses/${fixtures.course.id}/grades`, { waitUntil: 'domcontentloaded', timeout: DEFAULT_TIMEOUT_MS });
    await showVideoStep(recordedPage, 'Canvas evidence is complete', 'The learner completed a native assignment, a Classic Quiz, and the module in stock Canvas.');

    markActive('learner_resource_launch');
    const firstLaunch = await launchLearnerResource(recordedPage, learnerCanvas, fixtures, externalAssignment, martyOrigin);
    recordedPage = firstLaunch.page;
    const firstBootstrap = firstLaunch.bootstrap;
    pass('learner_resource_launch', 'The enrolled learner launched the Deep Linked resource through standard LTI 1.3 and reached ElevenID.');
    await showVideoStep(recordedPage, 'Portable learner launch verified', 'Canvas supplied the signed learner, course, and resource context; no email identity match was used.');

    const secondActivationAt = new Date().toISOString();
    markActive('nrps_roster');
    await validateAndActivateBinding(marty, binding.id);
    const rosterJob = await waitForLatestRosterJob(marty, organizationId, binding.id, secondActivationAt);
    markActive('background_pending_claim_unsigned');
    const pendingCandidate = await waitForCandidate(marty, organizationId, binding.id, 'pending_claim');
    requireCondition(Number(rosterJob?.result?.pending_claim || 0) >= 1 || pendingCandidate, 'background_candidate_not_pending', 'Background roster synchronization did not produce an unsigned pending claim.');
    pass('nrps_roster', 'NRPS plus the verified numeric Canvas identity joined the learner without email matching.');

    const secondLaunch = await launchLearnerResource(recordedPage, learnerCanvas, fixtures, externalAssignment, martyOrigin);
    recordedPage = secondLaunch.page;
    const secondBootstrap = secondLaunch.bootstrap;
    requireCondition(secondBootstrap.application_id === firstBootstrap.application_id, 'canvas_application_duplicate', 'A repeat learner launch created a duplicate application.');
    await recordedPage.getByTestId('canvas-pending-claim').waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
    const statusResponse = await recordedPage.evaluate(async () => {
      const serialized = sessionStorage.getItem('elevenid.canvas-lti.session.v1');
      const session = serialized ? JSON.parse(serialized) : null;
      const response = await fetch('/v1/integrations/canvas/lti/experience-sessions/current/evidence-status', {
        headers: { Authorization: `Bearer ${session?.token || ''}` },
        cache: 'no-store',
      });
      return response.ok ? response.json() : null;
    });
    requireCondition(statusResponse?.claim?.status === 'pending_claim' && statusResponse?.claim?.unsigned === true, 'background_claim_not_unsigned', 'Learner status did not expose an unsigned pending claim.');
    pass('background_pending_claim_unsigned', 'Background evaluation produced pending_claim with unsigned=true; no credential existed before wallet claim.');
    await showVideoStep(recordedPage, 'Background award remains unsigned', 'Roster evaluation created a pending claim, but signing waits for learner wallet claim.');

    markActive('authoritative_evidence_sync');
    const initialSync = await triggerLearnerSync(recordedPage, marty);
    requireCondition(Number(initialSync.job?.result?.requirements_checked) === 5 && initialSync.job?.result?.policy_allowed === true, 'authoritative_sync_incomplete', 'Marty did not verify every typed Canvas requirement.');
    const evidenceFacts = safeList(await marty.get(
      `/v1/organizations/${encodeURIComponent(organizationId)}/applicants/${encodeURIComponent(firstBootstrap.application_id)}/evidence-facts`,
    ));
    const currentHeads = validateAuthoritativeEvidenceHeads(
      evidenceFacts,
      pinnedBinding.evidence_requirements,
    );
    await recordedPage.getByTestId('canvas-authoritative-evidence-verified').waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
    await recordedPage.getByTestId('canvas-evidence-policy-permitted').waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
    requireCondition(currentHeads.length === 5, 'authoritative_sync_incomplete', 'The durable worker did not publish exactly five current authoritative evidence heads.');
    pass('authoritative_evidence_sync', 'The durable worker published five exact VERIFIED requirement heads with revision hashes and policy permitted them.');
    pass('marty_bound_ags_result', 'The exact pinned Marty line item contributed one of five verified authoritative requirements through AGS Results.');
    await showVideoStep(recordedPage, 'Authoritative evidence verified', 'AGS Results and Canvas REST facts were synchronized by the durable worker; policy permits the badge.');

    markActive('pre_issuance_grade_correction');
    await adminCanvas.putForm(`/api/v1/courses/${fixtures.course.id}/assignments/${fixtures.assignment.id}/submissions/${fixtures.learner.id}`, {
      'submission[posted_grade]': 40,
    }, [200]);
    const deniedSync = await triggerLearnerSync(recordedPage, marty);
    requireCondition(deniedSync.job?.result?.policy_allowed === false, 'pre_issuance_downgrade_not_applied', 'A pre-issuance grade downgrade did not change the current policy decision to deny.');
    await recordedPage.getByTestId('canvas-evidence-policy-not-permitted').waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
    await adminCanvas.putForm(`/api/v1/courses/${fixtures.course.id}/assignments/${fixtures.assignment.id}/submissions/${fixtures.learner.id}`, {
      'submission[posted_grade]': 95,
    }, [200]);
    const recoveredSync = await triggerLearnerSync(recordedPage, marty);
    requireCondition(recoveredSync.job?.result?.policy_allowed === true, 'pre_issuance_recovery_not_applied', 'The corrected pre-issuance score did not restore the current permit decision.');
    pass('pre_issuance_grade_correction', 'A 95 to 40 to 95 score revision denied then restored policy before issuance; current evidence heads won.');

    const approvalPath = `/v1/integrations/canvas/applications/${encodeURIComponent(firstBootstrap.application_id)}/approve`;
    const approvalBody = {
      review_notes: 'Approved by the Canvas OSS portability contract after authoritative policy permit.',
    };
    const concurrentApprovals = await Promise.all([
      marty.post(approvalPath, approvalBody, [200, 409]),
      marty.post(approvalPath, approvalBody, [200, 409]),
    ]);
    const reservedTransactionIds = concurrentApprovals
      .map((result) => String(result?.issuance_transaction_id || '').trim())
      .filter(Boolean);
    requireCondition(reservedTransactionIds.length >= 1, 'canvas_approval_reservation_missing', 'Concurrent Canvas approvals did not reserve a claim transaction.');
    requireCondition(new Set(reservedTransactionIds).size === 1, 'duplicate_canvas_claim_transaction', 'Concurrent Canvas approvals reserved different claim transactions.');
    await reloadLearnerExperience(recordedPage);
    await recordedPage.getByTestId('canvas-ready-to-claim').waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });

    const preClaimCredentials = safeList(await marty.get(`/v1/issued-credentials?organization_id=${encodeURIComponent(organizationId)}`))
      .filter((record) => String(record.application_id) === String(firstBootstrap.application_id));
    requireCondition(preClaimCredentials.length === 0, 'background_claim_signed_early', 'A credential existed before the learner wallet claim.');

    markActive('kms_open_badge_claim_and_verify');
    const claimResponsePromise = recordedPage.waitForResponse((response) => (
      response.request().method() === 'POST'
        && new URL(response.url()).pathname === `/v1/me/applications/${firstBootstrap.application_id}/claim`
    ), { timeout: DEFAULT_TIMEOUT_MS });
    await recordedPage.getByTestId('canvas-claim-action').click();
    const claimResponse = await claimResponsePromise;
    const claim = await responseJson(claimResponse, 'canvas_claim_offer_failed', 'Canvas learner claim offer failed', [200]);
    await recordedPage.getByTestId('credential-claim-dialog').waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
    await showVideoStep(recordedPage, 'Wallet claim starts signing', 'The learner initiated a standards-based wallet claim; the credential offer is intentionally not displayed in this artifact.');
    const wallet = await receiveAndVerifyCredential(claim?.credential_offer_uri || claim?.offer_url, templates.credential, martyOrigin);
    await recordedPage.getByTestId('credential-claim-dialog').getByRole('button', { name: /close|done/i }).first().click().catch(() => {});
    await reloadLearnerExperience(recordedPage);
    await recordedPage.getByTestId('canvas-claim-complete').waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });

    const issuedRecords = await waitFor(async () => {
      const records = safeList(await marty.get(`/v1/issued-credentials?organization_id=${encodeURIComponent(organizationId)}`));
      const matching = records.filter((record) => (
        String(record.application_id) === String(firstBootstrap.application_id)
          && String(record.credential_template_id) === String(templates.credential.id)
      ));
      requireCondition(matching.length <= 1, 'duplicate_canvas_issuance', 'The Canvas learner claim created duplicate credentials.');
      return matching[0] || null;
    }, DEFAULT_TIMEOUT_MS, 1_000, 'issued_credential_record_timeout');
    requireCondition(String(issuedRecords.status).toUpperCase() === 'ACTIVE' && issuedRecords.issuer_did === wallet.payload.iss, 'issued_credential_record_invalid', 'The canonical issued-credential record does not match the verified KMS-signed badge.');
    pass('kms_open_badge_claim_and_verify', 'Concurrent approval reserved one claim transaction; wallet proof binding triggered remote KMS signing and the Open Badge JWS verified against the published DID assertion key.');
    await showVideoStep(recordedPage, 'KMS-signed badge claimed', 'The wallet received a holder-bound Open Badge whose issuer signature verifies against the published DID document.');

    markActive('post_issuance_correction_review_only');
    await adminCanvas.putForm(`/api/v1/courses/${fixtures.course.id}/assignments/${fixtures.assignment.id}/submissions/${fixtures.learner.id}`, {
      'submission[posted_grade]': 40,
    }, [200]);
    const driftSync = await triggerLearnerSync(recordedPage, marty);
    requireCondition(driftSync.job?.result?.policy_allowed === false, 'post_issuance_drift_not_detected', 'Post-issuance grade drift did not produce a deny decision.');
    const correctionReview = await waitFor(async () => {
      const reviews = safeList(await marty.get(
        `/v1/integrations/canvas/evidence-policy-reviews?organization_id=${encodeURIComponent(organizationId)}&binding_id=${encodeURIComponent(binding.id)}&status=open&limit=100`,
      ));
      return reviews.find((review) => (
        String(review.application_id) === String(firstBootstrap.application_id)
          && String(review.credential_id) === String(issuedRecords.credential_id || issuedRecords.id)
      )) || null;
    }, DEFAULT_TIMEOUT_MS, 1_000, 'correction_review_timeout');
    const credentialAfterDrift = await marty.get(`/v1/issued-credentials/${encodeURIComponent(issuedRecords.credential_id || issuedRecords.id)}`);
    requireCondition(correctionReview?.status === 'open' && String(credentialAfterDrift?.status).toUpperCase() === 'ACTIVE', 'correction_changed_credential_status', 'Post-issuance correction did not leave the credential active with one open review.');
    pass('post_issuance_correction_review_only', 'A post-issuance downgrade created one open correction review while the credential remained ACTIVE.');
    await showVideoStep(recordedPage, 'Correction requires administrator action', 'The changed Canvas grade opened a review; the already-issued badge was not automatically suspended or revoked.');

    await adminCanvas.putForm(`/api/v1/courses/${fixtures.course.id}/assignments/${fixtures.assignment.id}/submissions/${fixtures.learner.id}`, {
      'submission[posted_grade]': 95,
    }, [200]);
    const recoverySync = await triggerLearnerSync(recordedPage, marty);
    requireCondition(recoverySync.job?.result?.policy_allowed === true, 'correction_recovery_not_applied', 'Recovered Canvas evidence did not restore a permit decision.');
    const remainingOpenReviews = safeList(await marty.get(
      `/v1/integrations/canvas/evidence-policy-reviews?organization_id=${encodeURIComponent(organizationId)}&binding_id=${encodeURIComponent(binding.id)}&status=open&limit=100`,
    )).filter((review) => String(review.application_id) === String(firstBootstrap.application_id));
    requireCondition(remainingOpenReviews.length === 0, 'correction_review_not_resolved', 'The correction review did not automatically resolve after Canvas evidence recovered.');
    pass('post_issuance_correction_review_only', 'A downgrade opened one review without changing credential status; recovery automatically resolved the review.');

    markActive('legacy_event_ingest_unavailable');
    const legacyResponse = await fetchWithTimeout(`${martyOrigin}/v1/integrations/canvas/evidence-events`, {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json', 'X-API-Key': martyApiKey },
      body: '{}',
    });
    requireCondition(legacyResponse.status === 410, 'legacy_event_ingest_available', `Legacy Canvas evidence ingestion returned HTTP ${legacyResponse.status}, not 410.`);
    pass('legacy_event_ingest_unavailable', 'Legacy custom Canvas event ingestion returned HTTP 410; the portable flow used standard reads only.');

    markActive('canvas_oauth_authorization');
    const disconnected = await marty.delete(`/v1/integrations/canvas/platforms/${encodeURIComponent(platformId)}/oauth`, [200]);
    requireCondition(disconnected?.status === 'disconnected' && safeList(disconnected?.scopes).length === 0, 'canvas_oauth_revoke_failed', 'Canvas OAuth did not complete remote token revocation before local disconnect.');
    pass('canvas_oauth_authorization', 'A stock scoped Canvas API key connected through capability-derived OAuth and its token was remotely revoked on disconnect.');

    await showVideoStep(recordedPage, 'Portable Canvas contract complete', 'Unmodified Canvas, standard LTI Advantage, documented REST APIs, durable evidence, and external KMS issuance all passed.');
    await finishRecordedVideo(recordedContext, recordedPage, args.video);
    recordedContext = null;
    recordedPage = null;
    videoWritten = true;

    requireCondition(activityResults.nativeSubmission && activityResults.quizSubmissionRecord, 'activity_observations_missing', 'Canvas activity observations were not retained in memory.');
    requireCondition(ledger.allOssRequiredPassed(), 'required_observation_missing', 'One or more required OSS observations did not pass.');
  } catch (error) {
    failure = error instanceof ContractFailure
      ? error
      : new ContractFailure('unexpected_driver_failure', 'The standard Canvas contract stopped on an unexpected driver error.');
    if (CASE_IDS.includes(activeCase) && !['new_quizzes_authoritative_submission', 'canvas_credentials_projection'].includes(activeCase)) {
      ledger.fail(activeCase, `${failure.code}: ${failure.message}`);
    }
  } finally {
    ledger.write(args.observations);

    if (recordedContext) {
      try {
        await finishRecordedVideo(recordedContext, recordedPage, args.video);
        videoWritten = true;
      } catch {
        videoWritten = false;
      }
      recordedContext = null;
    }

    if (marty && platformId) {
      await marty.delete(`/v1/integrations/canvas/platforms/${encodeURIComponent(platformId)}`, [204]).catch(() => {});
    }
    if (marty && integrationSecretId) {
      await marty.delete(`/v1/integrations/canvas/integration-secrets/${encodeURIComponent(integrationSecretId)}`, [204]).catch(() => {});
    }
    if (learnerContext) await learnerContext.close().catch(() => {});
    if (adminContext) await adminContext.close().catch(() => {});

    if (!videoWritten && browser) {
      await createFallbackVideo(browser, args.video, failure ? `${failure.code}: ${failure.message}` : 'Video finalization failed.').catch(() => {});
    }
    if (browser) await browser.close().catch(() => {});
  }

  if (failure) {
    process.stderr.write(`Canvas OSS standard contract failed (${sanitizeEvidence(failure.code)}).\n`);
    return 1;
  }
  process.stdout.write('Canvas OSS standard contract passed using stock Canvas and standard interfaces only.\n');
  return 0;
}

module.exports = {
  BLOCKING_READINESS_CHECK_CODES,
  CASE_IDS,
  CANVAS_OAUTH_SCOPES,
  ContractFailure,
  ObservationLedger,
  createHolderProof,
  didWebResolutionUrl,
  extractDeveloperKeyRecord,
  parseCredentialOfferUri,
  requireComposeExecutionBoundary,
  requireSecretFile,
  responseJson,
  sanitizeEvidence,
  validateAuthoritativeEvidenceHeads,
  validateReadinessSnapshot,
  verifyCompactJws,
};

if (require.main === module) {
  main().then((code) => {
    process.exitCode = code;
  }).catch(() => {
    process.stderr.write('Canvas OSS standard contract failed before safe finalization.\n');
    process.exitCode = 1;
  });
}
