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
const {readBoundedSecretFile}=require('./canvas-secret-files');
const { retireOwnedCanvasFixtures, retireCanvasApplication, findCanvasInventoryRecord } = require('./canvas-owned-fixture-cleanup');

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
  'url:GET|/api/v1/courses/:course_id/assignments/:id',
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
  const result = { observations: '', video: '', functionalRerun:false };
  for (let index = 2; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--observations') result.observations = argv[++index] || '';
    else if (arg === '--video') result.video = argv[++index] || '';
    else if (arg === '--functional-rerun' && !result.functionalRerun) result.functionalRerun = true;
    else fail('invalid_argument', `Unsupported argument: ${arg}`);
  }
  requireCondition(result.observations, 'observations_path_missing', '--observations is required.');
  requireCondition(result.functionalRerun || result.video, 'video_path_missing', '--video is required for recorded runs.');
  return {
    observations: path.resolve(result.observations),
    video: result.video ? path.resolve(result.video) : null,
    functionalRerun:result.functionalRerun,
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
    value = readBoundedSecretFile(filePath,{root:'/run/secrets',maxBytes:1024*1024}).value;
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
    /^mcr\.microsoft\.com\/playwright:v1\.63\.0-noble@sha256:[0-9a-f]{64}$/.test(baseImage),
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

function martyRequestSummary(method, requestPath) {
  // Only static contract route vocabulary may enter public failure evidence.
  const words = new Set(['v1', 'integrations', 'canvas', 'platforms', 'registration-config',
    'lti-installation', 'integration-secrets', 'oauth', 'authorizations', 'program-bindings',
    'validate', 'activate', 'applications', 'approve', 'credentials', 'evidence-sync-jobs']);
  const route = requestPath.split('?')[0].split('/').map(word => words.has(word) ? word : word ? ':resource' : '').join('/');
  return `Marty ${['GET', 'POST', 'PUT', 'DELETE'].includes(method) ? method : 'REQUEST'} ${route} failed`;
}

class MartyClient {
  constructor(origin, apiKey) {
    this.origin = origin;
    this.apiKey = apiKey;
  }

  async request(method, requestPath, { json = undefined, expected = [200], includeStatus = false } = {}) {
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
    const payload = await responseJson(response, 'marty_request_failed', martyRequestSummary(method, requestPath), expected);
    return includeStatus ? {status:response.status,payload} : payload;
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

function canvasRequestUrl(origin, requestPath) {
  requireCondition(requestPath.startsWith('/api/v1/'), 'canvas_api_path_rejected', 'Canvas request path is outside the documented REST API surface.');
  const url = new URL(requestPath, origin);
  requireCondition(url.origin === origin, 'canvas_api_origin_rejected', 'Canvas API request escaped the pinned origin.');
  return url;
}

class CanvasSessionClient {
  constructor(origin, context) { this.origin = origin; this.context = context; }

  async request(method, requestPath, { expected = [200], includeStatus = false, form } = {}) {
    const url = canvasRequestUrl(this.origin, requestPath);
    const headers = { Accept: 'application/json' };
    if (!['GET', 'HEAD'].includes(method)) {
      const csrf = (await this.context.cookies(this.origin)).find(cookie => cookie.name === '_csrf_token');
      requireCondition(csrf?.value, 'canvas_csrf_missing', 'Canvas password session lacks its CSRF token.');
      headers['X-CSRF-Token'] = decodeURIComponent(csrf.value);
    }
    const response = await this.context.request.fetch(url.href, {
      method, headers, ...(form ? { form } : {}),
      timeout: DEFAULT_TIMEOUT_MS, maxRedirects: 0, failOnStatusCode: false,
    });
    const value = await responseJson(response, 'canvas_session_request_failed', 'Canvas authenticated session request failed', expected);
    return includeStatus ? { status: response.status(), body: value, link: response.headers()['link'] } : value;
  }
}

class CanvasClient {
  constructor(origin, bearer) {
    this.origin = origin;
    this.bearer = bearer;
  }

  async request(method, requestPath, { form = undefined, json = undefined, expected = [200], includeStatus = false } = {}) {
    const url = canvasRequestUrl(this.origin, requestPath);
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
    const value = await responseJson(response, 'canvas_api_request_failed', 'Canvas documented REST request failed', expected);
    return includeStatus ? { status: response.status, body: value, link: response.headers.get('link') } : value;
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

async function loginCanvas(page, origin, email, password, { observe = () => {} } = {}) {
  observe('NAVIGATE_LOGIN');
  await page.goto(`${origin}/login/canvas`, { waitUntil: 'domcontentloaded', timeout: DEFAULT_TIMEOUT_MS });
  const identifier = page.locator('#pseudonym_session_unique_id, input[name="pseudonym_session[unique_id]"]').first();
  const passwordInput = page.locator('#pseudonym_session_password, input[name="pseudonym_session[password]"]').first();
  observe('FILL_LOGIN');
  await identifier.fill(email);
  await passwordInput.fill(password);
  observe('SUBMIT_LOGIN');
  await Promise.all([
    page.waitForURL((url) => url.origin === origin && !url.pathname.startsWith('/login'), { timeout: DEFAULT_TIMEOUT_MS }),
    page.locator('button[type="submit"], input[type="submit"]').first().click(),
  ]);
  observe('POST_LOGIN_ACCEPT');
  const accepted = page.getByRole('button', { name: /accept|agree|continue/i }).first();
  if (await accepted.isVisible().catch(() => false)) await accepted.click();
  observe('LOGIN_COMPLETE');
}

function canvasTokenExpiration(now, timeZone, deadlineEpoch = process.env.CANVAS_OSS_CONTRACT_DEADLINE_EPOCH || '') {
  const runDeadline = deadlineEpoch === '' ? now + 9_000_000 : Number(deadlineEpoch) * 1000;
  requireCondition(Number.isSafeInteger(runDeadline) && runDeadline > now && runDeadline <= now + 24 * 3600000,
    'canvas_contract_deadline_invalid', 'Canvas contract deadline must be future and within the bounded daily run window.');
  const timestamp = Math.ceil((runDeadline + 30 * 60 * 1000) / (30 * 60 * 1000)) * (30 * 60 * 1000);
  const parts = new Intl.DateTimeFormat('en-US', { timeZone, year: 'numeric', month: '2-digit',
    day: '2-digit', hour: 'numeric', minute: '2-digit', hour12: true }).formatToParts(new Date(timestamp));
  const part = type => parts.find(item => item.type === type).value;
  return { timestamp, date: `${part('month')}/${part('day')}/${part('year')}`,
    time: `${part('hour')}:${part('minute')} ${part('dayPeriod')}` };
}

function freshCanvasLearnerEmail(base, runSuffix) {
  const match = /^([a-z0-9._+-]+)@(marty\.demo|[a-z0-9.-]+\.test)$/i.exec(base);
  requireCondition(match && /^[A-Za-z0-9-]{8,100}$/.test(runSuffix),
    'canvas_learner_identity_invalid', 'Fresh Canvas fixtures require a synthetic mailbox and a run identity.');
  const nonce = crypto.createHash('sha256').update(runSuffix).digest('hex').slice(0, 16);
  return `${match[1].split('+')[0].slice(0, 40)}+${nonce}@${match[2]}`;
}

async function selectCanvasTokenExpirationTime(page, time, value) {
  await time.fill(value);
  // Filling the existing default (notably midnight) emits no change and leaves
  // the stock InstUI combobox closed. Explicitly open it before selecting.
  if (await time.getAttribute('aria-expanded') !== 'true') await time.press('ArrowDown');
  // Select the exact option rather than accepting a stale highlighted value.
  await page.getByRole('option', { name: value, exact: true }).click();
  requireCondition(await time.inputValue() === value,
    'canvas_personal_token_time_uncommitted', 'Canvas must commit the exact bounded expiration time before submission.');
}

async function createPersonalAccessToken(page, origin, purpose, onOwned = () => {}) {
  // Canvas resets the session at login; select the stock session locale after authentication.
  // Accessible dialog/button names below are deliberately the English contract.
  // Stock profile scripts bind the visible token button after DOMContentLoaded.
  // Wait for those scripts before the single UI click; never retry token creation.
  await page.goto(`${origin}/profile/settings?session_locale=en`, { waitUntil: 'load', timeout: DEFAULT_TIMEOUT_MS });
  const add = page.locator('.add_access_token_link').first();
  await add.waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
  await add.click();
  const dialog = page.getByRole('dialog', { name: /new access token/i });
  await dialog.waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
  await dialog.getByLabel(/^purpose/i).fill(purpose);
  const timeZone = await page.evaluate(() => window.ENV.TIMEZONE);
  const expiration = canvasTokenExpiration(Date.now(), timeZone);
  const date = dialog.getByLabel(/^expiration date\b/i);
  const time = dialog.getByLabel(/^expiration time\b/i);
  await date.fill(expiration.date); await date.press('Tab');
  // DateTimeInput asynchronously initializes an empty time when its date is
  // committed. Let that stock UI update finish before choosing a time.
  await page.waitForTimeout(400);
  await selectCanvasTokenExpirationTime(page, time, expiration.time);
  const valid = await dialog.locator('input[required]').evaluateAll(inputs =>
    inputs.every(input => input.checkValidity() && input.getAttribute('aria-invalid') !== 'true'));
  requireCondition(valid, 'canvas_personal_token_form_invalid', 'Canvas token purpose and bounded expiration must be valid before submission.');
  const responsePromise = page.waitForResponse((response) => (
    response.request().method() === 'POST'
      && new URL(response.url()).pathname === '/api/v1/users/self/tokens'
  ), { timeout: DEFAULT_TIMEOUT_MS });
  await dialog.getByRole('button', { name: /^generate token$/i }).click();
  const response = await responsePromise;
  const payload = await responseJson(response, 'canvas_personal_token_failed', 'Canvas personal token creation failed', [200, 201]);
  onOwned(payload?.id);
  const expiresAt = Date.parse(payload?.expires_at || '');
  requireCondition(Number.isFinite(expiresAt) && Math.abs(expiresAt - expiration.timestamp) <= 60_000,
    'canvas_personal_token_expiry_mismatch', 'Canvas must confirm the requested bounded token expiration.');
  const visible = String(payload?.visible_token || '').trim();
  requireCondition(visible.length >= 20, 'canvas_personal_token_missing', 'Canvas did not return a one-time personal token.');
  const details = page.getByRole('dialog', { name: /access token details/i });
  if (await details.isVisible().catch(() => false)) {
    await details.getByRole('button', { name: /close/i }).click().catch(() => {});
  }
  return visible;
}

function canvasOAuthRedirectChecks(target, authorizationUrl, martyOrigin) {
  return {originExpected:target.origin===martyOrigin,pathExpected:target.pathname==='/v1/integrations/canvas/oauth/callback',stateMatches:target.searchParams.get('state')===authorizationUrl.searchParams.get('state'),codePresent:Boolean(target.searchParams.get('code')),providerErrorPresent:target.searchParams.has('error')};
}

async function authorizeCanvasOAuth(page, authorizationUrl, {canvasOrigin, martyOrigin, captureAtProvider = false, observe = () => {}, timeout = DEFAULT_TIMEOUT_MS} = {}) {
  requireCondition(authorizationUrl.origin===canvasOrigin && authorizationUrl.pathname==='/login/oauth2/auth'
    && authorizationUrl.searchParams.get('state') && authorizationUrl.searchParams.get('client_id')
    && authorizationUrl.searchParams.get('redirect_uri')===martyOrigin+'/v1/integrations/canvas/oauth/callback',
  'canvas_oauth_authorization_unbound', 'OAuth authorization must bind the expected provider, client and callback.');
  let captured = null, observationFailure = null, nativeRequestObserved = false, timer;
  let completed;
  const captureReady = new Promise(resolve => {completed = resolve;});
  const pending = new Set();
  const inspectCallback = (target, phase, status) => {
    const checks = canvasOAuthRedirectChecks(target, authorizationUrl, martyOrigin);
    observe({phase,...(status===undefined?{}:{status}),...checks});
    requireCondition(checks.originExpected && checks.pathExpected && checks.stateMatches && checks.codePresent && !checks.providerErrorPresent,
      'canvas_oauth_redirect_binding_failed', 'Provider redirect did not bind the expected callback, nonce and issued code.');
    const value = {code:target.searchParams.get('code'),state:target.searchParams.get('state')};
    requireCondition(!captured || (captured.code===value.code && captured.state===value.state),
      'canvas_oauth_redirect_inconsistent', 'Observed OAuth redirects disagree.');
    captured = value;completed();
  };
  const providerRequest = request => {
    const url = new URL(request.url());
    return url.origin===canvasOrigin && ((request.method()==='GET' && url.pathname==='/login/oauth2/auth')
      || (request.method()==='POST' && url.pathname==='/login/oauth2/accept'));
  };
  const providerUrl = url => url.origin===canvasOrigin && ['/login/oauth2/auth','/login/oauth2/accept'].includes(url.pathname);
  const routeHandler = async route => {
    if (!providerRequest(route.request())) {await route.continue();return;}
    try {
      // Forward this real browser request unchanged; never follow its code-bearing redirect.
      const response = await route.fetch({maxRedirects:0,maxRetries:0,timeout});
      const location = response.headers().location;
      observe({phase:'PROVIDER_RESPONSE',status:response.status(),locationPresent:Boolean(location)});
      if (location && [302,303].includes(response.status())) {
        const target = new URL(location, canvasOrigin);
        if (target.origin!==canvasOrigin || target.pathname==='/v1/integrations/canvas/oauth/callback') {
          inspectCallback(target,'PROVIDER_CODE_HELD',response.status());
          await route.fulfill({status:200,contentType:'text/plain',body:'Diagnostic: a real provider-issued code was held before its native callback. No provider result was fabricated.'});
          return;
        }
      }
      await route.fulfill({response});
    } catch (error) {observationFailure=error;completed();await route.abort().catch(()=>{});}
  };
  const requestObserver = request => {
    const target = new URL(request.url());
    if (target.origin!==martyOrigin || target.pathname!=='/v1/integrations/canvas/oauth/callback') return;
    try {inspectCallback(target,'NATIVE_CALLBACK_REQUEST');nativeRequestObserved=true;}
    catch(error) {observationFailure=error;completed();}
  };
  const responseObserver = response => {
    if (!providerRequest(response.request()) || ![302,303].includes(response.status())) return;
    const task = (async()=>{
      const headers=await response.allHeaders(),location=headers.location;
      observe({phase:'NATIVE_PROVIDER_RESPONSE',status:response.status(),locationPresent:Boolean(location)});
      if (location) {const target=new URL(location,canvasOrigin);if(target.origin!==canvasOrigin || target.pathname==='/v1/integrations/canvas/oauth/callback')inspectCallback(target,'NATIVE_PROVIDER_REDIRECT',response.status());}
    })().catch(error=>{observationFailure=error;completed();});
    pending.add(task);task.finally(()=>pending.delete(task));
  };
  if (captureAtProvider) await page.route(providerUrl,routeHandler);
  else {page.on('request',requestObserver);page.on('response',responseObserver);}
  try {
    await page.goto(authorizationUrl.href,{waitUntil:'domcontentloaded',timeout});
    if (observationFailure) throw observationFailure;
    if (!captured) await page.locator('#oauth2_accept_form').getByRole('button',{name:/^authorize$/i}).click();
    if (captureAtProvider) {
      await Promise.race([captureReady,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new ContractFailure('canvas_oauth_code_not_observed','The real provider-issued redirect was not observed.')),timeout);})]);
    } else {
      await page.waitForURL(url=>url.origin===martyOrigin && url.searchParams.has('outcome'),{timeout});
      await Promise.all([...pending]);
      requireCondition(nativeRequestObserved,'canvas_oauth_native_callback_not_observed','The real native callback request was not observed.');
    }
    if (observationFailure) throw observationFailure;
    requireCondition(captured,'canvas_oauth_code_not_observed','The real provider-issued redirect was not observed.');
    return captured;
  } catch(error) {throw observationFailure||error;}
  finally {
    clearTimeout(timer);
    if(captureAtProvider)await page.unroute(providerUrl,routeHandler);
    else{page.off('request',requestObserver);page.off('response',responseObserver);await Promise.all([...pending]);}
  }
}

function canvasDeveloperKeysUrl(origin, accountId) {
  const url = new URL(`/accounts/${encodeURIComponent(accountId)}/developer_keys`, origin);
  url.searchParams.set('session_locale', 'en');
  return url.href;
}

async function openDeveloperKeyModal(page, origin, accountId, kind, {observe = () => {}} = {}) {
  observe('NAVIGATE');
  await page.goto(canvasDeveloperKeysUrl(origin, accountId), {
    waitUntil: 'domcontentloaded',
    timeout: DEFAULT_TIMEOUT_MS,
  });
  observe('TRIGGER');
  const trigger = page.locator('#add-developer-key-button').or(page.getByRole('button', { name: /create.*developer key|developer key/i })).first();
  await trigger.waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
  await trigger.click();
  observe('MENU');
  const menuName = kind === 'lti' ? /LTI Key$/i : /API Key$/i;
  await page.getByRole('menuitem', { name: menuName }).click();
  // Canvas labels the dialog "Create Developer Key"; "Key Settings" is its
  // visible heading, not the dialog's accessible name.
  observe('MODAL');
  const modal = page.getByRole('dialog', { name: /create developer key/i });
  await modal.waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
  await modal.getByRole('heading', { name: /^key settings$/i }).waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
  return modal;
}

async function saveDeveloperKey(page, modal, expectedName, onOwned, {kind = 'api', observe = () => {}} = {}) {
  const expectedOrigin = new URL(page.url()).origin;
  const account = /^\/accounts\/([1-9][0-9]*)\/developer_keys$/.exec(new URL(page.url()).pathname);
  requireCondition(account, 'canvas_developer_key_account_missing', 'Developer Key creation requires its exact stock account page.');
  requireCondition(['api', 'lti'].includes(kind), 'canvas_developer_key_kind_invalid', 'Developer Key creation kind must be explicit.');
  const expectedPath = kind === 'lti'
    ? `/api/lti/accounts/${account[1]}/developer_keys/tool_configuration`
    : `/api/v1/accounts/${account[1]}/developer_keys`;
  const responsePromise = page.waitForResponse((response) => {
    const parsed = new URL(response.url());
    return response.request().method() === 'POST' && parsed.origin === expectedOrigin
      && parsed.pathname === expectedPath;
  }, { timeout: DEFAULT_TIMEOUT_MS });
  observe('SUBMIT');
  await modal.getByRole('button', { name: /^save$/i }).click();
  observe('RESPONSE');
  const response = await responsePromise;
  const payload = await responseJson(response, 'canvas_developer_key_save_failed', 'Canvas Developer Key save failed', [200, 201]);
  const record = extractDeveloperKeyRecord(payload, expectedName);
  requireCondition(record?.name === expectedName && /^[1-9][0-9]*$/.test(String(record.id))
    && (typeof record.id !== 'number' || Number.isSafeInteger(record.id)),
    'canvas_developer_key_identity_mismatch', 'Canvas Developer Key response must identify the exact run-owned name and client ID.');
  onOwned?.(record.id);
  observe('JOURNAL');
  observe('HIDE');
  await modal.waitFor({ state: 'hidden', timeout: DEFAULT_TIMEOUT_MS });
  return record;
}

async function enableDeveloperKey(page, keyName, record, {observeBinding = () => {}} = {}) {
  const clientId = record.id;
  const expectedBinding = record.developer_key_account_binding;
  const row = page.getByRole('row').filter({ hasText: keyName }).first();
  await row.waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
  const toggle = row.getByRole('checkbox', { name: new RegExp(`(?:off|on).*${escapeRegExp(keyName)}`, 'i') }).first();
  const checked = await toggle.isChecked().catch(() => false);
  if (!checked) {
    const origin = new URL(page.url()).origin;
    const account = /^\/accounts\/([1-9][0-9]*)\/developer_keys$/.exec(new URL(page.url()).pathname);
    requireCondition(account && /^[1-9][0-9]*$/.test(String(clientId)), 'canvas_key_binding_identity_missing', 'Enabling a key requires its exact account and owned ID.');
    requireCondition(expectedBinding?.account_owns_binding === true && String(expectedBinding.developer_key_id) === String(clientId)
      && /^[1-9][0-9]*$/.test(String(expectedBinding.account_id))
      && (typeof expectedBinding.account_id !== 'number' || Number.isSafeInteger(expectedBinding.account_id)),
      'canvas_key_binding_reference_invalid', 'Creation must bind the exact owned key to its canonical global account.');
    const expectedPath = `/api/v1/accounts/${account[1]}/developer_keys/${clientId}/developer_key_account_bindings`;
    const responsePromise = page.waitForResponse(response => {
      const url = new URL(response.url());
      return response.request().method() === 'POST' && url.origin === origin && url.pathname === expectedPath;
    }, {timeout: DEFAULT_TIMEOUT_MS});
    await clickCanvasCheckboxLabel(row, toggle);
    const confirm = page.getByRole('button', { name: /switch to on|turn on|enable/i }).first();
    if (await confirm.isVisible().catch(() => false)) await confirm.click();
    const response = await responsePromise;
    const binding = await responseJson(response, 'canvas_key_binding_save_failed', 'Canvas key binding update failed', [200, 201]);
    const checks = {
      flatObject: binding !== null && typeof binding === 'object' && !Array.isArray(binding),
      keyMatches: String(binding?.developer_key_id) === String(clientId),
      accountMatches: String(binding?.account_id) === String(expectedBinding.account_id),
      accountOwnsBinding: binding?.account_owns_binding === true,
      on: binding?.workflow_state === 'on',
    };
    observeBinding(checks);
    requireCondition(Object.values(checks).every(value => value === true),
      'canvas_key_binding_identity_mismatch', 'Canvas must acknowledge the exact owned enabled key binding.');
  }
  await waitFor(async () => toggle.isChecked().catch(() => false), DEFAULT_TIMEOUT_MS, 500, 'canvas_developer_key_enable_timeout');
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function createLtiDeveloperKey(page, config) {
  const observe = config.observe || (() => {});
  const modal = await openDeveloperKeyModal(page, config.canvasOrigin, config.accountId, 'lti', {observe});
  observe('FILL');
  await modal.getByTestId('key-name-input').fill(config.name);
  await modal.getByTestId('owner-email-input').fill(config.ownerEmail);
  const method = modal.getByLabel(/^method$/i);
  await method.click();
  await page.getByRole('option', { name: /^enter url$/i }).click();
  await modal.getByLabel(/^json url\b/i).fill(config.registrationConfigUrl);
  const record = await saveDeveloperKey(page, modal, config.name, config.onOwned, {kind:'lti', observe});
  observe('ENABLE');
  await enableDeveloperKey(page, config.name, record, {observeBinding:config.observeBinding});
  return { clientId: String(record.id) };
}

async function clickCanvasCheckboxLabel(modal, input) {
  const id = await input.getAttribute('id');
  requireCondition(id && /^[A-Za-z][\w:-]{0,100}$/.test(id), 'canvas_checkbox_identity_missing', 'Canvas checkbox requires its stock associated label.');
  await modal.locator(`label[for=${JSON.stringify(id)}]`).click();
}

async function setCanvasCheckbox(modal, input, desired) {
  if (await input.isChecked() === desired) return;
  await clickCanvasCheckboxLabel(modal, input);
  requireCondition(await input.isChecked() === desired, 'canvas_checkbox_state_mismatch', 'Canvas checkbox did not reach the requested state.');
}

async function selectCanvasOauthScopes(modal, scopes) {
  await setCanvasCheckbox(modal, modal.getByRole('checkbox', { name: /enforce scopes/i }), true);
  await setCanvasCheckbox(modal, modal.getByRole('checkbox', { name: /allow include parameters/i }), false);
  const search = modal.getByRole('searchbox', { name: /search endpoints/i });
  for (const scope of scopes) {
    await search.fill(scope);
    await modal.page().waitForTimeout(450); // Stock scope filtering is debounced by400ms.
    // Canvas lazily mounts scope groups inside a separate scroll container.
    const input = modal.locator(`input[type="checkbox"][value=${JSON.stringify(scope)}]`);
    for (let step = 0; step < 100 && !(await input.count()); step += 1) {
      await modal.locator('[data-automation="scopes-list"]').evaluate(node => {
        for (let current = node.querySelector('[data-automation="scopes-group"]') || node; current; current = current.parentElement) {
          if (current.scrollHeight > current.clientHeight + 10 && ['auto', 'scroll'].includes(getComputedStyle(current).overflowY)) {
            current.scrollTop += 800; return;
          }
        }
      });
      await modal.page().waitForTimeout(100);
    }
    requireCondition(await input.count() === 1, 'canvas_oauth_scope_controls_missing', 'Canvas did not expose one exact requested scope.');
    await setCanvasCheckbox(modal, input, true);
  }
  await search.fill('');
}

function assertCanvasOauthCompletion(url, martyOrigin, platformId) {
  requireCondition(url.origin === martyOrigin && url.searchParams.get('outcome') === 'connected'
    && url.searchParams.get('platform_id') === platformId,
    'canvas_oauth_callback_not_connected', 'The native OAuth callback must confirm connection to the owned Canvas platform.');
}

async function createOauthDeveloperKey(page, config) {
  const observe = config.observe || (() => {});
  const modal = await openDeveloperKeyModal(page, config.canvasOrigin, config.accountId, 'api', {observe});
  observe('FILL');
  await modal.getByTestId('key-name-input').fill(config.name);
  await modal.getByTestId('owner-email-input').fill(config.ownerEmail);
  await modal.getByTestId('redirect-uris-input').fill(config.redirectUri);
  observe('SCOPES');
  await selectCanvasOauthScopes(modal, CANVAS_OAUTH_SCOPES);
  const record = await saveDeveloperKey(page, modal, config.name, config.onOwned, {observe});
  requireCondition(record.require_scopes === true && Array.isArray(record.scopes)
    && record.scopes.length === CANVAS_OAUTH_SCOPES.length
    && CANVAS_OAUTH_SCOPES.every(scope => record.scopes.includes(scope)),
    'canvas_oauth_scope_grant_mismatch', 'Canvas must persist exactly the required enforced OAuth scope allowlist.');
  observe('ENABLE');
  await enableDeveloperKey(page, config.name, record, {observeBinding:config.observeBinding});
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

async function selectProductionBadgeTemplates(marty, organizationId, selectors = {
  applicationTemplateId: process.env.CANVAS_OSS_APPLICATION_TEMPLATE_ID,
  credentialTemplateId: process.env.CANVAS_OSS_CREDENTIAL_TEMPLATE_ID,
}) {
  const explicitApplicationId = String(selectors.applicationTemplateId || '').trim();
  const explicitCredentialId = String(selectors.credentialTemplateId || '').trim();
  async function inventory(collection) {
    const rows = [];
    const seen = new Set();
    for (let offset = 0; offset < 10_000; offset += 100) {
      const page = safeList(await marty.get(`${collection}?organization_id=${encodeURIComponent(organizationId)}&limit=100&offset=${offset}`));
      for (const row of page) {
        requireCondition(row?.id && !seen.has(String(row.id)), 'template_inventory_pagination_invalid', 'Template inventory repeated or omitted a stable resource ID.');
        seen.add(String(row.id)); rows.push(row);
      }
      if (page.length < 100) return rows;
    }
    fail('template_inventory_limit', 'Template inventory exceeded the bounded selection limit.');
  }
  const applications = explicitApplicationId
    ? [await marty.get(`/v1/application-templates/${encodeURIComponent(explicitApplicationId)}`)]
    : await inventory('/v1/application-templates');
  const referencedCredentialId = explicitCredentialId
    || (explicitApplicationId ? String(applications[0]?.credential_template_id || '') : '');
  const credentials = referencedCredentialId
    ? [await marty.get(`/v1/credential-templates/${encodeURIComponent(referencedCredentialId)}`)]
    : await inventory('/v1/credential-templates');
  const credentialById = new Map(credentials.map((item) => [String(item.id), item]));
  const candidates = applications.filter((application) => {
    if (String(application.organization_id) !== organizationId) return false;
    if (String(application.status || '').toUpperCase() !== 'ACTIVE') return false;
    if (explicitApplicationId && String(application.id) !== explicitApplicationId) return false;
    const credential = credentialById.get(String(application.credential_template_id || ''));
    if (!credential || String(credential.status || '').toUpperCase() !== 'ACTIVE') return false;
    if (String(credential.organization_id) !== organizationId) return false;
    if (explicitCredentialId && String(credential.id) !== explicitCredentialId) return false;
    const type = String(credential.credential_type || '').replace(/[^a-z]/gi, '').toLowerCase();
    const claims = new Set((credential.claims || []).map(claim => claim.name));
    return ['openbadge', 'openbadgecredential'].includes(type)
      && ['achievement_name', 'course_name', 'quiz_name', 'score_percent', 'result', 'learning_context']
        .every(name => claims.has(name));
  });
  requireCondition(candidates.length === 1, 'badge_template_selection_ambiguous', 'Exactly one active Open Badge application/template pair must be selected for the portability lane.');
  const application = candidates[0];
  const credential = credentialById.get(String(application.credential_template_id));
  return { application, credential };
}

async function observePipelinePrerequisites(ledger, martyOrigin, canvasOrigin, markActive = () => {}, prerequisiteDirectory = '/artifacts') {
  markActive('upstream_source_and_image_provenance');
  const artifactRoot = path.resolve(prerequisiteDirectory);
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

async function publishCanvasCourse(adminCanvas, courseId) {
  const published = await adminCanvas.putForm(`/api/v1/courses/${courseId}`, {
    'course[event]': 'offer',
  }, [200]);
  requireCondition(String(published?.id) === String(courseId) && published?.workflow_state === 'available',
    'canvas_course_not_published', 'Canvas must confirm the owned course is published before learner activity.');
  return published;
}

async function createCanvasFixtures(adminCanvas, accountId, adminUserId, learnerEmail, learnerPassword, runSuffix, onOwned = () => {}) {
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
  onOwned('learner', learner.id);

  const course = await adminCanvas.postForm(`/api/v1/accounts/${encodeURIComponent(accountId)}/courses`, {
    'course[name]': `${RUN_NAME_PREFIX} ${runSuffix}`,
    'course[course_code]': `OSS-${runSuffix}`,
    'course[is_public]': false,
  }, [200, 201]);
  requireCondition(course?.id, 'canvas_course_create_failed', 'Canvas did not create the portability course.');
  onOwned('course', course.id);

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

  onOwned('assignment', assignment?.id);
  const quiz = await adminCanvas.postForm(`/api/v1/courses/${course.id}/quizzes`, {
    'quiz[title]': `Portable Classic Quiz ${runSuffix}`,
    'quiz[description]': 'A stock Classic Quiz used by the portable evidence contract.',
    'quiz[quiz_type]': 'assignment',
    'quiz[points_possible]': 100,
    'quiz[allowed_attempts]': 1,
    'quiz[show_correct_answers]': true,
    'quiz[published]': false,
  }, [200, 201]);
  onOwned('quiz', quiz?.id);
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
  onOwned('question', question?.id);
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
  onOwned('module', module?.id);
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
  await publishCanvasCourse(adminCanvas, course.id);
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

function canvasOwnedToolIndex(ids, toolId) {
  requireCondition(/^\d+$/.test(toolId), 'canvas_owned_tool_invalid', 'The installed Canvas tool requires an acknowledged numeric ID.');
  const matches = ids.flatMap((id, index) => String(id) === toolId ? [index] : []);
  requireCondition(matches.length === 1, 'canvas_owned_tool_ambiguous', 'The stock chooser must contain exactly one owned installed tool.');
  return matches[0];
}

async function runDeepLinkingViaAssignmentUi(page, fixtures, toolId, adminCanvas, previousIds, martyOrigin) {
  await page.goto(`${adminCanvas.origin}/courses/${fixtures.course.id}/assignments/new`, {
    waitUntil: 'domcontentloaded',
    timeout: DEFAULT_TIMEOUT_MS,
  });
  const name = page.locator('#assignment_name').or(page.getByLabel(/assignment name/i)).first();
  await name.fill(`Portable Marty activity ${Date.now().toString(36)}`);
  const submissionSelect = page.locator('#assignment_submission_type').or(page.getByLabel(/submission type/i)).first();
  await submissionSelect.selectOption({ value: 'external_tool' });
  await page.getByRole('button', { name: /^find$/i }).click();
  const chooser = page.getByRole('dialog', { name: /^configure external tool$/i });
  await chooser.waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
  const tools = chooser.locator('li.tool');
  await waitFor(async () => (await tools.count()) > 0, DEFAULT_TIMEOUT_MS, 100, 'canvas_tool_chooser_empty');
  // This is the stock rendered chooser model used by its own click handler.
  // Read only IDs to distinguish installations with identical visible titles;
  // navigation itself still uses the real chooser link and LTI launch.
  const ids = await tools.evaluateAll(nodes => nodes.map(node =>
    String(window.jQuery(node).data('tool')?.definition_id || '')));
  await tools.nth(canvasOwnedToolIndex(ids, toolId)).getByRole('link').click();
  const ltiFrame = await waitFor(() => page.frames().find((frame) => {
    try { return new URL(frame.url()).origin === martyOrigin; } catch { return false; }
  }), DEFAULT_TIMEOUT_MS, 500, 'deep_link_iframe_missing');
  await ltiFrame.getByRole('button', { name: /add marty activity to canvas/i }).click();
  await page.getByRole('dialog', { name: /^link resource from external tool$/i })
    .waitFor({ state: 'hidden', timeout: DEFAULT_TIMEOUT_MS });
  await waitFor(async () => {
    const value = await chooser.locator('#external_tool_create_url').inputValue();
    try { return new URL(value).origin === martyOrigin; } catch { return false; }
  }, DEFAULT_TIMEOUT_MS, 100, 'canvas_deep_link_return_missing');
  await chooser.getByRole('button', { name: /^select$/i }).click();
  await chooser.waitFor({ state: 'hidden', timeout: DEFAULT_TIMEOUT_MS });
  await page.getByRole('button', { name: /save\s*&\s*publish|save and publish/i }).click();
  return waitFor(
    () => findNewExternalAssignment(adminCanvas, fixtures.course.id, previousIds),
    DEFAULT_TIMEOUT_MS,
    1_000,
    'deep_link_assignment_missing',
  );
}

async function performInstructorDeepLinking(page, adminCanvas, fixtures, toolId, martyOrigin) {
  const before = safeList(await adminCanvas.get(`/api/v1/courses/${fixtures.course.id}/assignments?per_page=100`));
  const previousIds = new Set(before.map((item) => String(item.id)));
  // The portability claim must exercise the installed stock Canvas chooser and
  // assignment UI. An API-generated launch cannot substitute for instructor
  // adoption behavior in the full gate.
  const assignment = await runDeepLinkingViaAssignmentUi(
    page,
    fixtures,
    toolId,
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

function canvasLaunchErrorSummary(value, depth = 0) {
  if (!value || typeof value !== 'object' || depth > 3) return [];
  const result = [];
  for (const key of ['detail', 'details', 'message', 'error', 'error_description', 'code', 'error_code', 'reason']) {
    const item = value[key];
    if (typeof item === 'string') result.push(sanitizeEvidence(item)
      .replace(/https?:\/\/[^\s]+/gi, '[redacted-url]')
      .replace(/[A-Za-z0-9_-]{24,}/g, '[redacted-opaque]'));
    else if (Array.isArray(item)) result.push(...item.slice(0, 3).flatMap(entry => canvasLaunchErrorSummary(entry, depth + 1)));
    else if (item && typeof item === 'object') result.push(...canvasLaunchErrorSummary(item, depth + 1));
  }
  return [...new Set(result)].slice(0, 8);
}

async function openCanvasAssignmentResource(page, canvas, fixtures, externalAssignment, martyOrigin) {
  const documents = [];
  const reads = [];
  let presentation;
  const observeDocument = response => {
    const request = response.request();
    if ((!request.isNavigationRequest() && response.status() < 400) || documents.length >= 40) return;
    const url = new URL(response.url());
    const item = { status: response.status(), origin: url.origin === martyOrigin ? 'marty'
      : url.origin === canvas.origin ? 'canvas' : 'other',
    kind: url.pathname.startsWith('/v1/auth/canvas-lti/') ? 'canvas_auth_api'
      : url.pathname.startsWith('/v1/integrations/canvas/lti/') ? 'lti_api'
      : url.pathname.startsWith('/canvas/lti/') ? 'lti_ui' : 'other',
    json: (response.headers()['content-type'] || '').includes('application/json') };
    documents.push(item);
    if (item.json && item.origin === 'marty' && item.status >= 400) reads.push(response.json().then(value => {
      item.errors = canvasLaunchErrorSummary(value);
    }).catch(() => {}));
  };
  page.on('response', observeDocument);
  try {
  await page.goto(`${canvas.origin}/courses/${fixtures.course.id}/assignments`, {
    waitUntil: 'domcontentloaded', timeout: DEFAULT_TIMEOUT_MS,
  });
  const assignmentName = String(externalAssignment?.name || externalAssignment?.title || '').trim();
  requireCondition(assignmentName, 'canvas_assignment_name_missing', 'The Deep Linked Canvas assignment requires a visible name.');
  await page.getByRole('link', { name: assignmentName, exact: true }).first().click();
  await page.waitForURL(url => url.origin === canvas.origin
    && url.pathname === `/courses/${fixtures.course.id}/assignments/${externalAssignment.id}`,
  { timeout: DEFAULT_TIMEOUT_MS });
  const launchControl = page.getByRole('link', { name: /load .* in a new window|open .* in a new window|launch external tool/i })
    .or(page.getByRole('button', { name: /load .* in a new window|open .* in a new window|launch external tool/i })).first();
  presentation = await waitFor(async () => {
    const frames = [];
    for (const frame of page.frames()) {
      if (frame === page.mainFrame()) continue;
      try {
        if (new URL(frame.url()).origin === martyOrigin && await (await frame.frameElement()).isVisible()) frames.push(frame);
      } catch { /* A stock iframe may still be navigating. */ }
    }
    requireCondition(frames.length <= 1, 'canvas_resource_launch_ambiguous', 'Canvas must expose exactly one visible Marty resource launch.');
    if (frames.length === 1) return { surface: frames[0], page, popup: false };
    return await launchControl.isVisible() ? { popup: true } : null;
  }, DEFAULT_TIMEOUT_MS, 100, 'canvas_resource_launch_missing');
  if (presentation.popup) {
    const popupPromise = page.context().waitForEvent('page', { timeout: DEFAULT_TIMEOUT_MS });
    await launchControl.click();
    const popup = await popupPromise;
    await popup.waitForURL(url => url.origin === martyOrigin, { timeout: DEFAULT_TIMEOUT_MS });
    await popup.waitForLoadState('domcontentloaded', { timeout: DEFAULT_TIMEOUT_MS });
    presentation.surface = popup; presentation.page = popup;
  }
  await presentation.surface.getByTestId('canvas-lti-login-page').waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
  const experience = presentation.surface.getByTestId('canvas-lti-login-page');
  const verification = await waitFor(async () => {
    if (await experience.getByText(/^Canvas launch verified$/i).isVisible()) return { verified: true };
    if (await experience.getByRole('alert').first().isVisible()) return { verified: false };
    return null;
  }, DEFAULT_TIMEOUT_MS, 100, 'canvas_resource_ui_pending');
  requireCondition(verification.verified, 'canvas_resource_ui_not_verified',
    'The actual Marty resource UI reported an error before its verified state.');
  return presentation;
  } catch (error) {
    await Promise.allSettled(reads);
    const surface = presentation?.surface;
    const document = surface ? await surface.evaluate(() => {
      let body;
      try { body = JSON.parse(document.body?.textContent || ''); } catch { body = null; }
      return { contentType: document.contentType, hasAppRoot: Boolean(document.querySelector('#root')),
        bodyLength: document.body?.textContent?.length || 0, errorBody: body,
        alerts: [...document.querySelectorAll('[role=alert]')].slice(0, 4).map(node => node.textContent) };
    }).catch(() => null) : null;
    if (document) {
      document.errors = canvasLaunchErrorSummary(document.errorBody);
      document.alerts = canvasLaunchErrorSummary({ details: document.alerts.map(message => ({ message })) });
      delete document.errorBody;
    }
    error.canvasResourceDiagnostic = { documents, document };
    throw error;
  } finally {
    page.off('response', observeDocument);
  }
}

async function launchStaffResource(page, adminCanvas, fixtures, externalAssignment, martyOrigin) {
  const launch = await openCanvasAssignmentResource(page, adminCanvas, fixtures, externalAssignment, martyOrigin);
  if (launch.popup) await launch.page.close();
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

async function waitForCanvasCourseCompletion(canvas, fixtures) {
  return waitFor(async () => {
    const progress = await canvas.get(`/api/v1/courses/${fixtures.course.id}/users/${fixtures.learner.id}/progress`);
    const required = Number(progress?.requirement_count);
    const completed = Number(progress?.requirement_completed_count);
    // Canvas may retain completed_at while asynchronously recalculating module
    // progress after a grade correction. Require current nonempty counts.
    return Number.isFinite(required) && required > 0 && Number.isFinite(completed)
      && completed >= required ? progress : null;
  }, DEFAULT_TIMEOUT_MS, 1_000, 'course_completion_not_observed');
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
  // Both stock embedded and new-window launches exercise the assignment UI.
  const launch = await openCanvasAssignmentResource(page, learnerCanvas, fixtures, externalAssignment, martyOrigin);
  const launchedPage = launch.page;
  const bootstrapPromise = launchedPage.waitForResponse((response) => (
    response.request().method() === 'POST'
      && new URL(response.url()).origin === martyOrigin
      && new URL(response.url()).pathname.endsWith('/lti/experience-sessions/current/bootstrap')
  ), { timeout: DEFAULT_TIMEOUT_MS });
  await launch.surface.getByTestId('canvas-lti-continue').click();
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
      && new URL(response.url()).origin === new URL(page.url()).origin
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

function pinnedHttpsUrl(value, expectedOrigin, code, summary) {
  let url;
  try {
    url = new URL(String(value || ''));
  } catch {
    fail(code, summary);
  }
  requireCondition(
    url.protocol === 'https:'
      && url.origin === expectedOrigin
      && !url.username
      && !url.password
      && !url.search
      && !url.hash,
    code,
    summary,
  );
  return url;
}

async function resolveOid4vciEndpoints(metadata, issuerUrl, expectedOrigin, fetchImpl = fetchWithTimeout) {
  const declaredIssuer = pinnedHttpsUrl(
    metadata?.credential_issuer,
    expectedOrigin,
    'credential_metadata_issuer_unpinned',
    'OID4VCI metadata returned an invalid or untrusted credential issuer.',
  );
  requireCondition(
    declaredIssuer.href.replace(/\/$/, '') === issuerUrl.href.replace(/\/$/, ''),
    'credential_metadata_issuer_mismatch',
    'OID4VCI metadata did not describe the credential issuer in the offer.',
  );
  const credentialEndpoint = pinnedHttpsUrl(
    metadata?.credential_endpoint,
    expectedOrigin,
    'credential_endpoint_unpinned',
    'OID4VCI metadata returned an invalid or untrusted credential endpoint.',
  );

  let tokenEndpointValue = metadata?.token_endpoint;
  if (!tokenEndpointValue) {
    const authorizationServers = safeList(metadata?.authorization_servers);
    requireCondition(
      authorizationServers.length === 1,
      'authorization_server_ambiguous',
      'OID4VCI metadata must identify exactly one authorization server when it omits token_endpoint.',
    );
    const authorizationServer = pinnedHttpsUrl(
      authorizationServers[0],
      expectedOrigin,
      'authorization_server_unpinned',
      'OID4VCI metadata returned an invalid or untrusted authorization server.',
    );
    const authorizationPath = authorizationServer.pathname === '/'
      ? ''
      : authorizationServer.pathname.replace(/\/$/, '');
    const authorizationMetadataUrl = `${authorizationServer.origin}/.well-known/oauth-authorization-server${authorizationPath}`;
    const authorizationResponse = await fetchImpl(authorizationMetadataUrl, {
      headers: { Accept: 'application/json' },
    });
    const authorizationMetadata = await responseJson(
      authorizationResponse,
      'authorization_metadata_failed',
      'OAuth authorization server metadata request failed',
    );
    const discoveredIssuer = pinnedHttpsUrl(
      authorizationMetadata?.issuer,
      expectedOrigin,
      'authorization_server_issuer_unpinned',
      'OAuth authorization server metadata returned an invalid or untrusted issuer.',
    );
    requireCondition(
      discoveredIssuer.href.replace(/\/$/, '') === authorizationServer.href.replace(/\/$/, ''),
      'authorization_server_issuer_mismatch',
      'OAuth authorization server metadata did not describe the selected authorization server.',
    );
    tokenEndpointValue = authorizationMetadata?.token_endpoint;
  }

  const tokenEndpoint = pinnedHttpsUrl(
    tokenEndpointValue,
    expectedOrigin,
    'token_endpoint_unpinned',
    'OID4VCI metadata returned an invalid or untrusted token endpoint.',
  );
  const nonceEndpoint = metadata?.nonce_endpoint
    ? pinnedHttpsUrl(
      metadata.nonce_endpoint,
      expectedOrigin,
      'nonce_endpoint_unpinned',
      'OID4VCI metadata returned an invalid or untrusted nonce endpoint.',
    )
    : null;
  return { tokenEndpoint, credentialEndpoint, nonceEndpoint };
}

async function resolveProofNonce(token, nonceEndpoint, fetchImpl = fetchWithTimeout) {
  const tokenNonce = String(token?.c_nonce || token?.nonce || '').trim();
  if (tokenNonce) return tokenNonce;
  requireCondition(
    nonceEndpoint,
    'credential_nonce_endpoint_missing',
    'OID4VCI metadata omitted the nonce endpoint required by the token response.',
  );
  const nonceResponse = await fetchImpl(nonceEndpoint, {
    method: 'POST',
    headers: { Accept: 'application/json' },
  });
  const nonce = await responseJson(
    nonceResponse,
    'credential_nonce_failed',
    'OID4VCI proof nonce request failed',
  );
  const proofNonce = String(nonce?.c_nonce || nonce?.nonce || '').trim();
  requireCondition(
    proofNonce,
    'credential_nonce_response_incomplete',
    'OID4VCI nonce response omitted the proof nonce.',
  );
  return proofNonce;
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
  requireCondition(
    typeof expectedTemplate?.vct === 'string' && expectedTemplate.vct.trim().length > 0,
    'credential_template_vct_missing',
    'Credential verification requires the selected template\'s exact VCT before claiming its offer.',
  );
  const offer = parseCredentialOfferUri(offerUri);
  const issuerUrl = pinnedHttpsUrl(
    offer.issuer,
    expectedIssuerOrigin,
    'credential_issuer_unpinned',
    'The OID4VCI issuer is outside the reviewed beta origin.',
  );
  const metadataUrl = `${issuerUrl.origin}/.well-known/openid-credential-issuer${issuerUrl.pathname}`;
  const metadataResponse = await fetchWithTimeout(metadataUrl, { headers: { Accept: 'application/json' } });
  const metadata = await responseJson(metadataResponse, 'credential_metadata_failed', 'OID4VCI issuer metadata request failed');
  const { tokenEndpoint, credentialEndpoint, nonceEndpoint } = await resolveOid4vciEndpoints(
    metadata,
    issuerUrl,
    expectedIssuerOrigin,
  );

  const tokenResponse = await fetchWithTimeout(tokenEndpoint, {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
      'pre-authorized_code': offer.preAuthorizedCode,
    }).toString(),
  });
  const token = await responseJson(tokenResponse, 'credential_token_exchange_failed', 'OID4VCI token exchange failed');
  requireCondition(token?.access_token, 'credential_token_response_incomplete', 'OID4VCI token response omitted its access token.');
  const proofNonce = await resolveProofNonce(token, nonceEndpoint);

  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const holderJwk = publicHolderJwk(publicKey);
  const proof = createHolderProof(privateKey, holderJwk, offer.issuer, proofNonce);
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
    verified.payload.vct === expectedTemplate.vct,
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

function contractFailureLocation(error, activeCase) {
  // Retain actionable driver location without request bodies, URLs, credentials
  // or Playwright action arguments from the original exception message.
  const frame = String(error?.stack || '').match(/\b(run-canvas-oss-standard-contract|canvas-capture-sequence|audit-beta-canvas-capture)\.js:(\d+):(\d+)/);
  const name = /^[A-Za-z][A-Za-z0-9]{0,50}$/.test(String(error?.name || '')) ? error.name : 'Error';
  const result = { activeCase, errorType: name,
    sourceLocation: frame ? { file: frame[1]+'.js', line: Number(frame[2]), column: Number(frame[3]) } : null };
  if (error?.canvasResourceDiagnostic) result.canvasResource = error.canvasResourceDiagnostic;
  return result;
}

async function finishRecordedVideo(context, page, destination) {
  const video = page.video();
  await context.close();
  const source = await video.path();
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.copyFileSync(source, destination);
  if (path.resolve(source) !== path.resolve(destination)) fs.unlinkSync(source);
}

async function prepareCanvasCaptureFixtures({ browser, ledger, markActive = () => {},
  pass = () => {}, runSuffix, state = {}, prerequisiteDirectory = '/artifacts', ownershipDirectory }) {
  requireCondition(browser && /^[A-Za-z0-9-]{8,100}$/.test(runSuffix || ''),
    'canvas_run_identity_invalid', 'A fresh Canvas capture run identity is required.');
  if (process.env.DEMO_CANVAS_PRIVATE_RECOVERY_DIRECTORY) state.custody ||= createCanvasCaptureCustody(runSuffix);
  let marty, adminContext, learnerContext, platformId, integrationSecretId;
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
    const learnerEmail = freshCanvasLearnerEmail(requireSecretFile('CANVAS_OSS_LEARNER_EMAIL'), runSuffix);
    const learnerPassword = requireSecretFile('CANVAS_OSS_LEARNER_PASSWORD');
    const organizationId = requireEnv('CANVAS_OSS_ORGANIZATION_ID');
    state.organizationId = organizationId;
    const martyApiKey = requireSecretFile('CANVAS_OSS_MARTY_API_KEY');
    state.marty = marty = new MartyClient(martyOrigin, martyApiKey);
    const owned = { scope: 'OWNED_CANVAS_SETUP_RESOURCES', runSuffix, learnerEmail, resources: {} };
    Object.assign(state, { owned, runSuffix, canvasOrigin, martyOrigin });
    requireCondition(typeof ownershipDirectory === 'string' && path.isAbsolute(ownershipDirectory)
      && fs.statSync(ownershipDirectory).isDirectory(), 'canvas_ownership_directory_invalid', 'A writable per-run ownership evidence directory is required.');
    const ownershipPath = path.join(ownershipDirectory, 'owned-canvas-resources.json');
    fs.writeFileSync(ownershipPath, JSON.stringify(owned, null, 2) + '\n', { flag: 'wx' });
    const persistOwned = () => fs.writeFileSync(ownershipPath, JSON.stringify(owned, null, 2) + '\n');
    state.persistOwned = persistOwned;
    const remember = (kind, id) => {
      requireCondition(/^[0-9]+$/.test(String(id || '')), 'canvas_owned_resource_id_missing', 'Canvas must acknowledge an owned resource ID.');
      owned.resources[kind] = String(id); persistOwned();
    };
    persistOwned();


    await observePipelinePrerequisites(ledger, martyOrigin, canvasOrigin, markActive, prerequisiteDirectory);

    markActive('standard_lti_13_install');

    state.adminContext = adminContext = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    // Stock TokensController requires a password session even for its API.
    state.adminTokenCanvas = new CanvasSessionClient(canvasOrigin, adminContext);
    const adminPage = await adminContext.newPage();
    state.adminPage = adminPage;
    await loginCanvas(adminPage, canvasOrigin, adminEmail, adminPassword);
    state.custody?.retain('canvasAdminSession',JSON.stringify(await adminContext.cookies(canvasOrigin)));
    const adminBearer = await createPersonalAccessToken(adminPage, canvasOrigin, `OSS contract admin ${runSuffix}`, id => remember('adminAccessToken', id));
    const adminCanvas = new CanvasClient(canvasOrigin, adminBearer);
    state.adminCanvas = adminCanvas;
    const accounts = safeList(await adminCanvas.get('/api/v1/accounts?per_page=100'));
    const rootAccount = accounts.find((account) => !account.parent_account_id) || accounts[0];
    requireCondition(rootAccount?.id, 'canvas_root_account_missing', 'Canvas Accounts API did not return a root account.');
    const adminProfile = await adminCanvas.get('/api/v1/users/self/profile');
    require('./audit-beta-canvas-invalid-secret').assertCanvasLoginIdentity(adminProfile,adminEmail);
    requireCondition(adminProfile?.id, 'canvas_admin_profile_missing', 'Canvas Users API did not return the root administrator profile.');
    Object.assign(state, { accountId: String(rootAccount.id), adminId: String(adminProfile.id) });
    Object.assign(owned, { canvasOrigin, accountId: state.accountId, adminId: state.adminId }); persistOwned();

    const templates = await selectProductionBadgeTemplates(marty, organizationId);
    state.templates = templates;

    markActive('standard_lti_13_install');
    owned.martyPlatformIntent={name:`${RUN_NAME_PREFIX} ${runSuffix}`,state:'CREATING'};persistOwned();
    const platform = await marty.post('/v1/integrations/canvas/platforms', {
      display_name: `${RUN_NAME_PREFIX} ${runSuffix}`,
      canvas_base_url: canvasOrigin,
      enabled: true,
    }, [200]);
    owned.martyPlatformIntent.returnedId=platform?.id;owned.martyPlatformIntent.state='RESPONSE_UNVERIFIED';persistOwned();
    requireCondition(platform?.display_name===owned.martyPlatformIntent.name&&String(platform.organization_id)===organizationId,
      'marty_canvas_platform_identity_mismatch','Created Canvas platform must match its exact owned name and tenant.');
    owned.martyPlatformIntent.state='CREATED';
    state.platformId = platformId = String(platform?.id || '');
    requireCondition(platformId, 'marty_canvas_platform_missing', 'Marty did not create the organization-owned Canvas draft.');
    owned.martyPlatformId = platformId; persistOwned();
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
      onOwned: id => remember('ltiDeveloperKey', id),
      registrationConfigUrl,
    });
    const tool = await adminCanvas.postForm(`/api/v1/accounts/${rootAccount.id}/external_tools`, {
      client_id: ltiKey.clientId,
    }, [200, 201]);
    requireCondition(tool?.id && tool?.deployment_id, 'lti_tool_install_failed', 'Canvas External Tools API did not install the LTI 1.3 deployment.');
    remember('externalTool', tool.id);
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
      remember,
    );

    state.learnerContext = learnerContext = await browser.newContext({ viewport: { width: 1440, height: 900 } });
    state.learnerTokenCanvas = new CanvasSessionClient(canvasOrigin, learnerContext);
    const learnerSetupPage = await learnerContext.newPage();
    await loginCanvas(learnerSetupPage, canvasOrigin, learnerEmail, learnerPassword);
    state.custody?.retain('canvasLearnerSession',JSON.stringify(await learnerContext.cookies(canvasOrigin)));
    const learnerBearer = await createPersonalAccessToken(learnerSetupPage, canvasOrigin, `OSS contract learner ${runSuffix}`, id => remember('learnerAccessToken', id));
    const learnerCanvas = new CanvasClient(canvasOrigin, learnerBearer);
    state.learnerCanvas = learnerCanvas;
    const activityResults = await completeLearnerCanvasWork(learnerCanvas, adminCanvas, fixtures, markActive);
    pass('existing_assignment_submission', 'A learner submission and 95% score are authoritative through the documented Assignment Submissions API.');
    pass('classic_quiz_submission', 'A stock Classic Quiz was answered and its autograded score is authoritative through Assignment Submissions.');

    markActive('canvas_oauth_authorization');
    const oauthKey = await createOauthDeveloperKey(adminPage, {
      canvasOrigin,
      accountId: rootAccount.id,
      ownerEmail: adminEmail,
      name: `Marty OAuth ${runSuffix}`,
      onOwned: id => remember('oauthDeveloperKey', id),
      redirectUri: `${martyOrigin}/v1/integrations/canvas/oauth/callback`,
    });
    state.custody?.retain('canvasOwnedClientSecret',oauthKey.clientSecret);
    owned.martySecretIntent={name:`Canvas OAuth ${runSuffix}`,state:'CREATING'};persistOwned();
    const integrationSecret = await marty.post('/v1/integrations/canvas/integration-secrets', {
      organization_id: organizationId,
      name: `Canvas OAuth ${runSuffix}`,
      provider: 'canvas',
      purpose: 'oauth_client_secret',
      secret_value: oauthKey.clientSecret,
      metadata: { contract: 'canvas_oss_portability' },
      enabled: true,
    }, [200, 201]);
    owned.martySecretIntent.returnedId=integrationSecret?.id;owned.martySecretIntent.state='RESPONSE_UNVERIFIED';persistOwned();
    requireCondition(integrationSecret?.organization_id===organizationId&&integrationSecret.name===owned.martySecretIntent.name
      &&integrationSecret.provider==='canvas'&&integrationSecret.purpose==='oauth_client_secret',
      'marty_oauth_secret_identity_mismatch','Created OAuth reference must match its exact owned identity.');
    owned.martySecretIntent.state='CREATED';
    state.integrationSecretId = integrationSecretId = String(integrationSecret?.id || '');
    owned.martyIntegrationSecretId=integrationSecretId;persistOwned();
    requireCondition(integrationSecretId, 'marty_oauth_secret_reference_missing', 'Marty did not store the encrypted Canvas OAuth secret reference.');
    state.oauthMayExist=true;owned.martyOAuthMayExist=true;persistOwned();
    const oauthStart = await marty.post(`/v1/integrations/canvas/platforms/${encodeURIComponent(platformId)}/oauth/authorizations`, {
      client_id: oauthKey.clientId,
      client_secret_secret_id: integrationSecretId,
      capabilities: OAUTH_CAPABILITIES,
    }, [200]);
    const oauthUrl = new URL(String(oauthStart?.authorization_url || ''));
    requireCondition(oauthUrl.origin === canvasOrigin, 'canvas_oauth_url_unpinned', 'Marty returned an OAuth authorization URL outside Canvas.');
    await authorizeCanvasOAuth(adminPage,oauthUrl,{canvasOrigin,martyOrigin});
    assertCanvasOauthCompletion(new URL(adminPage.url()), martyOrigin, platformId);
    const connectedPlatform = await marty.get(`/v1/integrations/canvas/platforms/${encodeURIComponent(platformId)}`);
    requireCondition(connectedPlatform?.connection_config?.oauth_status === 'connected', 'canvas_oauth_not_connected', 'Canvas OAuth callback did not publish a connected organization-scoped connection.');
    state.oauthConnected = true;
    pass('canvas_oauth_authorization', 'A stock scoped Canvas API Developer Key completed the capability-derived OAuth flow.');

    const binding = await createProgramBinding(marty, platformId, templates, fixtures, runSuffix);
    requireCondition(binding?.id, 'canvas_binding_create_failed', 'Marty did not create the typed Canvas program binding.');
    state.binding=binding;owned.martyBindingId=String(binding.id);persistOwned();

    markActive('instructor_deep_linking');
    const externalAssignment = await performInstructorDeepLinking(adminPage, adminCanvas, fixtures, String(tool.id), martyOrigin);
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
    state.bindingActivationPossible=true;owned.martyBindingActivationPossible=true;persistOwned();
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
    await waitForCanvasCourseCompletion(adminCanvas, fixtures);
    pass('course_completion', 'Canvas CourseProgress reported all non-empty module requirements completed.');

  return Object.assign(state, { canvasOrigin, martyOrigin, organizationId, marty, martyApiKey,
    adminContext, learnerContext, adminCanvas, learnerCanvas, fixtures, templates,
    platformId, integrationSecretId, binding, pinnedBinding, externalAssignment, activityResults });
}

async function findCanvasDeveloperKey({ adminCanvas, canvasOrigin, accountId }, { id, name }) {
  const found = await findCanvasInventoryRecord(adminCanvas, canvasOrigin,
    `/api/v1/accounts/${accountId}/developer_keys`, key => String(key.id) === id);
  if (found) assert.equal(found.name, name, 'Canvas key belongs to another run');
  return found;
}

async function retireCanvasSetupFixtures(state, retirementConfirmed, oauthDisconnected, { planOnly = false } = {}) {
  if (!state.owned || Object.keys(state.owned.resources).length === 0) {
    return { scope: 'OWNED_CANVAS_FIXTURE_RETIREMENT', complete: true, resources: [] };
  }
  const { adminPage, canvasOrigin, accountId } = state;
  const findKey = key => findCanvasDeveloperKey(state, key);
  const selectKey = async key => {
    // Recovery sessions have not created the token that normally selects English.
    // Pin only this browser session before using English accessible action names.
    await adminPage.goto(canvasDeveloperKeysUrl(canvasOrigin, accountId), {
      waitUntil: 'domcontentloaded', timeout: DEFAULT_TIMEOUT_MS,
    });
    const row = adminPage.getByRole('row').filter({ has: adminPage.getByText(key.name, { exact: true }) });
    await row.waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });
    assert.equal(await row.count(), 1);
    assert.ok((await row.innerText()).includes(key.id), 'Canvas key row does not show the owned client ID');
    assert.equal(await row.getByRole('button', { name: /delete/i }).count(), 1);
    return row;
  };
  return retireOwnedCanvasFixtures({ ...state, retirementConfirmed, oauthDisconnected, planOnly, developerKeys: {
    async identity(key) {
      const current = await findKey(key);
      assert.ok(current, 'Canvas external tool key is not in its account inventory');
      return { id: current.id, binding: current.developer_key_account_binding };
    },
    async check(key) {
      if (!(await findKey(key))) return false;
      await selectKey(key);
      return true;
    },
    async remove(key) {
      assert.ok(await findKey(key), 'Canvas key disappeared before its UI operation');
      const row = await selectKey(key);
      const deleted = adminPage.waitForResponse(response => {
        const url = new URL(response.url());
        return response.request().method() === 'DELETE' && url.origin === canvasOrigin
          && /\/(?:developer_keys|lti_registrations)\//.test(url.pathname);
      }, { timeout: DEFAULT_TIMEOUT_MS }).then(response => ({ response }), () => ({ timeout: true }));
      const onDialog = dialog => {
        void (/delete|remove/i.test(dialog.message()) ? dialog.accept() : dialog.dismiss()).catch(() => {});
      };
      adminPage.on('dialog', onDialog);
      try {
        await row.getByRole('button', { name: /delete/i }).click();
        const dialog = adminPage.getByRole('dialog', { name: /delete|remove/i });
        if (await dialog.waitFor({ state: 'visible', timeout: 1_000 }).then(() => true, () => false)) {
          await dialog.getByRole('button', { name: /^delete(?: key| developer key| registration)?$/i }).click();
        }
        const result = await deleted;
        assert.ok(result.response && [200, 204].includes(result.response.status()));
      } finally {
        adminPage.off('dialog', onDialog);
      }
      assert.equal(await findKey(key), null, 'Canvas key remains after the UI deletion');
    },
  } });
}

function createCanvasCaptureCustody(runSuffix, directory = process.env.DEMO_CANVAS_PRIVATE_RECOVERY_DIRECTORY) {
  requireCondition(path.isAbsolute(directory || '') && fs.lstatSync(directory).isDirectory()
    && !fs.lstatSync(directory).isSymbolicLink(), 'canvas_private_custody_missing', 'Capture requires its protected owned recovery mount.');
  requireCondition(/^[A-Za-z0-9-]{8,100}$/.test(runSuffix), 'canvas_run_identity_invalid', 'Private custody needs the exact fresh run.');
  const files = new Set(), secretFiles = new Map(), journal = path.join(directory,runSuffix+'.custody.json');
  const write = (filename,value,exclusive,secret=false) => {
    const fd=fs.openSync(filename,exclusive?'wx':'w',0o600);
    try {
      if(secret) {const stat=fs.fstatSync(fd);secretFiles.set(filename,{dev:stat.dev,ino:stat.ino});}
      fs.writeFileSync(fd,value);fs.fsyncSync(fd);
    } finally {fs.closeSync(fd);}
  };
  write(journal,JSON.stringify({runSuffix,state:'OPEN',roles:[]}),true);
  const checkpoint = state => {
    const stat=fs.lstatSync(journal);assert(stat.isFile()&&!stat.isSymbolicLink());
    const next=journal+'.next';write(next,JSON.stringify({runSuffix,state,roles:[...files]}),true);fs.renameSync(next,journal);
  };
  return {
    retain(role,value) {
      requireCondition(['canvasAdminSession','canvasLearnerSession','canvasOwnedClientSecret','betaAdminSession'].includes(role)
        && typeof value==='string' && value.length>0 && Buffer.byteLength(value)<=131072,
      'canvas_private_custody_invalid','Only bounded owned authority can enter capture recovery.');
      const filename=path.join(directory,runSuffix+'-'+role+'.json');
      if(files.has(role)) {
        const expected=secretFiles.get(filename),actual=fs.lstatSync(filename);
        requireCondition(expected&&actual.dev===expected.dev&&actual.ino===expected.ino,
          'canvas_private_custody_changed','Private recovery file ownership changed.');
        requireCondition(fs.lstatSync(filename).isFile()&&!fs.lstatSync(filename).isSymbolicLink(),
          'canvas_private_custody_changed','Owned recovery file changed.');
        const next=filename+'.next';write(next,value,true,true);fs.renameSync(next,filename);
        secretFiles.set(filename,secretFiles.get(next));secretFiles.delete(next);
      } else {files.add(role);checkpoint('OPEN');write(filename,value,true,true);}
      checkpoint('OPEN');
    },
    retire() {
      for(const [filename,expected] of secretFiles) {
        const actual=fs.lstatSync(filename);
        requireCondition(actual.dev===expected.dev&&actual.ino===expected.ino,
          'canvas_private_custody_changed','Private recovery file ownership changed.');
        requireCondition(fs.lstatSync(filename).isFile()&&!fs.lstatSync(filename).isSymbolicLink(),
          'canvas_private_custody_changed','Owned recovery file changed.');
        fs.unlinkSync(filename);
      }
      checkpoint('RETIRED'); return true;
    },
  };
}

function requireCanvasSetupMutationReconciliation(state) {
  requireCondition(!state.bindingActivationPossible||Boolean(state.applicationId),
    'canvas_background_application_uncertain','An activated owned binding without its returned application tuple requires reconciliation.');
  for(const field of ['martyPlatformIntent','martySecretIntent']) {
    const intent=state.owned?.[field];
    requireCondition(!intent||intent.state==='CREATED','canvas_setup_creation_uncertain','Owned Canvas setup creation requires exact reconciliation.');
  }
}

async function retireCanvasOAuthAuthority(state, observe = () => {}, {requireAccess = false} = {}) {
  const {retireOwnedOAuthConnection}=require('./audit-beta-canvas-invalid-secret');
  const gateway=(requestPath,{method='GET',body}={})=>state.marty.request(method,requestPath,
    {json:body,expected:[200],includeStatus:true});
  return retireOwnedOAuthConnection(gateway,{},state.organizationId,state.platformId,observe,{requireAccess});
}

async function retireCanvasOwnedReferences(state) {
  requireCanvasSetupMutationReconciliation(state);
  if(state.platformId) {
    const target=`/v1/integrations/canvas/platforms/${encodeURIComponent(state.platformId)}`;
    await state.marty.delete(target,[204]);await state.marty.request('GET',target,{expected:[404]});
  }
  if(state.integrationSecretId) {
    await state.marty.delete(`/v1/integrations/canvas/integration-secrets/${encodeURIComponent(state.integrationSecretId)}`,[204]);
    const remaining=await state.marty.get('/v1/integrations/canvas/integration-secrets?organization_id='+encodeURIComponent(state.organizationId)+'&provider=canvas');
    assert(Array.isArray(remaining));assert(!remaining.some(row=>row.id===state.integrationSecretId));
  }
}

async function retireCanvasCaptureSessions(state, observe = () => {}) {
  const {retireCanvasSession}=require('./audit-beta-canvas-invalid-secret');
  const evidence={},failures=[];
  const emit=()=>{try {observe(JSON.parse(JSON.stringify(evidence)));} catch(error) {failures.push(error);}};
  for(const [role,context] of [['canvasLearnerSession',state.learnerContext],['canvasAdminSession',state.adminContext]]) {
    if(!context) continue;
    try {
    const cookies=await context.cookies(state.canvasOrigin);
    requireCondition(cookies.length>0,'canvas_session_custody_missing','Owned Canvas session acquisition requires reconciliation.');
    const response=await context.request.get(state.canvasOrigin+'/api/v1/users/self/profile',
      {maxRedirects:0,timeout:15000,headers:{Accept:'application/json'}});
    if([401,403].includes(response.status())) evidence[role]={alreadyDenied:true,status:response.status()};
    else {
      assert.equal(response.status(),200);
      await context.addCookies(cookies.map(cookie=>({...cookie})));
      await retireCanvasSession(context,(_,value)=>state.custody.retain(role,value),
        {observe:value=>{evidence[role]=value;emit()}});
    }
    emit();
    } catch(error) {failures.push(error);evidence[role]={retired:false,failureType:'OWNED_SESSION_RETIREMENT_FAILED'};emit();}
  }
  requireCondition(failures.length===0,'canvas_capture_sessions_incomplete','Owned Canvas sessions require reconciliation.');
  return evidence;
}

async function retireCanvasBetaSession(context, custody) {
  const origin=DEFAULT_MARTY_ORIGIN,cookies=await context.cookies(origin);
  requireCondition(cookies.length>0,'capture_beta_session_missing','Owned beta session custody is missing.');
  let custodyFailure;try {custody.retain('betaAdminSession',JSON.stringify(cookies));} catch(error) {custodyFailure=error;}
  const original=cookies.map(cookie=>cookie.name+'='+cookie.value).join('; ');
  let response,logoutFailure;
  try {response=await context.request.post(origin+'/v1/auth/logout',{maxRedirects:0,timeout:15000});} catch(error) {logoutFailure=error;}
  const old=await context.request.get(origin+'/v1/auth/me',{headers:{Cookie:original},maxRedirects:0,timeout:15000});
  const body=await old.json();
  requireCondition(!logoutFailure&&[302,303,307].includes(response?.status()),'capture_beta_logout_failed','Owned beta logout did not complete.');
  requireCondition(old.status()===200&&body.authenticated===false&&body.user==null,
    'capture_beta_session_authorized','Original beta session is not retired.');
  if(custodyFailure) throw custodyFailure;
  return {logoutStatus:response.status(),oldCookieAuthenticated:false};
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

  const preparationState = {};
  const markActive = (id) => { activeCase = id; };
  const pass = (id, evidence) => { ledger.pass(id, evidence); };

  try {
    const setup = await prepareCanvasCaptureFixtures({
      browser: browser = await chromium.launch({ headless: true }), ledger, markActive, pass, state: preparationState,
      runSuffix: `${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`,
      prerequisiteDirectory: path.dirname(args.observations), ownershipDirectory: path.dirname(args.observations),
    });
    ({ marty, adminContext, learnerContext, platformId, integrationSecretId } = setup);
    const { canvasOrigin, martyOrigin, organizationId, martyApiKey, learnerCanvas, adminCanvas,
      fixtures, templates, binding, pinnedBinding, externalAssignment, activityResults } = setup;
    recordedContext = await browser.newContext({
      viewport: { width: 1440, height: 900 },
      ...(!args.functionalRerun ? {recordVideo:{dir:path.dirname(args.video),size:{width:1440,height:900}}} : {}),
    });
    await copyCookies(learnerContext, recordedContext);
    recordedPage = await recordedContext.newPage();
    await recordedPage.goto(`${canvasOrigin}/courses/${fixtures.course.id}/grades`, { waitUntil: 'domcontentloaded', timeout: DEFAULT_TIMEOUT_MS });
    await showVideoStep(recordedPage, 'Canvas evidence is complete', 'The learner completed a native assignment, a Classic Quiz, and the module in stock Canvas.');

    markActive('learner_resource_launch');
    const firstLaunch = await launchLearnerResource(recordedPage, learnerCanvas, fixtures, externalAssignment, martyOrigin);
    recordedPage = firstLaunch.page;
    const firstBootstrap = firstLaunch.bootstrap;
    preparationState.applicationId = firstBootstrap.application_id;
    preparationState.owned.martyApplicationId=firstBootstrap.application_id;preparationState.persistOwned();
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
      `/v1/organizations/${encodeURIComponent(organizationId)}/applicants/${encodeURIComponent(firstBootstrap.application_id)}/evidence-facts?current_only=true`,
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
    await waitForCanvasCourseCompletion(adminCanvas, fixtures);
    const recoveredSync = await triggerLearnerSync(recordedPage, marty);
    requireCondition(recoveredSync.job?.result?.policy_allowed === true, 'pre_issuance_recovery_not_applied', 'The corrected pre-issuance score did not restore the current permit decision.');
    pass('pre_issuance_grade_correction', 'A 95 to 40 to 95 score revision denied then restored policy before issuance; current evidence heads won.');

    markActive('kms_open_badge_claim_and_verify');
    const approvalPath = `/v1/integrations/canvas/applications/${encodeURIComponent(firstBootstrap.application_id)}/approve`;
    const approvalBody = {
      review_notes: 'Approved by the Canvas OSS portability contract after authoritative policy permit.',
    };
    preparationState.approvalInFlight = true;
    const concurrentApprovals = await Promise.all([
      marty.post(approvalPath, approvalBody, [200, 409]),
      marty.post(approvalPath, approvalBody, [200, 409]),
    ]);
    const reservedTransactionIds = concurrentApprovals
      .map((result) => String(result?.issuance_transaction_id || '').trim())
      .filter(Boolean);
    requireCondition(reservedTransactionIds.length >= 1, 'canvas_approval_reservation_missing', 'Concurrent Canvas approvals did not reserve a claim transaction.');
    requireCondition(new Set(reservedTransactionIds).size === 1, 'duplicate_canvas_claim_transaction', 'Concurrent Canvas approvals reserved different claim transactions.');
    preparationState.transactionId = reservedTransactionIds[0];
    preparationState.approvalInFlight = false;
    await reloadLearnerExperience(recordedPage);
    await recordedPage.getByTestId('canvas-ready-to-claim').waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT_MS });

    const preClaimCredentials = safeList(await marty.get(`/v1/issued-credentials?organization_id=${encodeURIComponent(organizationId)}`))
      .filter((record) => String(record.application_id) === String(firstBootstrap.application_id));
    requireCondition(preClaimCredentials.length === 0, 'background_claim_signed_early', 'A credential existed before the learner wallet claim.');

    const claimResponsePromise = recordedPage.waitForResponse((response) => (
      response.request().method() === 'POST'
        && new URL(response.url()).pathname === '/v1/integrations/canvas/lti/experience-sessions/current/claim'
    ), { timeout: DEFAULT_TIMEOUT_MS });
    await recordedPage.getByTestId('canvas-claim-action').click();
    const claimResponse = await claimResponsePromise;
    const claim = await responseJson(claimResponse, 'canvas_claim_offer_failed', 'Canvas learner claim offer failed', [200]);
    requireCondition(claim.id === firstBootstrap.application_id
      && claim.organization_id === organizationId
      && claim.transaction_id === reservedTransactionIds[0],
    'canvas_claim_binding_mismatch', 'Learner claim did not reuse the exact approved application transaction.');
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
    await retireCanvasOAuthAuthority(preparationState, value => {preparationState.oauthRetirement=value}, {requireAccess:true});
    preparationState.oauthConnected = false;preparationState.oauthMayExist=false;
    pass('canvas_oauth_authorization', 'A stock scoped Canvas API key connected through capability-derived OAuth and its token was remotely revoked on disconnect.');

    await showVideoStep(recordedPage, 'Portable Canvas contract complete', 'Unmodified Canvas, standard LTI Advantage, documented REST APIs, durable evidence, and external KMS issuance all passed.');
    if (args.functionalRerun) await recordedContext.close();
    else await finishRecordedVideo(recordedContext, recordedPage, args.video);
    recordedContext = null;
    recordedPage = null;
    videoWritten = true;

    requireCondition(activityResults.nativeSubmission && activityResults.quizSubmissionRecord, 'activity_observations_missing', 'Canvas activity observations were not retained in memory.');
    requireCondition(ledger.allOssRequiredPassed(), 'required_observation_missing', 'One or more required OSS observations did not pass.');
  } catch (error) {
    ledger.driverFailure = contractFailureLocation(error, activeCase);
    failure = error instanceof ContractFailure
      ? error
      : new ContractFailure('unexpected_driver_failure', 'The standard Canvas contract stopped on an unexpected driver error.');
    if (CASE_IDS.includes(activeCase) && !['new_quizzes_authoritative_submission', 'canvas_credentials_projection'].includes(activeCase)) {
      ledger.fail(activeCase, `${failure.code}: ${failure.message}`);
    }
  } finally {
    ledger.write(args.observations);
    if (ledger.driverFailure) fs.writeFileSync(path.join(path.dirname(args.observations), 'driver-failure-location.json'),
      JSON.stringify(ledger.driverFailure, null, 2) + '\n');

    if (recordedContext) {
      try {
        if (args.functionalRerun) await recordedContext.close();
        else await finishRecordedVideo(recordedContext, recordedPage, args.video);
        videoWritten = true;
      } catch {
        videoWritten = false;
      }
      recordedContext = null;
    }

    marty ||= preparationState.marty;
    platformId ||= preparationState.platformId;
    integrationSecretId ||= preparationState.integrationSecretId;
    adminContext ||= preparationState.adminContext;
    learnerContext ||= preparationState.learnerContext;
    try {
      requireCanvasSetupMutationReconciliation(preparationState);
      const issuanceRetirement = await retireCanvasApplication({ marty, organizationId: preparationState.organizationId,
        applicationId: preparationState.applicationId, credentialTemplateId: preparationState.templates?.credential?.id,
        bindingId: preparationState.binding?.id,
        transactionId: preparationState.transactionId, reconcile() {
          assert.ok(!preparationState.approvalInFlight, 'Unknown Canvas approval requires reconciliation');
        } });
      if (marty && platformId && (preparationState.oauthConnected||preparationState.oauthMayExist)) {
        await retireCanvasOAuthAuthority(preparationState, value => {preparationState.oauthRetirement=value}, {requireAccess:false});
        preparationState.oauthConnected = false;preparationState.oauthMayExist=false;
      }
      if (marty) await retireCanvasOwnedReferences(preparationState);
      const retired = await retireCanvasSetupFixtures(preparationState, true, !preparationState.oauthConnected);
      retired.issuanceRetirement = issuanceRetirement;
      if (preparationState.custody) {
        retired.sessionRetirement=await retireCanvasCaptureSessions(preparationState,value=>fs.writeFileSync(
          path.join(path.dirname(args.observations),'owned-canvas-session-retirement.json'),JSON.stringify(value,null,2)+'\n'));
        retired.sessionsRetired=true;retired.privateAuthorityRetired=preparationState.custody.retire();
      }
      fs.writeFileSync(path.join(path.dirname(args.observations), 'owned-canvas-cleanup.json'),
        JSON.stringify(retired, null, 2) + '\n', { flag: 'wx' });
    } catch (error) {
      failure ||= new ContractFailure('owned_canvas_cleanup_incomplete', 'Run-owned Canvas resources require recovery; custody is retained.');
      const cleanupFailure = contractFailureLocation(error, 'owned_fixture_cleanup');
      ledger.driverFailure ||= cleanupFailure;
      fs.writeFileSync(path.join(path.dirname(args.observations), 'owned-canvas-cleanup-failure.json'),
        JSON.stringify(cleanupFailure, null, 2) + '\n', { flag: 'wx' });
    }
    ledger.write(args.observations);
    if (ledger.driverFailure) fs.writeFileSync(path.join(path.dirname(args.observations), 'driver-failure-location.json'),
      JSON.stringify(ledger.driverFailure, null, 2) + '\n');
    if (learnerContext) await learnerContext.close().catch(() => {});
    if (adminContext) await adminContext.close().catch(() => {});

    if (!args.functionalRerun && !videoWritten && browser) {
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
  authorizeCanvasOAuth,
  canvasOAuthRedirectChecks,
  saveDeveloperKey,
  enableDeveloperKey,
  requireSecretFile,
  parseArgs,
  loginCanvas,
  createOauthDeveloperKey,
  createCanvasCaptureCustody,
  requireCanvasSetupMutationReconciliation,
  retireCanvasOAuthAuthority,
  retireCanvasOwnedReferences,
  retireCanvasCaptureSessions,
  retireCanvasBetaSession,
  createLtiDeveloperKey,
  retireCanvasApplication,
  retireCanvasSetupFixtures,
  CanvasClient,
  CanvasSessionClient,
  findCanvasDeveloperKey,
  waitForCanvasCourseCompletion,
  canvasLaunchErrorSummary,
  canvasOwnedToolIndex,
  assertCanvasOauthCompletion,
  publishCanvasCourse,
  contractFailureLocation,
  canvasTokenExpiration,
  selectCanvasTokenExpirationTime,
  freshCanvasLearnerEmail,
  martyRequestSummary,
  selectProductionBadgeTemplates,
  selectCanvasOauthScopes,
  observePipelinePrerequisites,
  prepareCanvasCaptureFixtures,
  validateAndActivateBinding,
  waitForLatestRosterJob,
  waitForCandidate,
  launchLearnerResource,
  triggerLearnerSync,
  reloadLearnerExperience,
  waitFor,
  waitForJob,
  BLOCKING_READINESS_CHECK_CODES,
  CASE_IDS,
  CANVAS_OAUTH_SCOPES,
  ContractFailure,
  ObservationLedger,
  createHolderProof,
  didWebResolutionUrl,
  extractDeveloperKeyRecord,
  parseCredentialOfferUri,
  receiveAndVerifyCredential,
  resolveOid4vciEndpoints,
  resolveProofNonce,
  requireComposeExecutionBoundary,
  requireSecretFile,
  responseJson,
  sanitizeEvidence,
  validateAuthoritativeEvidenceHeads,
  validateReadinessSnapshot,
  verifyCompactJws,
  verifyCompactJwsStructure,
  verificationMethodFromDidDocument,
};

if (require.main === module) {
  main().then((code) => {
    process.exitCode = code;
  }).catch(() => {
    process.stderr.write('Canvas OSS standard contract failed before safe finalization.\n');
    process.exitCode = 1;
  });
}
