import { createApiClient } from '@elevenid/marty-api-core';

const baseUrl = import.meta.env.VITE_API_URL || '';
const prefix = '/v1/flows/public/verification';
const client = createApiClient({
  baseUrl,
  // This public client deliberately has no browser login/session authority.
  requestOptions: () => ({ credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer', redirect: 'error' }),
});

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const revision = /^sha256:[0-9a-f]{64}$/;
const slug = /^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$/;
const validSlug = value => typeof value === 'string' && slug.test(value);
const statuses = new Set(['awaiting_wallet', 'verifying', 'completed', 'failed', 'cancelled', 'expired']);

function invalidResponse() {
  const error = new Error('Verification response unavailable');
  error.code = 'verification_response_invalid';
  return error;
}

function text(value, maximum) {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum;
}

function publicCatalog(value) {
  if (!value || !revision.test(value.revision) || !text(value.notice, 2048)
    || !Array.isArray(value.scenarios) || value.scenarios.length < 1 || value.scenarios.length > 8) throw invalidResponse();
  if (!value.retention_policy || value.retention_policy.result_access_seconds !== 600 || value.retention_policy.receipt_days !== 30) throw invalidResponse();
  const retention_policy = { result_access_seconds: value.retention_policy.result_access_seconds, receipt_days: value.retention_policy.receipt_days };
  const scenarioIds = new Set();
  const scenarios = value.scenarios.map(scenario => {
    if (!scenario || !validSlug(scenario.id) || scenarioIds.has(scenario.id) || !text(scenario.label, 120)
      || !Array.isArray(scenario.choices) || scenario.choices.length < 1 || scenario.choices.length > 8) throw invalidResponse();
    scenarioIds.add(scenario.id);
    const ids = new Set();
    const choices = scenario.choices.map(choice => {
      if (!choice || !validSlug(choice.id) || ids.has(choice.id) || !text(choice.label, 160)) throw invalidResponse();
      ids.add(choice.id);
      return { id: choice.id, label: choice.label };
    });
    return { id: scenario.id, label: scenario.label, choices };
  });
  const examples = value.examples ?? [];
  if (!Array.isArray(examples) || examples.length > 16) throw invalidResponse();
  const exampleIds = new Set();
  const projectedExamples = examples.map(example => {
    if (!example || !validSlug(example.id) || exampleIds.has(example.id) || !scenarioIds.has(example.scenario_id)
      || !text(example.label, 120) || !text(example.description, 400)) throw invalidResponse();
    exampleIds.add(example.id);
    return { id: example.id, scenario_id: example.scenario_id, label: example.label, description: example.description };
  });
  return { revision: value.revision, notice: value.notice, retention_policy, scenarios, examples: projectedExamples };
}

function publicPreview(value, selection) {
  if (!value || value.catalog_revision !== selection.catalog_revision || value.scenario_id !== selection.scenario_id
    || value.choice_id !== selection.choice_id || !/^[0-9a-f]{64}$/.test(value.request_digest)
    || !Array.isArray(value.claims) || value.claims.length < 1 || value.claims.length > 16) throw invalidResponse();
  const names = new Set();
  const scalar = value => typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value)) || text(value, 160);
  const kinds = new Set(['presence', 'equals', 'not_equals', 'greater_than', 'less_than', 'greater_or_equal', 'less_or_equal', 'in_set', 'not_in_set', 'regex', 'age_over']);
  const claims = value.claims.map(claim => {
    if (!claim || !text(claim.name, 128) || names.has(claim.name) || !text(claim.display_name, 160) || typeof claim.required !== 'boolean'
      || (claim.purpose != null && !text(claim.purpose, 400)) || (claim.intent_to_retain != null && typeof claim.intent_to_retain !== 'boolean')
      || !Array.isArray(claim.constraints) || claim.constraints.length > 4) throw invalidResponse();
    names.add(claim.name);
    const constraints = claim.constraints.map(item => {
      if (!item || !kinds.has(item.kind) || (item.value != null && !scalar(item.value)
        && !(Array.isArray(item.value) && item.value.length <= 8 && item.value.every(scalar)))) throw invalidResponse();
      return { kind: item.kind, value: item.value ?? null };
    });
    return { name: claim.name, display_name: claim.display_name, required: claim.required,
      purpose: claim.purpose ?? null, intent_to_retain: claim.intent_to_retain ?? null, constraints };
  });
  return { catalog_revision: value.catalog_revision, scenario_id: value.scenario_id, choice_id: value.choice_id,
    request_digest: value.request_digest, claims };
}

function publicSession(value) {
  if (!value || !uuid.test(value.session_id) || !validSlug(value.scenario_id) || !validSlug(value.choice_id)
    || !revision.test(value.catalog_revision) || !statuses.has(value.status)
    || !text(value.expires_at, 64) || !text(value.access_expires_at, 64)
    || !Number.isFinite(Date.parse(value.expires_at)) || !Number.isFinite(Date.parse(value.access_expires_at))
    || Date.parse(value.access_expires_at) !== Date.parse(value.expires_at) + 600_000) throw invalidResponse();
  if (value.example_id !== undefined && !validSlug(value.example_id)) throw invalidResponse();
  if (value.example_status !== undefined && (!value.example_id
    || !['running', 'input_rejected', 'retry_available', 'retry_exhausted'].includes(value.example_status)
    || !['awaiting_wallet', 'verifying'].includes(value.status))) throw invalidResponse();
  const pending = value.status === 'awaiting_wallet' || value.status === 'verifying';
  if (value.status === 'completed' ? value.verified !== true
    : value.status === 'failed' ? value.verified !== false : value.verified !== undefined) throw invalidResponse();
  if (pending && !value.example_id) {
    if (!text(value.wallet_uri, 8192)) throw invalidResponse();
    try {
      const uri = new URL(value.wallet_uri);
      if (uri.protocol !== 'openid4vp:' || uri.hostname !== 'authorize' || uri.username || uri.password || uri.hash) throw invalidResponse();
      if (uri.searchParams.getAll('request_uri').length !== 1 || uri.searchParams.getAll('client_id').length !== 1
        || !uri.searchParams.get('client_id')) throw invalidResponse();
      const request = new URL(uri.searchParams.get('request_uri'));
      const loopback = request.hostname === 'localhost' || request.hostname === '127.0.0.1' || request.hostname === '[::1]';
      if ((request.protocol !== 'https:' && !(request.protocol === 'http:' && loopback)) || request.username || request.password
        || request.pathname !== `/v1/flows/instances/${value.session_id}/request` || request.search || request.hash) throw invalidResponse();
    } catch { throw invalidResponse(); }
  } else if (value.wallet_uri !== undefined) throw invalidResponse();
  // Keep only the visitor contract. Never pass generic claims/provider data to
  // the page or its recovery storage if an upstream response adds extra fields.
  return { session_id: value.session_id, scenario_id: value.scenario_id, choice_id: value.choice_id,
    ...(value.example_id ? { example_id: value.example_id } : {}),
    ...(value.example_status ? { example_status: value.example_status } : {}),
    catalog_revision: value.catalog_revision, status: value.status, expires_at: value.expires_at,
    access_expires_at: value.access_expires_at, ...(pending && !value.example_id ? { wallet_uri: value.wallet_uri } : {}),
    ...(['completed', 'failed'].includes(value.status) ? { verified: value.verified } : {}) };
}

function sessionPath(id) {
  if (!uuid.test(id)) throw new Error('Invalid verification session');
  return `${prefix}/sessions/${id}`;
}

function publicOptions(options = {}) {
  return { signal: options.signal, credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer', redirect: 'error' };
}

function capabilityOptions(key, options) {
  if (typeof key !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(key)) throw new Error('Invalid verification capability');
  return { ...publicOptions(options), headers: { 'X-Verification-Session': key } };
}

export function createVerificationCapability() {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export const publicVerificationApi = {
  async catalog(options) { return publicCatalog(await client.get(`${prefix}/catalog`, publicOptions(options))); },
  async preview(selection, options) {
    const body = { catalog_revision: selection.catalog_revision, scenario_id: selection.scenario_id, choice_id: selection.choice_id };
    if (!revision.test(body.catalog_revision) || !validSlug(body.scenario_id) || !validSlug(body.choice_id)) throw new Error('Invalid preview selection');
    return publicPreview(await client.post(`${prefix}/preview`, body, publicOptions(options)), body);
  },
  async launch(selection, key, options) {
    // The capability remains in a header across retries, never in a URL/body.
    const body = { catalog_revision: selection.catalog_revision, scenario_id: selection.scenario_id,
      choice_id: selection.choice_id, consent: selection.consent === true,
      ...(selection.example_id !== undefined ? { example_id: selection.example_id } : {}),
      ...(selection.request_digest !== undefined ? { request_digest: selection.request_digest } : {}) };
    if (body.request_digest !== undefined && !/^[0-9a-f]{64}$/.test(body.request_digest)) throw new Error('Invalid request preview');
    if (body.example_id !== undefined && !validSlug(body.example_id)) throw new Error('Invalid example selection');
    const session = publicSession(await client.post(`${prefix}/sessions`, body, capabilityOptions(key, options)));
    if (session.catalog_revision !== body.catalog_revision || session.scenario_id !== body.scenario_id
      || session.choice_id !== body.choice_id || session.example_id !== body.example_id) throw invalidResponse();
    return session;
  },
  async session(id, key, options) {
    const session = publicSession(await client.get(sessionPath(id), capabilityOptions(key, options)));
    if (session.session_id !== id) throw invalidResponse();
    return session;
  },
  async example(id, key, options) {
    const session = publicSession(await client.post(`${sessionPath(id)}/example`, {}, capabilityOptions(key, options)));
    if (session.session_id !== id || !session.example_id) throw invalidResponse();
    return session;
  },
  async cancel(id, key, options) {
    const session = publicSession(await client.post(`${sessionPath(id)}/cancel`, {}, capabilityOptions(key, options)));
    if (session.session_id !== id || ['awaiting_wallet', 'verifying'].includes(session.status)) throw invalidResponse();
    return session;
  },
};
