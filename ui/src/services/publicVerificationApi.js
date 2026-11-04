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
  return { revision: value.revision, notice: value.notice, scenarios };
}

function publicSession(value) {
  if (!value || !uuid.test(value.session_id) || !validSlug(value.scenario_id) || !validSlug(value.choice_id)
    || !revision.test(value.catalog_revision) || !statuses.has(value.status)
    || !text(value.expires_at, 64) || !text(value.access_expires_at, 64)
    || !Number.isFinite(Date.parse(value.expires_at)) || !Number.isFinite(Date.parse(value.access_expires_at))
    || Date.parse(value.access_expires_at) !== Date.parse(value.expires_at) + 600_000) throw invalidResponse();
  const pending = value.status === 'awaiting_wallet' || value.status === 'verifying';
  if (value.status === 'completed' ? value.verified !== true
    : value.status === 'failed' ? value.verified !== false : value.verified !== undefined) throw invalidResponse();
  if (pending) {
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
    catalog_revision: value.catalog_revision, status: value.status, expires_at: value.expires_at,
    access_expires_at: value.access_expires_at, ...(pending ? { wallet_uri: value.wallet_uri } : {}),
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
  async launch(selection, key, options) {
    // The capability remains in a header across retries, never in a URL/body.
    const body = { catalog_revision: selection.catalog_revision, scenario_id: selection.scenario_id,
      choice_id: selection.choice_id, consent: selection.consent === true };
    const session = publicSession(await client.post(`${prefix}/sessions`, body, capabilityOptions(key, options)));
    if (session.catalog_revision !== body.catalog_revision || session.scenario_id !== body.scenario_id
      || session.choice_id !== body.choice_id) throw invalidResponse();
    return session;
  },
  async session(id, key, options) {
    const session = publicSession(await client.get(sessionPath(id), capabilityOptions(key, options)));
    if (session.session_id !== id) throw invalidResponse();
    return session;
  },
  async cancel(id, key, options) {
    const session = publicSession(await client.post(`${sessionPath(id)}/cancel`, {}, capabilityOptions(key, options)));
    if (session.session_id !== id || ['awaiting_wallet', 'verifying'].includes(session.status)) throw invalidResponse();
    return session;
  },
};
