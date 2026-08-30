import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { createGatewayClient, normalizeGatewayOrigin } from './gateway.mjs';
import { verifyMartyWebhook } from './webhook.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const publicDir = join(root, 'public');
const MAX_JSON_BODY_BYTES = 64 * 1024;

function requireSecret(name, value, minimumLength = 16) {
  const candidate = String(value || '');
  if (candidate.length < minimumLength || /change[-_ ]?me|replace[-_ ]?me|placeholder/i.test(candidate)) {
    throw new Error(`${name} is required and must not be a placeholder`);
  }
  return candidate;
}

async function readJsonBody(request) {
  const contentType = String(request.headers?.['content-type'] || '').split(';', 1)[0].trim().toLowerCase();
  if (contentType !== 'application/json') {
    return { error: { status: 415, body: { status: 'rejected', code: 'JSON_CONTENT_TYPE_REQUIRED' } } };
  }
  const declaredLength = Number(request.headers?.['content-length']);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_JSON_BODY_BYTES) {
    request.resume?.();
    return { error: { status: 413, body: { status: 'rejected', code: 'BODY_TOO_LARGE' } } };
  }
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += bytes.length;
    if (length > MAX_JSON_BODY_BYTES) {
      request.resume?.();
      return { error: { status: 413, body: { status: 'rejected', code: 'BODY_TOO_LARGE' } } };
    }
    chunks.push(bytes);
  }
  try {
    return { value: JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}') };
  } catch {
    return { error: { status: 400, body: { status: 'rejected', code: 'INVALID_JSON' } } };
  }
}

export function createNorthstarApp(config, { fetchImpl = fetch } = {}) {
  const gatewayOrigin = normalizeGatewayOrigin(config.gatewayOrigin);
  const runtimeKey = requireSecret('runtimeKey', config.runtimeKey);
  const readOnlyKey = requireSecret('readOnlyKey', config.readOnlyKey);
  const evidenceKey = requireSecret('evidenceKey', config.evidenceKey);
  const webhookSecret = requireSecret('webhookSecret', config.webhookSecret, 32);
  const organizationId = String(config.organizationId || '').trim();
  const applicationId = String(config.applicationId || '').trim();
  const webhookId = String(config.webhookId || '').trim();
  if (!organizationId || !applicationId || !webhookId) {
    throw new Error('organizationId, applicationId, and webhookId are required');
  }
  const state = {
    applicationStatus: 'SUBMITTED',
    enrollmentStatus: 'Waiting for approval',
    webhookStatus: 'Waiting for signed event',
    webhookEvents: [],
    processedEventIds: new Set(),
    gatewayRequests: [],
    lastGatewayResult: null,
    deliveryEvidence: null,
  };
  const gateway = createGatewayClient({
    origin: gatewayOrigin,
    fetchImpl,
    observe: (request) => state.gatewayRequests.push(request),
  });

  function safeState() {
    return {
      partner: 'Northstar Admissions',
      syntheticData: true,
      gatewayOrigin,
      organizationId,
      application: { id: applicationId, status: state.applicationStatus },
      integration: {
        runtimeKeyPrefix: String(config.runtimeKeyPrefix || 'mk_live_••••'),
        runtimeScopes: ['applications:read', 'applications:approve'],
        readOnlyScopes: ['applications:read'],
        callbackUrl: String(config.callbackUrl || 'https://admissions-test.elevenidllc.com/webhooks/marty'),
        subscriptionEvent: 'application.approved',
      },
      enrollmentStatus: state.enrollmentStatus,
      webhookStatus: state.webhookStatus,
      webhookEvents: state.webhookEvents,
      gatewayRequests: state.gatewayRequests,
      lastGatewayResult: state.lastGatewayResult,
      deliveryEvidence: state.deliveryEvidence,
    };
  }

  async function approve(mode) {
    const apiKey = mode === 'read-only' ? readOnlyKey : runtimeKey;
    const result = await gateway(
      `/v1/organizations/${encodeURIComponent(organizationId)}/applicants/${encodeURIComponent(applicationId)}/approve`,
      { method: 'POST', organizationId, apiKey, body: { notes: 'Approved by Northstar Admissions' } },
    );
    state.lastGatewayResult = { mode, status: result.status, requestId: result.requestId, detail: result.payload?.detail };
    const refreshed = await refreshApplication();
    if (refreshed.status !== 200) {
      return { ok: false, status: refreshed.status, requestId: result.requestId, payload: refreshed.body };
    }
    return result;
  }

  async function refreshApplication() {
    const result = await gateway(
      `/v1/organizations/${encodeURIComponent(organizationId)}/applicants`,
      { method: 'GET', organizationId, apiKey: readOnlyKey },
    );
    if (!result.ok) return { status: result.status, body: { detail: result.payload?.detail || 'Applicant lookup failed' } };
    const applicants = Array.isArray(result.payload)
      ? result.payload
      : result.payload?.applicants || result.payload?.applications || result.payload?.items || [];
    const application = applicants.find((item) => item.id === applicationId || item.application_id === applicationId);
    if (!application) return { status: 404, body: { detail: 'Prepared application was not returned by the public gateway' } };
    state.applicationStatus = String(application.status || '').toUpperCase();
    return { status: 200, body: { application_id: applicationId, status: state.applicationStatus } };
  }

  async function receiveWebhook(request) {
    const parsed = await readJsonBody(request);
    if (parsed.error) return parsed.error;
    const payload = parsed.value;
    const verification = verifyMartyWebhook({ secret: webhookSecret, headers: request.headers, payload });
    if (!verification.ok) {
      state.webhookStatus = `Rejected: ${verification.code}`;
      return { status: 401, body: { status: 'rejected', code: verification.code } };
    }
    if (payload.organization_id !== organizationId || payload.data?.application_id !== applicationId) {
      state.webhookStatus = 'Rejected: event scope mismatch';
      return { status: 422, body: { status: 'rejected', code: 'EVENT_SCOPE_MISMATCH' } };
    }
    if (state.processedEventIds.has(payload.id)) {
      return { status: 200, body: { status: 'duplicate_ignored', event_id: payload.id } };
    }
    state.processedEventIds.add(payload.id);
    state.webhookEvents.push({
      eventId: payload.id,
      type: payload.type,
      timestamp: payload.timestamp,
      deliveryId: request.headers['x-mip-delivery-id'] || null,
      verified: true,
    });
    state.webhookStatus = 'Signature verified';
    state.enrollmentStatus = 'Enrollment workflow ready';
    return { status: 200, body: { status: 'processed', event_id: payload.id } };
  }

  async function refreshDeliveryEvidence() {
    const eventId = state.webhookEvents.at(-1)?.eventId;
    if (!eventId) return { status: 409, body: { detail: 'No verified webhook event is available' } };
    const result = await gateway(
      `/v1/webhooks/${encodeURIComponent(webhookId)}/deliveries?organization_id=${encodeURIComponent(organizationId)}`,
      { method: 'GET', organizationId, apiKey: evidenceKey },
    );
    const deliveries = Array.isArray(result.payload) ? result.payload : result.payload?.deliveries || [];
    const match = deliveries.find((delivery) => delivery.event_id === eventId);
    if (result.ok && match) {
      state.deliveryEvidence = {
        eventId: match.event_id,
        deliveryId: match.id || match.delivery_id,
        status: match.status || (match.success === true ? 'DELIVERED' : match.success === false ? 'FAILED' : 'UNKNOWN'),
        responseStatusCode: match.response_status_code,
      };
    }
    return {
      status: result.ok ? (match ? 200 : 202) : result.status,
      body: match ? state.deliveryEvidence : { detail: result.payload?.detail || 'Delivery record is not available yet' },
    };
  }

  return { state, safeState, approve, receiveWebhook, refreshApplication, refreshDeliveryEvidence };
}

function json(response, status, body) {
  response.writeHead(status, responseHeaders('application/json; charset=utf-8'));
  response.end(JSON.stringify(body));
}

function responseHeaders(contentType) {
  return {
    'content-type': contentType,
    'cache-control': 'no-store',
    'content-security-policy': "default-src 'self'; base-uri 'none'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self'; style-src 'self'",
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
  };
}

export function loadRunConfig(config = process.env) {
  let run = {};
  if (config.NORTHSTAR_RUN_SECRET_FILE) {
    run = JSON.parse(readFileSync(config.NORTHSTAR_RUN_SECRET_FILE, 'utf8'));
  }
  return {
    gatewayOrigin: config.MARTY_PUBLIC_GATEWAY_ORIGIN || run.gateway_origin,
    organizationId: config.NORTHSTAR_ORGANIZATION_ID || run.organization_id,
    applicationId: config.NORTHSTAR_APPLICATION_ID || run.application_id,
    webhookId: config.NORTHSTAR_WEBHOOK_ID || run.webhook_id,
    runtimeKey: config.NORTHSTAR_RUNTIME_API_KEY || run.runtime_api_key,
    readOnlyKey: config.NORTHSTAR_READ_ONLY_API_KEY || run.read_only_api_key,
    evidenceKey: config.NORTHSTAR_EVIDENCE_API_KEY || run.evidence_api_key,
    runtimeKeyPrefix: config.NORTHSTAR_RUNTIME_KEY_PREFIX || run.runtime_key_prefix,
    webhookSecret: config.NORTHSTAR_WEBHOOK_SECRET || run.webhook_signing_secret,
    callbackUrl: config.NORTHSTAR_CALLBACK_URL || run.callback_url,
  };
}

export function startServer(config = process.env) {
  const app = createNorthstarApp(loadRunConfig(config));
  const server = createServer(async (request, response) => {
    const url = new URL(request.url, 'http://northstar.local');
    if (request.method === 'GET' && url.pathname === '/api/demo-state') return json(response, 200, app.safeState());
    if (request.method === 'POST' && url.pathname === '/api/applications/refresh') {
      const result = await app.refreshApplication();
      return json(response, result.status, result.body);
    }
    if (request.method === 'POST' && url.pathname === `/api/applications/${encodeURIComponent(app.safeState().application.id)}/approve`) {
      const parsed = await readJsonBody(request);
      if (parsed.error) return json(response, parsed.error.status, parsed.error.body);
      const result = await app.approve(parsed.value.mode);
      return json(response, result.status, { status: result.status, requestId: result.requestId, detail: result.payload?.detail });
    }
    if (request.method === 'POST' && url.pathname === '/webhooks/marty') {
      const result = await app.receiveWebhook(request);
      return json(response, result.status, result.body);
    }
    if (request.method === 'POST' && url.pathname === '/api/delivery-evidence/refresh') {
      const result = await app.refreshDeliveryEvidence();
      return json(response, result.status, result.body);
    }
    const asset = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
    if (request.method === 'GET' && ['index.html', 'app.js', 'styles.css'].includes(asset)) {
      const content = await readFile(join(publicDir, asset));
      const contentType = asset.endsWith('.html') ? 'text/html' : asset.endsWith('.js') ? 'text/javascript' : 'text/css';
      response.writeHead(200, responseHeaders(`${contentType}; charset=utf-8`));
      return response.end(content);
    }
    return json(response, 404, { detail: 'Not found' });
  });
  const port = Number(config.PORT || 4175);
  server.listen(port, config.HOST || '127.0.0.1');
  server.headersTimeout = 10_000;
  server.requestTimeout = 10_000;
  return { app, server };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) startServer();
