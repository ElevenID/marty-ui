import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { createNorthstarApp, loadRunConfig, startServer } from '../src/server.mjs';
import { expectedSignature } from '../src/webhook.mjs';

const secret = '0123456789abcdef0123456789abcdef';
const approvalRequestId = '11111111-1111-4111-8111-111111111111';
const config = {
  gatewayOrigin: 'https://beta.elevenidllc.com', organizationId: 'org-1', applicationId: 'app-1',
  webhookId: 'webhook-1', runtimeKey: 'mk_live_runtime-secret', readOnlyKey: 'mk_live_readonly-secret',
  evidenceKey: 'mk_live_evidence-secret', webhookSecret: secret,
  callbackUrl: 'https://admissions-test.elevenidllc.com/webhooks/marty',
};

function webhookRequest(payload, signature = expectedSignature(secret, payload)) {
  const body = Buffer.from(JSON.stringify(payload));
  return {
    headers: {
      'content-type': 'application/json',
      'x-mip-signature': signature, 'x-mip-event': payload.type, 'x-mip-event-id': payload.id,
      'x-mip-timestamp': payload.timestamp, 'x-mip-delivery-id': 'delivery-1',
    },
    async *[Symbol.asyncIterator]() { yield body; },
  };
}

test('safe browser state excludes API keys and signing secrets', () => {
  const app = createNorthstarApp({
    ...config,
    preparationGatewayRequests: [{
      origin: 'https://beta.elevenidllc.com',
      method: 'POST',
      path: '/v1/webhooks',
      authentication: 'API_KEY',
      idempotencyKey: 'northstar-safe-idempotency-id',
    }],
  }, { fetchImpl: async () => new Response('{}') });
  const serialized = JSON.stringify(app.safeState());
  assert.equal(serialized.includes('runtime-secret'), false);
  assert.equal(serialized.includes('readonly-secret'), false);
  assert.equal(serialized.includes('evidence-secret'), false);
  assert.equal(serialized.includes(secret), false);
  assert.deepEqual(app.safeState().preparationGatewayRequests, [{
    origin: 'https://beta.elevenidllc.com',
    method: 'POST',
    path: '/v1/webhooks',
    authentication: 'API_KEY',
    idempotencyKey: 'northstar-safe-idempotency-id',
  }]);
});

test('preparation request evidence fails closed on a direct Marty service boundary', () => {
  assert.throws(() => createNorthstarApp({
    ...config,
    preparationGatewayRequests: [{
      origin: 'http://notification:8010', method: 'POST', path: '/v1/webhooks',
    }],
  }), /configured public gateway/);
  assert.throws(() => createNorthstarApp({
    ...config,
    preparationGatewayRequests: [{
      origin: config.gatewayOrigin, method: 'POST', path: '/internal/events',
    }],
  }), /Non-public Marty route rejected/);
});

test('run-secret loading carries only sanitized preparation observations into app config', () => {
  const directory = mkdtempSync(join(tmpdir(), 'northstar-run-config-'));
  const runFile = join(directory, 'run.json');
  const observation = {
    origin: config.gatewayOrigin,
    method: 'POST',
    path: '/v1/subscriptions',
    authentication: 'API_KEY',
    idempotencyKey: 'northstar-preparation-id',
  };
  writeFileSync(runFile, JSON.stringify({
    gateway_origin: config.gatewayOrigin,
    organization_id: config.organizationId,
    application_id: config.applicationId,
    webhook_id: config.webhookId,
    runtime_api_key: config.runtimeKey,
    read_only_api_key: config.readOnlyKey,
    evidence_api_key: config.evidenceKey,
    webhook_signing_secret: config.webhookSecret,
    callback_url: config.callbackUrl,
    outbound_requests: [observation],
  }));
  try {
    const loaded = loadRunConfig({ NORTHSTAR_RUN_SECRET_FILE: runFile });
    assert.deepEqual(loaded.preparationGatewayRequests, [observation]);
    const serialized = JSON.stringify(createNorthstarApp(loaded).safeState());
    assert.equal(serialized.includes(config.runtimeKey), false);
    assert.equal(serialized.includes(config.webhookSecret), false);
    assert.match(serialized, /northstar-preparation-id/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('delivery evidence is retrieved through the public gateway and sanitized', async () => {
  const payload = {
    id: 'event-3', type: 'application.approved', timestamp: '2026-08-30T00:00:00Z',
    organization_id: 'org-1', correlation_id: approvalRequestId,
    data: { application_id: 'app-1', status: 'APPROVED' },
  };
  const app = createNorthstarApp(config, {
    fetchImpl: async (url, options) => {
      assert.equal(url.origin, 'https://beta.elevenidllc.com');
      if (url.pathname.endsWith('/approve')) {
        return new Response(JSON.stringify({ status: 'APPROVED' }), {
          status: 200, headers: {
            'content-type': 'application/json', 'x-mip-version': '0.5.0', 'x-request-id': approvalRequestId,
          },
        });
      }
      if (url.pathname.endsWith('/applicants')) {
        return new Response(JSON.stringify({ applicants: [{ id: 'app-1', status: 'APPROVED' }] }), {
          status: 200, headers: { 'content-type': 'application/json', 'x-mip-version': '0.5.0' },
        });
      }
      assert.equal(url.pathname, '/v1/webhooks/webhook-1/deliveries');
      assert.equal(options.headers.get('X-API-Key'), 'mk_live_evidence-secret');
      return new Response(JSON.stringify([{
        id: 'delivery-3', event_id: 'event-3', correlation_id: approvalRequestId,
        organization_id: 'org-1', webhook_id: 'webhook-1',
        success: true, response_status_code: 200,
      }]), {
        status: 200, headers: { 'content-type': 'application/json', 'x-mip-version': '0.5.0' },
      });
    },
  });
  assert.equal((await app.approve('runtime')).status, 200);
  assert.equal((await app.receiveWebhook(webhookRequest(payload))).status, 200);
  assert.equal((await app.refreshDeliveryEvidence()).status, 200);
  assert.deepEqual(app.safeState().deliveryEvidence, {
    eventId: 'event-3', deliveryId: 'delivery-3', correlationId: approvalRequestId,
    organizationId: 'org-1', webhookId: 'webhook-1',
    status: 'DELIVERED', responseStatusCode: 200,
  });
  assert.equal(JSON.stringify(app.safeState()).includes('evidence-secret'), false);
});

test('approval state is re-read through the public applicant route', async () => {
  const requests = [];
  const app = createNorthstarApp(config, {
    fetchImpl: async (url, options) => {
      requests.push({ path: url.pathname, method: options.method, key: options.headers.get('X-API-Key') });
      if (options.method === 'POST') {
        return new Response(JSON.stringify({ status: 'APPROVED' }), {
          status: 200, headers: { 'content-type': 'application/json', 'x-mip-version': '0.5.0', 'x-request-id': approvalRequestId },
        });
      }
      return new Response(JSON.stringify({ applicants: [{ id: 'app-1', status: 'APPROVED' }] }), {
        status: 200, headers: { 'content-type': 'application/json', 'x-mip-version': '0.5.0' },
      });
    },
  });
  assert.equal((await app.approve('runtime')).status, 200);
  assert.deepEqual(requests, [
    { path: '/v1/organizations/org-1/applicants/app-1/approve', method: 'POST', key: 'mk_live_runtime-secret' },
    { path: '/v1/organizations/org-1/applicants', method: 'GET', key: 'mk_live_readonly-secret' },
  ]);
  assert.equal(app.safeState().application.status, 'APPROVED');
});

test('public server bounds JSON bodies and sends browser security headers', async () => {
  const { server } = startServer({
    PORT: '0',
    MARTY_PUBLIC_GATEWAY_ORIGIN: config.gatewayOrigin,
    NORTHSTAR_ORGANIZATION_ID: config.organizationId,
    NORTHSTAR_APPLICATION_ID: config.applicationId,
    NORTHSTAR_WEBHOOK_ID: config.webhookId,
    NORTHSTAR_RUNTIME_API_KEY: config.runtimeKey,
    NORTHSTAR_READ_ONLY_API_KEY: config.readOnlyKey,
    NORTHSTAR_EVIDENCE_API_KEY: config.evidenceKey,
    NORTHSTAR_WEBHOOK_SECRET: config.webhookSecret,
    NORTHSTAR_CALLBACK_URL: config.callbackUrl,
  });
  await once(server, 'listening');
  const address = server.address();
  const origin = `http://127.0.0.1:${address.port}`;
  try {
    const health = await fetch(`${origin}/health`);
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), { status: 'healthy', service: 'northstar-admissions' });

    const state = await fetch(`${origin}/api/demo-state`);
    assert.equal(state.status, 200);
    assert.match(state.headers.get('content-security-policy'), /frame-ancestors 'none'/);
    assert.equal(state.headers.get('cache-control'), 'no-store');
    assert.equal(state.headers.get('x-content-type-options'), 'nosniff');

    const unsupported = await fetch(`${origin}/api/applications/app-1/approve`, {
      method: 'POST', headers: { 'content-type': 'text/plain' }, body: '{}',
    });
    assert.equal(unsupported.status, 415);
    assert.equal((await unsupported.json()).code, 'JSON_CONTENT_TYPE_REQUIRED');

    const oversized = await fetch(`${origin}/webhooks/marty`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ data: 'x'.repeat(64 * 1024) }),
    });
    assert.equal(oversized.status, 413);
    assert.equal((await oversized.json()).code, 'BODY_TOO_LARGE');

    const disabledTestControl = await fetch(`${origin}/api/test-events/invalid-signature`, { method: 'POST' });
    assert.equal(disabledTestControl.status, 404);
  } finally {
    server.close();
    await once(server, 'close');
  }
});

test('public gateway failures become a safe retryable partner response', async () => {
  const { server } = startServer({
    PORT: '0',
    MARTY_PUBLIC_GATEWAY_ORIGIN: config.gatewayOrigin,
    NORTHSTAR_ORGANIZATION_ID: config.organizationId,
    NORTHSTAR_APPLICATION_ID: config.applicationId,
    NORTHSTAR_WEBHOOK_ID: config.webhookId,
    NORTHSTAR_RUNTIME_API_KEY: config.runtimeKey,
    NORTHSTAR_READ_ONLY_API_KEY: config.readOnlyKey,
    NORTHSTAR_EVIDENCE_API_KEY: config.evidenceKey,
    NORTHSTAR_WEBHOOK_SECRET: config.webhookSecret,
    NORTHSTAR_CALLBACK_URL: config.callbackUrl,
  }, { fetchImpl: async () => { throw new Error('sensitive upstream failure'); } });
  await once(server, 'listening');
  const address = server.address();
  try {
    const response = await fetch(`http://127.0.0.1:${address.port}/api/applications/refresh`, { method: 'POST' });
    assert.equal(response.status, 503);
    assert.deepEqual(await response.json(), {
      status: 'unavailable',
      code: 'PUBLIC_GATEWAY_UNAVAILABLE',
      detail: 'Northstar could not reach the Marty public gateway. Retry when the integration is available.',
    });
  } finally {
    server.close();
    await once(server, 'close');
  }
});

test('receiver resilience controls require explicit enablement and expose no secret material', async () => {
  const { server } = startServer({
    PORT: '0',
    MARTY_PUBLIC_GATEWAY_ORIGIN: config.gatewayOrigin,
    NORTHSTAR_ORGANIZATION_ID: config.organizationId,
    NORTHSTAR_APPLICATION_ID: config.applicationId,
    NORTHSTAR_WEBHOOK_ID: config.webhookId,
    NORTHSTAR_RUNTIME_API_KEY: config.runtimeKey,
    NORTHSTAR_READ_ONLY_API_KEY: config.readOnlyKey,
    NORTHSTAR_EVIDENCE_API_KEY: config.evidenceKey,
    NORTHSTAR_WEBHOOK_SECRET: config.webhookSecret,
    NORTHSTAR_CALLBACK_URL: config.callbackUrl,
    NORTHSTAR_RECEIVER_TEST_CONTROLS_ENABLED: 'true',
  });
  await once(server, 'listening');
  const address = server.address();
  const origin = `http://127.0.0.1:${address.port}`;
  try {
    const invalid = await fetch(`${origin}/api/test-events/invalid-signature`, { method: 'POST' });
    assert.equal(invalid.status, 200);
    assert.deepEqual(await invalid.json(), {
      kind: 'INVALID_SIGNATURE', receiverStatus: 401, code: 'INVALID_SIGNATURE', admissionsUnchanged: true,
    });
    const duplicate = await fetch(`${origin}/api/test-events/duplicate`, { method: 'POST' });
    assert.equal(duplicate.status, 409);
    const serialized = JSON.stringify(await (await fetch(`${origin}/api/demo-state`)).json());
    assert.equal(serialized.includes(secret), false);
    assert.equal(serialized.includes('runtime-secret'), false);
  } finally {
    server.close();
    await once(server, 'close');
  }
});

test('valid events update enrollment once and invalid signatures do not', async () => {
  const app = createNorthstarApp(config, { fetchImpl: async (url, options) => {
    if (options.method === 'POST' && url.pathname.endsWith('/approve')) {
      return new Response(JSON.stringify({ status: 'APPROVED' }), {
        status: 200, headers: {
          'content-type': 'application/json', 'x-mip-version': '0.5.0', 'x-request-id': approvalRequestId,
        },
      });
    }
    return new Response(JSON.stringify({ applicants: [{ id: 'app-1', status: 'APPROVED' }] }), {
      status: 200, headers: { 'content-type': 'application/json', 'x-mip-version': '0.5.0' },
    });
  } });
  const payload = {
    id: 'event-1', type: 'application.approved', timestamp: '2026-08-30T00:00:00Z',
    organization_id: 'org-1', correlation_id: approvalRequestId,
    data: { application_id: 'app-1', status: 'APPROVED' },
  };
  assert.equal((await app.testDuplicateEvent()).status, 409);
  const invalidTest = await app.testInvalidSignature();
  assert.equal(invalidTest.status, 200);
  assert.deepEqual(invalidTest.body, {
    kind: 'INVALID_SIGNATURE', receiverStatus: 401, code: 'INVALID_SIGNATURE', admissionsUnchanged: true,
  });
  assert.equal(app.safeState().enrollmentStatus, 'Waiting for approval');
  assert.equal(app.safeState().webhookEvents.length, 0);
  assert.equal((await app.approve('runtime')).status, 200);
  const mismatched = { ...payload, id: 'event-mismatch', correlation_id: '22222222-2222-4222-8222-222222222222' };
  assert.deepEqual(await app.receiveWebhook(webhookRequest(mismatched)), {
    status: 422,
    body: { status: 'rejected', code: 'APPROVAL_CORRELATION_MISMATCH' },
  });
  assert.equal(app.safeState().webhookEvents.length, 0);
  assert.equal((await app.receiveWebhook(webhookRequest(payload))).body.status, 'processed');
  assert.equal(app.safeState().enrollmentStatus, 'Enrollment workflow ready');
  const duplicateTest = await app.testDuplicateEvent();
  assert.equal(duplicateTest.status, 200);
  assert.deepEqual(duplicateTest.body, {
    kind: 'DUPLICATE_EVENT', receiverStatus: 200, code: 'duplicate_ignored',
    eventId: 'event-1', admissionsUnchanged: true,
  });
  assert.equal(app.safeState().webhookEvents.length, 1);
  const invalid = { ...payload, id: 'event-2' };
  assert.equal((await app.receiveWebhook(webhookRequest(invalid, 'sha256=bad'))).status, 401);
  assert.equal(app.safeState().webhookEvents.length, 1);
});
