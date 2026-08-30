import assert from 'node:assert/strict';
import { once } from 'node:events';
import test from 'node:test';

import { createNorthstarApp, startServer } from '../src/server.mjs';
import { expectedSignature } from '../src/webhook.mjs';

const secret = '0123456789abcdef0123456789abcdef';
const config = {
  gatewayOrigin: 'https://beta.elevenidllc.com', organizationId: 'org-1', applicationId: 'app-1',
  webhookId: 'webhook-1', runtimeKey: 'mk_live_runtime-secret', readOnlyKey: 'mk_live_readonly-secret',
  evidenceKey: 'mk_live_evidence-secret', webhookSecret: secret,
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
  const app = createNorthstarApp(config, { fetchImpl: async () => new Response('{}') });
  const serialized = JSON.stringify(app.safeState());
  assert.equal(serialized.includes('runtime-secret'), false);
  assert.equal(serialized.includes('readonly-secret'), false);
  assert.equal(serialized.includes('evidence-secret'), false);
  assert.equal(serialized.includes(secret), false);
});

test('delivery evidence is retrieved through the public gateway and sanitized', async () => {
  const payload = {
    id: 'event-3', type: 'application.approved', timestamp: '2026-08-30T00:00:00Z',
    organization_id: 'org-1', data: { application_id: 'app-1', status: 'APPROVED' },
  };
  const app = createNorthstarApp(config, {
    fetchImpl: async (url, options) => {
      assert.equal(url.origin, 'https://beta.elevenidllc.com');
      assert.equal(url.pathname, '/v1/webhooks/webhook-1/deliveries');
      assert.equal(options.headers.get('X-API-Key'), 'mk_live_evidence-secret');
      return new Response(JSON.stringify([{ id: 'delivery-3', event_id: 'event-3', success: true, response_status_code: 200 }]), {
        status: 200, headers: { 'content-type': 'application/json', 'x-mip-version': '0.5.0' },
      });
    },
  });
  await app.receiveWebhook(webhookRequest(payload));
  assert.equal((await app.refreshDeliveryEvidence()).status, 200);
  assert.deepEqual(app.safeState().deliveryEvidence, {
    eventId: 'event-3', deliveryId: 'delivery-3', status: 'DELIVERED', responseStatusCode: 200,
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
          status: 200, headers: { 'content-type': 'application/json', 'x-mip-version': '0.5.0', 'x-request-id': 'request-1' },
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
  const app = createNorthstarApp(config, { fetchImpl: async () => new Response('{}') });
  const payload = {
    id: 'event-1', type: 'application.approved', timestamp: '2026-08-30T00:00:00Z',
    organization_id: 'org-1', data: { application_id: 'app-1', status: 'APPROVED' },
  };
  assert.equal((await app.testDuplicateEvent()).status, 409);
  const invalidTest = await app.testInvalidSignature();
  assert.equal(invalidTest.status, 200);
  assert.deepEqual(invalidTest.body, {
    kind: 'INVALID_SIGNATURE', receiverStatus: 401, code: 'INVALID_SIGNATURE', admissionsUnchanged: true,
  });
  assert.equal(app.safeState().enrollmentStatus, 'Waiting for approval');
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
