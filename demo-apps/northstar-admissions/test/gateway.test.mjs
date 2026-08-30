import assert from 'node:assert/strict';
import test from 'node:test';

import {
  assertPublicGatewayUrl,
  createGatewayClient,
  MIP_VERSION,
  NORTHSTAR_CALLBACK_URL,
  normalizeNorthstarCallbackUrl,
} from '../src/gateway.mjs';

test('only the configured public gateway origin and v1 routes are accepted', () => {
  assert.equal(assertPublicGatewayUrl('https://beta.elevenidllc.com', '/v1/webhooks').href, 'https://beta.elevenidllc.com/v1/webhooks');
  assert.throws(() => assertPublicGatewayUrl('https://beta.elevenidllc.com', 'http://notification:8010/v1/webhooks'), /Direct Marty service access rejected/);
  assert.throws(() => assertPublicGatewayUrl('https://beta.elevenidllc.com', '/internal/events'), /Non-public Marty route rejected/);
});

test('only the canonical Northstar HTTPS callback is accepted', () => {
  assert.equal(normalizeNorthstarCallbackUrl(NORTHSTAR_CALLBACK_URL), NORTHSTAR_CALLBACK_URL);
  for (const candidate of [
    'http://admissions-test.elevenidllc.com/webhooks/marty',
    'https://other.example.test/webhooks/marty',
    'https://admissions-test.elevenidllc.com/webhooks/other',
    'https://user:secret@admissions-test.elevenidllc.com/webhooks/marty',
    'https://admissions-test.elevenidllc.com/webhooks/marty?token=value',
    'https://admissions-test.elevenidllc.com/webhooks/marty#fragment',
  ]) assert.throws(() => normalizeNorthstarCallbackUrl(candidate), /must be exactly/);
});

test('gateway observations are sanitized and requests carry the intended public headers', async () => {
  const observations = [];
  let captured;
  const client = createGatewayClient({
    origin: 'https://beta.elevenidllc.com',
    observe: (entry) => observations.push(entry),
    fetchImpl: async (url, init) => {
      captured = { url: String(url), init };
      return new Response(JSON.stringify({ status: 'APPROVED' }), {
        status: 200,
        headers: { 'x-request-id': 'req-1', 'x-mip-version': MIP_VERSION },
      });
    },
  });
  const result = await client('/v1/organizations/org-1/applicants/app-1/approve', {
    method: 'POST', organizationId: 'org-1', apiKey: 'mk_live_secret-value', body: { notes: 'Approved' },
  });
  assert.equal(result.requestId, 'req-1');
  assert.equal(captured.url, 'https://beta.elevenidllc.com/v1/organizations/org-1/applicants/app-1/approve');
  assert.equal(captured.init.headers.get('X-Organization-ID'), 'org-1');
  assert.equal(captured.init.headers.get('X-API-Key'), 'mk_live_secret-value');
  assert.equal(captured.init.headers.get('X-MIP-Version'), '0.5.0');
  assert.equal(JSON.stringify(observations).includes('secret-value'), false);
  assert.equal(observations[0].origin, 'https://beta.elevenidllc.com');
});

test('gateway responses without the negotiated MIP version fail closed', async () => {
  const client = createGatewayClient({
    origin: 'https://beta.elevenidllc.com',
    fetchImpl: async () => new Response('{}', { status: 200 }),
  });
  await assert.rejects(
    client('/v1/webhooks', { apiKey: 'mk_live_secret-value', organizationId: 'org-1' }),
    /did not confirm MIP 0\.5\.0/,
  );
});
