import { beforeEach, describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { createApiKey } from '../apiKeysApi';
import { createWebhook, createWebhookConfiguration } from '../webhooksApi';
import { createSubscription } from '../subscriptionsApi';

const organization = '11111111-1111-4111-8111-111111111111';
const endpoint = { name: 'Fixture endpoint', url: 'https://fixture.example.invalid/events',
  eventTypes: ['application.approved'], description: 'Fixture description' };
type Options = { isCurrent?: () => boolean; headers?: Record<string, string> };
const operations = {
  key: (options?: Options) => createApiKey(` ${organization} `, { name: 'Fixture key', scopes: ['flows:execute'],
    expiresAt: '2027-01-01T00:00:00Z' }, options),
  endpoint: (options?: Options) => createWebhook(` ${organization} `, endpoint, options),
  subscription: (options?: Options) => createSubscription(` ${organization} `, {
    name: 'Fixture deliveries', eventTypes: endpoint.eventTypes, deliveryTargetId: 'endpoint-fixture',
  }, options),
  configuration: (options?: Options) => createWebhookConfiguration(` ${organization} `, endpoint, options),
};
type Operation = keyof typeof operations;
let writes: Array<{ path: string; organization: string | null; body: Record<string, unknown>;
  idempotency: string | null; fixtureHeader: string | null; scopeHeader: string | null }>;
beforeEach(() => {
  writes = [];
  server.use(http.post('*/v1/:resource', async ({ request, params }) => {
    const url = new URL(request.url); const body = await request.json() as Record<string, unknown>;
    writes.push({ path: url.pathname, organization: url.searchParams.get('organization_id'), body,
      idempotency: request.headers.get('Idempotency-Key'), fixtureHeader: request.headers.get('X-Fixture'),
      scopeHeader: request.headers.get('isCurrent') });
    return HttpResponse.json(params.resource === 'webhooks'
      ? { id: 'endpoint-fixture', ...body, endpoint_url: body.url, events: body.event_types }
      : { id: 'created-fixture', ...body });
  }));
});

describe('optional API key creation ownership compatibility', () => {
  it.each<Operation>(['key', 'endpoint', 'subscription', 'configuration'])('refuses an already-obsolete %s without a POST', async (operation) => {
    await expect(operations[operation]({ isCurrent: () => false })).rejects.toMatchObject({ name: 'AbortError' });
    expect(writes).toEqual([]);
  });

  it.each<Operation>(['key', 'endpoint', 'subscription', 'configuration'])('keeps the unscoped %s wire payload and default behavior with a current owner', async (operation) => {
    const legacy = await operations[operation]();
    const previous = writes.map(write => ({ path: write.path, organization: write.organization, body: write.body }));
    writes = [];
    const current = await operations[operation]({ isCurrent: () => true, headers: { 'X-Fixture': 'current-owner' } });
    expect(current).toEqual(legacy);
    expect(writes.map(write => ({ path: write.path, organization: write.organization, body: write.body }))).toEqual(previous);
    expect(writes).toHaveLength(operation === 'configuration' ? 2 : 1);
    for (const write of writes) {
      expect(write.idempotency).toBeTruthy();
      expect(write.fixtureHeader).toBe('current-owner');
      expect(write.scopeHeader).toBeNull();
      expect(write.body).not.toHaveProperty('isCurrent');
      expect(write.body).not.toHaveProperty('headers');
    }
    if (operation === 'key') expect(writes[0]).toMatchObject({ organization,
      body: { name: 'Fixture key', scopes: ['flows:execute'], expires_at: '2027-01-01T00:00:00Z' } });
    if (operation === 'subscription') expect(writes[0].body).toEqual({ organization_id: organization,
      name: 'Fixture deliveries', description: '', event_types: endpoint.eventTypes,
      delivery_channel: 'WEBHOOK', delivery_target_id: 'endpoint-fixture', filter: {}, enabled: true });
  });
});
