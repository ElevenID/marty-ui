import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Suspense, useLayoutEffect } from 'react';
import { BrowserRouter, Route, Routes, useLocation, useNavigate } from 'react-router';
import { act, waitFor, within } from '@testing-library/react';
import { http, HttpResponse } from 'msw';

import { renderWithoutRouter, screen } from '@test/utils';
import { server } from '@test/mocks/server';
import { AuthContext } from '../../../contexts/AuthContext';
import { ConsoleProvider, useConsole } from '../../../contexts/ConsoleContext';
import { NotificationProvider } from '../../../contexts/NotificationContext';
import { ASYNC_GATEWAY_EVENT_PRESET } from '../../../services/webhookEvents';
import ApiKeysPage from './ApiKeysPage';

const pending = vi.hoisted(() => ({ mutations: [] as Promise<unknown>[] }));
// Observe settlement without replacing the real APIs, providers, permission
// hook, idempotency helper, installed SDK transport, or browser router.
vi.mock('../../../services/apiKeysApi', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../services/apiKeysApi')>();
  return { ...actual, createApiKey: (...args: Parameters<typeof actual.createApiKey>) => {
    const result = actual.createApiKey(...args);
    pending.mutations.push(result);
    return result;
  } };
});
vi.mock('../../../services/webhooksApi', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../services/webhooksApi')>();
  return { ...actual, createWebhookConfiguration: (...args: Parameters<typeof actual.createWebhookConfiguration>) => {
    const result = actual.createWebhookConfiguration(...args);
    pending.mutations.push(result);
    return result;
  } };
});

const PAGE = '/console/org/api-keys';
const DESTINATION = '/console/org/trust';
const ORGANIZATION = '11111111-1111-4111-8111-111111111111';
const KEY_ID = '22222222-2222-4222-8222-222222222222';
const WEBHOOK_ID = '33333333-3333-4333-8333-333333333333';
const SUBSCRIPTION_ID = '44444444-4444-4444-8444-444444444444';
const NAME = 'API key continuation fixture';
const CALLBACK = 'https://fixture.example.invalid/events';
const CREATED_AT = '2026-11-09T20:00:00Z';
const organizations = [{ id: ORGANIZATION, name: 'Fixture organization', display_name: 'Fixture organization',
  membership: { status: 'active', roles: [{ name: 'owner' }], has_org_console_access: true } }];
const auth = { user: { user_id: 'api-key-continuation-fixture-user', roles: ['owner'],
  capabilities: { 'org:view': true }, organizations }, isAuthenticated: true, isLoading: false };
let navigateTo: ReturnType<typeof useNavigate>;
let permissionReads: string[];

function CurrentScope() {
  const navigate = useNavigate();
  const location = useLocation();
  const { activeOrgId } = useConsole();
  useLayoutEffect(() => { navigateTo = navigate; }, [navigate]);
  return <>
    <output data-testid="committed-route">{location.pathname}{location.search}{location.hash}</output>
    <output data-testid="current-organization">{activeOrgId}</output>
  </>;
}
function ReadyRoutes({ destination }: { destination: React.ReactNode }) {
  const { isLoading } = useConsole();
  if (isLoading) return <p>Loading console</p>;
  return <Routes>
    <Route path={PAGE} element={<ApiKeysPage />} />
    <Route path={DESTINATION} element={destination} />
  </Routes>;
}
function page(destination: React.ReactNode = <h1>Current Trust overview</h1>) {
  return <BrowserRouter><AuthContext.Provider value={auth as any}><ConsoleProvider><NotificationProvider>
    <Suspense fallback={<h1>Loading destination</h1>}>
      <CurrentScope /><ReadyRoutes destination={destination} />
    </Suspense>
  </NotificationProvider></ConsoleProvider></AuthContext.Provider></BrowserRouter>;
}
function deferredDestination() {
  let ready = false;
  let release!: () => void;
  const waiting = new Promise<void>(resolve => { release = resolve; });
  function Destination() {
    if (!ready) throw waiting;
    return <h1>Current Trust overview</h1>;
  }
  return { element: <Destination />, async settle() {
    await act(async () => { ready = true; release(); });
  } };
}
async function settleActualMutations() {
  const observed = new Set<Promise<unknown>>();
  do {
    const batch = pending.mutations.filter(promise => !observed.has(promise));
    batch.forEach(promise => observed.add(promise));
    await act(async () => { await Promise.allSettled(batch); });
  } while (pending.mutations.some(promise => !observed.has(promise)));
}
type Write = { path: string; organization: string | null; body: Record<string, unknown>;
  browserPath: string; idempotencyKey: string | null };
function requests() {
  const writes: Write[] = [];
  let releaseKey!: () => void;
  const keyReady = new Promise<void>(resolve => { releaseKey = resolve; });
  const record = async (request: Request) => {
    const url = new URL(request.url);
    const body = await request.json() as Record<string, unknown>;
    writes.push({ path: url.pathname, organization: url.searchParams.get('organization_id')
      || body.organization_id as string || null, body, browserPath: window.location.pathname,
    idempotencyKey: request.headers.get('Idempotency-Key') });
    return body;
  };
  server.use(
    http.get('*/v1/api-keys', () => HttpResponse.json([])),
    http.get('*/v1/webhooks', () => HttpResponse.json([])),
    http.get('*/v1/webhooks/event-types', () => HttpResponse.json({ event_types: ASYNC_GATEWAY_EVENT_PRESET })),
    http.post('*/v1/api-keys', async ({ request }) => {
      const body = await record(request);
      await keyReady;
      return HttpResponse.json({ id: KEY_ID, organization_id: ORGANIZATION, name: body.name,
        key: 'fixture_only_not_a_real_api_key', key_prefix: 'fixture_', scopes: body.scopes,
        enabled: true, scope_type: 'ORGANIZATION', created_at: CREATED_AT });
    }),
    http.post('*/v1/webhooks', async ({ request }) => {
      const body = await record(request);
      return HttpResponse.json({ id: WEBHOOK_ID, organization_id: body.organization_id,
        name: body.name, description: body.description, endpoint_url: body.url,
        events: body.event_types, signing_secret: 'fixture_only_not_a_real_webhook_secret',
        enabled: true, status: 'active', failure_count: 0, created_at: CREATED_AT, updated_at: CREATED_AT });
    }),
    http.post('*/v1/subscriptions', async ({ request }) => {
      const body = await record(request);
      return HttpResponse.json({ id: SUBSCRIPTION_ID, organization_id: body.organization_id,
        name: body.name, description: body.description, event_types: body.event_types,
        delivery: { channel: 'WEBHOOK', target_id: body.delivery_target_id },
        delivery_target_id: body.delivery_target_id, enabled: true,
        retry_policy: { max_attempts: 3, initial_backoff_seconds: 1, max_backoff_seconds: 30 },
        created_at: CREATED_AT, updated_at: CREATED_AT });
    }),
  );
  return { writes, async settle() { releaseKey(); await settleActualMutations(); } };
}
async function beginCreate(user: ReturnType<typeof renderWithoutRouter>['user'], writes: Write[]) {
  await waitFor(() => expect(screen.getByTestId('current-organization')).toHaveTextContent(ORGANIZATION));
  const button = await screen.findByRole('button', { name: /create api key|generate api key|deploy\.apiKeysPage\.generateKey/i });
  await waitFor(() => expect(button).toBeEnabled());
  await user.click(button);
  const dialog = screen.getByRole('dialog');
  await user.type(within(dialog).getByLabelText('Key name'), NAME);
  await user.type(within(dialog).getByLabelText('Callback URL'), CALLBACK);
  await user.click(within(dialog).getByRole('button', { name: 'Create integration key' }));
  await waitFor(() => expect(writes).toHaveLength(1));
  expect(writes[0]).toMatchObject({ path: '/v1/api-keys', organization: ORGANIZATION,
    browserPath: PAGE, body: { name: NAME, scopes: ['flows:execute'], expires_at: null } });
  expect(permissionReads).toContain(ORGANIZATION);
}

beforeEach(() => {
  pending.mutations.length = 0;
  permissionReads = [];
  window.localStorage.clear();
  window.history.replaceState({}, '', PAGE);
  server.use(
    http.get('/v1/me/preferences', () => HttpResponse.json({ last_view_mode: 'org_admin', last_active_org_id: ORGANIZATION })),
    http.put('/v1/me/preferences', async ({ request }) => HttpResponse.json(await request.json() as Record<string, unknown>)),
    http.get('*/v1/organizations/mine', () => HttpResponse.json(organizations)),
    http.get('*/v1/organizations/:organizationId/members/me/permissions', ({ params }) => {
      permissionReads.push(String(params.organizationId));
      return HttpResponse.json({ permissions: ['api-key:view', 'api-key:create', 'api-key:revoke',
        'webhook:view', 'webhook:create'], roles: [{ name: 'owner' }] });
    }),
  );
});

describe('API key paired callback continuation ownership', () => {
  it('creates a current key, endpoint and delivery subscription through the real APIs', async () => {
    const request = requests(); const { user } = renderWithoutRouter(page());
    try {
      await beginCreate(user, request.writes);
      await request.settle();
      expect(await screen.findByRole('heading', { name: 'Integration provisioned' })).toBeInTheDocument();
      expect(request.writes.map(write => [write.path, write.organization, write.browserPath])).toEqual([
        ['/v1/api-keys', ORGANIZATION, PAGE], ['/v1/webhooks', ORGANIZATION, PAGE],
        ['/v1/subscriptions', ORGANIZATION, PAGE],
      ]);
      expect(request.writes[1].body).toMatchObject({ url: CALLBACK, event_types: ASYNC_GATEWAY_EVENT_PRESET,
        description: `Callback for ${NAME} [api-key:${KEY_ID}]` });
      expect(request.writes[2].body).toMatchObject({ delivery_channel: 'WEBHOOK',
        delivery_target_id: WEBHOOK_ID, event_types: ASYNC_GATEWAY_EVENT_PRESET, enabled: true });
      request.writes.forEach(write => expect(write.idempotencyKey).toBeTruthy());
    } finally { await request.settle(); }
  });

  it('does not provision a callback after navigation has committed and unmounted the page', async () => {
    const request = requests(); const { user } = renderWithoutRouter(page());
    try {
      await beginCreate(user, request.writes);
      await act(async () => { navigateTo(DESTINATION); });
      expect(await screen.findByRole('heading', { name: 'Current Trust overview' })).toBeInTheDocument();
      await request.settle();
      expect(request.writes.map(write => write.path)).toEqual(['/v1/api-keys']);
    } finally { await request.settle(); }
  });

  it('does not provision a callback after the browser leaves while the destination is suspended', async () => {
    const request = requests(); const destination = deferredDestination();
    const { user } = renderWithoutRouter(page(destination.element));
    try {
      await beginCreate(user, request.writes);
      await act(async () => { navigateTo(DESTINATION); });
      expect(window.location.pathname).toBe(DESTINATION);
      expect(screen.getByTestId('committed-route')).toHaveTextContent(PAGE);
      expect(screen.getByRole('dialog')).toBeInTheDocument();
      await request.settle();
      expect(request.writes.filter(write => write.path !== '/v1/api-keys')).toEqual([]);
      expect(screen.queryByRole('heading', { name: 'Integration provisioned' })).not.toBeInTheDocument();
    } finally { await request.settle(); await destination.settle(); }
  });
});
