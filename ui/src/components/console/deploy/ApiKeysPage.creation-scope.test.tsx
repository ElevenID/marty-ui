import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Suspense, useLayoutEffect, useState } from 'react';
import { BrowserRouter, Route, Routes, useLocation, useNavigate } from 'react-router';
import { act, fireEvent, waitFor, within } from '@testing-library/react';
import { http, HttpResponse } from 'msw';

import { renderWithoutRouter, screen } from '@test/utils';
import { server } from '@test/mocks/server';
import { AuthContext } from '../../../contexts/AuthContext';
import { ConsoleProvider, useConsole } from '../../../contexts/ConsoleContext';
import { NotificationProvider } from '../../../contexts/NotificationContext';
import { ASYNC_GATEWAY_EVENT_PRESET } from '../../../services/webhookEvents';
import ApiKeysPage from './ApiKeysPage';

const pending = vi.hoisted(() => ({ mutations: [] as Promise<unknown>[], reads: [] as Promise<unknown>[],
  keyOwners: [] as Array<(() => boolean) | undefined>, refreshPermissions: null as null | (() => Promise<unknown>) }));
// Observe settlement without replacing the real APIs, providers, permission
// hook, idempotency helper, installed SDK transport, or browser router.
vi.mock('../../../services/apiKeysApi', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../services/apiKeysApi')>();
  return { ...actual, listApiKeys: (...args: Parameters<typeof actual.listApiKeys>) => {
    const result = actual.listApiKeys(...args); pending.reads.push(result); return result;
  }, createApiKey: (...args: Parameters<typeof actual.createApiKey>) => {
    const result = actual.createApiKey(...args);
    pending.keyOwners.push((args[2] as { isCurrent?: () => boolean } | undefined)?.isCurrent);
    pending.mutations.push(result);
    return result;
  } };
});
vi.mock('../../../hooks/usePermissions', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../hooks/usePermissions')>();
  return { ...actual, usePermissions: () => {
    const result = actual.usePermissions();
    pending.refreshPermissions = result.refresh;
    return result;
  } };
});
vi.mock('../../../services/rbacApi', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../services/rbacApi')>();
  return { ...actual, getMyPermissions: (...args: Parameters<typeof actual.getMyPermissions>) => {
    const result = actual.getMyPermissions(...args); pending.reads.push(result); return result;
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
const OTHER_ORGANIZATION = '55555555-5555-4555-8555-555555555555';
const KEY_ID = '22222222-2222-4222-8222-222222222222';
const WEBHOOK_ID = '33333333-3333-4333-8333-333333333333';
const SUBSCRIPTION_ID = '44444444-4444-4444-8444-444444444444';
const NAME = 'API key continuation fixture';
const CALLBACK = 'https://fixture.example.invalid/events';
const CREATED_AT = '2026-11-09T20:00:00Z';
const organizations = [ORGANIZATION, OTHER_ORGANIZATION].map(id => ({ id, name: `Fixture ${id}`, display_name: `Fixture ${id}`,
  membership: { status: 'active', roles: [{ name: 'owner' }], has_org_console_access: true } }));
const auth = { user: { user_id: 'api-key-continuation-fixture-user', roles: ['owner'],
  capabilities: { 'org:view': true }, organizations }, isAuthenticated: true, isLoading: false };
let navigateTo: ReturnType<typeof useNavigate>;
let selectOrganization: (id: string) => Promise<unknown>;
let changeSession: React.Dispatch<React.SetStateAction<typeof auth>>;
let permissionReads: string[];
let grants: string[];

function CurrentScope() {
  const navigate = useNavigate();
  const location = useLocation();
  const { activeOrgId, setActiveOrgId } = useConsole();
  useLayoutEffect(() => { navigateTo = navigate; selectOrganization = setActiveOrgId; }, [navigate, setActiveOrgId]);
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
    <Route path="/console/org" element={<h1>Organization home</h1>} />
  </Routes>;
}
function page(destination: React.ReactNode = <h1>Current Trust overview</h1>) {
  function Session() {
    const [session, setSession] = useState(auth);
    useLayoutEffect(() => { changeSession = setSession; }, []);
    return <AuthContext.Provider value={session as any}><ConsoleProvider><NotificationProvider>
    <Suspense fallback={<h1>Loading destination</h1>}>
      <CurrentScope /><ReadyRoutes destination={destination} />
    </Suspense>
    </NotificationProvider></ConsoleProvider></AuthContext.Provider>;
  }
  return <BrowserRouter><Session /></BrowserRouter>;
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
async function settleActual(read: () => Promise<unknown>[] = () => pending.mutations) {
  const observed = new Set<Promise<unknown>>();
  do {
    const batch = read().filter(promise => !observed.has(promise));
    batch.forEach(promise => observed.add(promise));
    await act(async () => { await Promise.allSettled(batch); });
  } while (read().some(promise => !observed.has(promise)));
}
function holdOrganizationSwitch() {
  let release!: () => void;
  const ready = new Promise<void>(resolve => { release = resolve; });
  let selection: Promise<unknown> | undefined;
  const persisted: unknown[] = [];
  server.use(http.put('/v1/me/preferences', async ({ request }) => {
    const body = await request.json() as Record<string, unknown>;
    persisted.push(body.last_active_org_id);
    if (body.last_active_org_id === OTHER_ORGANIZATION) await ready;
    return HttpResponse.json(body);
  }));
  return { async start() {
    act(() => { selection = selectOrganization(OTHER_ORGANIZATION); void selection.catch(() => undefined); });
    await waitFor(() => expect(persisted).toContain(OTHER_ORGANIZATION));
  }, async settle() {
    await act(async () => { release(); await selection?.catch(() => undefined); });
  } };
}
type Write = { method: string; path: string; organization: string | null; body: Record<string, unknown>;
  browserPath: string; idempotencyKey: string | null };
type Stage = 'key' | 'endpoint' | 'subscription';
const paths: Record<Stage, string> = { key: '/v1/api-keys', endpoint: '/v1/webhooks', subscription: '/v1/subscriptions' };
function requests(hold: Stage = 'key', failure?: 'network' | 'http') {
  const writes: Write[] = [];
  let release!: () => void;
  const ready = new Promise<void>(resolve => { release = resolve; });
  const attempts = new Map<string, number>();
  const record = async (request: Request) => {
    const url = new URL(request.url);
    const body = request.method === 'DELETE' ? {} : await request.json() as Record<string, unknown>;
    writes.push({ method: request.method, path: url.pathname, organization: url.searchParams.get('organization_id')
      || body.organization_id as string || null, body, browserPath: window.location.pathname,
    idempotencyKey: request.headers.get('Idempotency-Key') });
    return body;
  };
  const firstResponse = async (stage: Stage) => {
    attempts.set(stage, (attempts.get(stage) || 0) + 1);
    if (stage !== hold || attempts.get(stage) !== 1) return null;
    await ready;
    return failure === 'network' ? HttpResponse.error()
      : failure === 'http' ? HttpResponse.json({ error: 'unavailable', error_description: 'Fixture service unavailable' }, { status: 503 })
        : null;
  };
  server.use(
    http.get('*/v1/api-keys', () => HttpResponse.json([])),
    http.get('*/v1/webhooks', () => HttpResponse.json([])),
    http.get('*/v1/webhooks/event-types', () => HttpResponse.json({ event_types: ASYNC_GATEWAY_EVENT_PRESET })),
    http.post('*/v1/api-keys', async ({ request }) => {
      const body = await record(request);
      const failed = await firstResponse('key');
      if (failed) return failed;
      return HttpResponse.json({ id: KEY_ID, organization_id: new URL(request.url).searchParams.get('organization_id'), name: body.name,
        key: 'fixture_only_not_a_real_api_key', key_prefix: 'fixture_', scopes: body.scopes,
        enabled: true, scope_type: 'ORGANIZATION', created_at: CREATED_AT });
    }),
    http.post('*/v1/webhooks', async ({ request }) => {
      const body = await record(request);
      const failed = await firstResponse('endpoint');
      if (failed) return failed;
      return HttpResponse.json({ id: WEBHOOK_ID, organization_id: body.organization_id,
        name: body.name, description: body.description, endpoint_url: body.url,
        events: body.event_types, signing_secret: 'fixture_only_not_a_real_webhook_secret',
        enabled: true, status: 'active', failure_count: 0, created_at: CREATED_AT, updated_at: CREATED_AT });
    }),
    http.post('*/v1/subscriptions', async ({ request }) => {
      const body = await record(request);
      const failed = await firstResponse('subscription');
      if (failed) return failed;
      return HttpResponse.json({ id: SUBSCRIPTION_ID, organization_id: body.organization_id,
        name: body.name, description: body.description, event_types: body.event_types,
        delivery: { channel: 'WEBHOOK', target_id: body.delivery_target_id },
        delivery_target_id: body.delivery_target_id, enabled: true,
        retry_policy: { max_attempts: 3, initial_backoff_seconds: 1, max_backoff_seconds: 30 },
        created_at: CREATED_AT, updated_at: CREATED_AT });
    }),
    http.delete('*/v1/webhooks/:webhookId', async ({ request }) => {
      await record(request);
      return HttpResponse.json({ success: true });
    }),
  );
  return { writes, release, async waitForHeld() {
    await waitFor(() => expect(writes.some(write => write.path === paths[hold])).toBe(true));
  }, async settle() { release(); await settleActual(); } };
}
async function fillCreate(user: ReturnType<typeof renderWithoutRouter>['user'], organization = ORGANIZATION) {
  await waitFor(() => expect(screen.getByTestId('current-organization')).toHaveTextContent(organization));
  const button = await screen.findByRole('button', { name: /create api key|generate api key|deploy\.apiKeysPage\.generateKey/i });
  await waitFor(() => expect(button).toBeEnabled());
  await user.click(button);
  const dialog = screen.getByRole('dialog');
  await user.type(within(dialog).getByLabelText('Key name'), NAME);
  await user.type(within(dialog).getByLabelText('Callback URL'), CALLBACK);
  return within(dialog).getByRole('button', { name: 'Create integration key' });
}
async function beginCreate(user: ReturnType<typeof renderWithoutRouter>['user'], request: ReturnType<typeof requests>) {
  await user.click(await fillCreate(user));
  await request.waitForHeld();
  expect(permissionReads).toContain(ORGANIZATION);
}

beforeEach(() => {
  pending.mutations.length = 0; pending.reads.length = 0; pending.keyOwners.length = 0; pending.refreshPermissions = null;
  permissionReads = [];
  grants = ['api-key:view', 'api-key:create', 'api-key:revoke', 'webhook:view', 'webhook:create', 'webhook:delete'];
  window.localStorage.clear();
  window.history.replaceState({}, '', PAGE);
  server.use(
    http.get('/v1/me/preferences', () => HttpResponse.json({ last_view_mode: 'org_admin', last_active_org_id: ORGANIZATION })),
    http.put('/v1/me/preferences', async ({ request }) => HttpResponse.json(await request.json() as Record<string, unknown>)),
    http.get('*/v1/organizations/mine', () => HttpResponse.json(organizations)),
    http.get('*/v1/organizations/:organizationId/members/me/permissions', ({ params }) => {
      permissionReads.push(String(params.organizationId));
      return HttpResponse.json({ permissions: grants, roles: [{ name: 'owner' }] });
    }),
  );
});

describe('API key creation pipeline boundaries', () => {
  it.each<Stage>(['key', 'endpoint', 'subscription'])('keeps the same idempotency key for a current %s retry', async (stage) => {
    const request = requests(stage, 'network'); const { user } = renderWithoutRouter(page());
    try {
      await beginCreate(user, request);
      await request.settle();
      expect(await screen.findByRole('heading', { name: 'Integration provisioned' })).toBeInTheDocument();
      const retried = request.writes.filter(write => write.path === paths[stage]);
      expect(retried).toHaveLength(2);
      expect(retried[0].idempotencyKey).toBeTruthy();
      expect(retried[1].idempotencyKey).toBe(retried[0].idempotencyKey);
      expect(retried[1].body).toEqual(retried[0].body);
      expect(request.writes.filter(write => write.method === 'DELETE')).toHaveLength(0);
    } finally { await request.settle(); }
  });

  it.each<Stage>(['key', 'endpoint', 'subscription'])('does not retry an obsolete %s or start later writes before destination commit', async (stage) => {
    const request = requests(stage, 'network'); const destination = deferredDestination();
    const { user } = renderWithoutRouter(page(destination.element));
    try {
      await beginCreate(user, request);
      const submitted = [...request.writes];
      await act(async () => { navigateTo(DESTINATION); });
      expect(window.location.pathname).toBe(DESTINATION);
      expect(screen.getByTestId('committed-route')).toHaveTextContent(PAGE);
      await request.settle();
      expect(request.writes).toEqual(submitted);
      expect(screen.queryByRole('heading', { name: 'Integration provisioned' })).not.toBeInTheDocument();
    } finally { await request.settle(); await destination.settle(); }
  });

  it('does not start a subscription after an endpoint acknowledgement arrives on a suspended destination', async () => {
    const request = requests('endpoint'); const destination = deferredDestination();
    const { user } = renderWithoutRouter(page(destination.element));
    try {
      await beginCreate(user, request);
      await act(async () => { navigateTo(DESTINATION); });
      await request.settle();
      expect(request.writes.map(write => write.path)).toEqual(['/v1/api-keys', '/v1/webhooks']);
      expect(screen.queryByDisplayValue('fixture_only_not_a_real_api_key')).not.toBeInTheDocument();
    } finally { await request.settle(); await destination.settle(); }
  });

  it('does not compensate after a failed subscription settles outside the owning browser entry', async () => {
    const request = requests('subscription', 'http'); const destination = deferredDestination();
    const { user } = renderWithoutRouter(page(destination.element));
    try {
      await beginCreate(user, request);
      await act(async () => { navigateTo(DESTINATION); });
      await request.settle();
      expect(request.writes.map(write => [write.method, write.path])).toEqual([
        ['POST', '/v1/api-keys'], ['POST', '/v1/webhooks'], ['POST', '/v1/subscriptions'],
      ]);
    } finally { await request.settle(); await destination.settle(); }
  });

  it('preserves normal current compensation and the acknowledged key after subscription failure', async () => {
    const request = requests('subscription', 'http'); const { user } = renderWithoutRouter(page());
    try {
      await beginCreate(user, request); await request.settle();
      expect(await screen.findByLabelText('API key')).toHaveValue('fixture_only_not_a_real_api_key');
      expect(screen.getByText(/Callback creation failed/)).toBeInTheDocument();
      expect(request.writes.map(write => [write.method, write.path])).toEqual([
        ['POST', '/v1/api-keys'], ['POST', '/v1/webhooks'], ['POST', '/v1/subscriptions'],
        ['DELETE', `/v1/webhooks/${WEBHOOK_ID}`],
      ]);
      expect(request.writes.at(-1)?.organization).toBe(ORGANIZATION);
      expect(screen.queryByRole('button', { name: 'Create integration key' })).not.toBeInTheDocument();
    } finally { await request.settle(); }
  });

  it('preserves the acknowledged key without recreating it after endpoint failure', async () => {
    const request = requests('endpoint', 'http'); const { user } = renderWithoutRouter(page());
    try {
      await beginCreate(user, request); await request.settle();
      expect(await screen.findByLabelText('API key')).toHaveValue('fixture_only_not_a_real_api_key');
      expect(screen.getByText(/Callback creation failed/)).toBeInTheDocument();
      expect(request.writes.map(write => write.path)).toEqual(['/v1/api-keys', '/v1/webhooks']);
      expect(screen.queryByRole('button', { name: 'Create integration key' })).not.toBeInTheDocument();
    } finally { await request.settle(); }
  });

  it('keeps an acknowledged current key when both creation grants are withdrawn and skips its callback', async () => {
    const request = requests(); const { user } = renderWithoutRouter(page());
    try {
      await beginCreate(user, request);
      grants = ['api-key:view', 'webhook:view'];
      await act(async () => { await pending.refreshPermissions?.(); });
      await request.settle();
      expect(await screen.findByLabelText('API key')).toHaveValue('fixture_only_not_a_real_api_key');
      expect(screen.getByText(/Callback creation was skipped because your creation permissions are no longer available/)).toBeInTheDocument();
      expect(request.writes.map(write => write.path)).toEqual(['/v1/api-keys']);
    } finally { await request.settle(); }
  });

  it('stops the nested subscription when callback permission is withdrawn during endpoint creation', async () => {
    const request = requests('endpoint'); const { user } = renderWithoutRouter(page());
    try {
      await beginCreate(user, request);
      grants = ['api-key:view', 'api-key:create', 'webhook:view'];
      await act(async () => { await pending.refreshPermissions?.(); });
      await request.settle();
      expect(await screen.findByLabelText('API key')).toHaveValue('fixture_only_not_a_real_api_key');
      expect(screen.getByText(/Callback creation failed/)).toBeInTheDocument();
      expect(request.writes.map(write => write.path)).toEqual(['/v1/api-keys', '/v1/webhooks']);
    } finally { await request.settle(); }
  });

  it('invalidates a pending retry when the real provider selects a different organization', async () => {
    const request = requests('key', 'network'); const selection = holdOrganizationSwitch();
    const { user } = renderWithoutRouter(page());
    try {
      await beginCreate(user, request);
      await selection.start();
      await settleActual(() => pending.reads);
      expect(screen.getByTestId('current-organization')).toHaveTextContent(OTHER_ORGANIZATION);
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      await request.settle();
      expect(request.writes.map(write => write.path)).toEqual(['/v1/api-keys']);
      await user.click(await fillCreate(user, OTHER_ORGANIZATION));
      await settleActual();
      expect(await screen.findByRole('heading', { name: 'Integration provisioned' })).toBeInTheDocument();
      expect(request.writes.slice(1).map(write => write.organization)).toEqual([
        OTHER_ORGANIZATION, OTHER_ORGANIZATION, OTHER_ORGANIZATION,
      ]);
    } finally { await request.settle(); await selection.settle(); }
  });

  it.each(['principal', 'signed-out'])('invalidates a pending retry after the real %s session boundary', async (boundary) => {
    const request = requests('key', 'network'); const { user } = renderWithoutRouter(page());
    try {
      await beginCreate(user, request);
      await act(async () => { changeSession(boundary === 'signed-out'
        ? { ...auth, isAuthenticated: false }
        : { ...auth, user: { ...auth.user, user_id: 'replacement-fixture-user' } }); });
      await settleActual(() => pending.reads);
      await request.settle();
      expect(request.writes.map(write => write.path)).toEqual(['/v1/api-keys']);
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      expect(screen.queryByDisplayValue('fixture_only_not_a_real_api_key')).not.toBeInTheDocument();
    } finally { await request.settle(); }
  });

  it('does not accept a replacement organization form under a still-suspended browser destination', async () => {
    const request = requests(); const destination = deferredDestination(); const selection = holdOrganizationSwitch();
    const { user } = renderWithoutRouter(page(destination.element));
    try {
      await fillCreate(user);
      await act(async () => { navigateTo(DESTINATION); });
      await selection.start();
      await settleActual(() => pending.reads);
      expect(permissionReads).toContain(OTHER_ORGANIZATION);
      expect(window.location.pathname).toBe(DESTINATION);
      expect(screen.getByTestId('committed-route')).toHaveTextContent(PAGE);
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      const create = await screen.findByRole('button', { name: /create api key|generate api key|deploy\.apiKeysPage\.generateKey/i });
      expect(create).toBeDisabled();
      fireEvent.click(create);
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      expect(request.writes).toEqual([]);
      await act(async () => { navigateTo(-1); });
      await waitFor(() => expect(window.location.pathname).toBe(PAGE));
      await destination.settle();
      await user.click(await fillCreate(user, OTHER_ORGANIZATION));
      await request.waitForHeld(); await request.settle();
      expect(await screen.findByRole('heading', { name: 'Integration provisioned' })).toBeInTheDocument();
      expect(request.writes.map(write => write.organization)).toEqual([
        OTHER_ORGANIZATION, OTHER_ORGANIZATION, OTHER_ORGANIZATION,
      ]);
    } finally { await request.settle(); await selection.settle(); await destination.settle(); }
  });

  it('keeps the actual principal reset that commits a suspended destination from reviving old creation', async () => {
    const request = requests('key', 'network'); const destination = deferredDestination();
    const { user } = renderWithoutRouter(page(destination.element));
    try {
      await beginCreate(user, request);
      await act(async () => { navigateTo(DESTINATION); });
      expect(screen.getByTestId('committed-route')).toHaveTextContent(PAGE);
      await act(async () => { changeSession({ ...auth, user: { ...auth.user, user_id: 'replacement-fixture-user' } }); });
      await settleActual(() => pending.reads);
      // The real provider resets its membership/preference loading state and
      // commits the pending route here. Do not invent a retained old route.
      await waitFor(() => expect(screen.getByTestId('committed-route')).toHaveTextContent(DESTINATION));
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      await request.settle();
      expect(request.writes.map(write => write.path)).toEqual(['/v1/api-keys']);
      expect(screen.queryByDisplayValue('fixture_only_not_a_real_api_key')).not.toBeInTheDocument();
      await destination.settle();
      expect(await screen.findByRole('heading', { name: 'Current Trust overview' })).toBeInTheDocument();
      await act(async () => { navigateTo(-1); });
      await waitFor(() => expect(window.location.pathname).toBe(PAGE));
      await user.click(await fillCreate(user)); await settleActual();
      expect(await screen.findByRole('heading', { name: 'Integration provisioned' })).toBeInTheDocument();
      expect(request.writes.map(write => write.path)).toEqual([
        '/v1/api-keys', '/v1/api-keys', '/v1/webhooks', '/v1/subscriptions',
      ]);
    } finally { await request.settle(); await destination.settle(); }
  });

  it('invalidates the old owner synchronously during Back and returns a usable fresh creation dialog', async () => {
    const request = requests(); const destination = deferredDestination();
    const { user } = renderWithoutRouter(page(destination.element));
    const duringBack: Array<{ browserPath: string; oldOwnerCurrent: boolean | undefined }> = [];
    let oldOwner: (() => boolean) | undefined;
    const observeBack = () => {
      duringBack.push({ browserPath: window.location.pathname, oldOwnerCurrent: oldOwner?.() });
      request.release();
    };
    try {
      await beginCreate(user, request);
      oldOwner = pending.keyOwners[0];
      expect(oldOwner?.()).toBe(true);
      await act(async () => { navigateTo(DESTINATION); });
      // This later capture listener runs before the outer bubble listener can
      // schedule its returned-entry remount. The original action must be dead.
      window.addEventListener('popstate', observeBack, true);
      await act(async () => { navigateTo(-1); });
      await waitFor(() => expect(duringBack).toEqual([{ browserPath: PAGE, oldOwnerCurrent: false }]));
      await request.settle(); await destination.settle();
      expect(request.writes.map(write => write.path)).toEqual(['/v1/api-keys']);
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
      await user.click(await fillCreate(user)); await settleActual();
      expect(await screen.findByRole('heading', { name: 'Integration provisioned' })).toBeInTheDocument();
      expect(request.writes.map(write => write.path)).toEqual([
        '/v1/api-keys', '/v1/api-keys', '/v1/webhooks', '/v1/subscriptions',
      ]);
    } finally {
      window.removeEventListener('popstate', observeBack, true);
      await request.settle(); await destination.settle();
    }
  });

  it('does not create two keys from same-turn duplicate submission', async () => {
    const request = requests(); const { user } = renderWithoutRouter(page());
    try {
      const submit = await fillCreate(user);
      act(() => { fireEvent.click(submit); fireEvent.click(submit); });
      await request.waitForHeld(); await request.settle();
      expect(await screen.findByRole('heading', { name: 'Integration provisioned' })).toBeInTheDocument();
      expect(request.writes.filter(write => write.path === '/v1/api-keys')).toHaveLength(1);
    } finally { await request.settle(); }
  });

  it('does not submit an already-open form from a suspended destination', async () => {
    const request = requests(); const destination = deferredDestination();
    const { user } = renderWithoutRouter(page(destination.element));
    try {
      const submit = await fillCreate(user);
      await act(async () => { navigateTo(DESTINATION); });
      expect(window.location.pathname).toBe(DESTINATION);
      expect(screen.getByTestId('committed-route')).toHaveTextContent(PAGE);
      fireEvent.click(submit);
      await request.settle();
      expect(request.writes).toEqual([]);
    } finally { await request.settle(); await destination.settle(); }
  });

  it('invalidates pending creation when the browser enters a new query/history entry on the same page', async () => {
    const request = requests(); const { user } = renderWithoutRouter(page());
    try {
      await beginCreate(user, request);
      await act(async () => { navigateTo(`${PAGE}?replacement=1`); });
      await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
      await request.settle();
      expect(request.writes.map(write => write.path)).toEqual(['/v1/api-keys']);
      await user.click(await fillCreate(user)); await settleActual();
      expect(await screen.findByRole('heading', { name: 'Integration provisioned' })).toBeInTheDocument();
      expect(request.writes.map(write => write.path)).toEqual([
        '/v1/api-keys', '/v1/api-keys', '/v1/webhooks', '/v1/subscriptions',
      ]);
    } finally { await request.settle(); }
  });

  it('keeps pending form values stable when edit events arrive in the submit turn', async () => {
    const request = requests(); const { user } = renderWithoutRouter(page());
    try {
      const submit = await fillCreate(user);
      const name = screen.getByLabelText('Key name');
      const callback = screen.getByLabelText('Callback URL');
      act(() => {
        fireEvent.click(submit);
        fireEvent.change(name, { target: { value: 'Replacement name' } });
        fireEvent.change(callback, { target: { value: 'https://replacement.example.invalid/events' } });
      });
      await request.waitForHeld();
      expect(name).toHaveValue(NAME); expect(callback).toHaveValue(CALLBACK);
      expect(name).toBeDisabled(); expect(callback).toBeDisabled();
      await request.settle();
      expect(await screen.findByRole('heading', { name: 'Integration provisioned' })).toBeInTheDocument();
      expect(request.writes[0].body.name).toBe(NAME);
      expect(request.writes[1].body.url).toBe(CALLBACK);
    } finally { await request.settle(); }
  });

  it('allows a deliberate retry after a definitive current key-creation failure', async () => {
    const request = requests('key', 'http'); const { user } = renderWithoutRouter(page());
    try {
      await beginCreate(user, request); await request.settle();
      const submit = screen.getByRole('button', { name: 'Create integration key' });
      await waitFor(() => expect(submit).toBeEnabled());
      await user.click(submit); await settleActual();
      expect(await screen.findByRole('heading', { name: 'Integration provisioned' })).toBeInTheDocument();
      expect(request.writes.filter(write => write.path === '/v1/api-keys')).toHaveLength(2);
    } finally { await request.settle(); }
  });
});
