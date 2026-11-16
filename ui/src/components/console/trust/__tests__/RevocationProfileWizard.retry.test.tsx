import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Suspense, useLayoutEffect } from 'react';
import { BrowserRouter, Route, Routes, useLocation, useNavigate } from 'react-router';
import { act, fireEvent, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { renderWithoutRouter, screen } from '@test/utils';
import RevocationProfileWizard from '../RevocationProfileWizard';

const { createProfile, context, permission, grants } = vi.hoisted(() => ({
  createProfile: vi.fn(), context: { activeOrgId: 'org-1' as string | null },
  permission: { isLoading: false }, grants: new Set<string>(),
}));
vi.mock('../../../../services/presentationPolicyApi', () => ({
  createRevocationProfile: createProfile,
}));
vi.mock('../../../../contexts/ConsoleContext', () => ({
  useConsole: () => context,
}));
vi.mock('../../../../hooks/usePermissions', () => ({
  usePermissions: () => ({ ...permission, can: (resource: string, action: string) => grants.has(resource + ':' + action) }),
}));

const CREATED_ID = '11111111-1111-4111-8111-111111111111';
const NEW_PATH = '/console/org/trust/revocation/new';
const CURRENT_PATH = '/console/org/trust';

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

// Exact public create ProfileResponse: native creation returns DRAFT, not ACTIVE.
const createdProfile = (overrides: Record<string, unknown> = {}) => ({
  id: CREATED_ID, organization_id: 'org-1', name: 'New revocation profile', status: 'DRAFT',
  check_mode: 'ALWAYS', revocation_mechanism: ['STATUS_LIST_2021'], mechanism_priority: ['STATUS_LIST_2021'],
  issuer_config: { auto_allocate_index: true, batch_update_interval_seconds: 600, list_size: 131072 },
  status_list_url: 'https://status.example.test/v1/organizations/org-1/revocation-profiles/' + CREATED_ID + '/status-lists/{mechanism}/{purpose}',
  created_at: '2026-11-09T12:00:00+00:00', updated_at: '2026-11-09T12:00:00+00:00',
  ...overrides,
});

let navigateTo: ReturnType<typeof useNavigate>;
function CurrentRoute() {
  const navigate = useNavigate();
  useLayoutEffect(() => { navigateTo = navigate; }, [navigate]);
  const location = useLocation();
  return <output data-testid="current-route" data-entry-key={location.key}>{location.pathname}{location.search}{location.hash}</output>;
}

function page() {
  return <><CurrentRoute /><Routes>
    <Route path={NEW_PATH} element={<RevocationProfileWizard />} />
    <Route path={CURRENT_PATH} element={<h1>Current Trust overview</h1>} />
    <Route path="/console/org/trust/revocation/:id" element={<h1>Created profile detail</h1>} />
  </Routes></>;
}

function fillName(name = 'New revocation profile') {
  fireEvent.change(screen.getByTestId('revocationWizard.name'), { target: { value: name } });
}
function submit() { fireEvent.click(screen.getByTestId('revocationWizard.submit')); }

beforeEach(() => {
  createProfile.mockReset().mockResolvedValue(createdProfile());
  context.activeOrgId = 'org-1'; permission.isLoading = false;
  grants.clear(); grants.add('revocation-profile:create');
  window.history.replaceState({}, '', NEW_PATH);
});


describe('Revocation wizard actual transport retry ownership', () => {
  it('does not dispatch another POST after an old network failure arrives on a newer route', async () => {
    const api = await vi.importActual<typeof import('../../../../services/presentationPolicyApi')>(
      '../../../../services/presentationPolicyApi',
    );
    createProfile.mockImplementation(api.createRevocationProfile);
    const reply = deferred<Response>();
    const requests: Array<{ body: Record<string, unknown>, path: string, method: string, url: string, idempotencyKey: string | null }> = [];
    server.use(http.post('*/v1/revocation-profiles', async ({ request }) => {
      requests.push({ body: await request.json() as Record<string, unknown>, path: window.location.pathname, method: request.method, url: request.url, idempotencyKey: request.headers.get('Idempotency-Key') });
      return requests.length === 1 ? await reply.promise : HttpResponse.json(createdProfile());
    }));
    renderWithoutRouter(<BrowserRouter>{page()}</BrowserRouter>);
    fillName('Old create before navigation'); submit();
    await waitFor(() => expect(requests).toHaveLength(1));
    await act(async () => { await navigateTo(CURRENT_PATH); });
    expect(screen.getByRole('heading', { name: 'Current Trust overview' })).toBeInTheDocument();
    await act(async () => {
      reply.resolve(HttpResponse.error());
      await createProfile.mock.results[0].value.catch(() => undefined);
    });
    expect(screen.getByTestId('current-route').textContent).toBe(CURRENT_PATH);
    expect(requests.map(({ method: _method, url: _url, idempotencyKey: _key, ...observed }) => observed)).toEqual([{ body: expect.objectContaining({ organization_id: 'org-1' }), path: NEW_PATH }]);
  });

  it('keeps a same-key network retry for the current wizard and navigates on its DRAFT response', async () => {
    const api = await vi.importActual<typeof import('../../../../services/presentationPolicyApi')>(
      '../../../../services/presentationPolicyApi',
    );
    createProfile.mockImplementation(api.createRevocationProfile);
    const requests: Array<{ body: unknown, key: string | null }> = [];
    server.use(http.post('*/v1/revocation-profiles', async ({ request }) => {
      requests.push({ body: await request.json(), key: request.headers.get('Idempotency-Key') });
      return requests.length === 1 ? HttpResponse.error() : HttpResponse.json(createdProfile());
    }));
    renderWithoutRouter(<BrowserRouter>{page()}</BrowserRouter>);
    fillName('Current create'); submit();
    await screen.findByRole('heading', { name: 'Created profile detail' });
    expect(requests).toHaveLength(2);
    expect(requests[0].key).toBeTruthy();
    expect(requests[1]).toEqual(requests[0]);
    expect(requests[0].body).toEqual(expect.objectContaining({ organization_id: 'org-1', name: 'Current create' }));
  });

  it('stops a network retry while newer browser history is waiting for React to replace the old wizard', async () => {
    const api = await vi.importActual<typeof import('../../../../services/presentationPolicyApi')>(
      '../../../../services/presentationPolicyApi',
    );
    createProfile.mockImplementation(api.createRevocationProfile);
    const reply = deferred<Response>();
    const transition = deferred<void>();
    let destinationReady = false;
    function Destination() {
      if (!destinationReady) throw transition.promise;
      return <h1>Current Trust overview</h1>;
    }
    const requests: Array<{ body: unknown, path: string }> = [];
    server.use(http.post('*/v1/revocation-profiles', async ({ request }) => {
      requests.push({ body: await request.json(), path: window.location.pathname });
      return requests.length === 1 ? await reply.promise : HttpResponse.json(createdProfile());
    }));
    renderWithoutRouter(<BrowserRouter><Suspense fallback={<h1>Loading destination</h1>}>
      <CurrentRoute /><Routes>
        <Route path={NEW_PATH} element={<RevocationProfileWizard />} />
        <Route path={CURRENT_PATH} element={<Destination />} />
        <Route path="/console/org/trust/revocation/:id" element={<h1>Created profile detail</h1>} />
      </Routes>
    </Suspense></BrowserRouter>);
    fillName('Precommit create'); submit();
    await waitFor(() => expect(requests).toHaveLength(1));
    const oldKey = screen.getByTestId('current-route').getAttribute('data-entry-key');
    try {
      await act(async () => { navigateTo(CURRENT_PATH); });
      expect(window.location.pathname).toBe(CURRENT_PATH);
      expect(window.history.state?.key).not.toBe(oldKey);
      expect(screen.getByTestId('current-route').textContent).toBe(NEW_PATH);
      expect(screen.getByTestId('current-route')).toHaveAttribute('data-entry-key', oldKey);
      expect(screen.getByTestId('revocationWizard.name')).toHaveValue('Precommit create');
      await act(async () => {
        reply.resolve(HttpResponse.error());
        await createProfile.mock.results[0].value.catch(() => undefined);
      });
      // The old React view is still mounted; only the browser-entry predicate
      // can stop this nested transport continuation before the new view commits.
      expect(screen.getByTestId('current-route')).toHaveAttribute('data-entry-key', oldKey);
      expect(requests).toHaveLength(1);
      expect(window.location.pathname).toBe(CURRENT_PATH);
      expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    } finally {
      destinationReady = true;
      await act(async () => { transition.resolve(); });
    }
    expect(screen.getByRole('heading', { name: 'Current Trust overview' })).toBeInTheDocument();
  });
});
