import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Suspense, useLayoutEffect } from 'react';
import { BrowserRouter, Route, Routes, useLocation, useNavigate } from 'react-router';
import { act, fireEvent, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { renderWithoutRouter, screen } from '@test/utils';
import IssuerIdentityWizard from './IssuerIdentityWizard';

const { submission, capabilityReads, showNotification, scope, auth, permission, grants } = vi.hoisted(() => ({
  submission: { pending: null as Promise<unknown> | null }, capabilityReads: [] as Promise<unknown>[],
  showNotification: vi.fn(),
  scope: { activeOrgId: 'org-1' as string | null, memberships: [{ id: 'org-1', display_name: 'Test Org' }] },
  auth: { organizationName: 'Test Org', isAuthenticated: true, user: { id: 'principal-1' } },
  permission: { isLoading: false }, grants: new Set<string>(),
}));
vi.mock('../../../hooks/useAuth', () => ({ useAuth: () => auth }));
vi.mock('../../../contexts/ConsoleContext', () => ({ useConsole: () => scope }));
vi.mock('../../../hooks/usePermissions', () => ({
  usePermissions: () => ({ ...permission, can: (resource: string, action: string) => grants.has(resource + ':' + action) }),
}));
vi.mock('../../../hooks/useNotifications', () => ({ useNotifications: () => ({ showNotification }) }));
// Keep the actual API helper, native payload serializer and idempotent retry.
// Capture only its promise so both assertions wait for every internal attempt.
vi.mock('../../../services/issuerIdentitiesApi', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../services/issuerIdentitiesApi')>();
  return { ...actual, default: { ...actual.default,
    getIssuerIdentityCapabilities: (...args: Parameters<typeof actual.getIssuerIdentityCapabilities>) => {
      const pending = actual.getIssuerIdentityCapabilities(...args);
      capabilityReads.push(pending);
      return pending;
    },
    createIssuerIdentity: (...args: Parameters<typeof actual.createIssuerIdentity>) => {
      submission.pending = actual.createIssuerIdentity(...args);
      return submission.pending;
    },
  } };
});

const NEW_PATH = '/console/org/deploy/issuer-identity/new';
const CURRENT_PATH = '/console/org/trust';
const LIST_PATH = '/console/org/deploy/issuer-identity';
const DID = 'did:web:issuer.example.test:orgs:test-org';
const TUPLE = { issuer_did: DID, key_purpose: 'vc_jwt_issuer', credential_format: 'SD_JWT_VC', algorithm: 'ES256' };
const createdIdentity = () => ({ created: true, identity: { ...TUPLE, status: 'active' }, config_revision: null });
const advertisedCapabilities = (organization_id = 'org-1') => ({ organization_id, basis: 'configuration',
  managed_issuer_did_prefix: 'did:web:issuer.example.test:orgs:',
  creation_options: [{ key_purpose: TUPLE.key_purpose, credential_format: TUPLE.credential_format, algorithm: TUPLE.algorithm }],
});
let navigateTo: ReturnType<typeof useNavigate>;
function CurrentRoute() {
  const navigate = useNavigate();
  useLayoutEffect(() => { navigateTo = navigate; }, [navigate]);
  const location = useLocation();
  return <output data-testid="current-route" data-entry-key={location.key}>{location.pathname}{location.search}{location.hash}</output>;
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

function page() {
  return <BrowserRouter><CurrentRoute /><Routes>
    <Route path={NEW_PATH} element={<IssuerIdentityWizard />} />
    <Route path={CURRENT_PATH} element={<h1>Current Trust overview</h1>} />
    <Route path={LIST_PATH} element={<h1>Issuer identities</h1>} />
  </Routes></BrowserRouter>;
}
async function ready() {
  await waitFor(() => expect(screen.getByLabelText(/Issuer DID/)).toHaveValue(DID));
}
function submit() { fireEvent.click(screen.getByRole('button', { name: 'Create managed identity' })); }

function installRequests(delayed?: 'discovery' | 'recheck' | 'create' | 'retry') {
  const reply = deferred<Response>();
  const reads: Array<{ organization: string | null; route: string }> = [];
  const writes: Array<{ body: unknown; key: string | null; route: string }> = [];
  let heldResponse: Response;
  server.use(
    http.get('*/v1/signing-keys/issuer-identities/capabilities', ({ request }) => {
      const organization = new URL(request.url).searchParams.get('organization_id');
      reads.push({ organization, route: window.location.pathname });
      const response = HttpResponse.json(advertisedCapabilities(organization!));
      if ((delayed === 'discovery' && reads.length === 1) || (delayed === 'recheck' && reads.length === 2)) {
        heldResponse = response; return reply.promise;
      }
      return response;
    }),
    http.post('*/v1/signing-keys/issuer-identities', async ({ request }) => {
      const body = await request.json() as Record<string, unknown>;
      writes.push({ body, key: request.headers.get('Idempotency-Key'), route: window.location.pathname });
      const response = HttpResponse.json({ created: true, identity: { issuer_did: body.issuer_did,
        key_purpose: body.key_purpose, credential_format: body.credential_format,
        algorithm: body.algorithm, status: 'active' }, config_revision: null });
      if (delayed === 'retry' && writes.length === 1) return HttpResponse.error();
      if ((delayed === 'create' && writes.length === 1) || (delayed === 'retry' && writes.length === 2)) {
        heldResponse = response; return reply.promise;
      }
      return response;
    }),
  );
  return { reads, writes, async settle(response?: Response) {
    await act(async () => {
      const pending = [...capabilityReads, ...(submission.pending ? [submission.pending] : [])];
      reply.resolve(response || heldResponse);
      await Promise.allSettled(pending);
    });
  } };
}

function holdDestination(samePath = false) {
  const transition = deferred<void>();
  let destinationReady = false;
  const initialKey = window.history.state?.key || 'default';
  function Destination() {
    if (!destinationReady) throw transition.promise;
    return <h1>Current Trust overview</h1>;
  }
  function Entry() {
    const location = useLocation();
    return location.key === initialKey ? <IssuerIdentityWizard /> : <Destination />;
  }
  renderWithoutRouter(<BrowserRouter><Suspense fallback={<h1>Loading destination</h1>}>
    <CurrentRoute /><Routes>
      <Route path={NEW_PATH} element={samePath ? <Entry /> : <IssuerIdentityWizard />} />
      <Route path={CURRENT_PATH} element={<Destination />} />
      <Route path={LIST_PATH} element={<h1>Issuer identities</h1>} />
    </Routes>
  </Suspense></BrowserRouter>);
  return async () => { destinationReady = true; await act(async () => { transition.resolve(); }); };
}

beforeEach(() => {
  submission.pending = null; capabilityReads.length = 0; showNotification.mockReset();
  scope.activeOrgId = 'org-1'; auth.user = { id: 'principal-1' }; auth.isAuthenticated = true;
  permission.isLoading = false;
  grants.clear(); grants.add('signing-key:view'); grants.add('signing-key:create');
  window.history.replaceState({}, '', NEW_PATH);
});

describe('Issuer identity wizard actual adapter retry ownership', () => {
  it.each([false, true])('keeps the network retry within the current route (leave: %s)', async (leave) => {
    const reply = deferred<Response>();
    const writes: Array<{ route: string; body: unknown; key: string | null }> = [];
    server.use(
      http.get('*/v1/signing-keys/issuer-identities/capabilities', () => HttpResponse.json({
        organization_id: 'org-1', basis: 'configuration', managed_issuer_did_prefix: 'did:web:issuer.example.test:orgs:',
        creation_options: [{ key_purpose: 'vc_jwt_issuer', credential_format: 'SD_JWT_VC', algorithm: 'ES256' }],
      })),
      http.post('*/v1/signing-keys/issuer-identities', async ({ request }) => {
        const body = await request.json() as Record<string, unknown>;
        writes.push({ route: window.location.pathname, body, key: request.headers.get('Idempotency-Key') });
        return writes.length === 1 ? reply.promise : HttpResponse.json({ created: true,
          identity: { issuer_did: body.issuer_did, key_purpose: body.key_purpose,
            credential_format: body.credential_format, algorithm: body.algorithm, status: 'active' },
          config_revision: 'test-revision',
        });
      }),
    );
    renderWithoutRouter(<BrowserRouter><CurrentRoute /><Routes>
      <Route path={NEW_PATH} element={<IssuerIdentityWizard />} />
      <Route path={CURRENT_PATH} element={<h1>Current Trust overview</h1>} />
      <Route path={LIST_PATH} element={<h1>Issuer identities</h1>} />
    </Routes></BrowserRouter>);
    await waitFor(() => expect(screen.getByLabelText(/Issuer DID/)).toHaveValue(DID));
    fireEvent.click(screen.getByRole('button', { name: 'Create managed identity' }));
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(submission.pending).toBeInstanceOf(Promise);
    if (leave) {
      await act(async () => { await navigateTo(CURRENT_PATH); });
      expect(screen.getByRole('heading', { name: 'Current Trust overview' })).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Create managed identity' })).not.toBeInTheDocument();
    }
    await act(async () => { reply.resolve(HttpResponse.error()); await submission.pending?.catch(() => undefined); });
    if (leave) {
      expect(screen.getByTestId('current-route')).toHaveTextContent(CURRENT_PATH);
      expect(showNotification).not.toHaveBeenCalled();
      expect(writes.map(({ route }) => route), `REQUEST_TRACE=${JSON.stringify(writes)}`).toEqual([NEW_PATH]);
    } else {
      expect(writes).toHaveLength(2);
      expect(writes[0].key).toBeTruthy(); expect(writes[1]).toEqual(writes[0]);
      expect(writes[0].body).toEqual({ organization_id: 'org-1', issuer_did: DID,
        key_purpose: 'vc_jwt_issuer', credential_format: 'SD_JWT_VC', algorithm: 'ES256' });
      expect(showNotification).toHaveBeenCalledWith('Issuer identity created.', 'success');
      expect(screen.getByRole('heading', { name: 'Issuer identities' })).toBeInTheDocument();
    }
  });
});

describe('issuer wizard native grants and view lifetime', () => {
  it.each([
    ['no organization', () => { scope.activeOrgId = null; }, /Select an organization/],
    ['missing view grant', () => { grants.delete('signing-key:view'); }, /permission to view issuer capabilities/],
    ['missing create grant', () => { grants.delete('signing-key:create'); }, /permission to create issuer identities/],
    ['unrelated legacy grants', () => { grants.clear(); grants.add('issuer-profile:create'); grants.add('issuer-profile:view'); }, /permission to view issuer capabilities/],
  ] as const)('does not read or create with %s', async (_label, changeScope, message) => {
    const requests = installRequests(); changeScope();
    renderWithoutRouter(page());
    expect(screen.getByText(message)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Create managed identity' })).not.toBeInTheDocument();
    expect(capabilityReads).toHaveLength(0); expect(requests.writes).toHaveLength(0);
  });

  it('waits for permissions before discovering capabilities', async () => {
    const requests = installRequests(); permission.isLoading = true;
    const view = renderWithoutRouter(page());
    expect(screen.getByRole('progressbar')).toBeInTheDocument(); expect(capabilityReads).toHaveLength(0);
    permission.isLoading = false; view.rerender(page()); await ready();
    expect(requests.reads).toEqual([{ organization: 'org-1', route: NEW_PATH }]);
  });

  it.each(['discovery', 'recheck', 'create', 'retry'] as const)('ends %s continuation after route unmount', async (stage) => {
    const requests = installRequests(stage); renderWithoutRouter(page());
    if (stage === 'discovery') await waitFor(() => expect(requests.reads).toHaveLength(1));
    else {
      await ready(); submit();
      await waitFor(() => expect(stage === 'recheck' ? requests.reads : requests.writes)
        .toHaveLength(stage === 'recheck' || stage === 'retry' ? 2 : 1));
    }
    await act(async () => { navigateTo(CURRENT_PATH); });
    await requests.settle();
    expect(screen.getByRole('heading', { name: 'Current Trust overview' })).toBeInTheDocument();
    expect(showNotification).not.toHaveBeenCalled();
    expect(requests.writes).toHaveLength(stage === 'create' ? 1 : stage === 'retry' ? 2 : 0);
  });

  it.each(['recheck', 'create'] as const)('does not surface an obsolete ordinary %s error', async (stage) => {
    const requests = installRequests(stage); renderWithoutRouter(page()); await ready(); submit();
    await waitFor(() => expect(stage === 'recheck' ? requests.reads : requests.writes).toHaveLength(stage === 'recheck' ? 2 : 1));
    await act(async () => { navigateTo(CURRENT_PATH); });
    await requests.settle(HttpResponse.json({ error: { message: 'Old request rejected' } }, { status: 403 }));
    expect(screen.getByRole('heading', { name: 'Current Trust overview' })).toBeInTheDocument();
    expect(screen.queryByText(/Old request rejected/)).not.toBeInTheDocument();
    expect(showNotification).not.toHaveBeenCalled();
  });

  const invalidations = [
    ['organization', () => { scope.activeOrgId = 'org-2'; }],
    ['principal', () => { auth.user = { id: 'principal-2' }; }],
    ['authentication generation', () => { auth.isAuthenticated = false; }],
    ['view grant', () => { grants.delete('signing-key:view'); }],
    ['create grant', () => { grants.delete('signing-key:create'); }],
    ['permission loading', () => { permission.isLoading = true; }],
  ] as const;
  it.each(invalidations)('stops an old capability recheck after %s changes', async (_label, invalidate) => {
    const requests = installRequests('recheck'); const view = renderWithoutRouter(page());
    await ready(); submit(); await waitFor(() => expect(requests.reads).toHaveLength(2));
    invalidate(); view.rerender(page()); await requests.settle();
    expect(requests.writes).toHaveLength(0); expect(showNotification).not.toHaveBeenCalled();
    expect(screen.getByTestId('current-route')).toHaveTextContent(NEW_PATH);
  });
  it.each(invalidations)('stops an internal create retry after %s changes', async (_label, invalidate) => {
    const requests = installRequests('create'); const view = renderWithoutRouter(page());
    await ready(); submit(); await waitFor(() => expect(requests.writes).toHaveLength(1));
    invalidate(); view.rerender(page()); await requests.settle(HttpResponse.error());
    expect(requests.writes).toHaveLength(1); expect(showNotification).not.toHaveBeenCalled();
    expect(screen.getByTestId('current-route')).toHaveTextContent(NEW_PATH);
  });

  it.each([NEW_PATH, NEW_PATH + '?entry=next', NEW_PATH + '#next'])('resets an obsolete form for a committed entry %s', async (next) => {
    const requests = installRequests('create'); renderWithoutRouter(page()); await ready();
    fireEvent.change(screen.getByLabelText(/Issuer DID/), { target: { value: DID + '-old' } }); submit();
    await waitFor(() => expect(requests.writes).toHaveLength(1));
    const oldKey = window.history.state?.key;
    await act(async () => { navigateTo(next); }); await ready();
    expect(window.history.state?.key).not.toBe(oldKey);
    await requests.settle();
    expect(showNotification).not.toHaveBeenCalled(); expect(requests.writes).toHaveLength(1);
    expect(screen.getByTestId('current-route').textContent).toBe(next);
    expect(screen.getByLabelText(/Issuer DID/)).toHaveValue(DID);
  });
});

describe('issuer wizard actual browser history before React commit', () => {
  it.each([
    ['recheck', false], ['create', false], ['create', true], ['retry', false],
  ] as const)('stops %s settlement while the old view remains mounted (network failure: %s)', async (stage, networkFailure) => {
    const requests = installRequests(stage); const release = holdDestination();
    await ready(); submit();
    await waitFor(() => expect(stage === 'recheck' ? requests.reads : requests.writes)
      .toHaveLength(stage === 'recheck' || stage === 'retry' ? 2 : 1));
    const oldKey = screen.getByTestId('current-route').getAttribute('data-entry-key');
    try {
      await act(async () => { navigateTo(CURRENT_PATH); });
      expect(window.location.pathname).toBe(CURRENT_PATH); expect(window.history.state?.key).not.toBe(oldKey);
      expect(screen.getByTestId('current-route').textContent).toBe(NEW_PATH);
      expect(screen.getByTestId('current-route')).toHaveAttribute('data-entry-key', oldKey);
      expect(screen.getByLabelText(/Issuer DID/)).toHaveValue(DID);
      await requests.settle(networkFailure ? HttpResponse.error() : undefined);
      expect(requests.writes).toHaveLength(stage === 'create' ? 1 : stage === 'retry' ? 2 : 0);
      expect(showNotification).not.toHaveBeenCalled(); expect(window.location.pathname).toBe(CURRENT_PATH);
      expect(screen.getByTestId('current-route')).toHaveAttribute('data-entry-key', oldKey);
    } finally { await release(); }
    expect(screen.getByRole('heading', { name: 'Current Trust overview' })).toBeInTheDocument();
  });

  it('does not dispatch or edit an old visible form after history changes', async () => {
    const requests = installRequests(); const release = holdDestination(); await ready();
    const form = screen.getByRole('button', { name: 'Create managed identity' }).closest('form')!;
    try {
      await act(async () => { navigateTo(CURRENT_PATH); });
      fireEvent.change(screen.getByLabelText(/Issuer DID/), { target: { value: DID + '-obsolete' } });
      fireEvent.click(screen.getByRole('button', { name: 'Refresh issuer capabilities' }));
      fireEvent.click(screen.getByRole('button', { name: 'Back to issuer identities' }));
      fireEvent.submit(form);
      expect(screen.getByLabelText(/Issuer DID/)).toHaveValue(DID);
      expect(capabilityReads).toHaveLength(1); expect(requests.writes).toHaveLength(0);
      expect(window.location.pathname).toBe(CURRENT_PATH);
    } finally { await release(); }
  });

  it('stops a nested retry for a new history entry with the identical URL', async () => {
    const requests = installRequests('create'); const release = holdDestination(true);
    await ready(); submit(); await waitFor(() => expect(requests.writes).toHaveLength(1));
    const oldKey = screen.getByTestId('current-route').getAttribute('data-entry-key');
    try {
      await act(async () => { navigateTo(NEW_PATH); });
      expect(window.location.pathname).toBe(NEW_PATH); expect(window.history.state?.key).not.toBe(oldKey);
      expect(screen.getByTestId('current-route')).toHaveAttribute('data-entry-key', oldKey);
      await requests.settle(HttpResponse.error());
      expect(requests.writes).toHaveLength(1); expect(showNotification).not.toHaveBeenCalled();
    } finally { await release(); }
  });
});

describe('issuer wizard current form and native acknowledgments', () => {
  it('locks submitted inputs and rejects same-turn duplicates while capabilities are rechecked', async () => {
    const requests = installRequests('recheck'); renderWithoutRouter(page()); await ready();
    const form = screen.getByRole('button', { name: 'Create managed identity' }).closest('form')!;
    act(() => { fireEvent.submit(form); fireEvent.submit(form); });
    await waitFor(() => expect(requests.reads).toHaveLength(2));
    expect(screen.getByLabelText(/Issuer DID/)).toBeDisabled();
    for (const name of [/Signing purpose/, /Credential format/, /Algorithm/]) {
      expect(screen.getByRole('combobox', { name })).toHaveAttribute('aria-disabled', 'true');
    }
    expect(screen.getByRole('button', { name: 'Refresh issuer capabilities' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
    fireEvent.change(screen.getByLabelText(/Issuer DID/), { target: { value: DID + '-changed' } });
    fireEvent.submit(form); await requests.settle();
    await screen.findByRole('heading', { name: 'Issuer identities' });
    expect(requests.reads).toHaveLength(2); expect(requests.writes).toHaveLength(1);
    expect(requests.writes[0].body).toEqual({ organization_id: 'org-1', ...TUPLE });
  });

  it.each([
    ['missing identity', (value: Record<string, any>) => { delete value.identity; }],
    ['wrong DID', (value: Record<string, any>) => { value.identity.issuer_did = 'did:web:other'; }],
    ['wrong purpose', (value: Record<string, any>) => { value.identity.key_purpose = 'mdoc_dsc'; }],
    ['wrong format', (value: Record<string, any>) => { value.identity.credential_format = 'VC_JWT'; }],
    ['wrong algorithm', (value: Record<string, any>) => { value.identity.algorithm = 'RS256'; }],
    ['inactive status', (value: Record<string, any>) => { value.identity.status = 'inactive'; }],
    ['missing status', (value: Record<string, any>) => { delete value.identity.status; }],
    ['missing created', (value: Record<string, any>) => { delete value.created; }],
    ['nonboolean created', (value: Record<string, any>) => { value.created = 'true'; }],
  ] as const)('does not claim success for %s', async (_label, mutate) => {
    const requests = installRequests('create'); renderWithoutRouter(page()); await ready(); submit();
    await waitFor(() => expect(requests.writes).toHaveLength(1));
    const response = createdIdentity(); mutate(response); await requests.settle(HttpResponse.json(response));
    expect(screen.getByText(/The server did not confirm the requested issuer identity/)).toBeInTheDocument();
    expect(screen.getByTestId('current-route')).toHaveTextContent(NEW_PATH);
    expect(showNotification).not.toHaveBeenCalled(); expect(requests.writes).toHaveLength(1);
  });

  it.each([true, false])('accepts the exact native tuple with created=%s, no organization field and null revision', async (created) => {
    const requests = installRequests('create'); renderWithoutRouter(page()); await ready(); submit();
    await waitFor(() => expect(requests.writes).toHaveLength(1));
    await requests.settle(HttpResponse.json({ ...createdIdentity(), created }));
    expect(showNotification).toHaveBeenCalledWith(created ? 'Issuer identity created.' : 'Issuer identity already exists.', 'success');
    expect(screen.getByRole('heading', { name: 'Issuer identities' })).toBeInTheDocument();
  });

  it('shows a current ordinary create failure and allows an explicit new submission', async () => {
    const requests = installRequests('create'); renderWithoutRouter(page()); await ready(); submit();
    await waitFor(() => expect(requests.writes).toHaveLength(1));
    await requests.settle(HttpResponse.json({ error: { message: 'Issuer policy rejected the request' } }, { status: 409 }));
    expect(screen.getByText(/Issuer policy rejected the request/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create managed identity' })).toBeEnabled();
    expect(requests.writes).toHaveLength(1); submit();
    await screen.findByRole('heading', { name: 'Issuer identities' });
    expect(requests.writes).toHaveLength(2); expect(requests.writes[0].key).not.toBe(requests.writes[1].key);
  });

  it.each(['discovery', 'recheck'] as const)('uses one capability attempt and supports explicit recovery after current %s network failure', async (stage) => {
    const requests = installRequests(stage); renderWithoutRouter(page());
    if (stage === 'recheck') { await ready(); submit(); }
    await waitFor(() => expect(requests.reads).toHaveLength(stage === 'recheck' ? 2 : 1));
    await requests.settle(HttpResponse.error());
    expect(requests.reads).toHaveLength(stage === 'recheck' ? 2 : 1); expect(requests.writes).toHaveLength(0);
    expect(screen.getAllByRole('alert').some(node => /Failed to fetch|fetch failed/.test(node.textContent || ''))).toBe(true);
    if (stage === 'discovery') {
      fireEvent.click(screen.getByRole('button', { name: 'Refresh issuer capabilities' })); await ready();
    }
    submit(); await screen.findByRole('heading', { name: 'Issuer identities' });
    expect(requests.writes).toHaveLength(1);
  });
});
