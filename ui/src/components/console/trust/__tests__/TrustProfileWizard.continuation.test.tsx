import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Suspense, useLayoutEffect } from 'react';
import { BrowserRouter, Route, Routes, useLocation, useNavigate } from 'react-router';
import { act, fireEvent, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { renderWithoutRouter, screen } from '@test/utils';
import TrustProfileWizard from '../TrustProfileWizard';

const { submission, context, permission, grants, auth } = vi.hoisted(() => ({
  submission: { pending: null as Promise<unknown> | null },
  context: { activeOrgId: 'org-1' as string | null },
  permission: { isLoading: false }, grants: new Set<string>(),
  auth: { isAuthenticated: true, user: { id: 'principal-1' } },
}));
vi.mock('../../../../contexts/ConsoleContext', () => ({
  useConsole: () => context,
}));
vi.mock('../../../../hooks/useAuth', () => ({ useAuth: () => auth }));
vi.mock('../../../../hooks/usePermissions', () => ({
  usePermissions: () => ({ ...permission, can: (resource: string, action: string) => grants.has(resource + ':' + action) }),
}));
vi.mock('../../../../services/walletRegistryApi', () => ({ listWallets: async () => [] }));
// Preserve the actual hook and every lifecycle guard; capture its real callback
// promise only so the regression can wait for the entire request chain to settle.
vi.mock('../../../../hooks/useWizard', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../hooks/useWizard')>();
  return { ...actual, useWizard: (config: any) => actual.useWizard({
    ...config,
    onSubmit: (data: unknown) => {
      submission.pending = config.onSubmit(data);
      return submission.pending;
    },
  }) };
});

const NEW_PATH = '/console/org/trust/profiles/new';
const CURRENT_PATH = '/console/org/trust';
const PROFILE_ID = '11111111-1111-4111-8111-111111111111';
const ISSUER_ID = '22222222-2222-4222-8222-222222222222';
const RELATIONSHIP_ID = '33333333-3333-4333-8333-333333333333';
const DID = 'did:web:issuer.example.test';

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

let navigateTo: ReturnType<typeof useNavigate>;
function CurrentRoute() {
  const navigate = useNavigate();
  useLayoutEffect(() => { navigateTo = navigate; }, [navigate]);
  const location = useLocation();
  return <output data-testid="current-route" data-entry-key={location.key}>{location.pathname}{location.search}{location.hash}</output>;
}
function page() {
  return <BrowserRouter><CurrentRoute /><Routes>
    <Route path={NEW_PATH} element={<TrustProfileWizard />} />
    <Route path={CURRENT_PATH} element={<h1>Current Trust overview</h1>} />
    <Route path="/console/org/templates/credentials" element={<h1>Credential Templates</h1>} />
  </Routes></BrowserRouter>;
}

async function submitRealWizard() {
  fireEvent.change(screen.getByTestId('wizard.trustProfile.name'), { target: { value: 'Delayed trust profile' } });
  fireEvent.click(screen.getByTestId('wizard.trustProfile.next'));
  fireEvent.change(await screen.findByTestId('wizard.trustProfile.issuerDid'), { target: { value: DID } });
  fireEvent.click(screen.getByTestId('wizard.trustProfile.addIssuer'));
  fireEvent.click(screen.getByTestId('wizard.trustProfile.next'));
  fireEvent.click(await screen.findByTestId('wizard.trustProfile.skip'));
  fireEvent.click(await screen.findByTestId('wizard.trustProfile.submit'));
}

beforeEach(() => {
  submission.pending = null;
  context.activeOrgId = 'org-1'; permission.isLoading = false;
  auth.isAuthenticated = true; auth.user = { id: 'principal-1' };
  grants.clear();
  for (const grant of ['trust-profile:create', 'trust-profile:view', 'trust-profile:activate', 'trusted-issuer:view', 'trusted-issuer:create']) grants.add(grant);
  window.history.replaceState({}, '', NEW_PATH);
});

describe('Trust wizard actual adapter continuation ownership', () => {
  it.each([false, true])('suppresses follow-up writes after navigation: %s', async (leave) => {
    const reply = deferred<Response>();
    const writes: Array<{ endpoint: string; route: string; body: unknown }> = [];
    let createdBody: Record<string, unknown> = {};
    server.use(
      http.post('*/v1/trust-profiles', async ({ request }) => {
        createdBody = await request.json() as Record<string, unknown>;
        writes.push({ endpoint: 'create', route: window.location.pathname, body: createdBody });
        return reply.promise;
      }),
      http.get('*/v1/issuer-entities', () => HttpResponse.json([])),
      http.post('*/v1/issuer-entities', async ({ request }) => {
        const body = await request.json() as Record<string, unknown>;
        writes.push({ endpoint: 'issuer-entity', route: window.location.pathname, body });
        return HttpResponse.json({ ...body, id: ISSUER_ID, is_system_issuer: false }, { status: 201 });
      }),
      http.post('*/v1/trust-profiles/:id/issuers', async ({ request, params }) => {
        const body = await request.json() as Record<string, unknown>;
        writes.push({ endpoint: 'issuer-link', route: window.location.pathname, body });
        return HttpResponse.json({ ...body, id: RELATIONSHIP_ID, trust_profile_id: params.id }, { status: 201 });
      }),
      http.post('*/v1/trust-profiles/:id/activate', async ({ request }) => {
        writes.push({ endpoint: 'activate', route: window.location.pathname, body: await request.json() });
        return HttpResponse.json({ ...createdBody, id: PROFILE_ID, status: 'ACTIVE' });
      }),
    );
    renderWithoutRouter(page());
    await submitRealWizard();
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(submission.pending).toBeInstanceOf(Promise);
    if (leave) {
      await act(async () => { await navigateTo(CURRENT_PATH); });
      expect(screen.getByRole('heading', { name: 'Current Trust overview' })).toBeInTheDocument();
      expect(screen.queryByTestId('wizard.trustProfile.submit')).not.toBeInTheDocument();
    }
    await act(async () => {
      reply.resolve(HttpResponse.json({ ...createdBody, id: PROFILE_ID, status: 'DRAFT' }, { status: 201 }));
      await submission.pending?.catch(() => undefined);
    });
    if (leave) {
      // The actual useWizard unmount guard already suppresses final UI state.
      expect(screen.getByTestId('current-route')).toHaveTextContent(CURRENT_PATH);
      expect(screen.queryByTestId('wizard.trustProfile.success')).not.toBeInTheDocument();
      expect(writes.map(({ endpoint, route }) => ({ endpoint, route }))).toEqual([
        { endpoint: 'create', route: NEW_PATH },
      ]);
    } else {
      expect(writes.map(({ endpoint }) => endpoint)).toEqual(['create', 'issuer-entity', 'issuer-link', 'activate']);
      expect(screen.getByTestId('wizard.trustProfile.success')).toBeInTheDocument();
    }
  });
});

type Stage = 'create' | 'issuer-inventory' | 'issuer-entity' | 'issuer-link' | 'registry' | 'activate' | 'activation-readback';
const REGISTRY_URL = 'https://registry.example.test/v1/trust-registry/sync';
const SYNCED_AT = '2026-11-09T14:00:00Z';

function installChain(options: {
  delayed?: Stage;
  createNetworkFailure?: boolean;
  activationNetworkFailure?: boolean;
  readNetworkFailure?: 'issuer-inventory' | 'activation-readback';
  overrides?: Partial<Record<Stage, Record<string, unknown>>>;
} = {}) {
  const pending = deferred<Response>();
  let heldResponse: Response;
  const calls: Array<{ stage: Stage; route: string; method: string; body: unknown; key: string | null }> = [];
  let createdBody: Record<string, unknown> = {};
  const respond = async (stage: Stage, request: Request, response: Response) => {
    calls.push({ stage, route: window.location.pathname, method: request.method,
      body: request.method === 'GET' ? null : await request.clone().json(),
      key: request.headers.get('Idempotency-Key') });
    if (options.delayed === stage && calls.filter(call => call.stage === stage).length === 1) {
      heldResponse = response;
      return pending.promise;
    }
    return response;
  };
  const json = (stage: Stage, value: Record<string, unknown>, status = 200) => (
    HttpResponse.json({ ...value, ...options.overrides?.[stage] }, { status })
  );
  server.use(
    http.post('*/v1/trust-profiles', async ({ request }) => {
      createdBody = await request.clone().json() as Record<string, unknown>;
      const response = options.createNetworkFailure && !calls.some(call => call.stage === 'create')
        ? HttpResponse.error() : json('create', { ...createdBody, id: PROFILE_ID, status: 'DRAFT' }, 201);
      return respond('create', request, response);
    }),
    http.get('*/v1/issuer-entities', ({ request }) => respond('issuer-inventory', request,
      options.readNetworkFailure === 'issuer-inventory' && !calls.some(call => call.stage === 'issuer-inventory')
        ? HttpResponse.error() : HttpResponse.json([]))),
    http.post('*/v1/issuer-entities', async ({ request }) => respond('issuer-entity', request,
      json('issuer-entity', { ...await request.clone().json() as object, id: ISSUER_ID, is_system_issuer: false }, 201))),
    http.post('*/v1/trust-profiles/:id/issuers', async ({ request, params }) => respond('issuer-link', request,
      json('issuer-link', { ...await request.clone().json() as object, id: RELATIONSHIP_ID, trust_profile_id: params.id }, 201))),
    http.post('*/v1/trust-profiles/:id/registry-sync', ({ request, params }) => respond('registry', request,
      json('registry', { trust_profile_id: params.id, synchronized_at: SYNCED_AT,
        sources: [{ url: REGISTRY_URL, protocol: 'MARTY_TRUST_REGISTRY_SYNC_V1', sequence: 1, synchronized_at: SYNCED_AT }] }))),
    http.post('*/v1/trust-profiles/:id/activate', ({ request }) => respond('activate', request,
      options.activationNetworkFailure ? HttpResponse.error() : json('activate', { ...createdBody, id: PROFILE_ID, status: 'ACTIVE' }))),
    http.get('*/v1/trust-profiles/:id', ({ request }) => respond('activation-readback', request,
      options.readNetworkFailure === 'activation-readback' && !calls.some(call => call.stage === 'activation-readback')
        ? HttpResponse.error() : json('activation-readback', { ...createdBody, id: PROFILE_ID, status: 'ACTIVE' }))),
  );
  return { calls, settle: (networkFailure = false) => pending.resolve(networkFailure ? HttpResponse.error() : heldResponse) };
}

async function prepareWizard({ issuer = true, secondIssuer = false, registry = false, activate = true } = {}) {
  fireEvent.change(screen.getByTestId('wizard.trustProfile.name'), { target: { value: 'Owned trust profile' } });
  fireEvent.click(screen.getByTestId('wizard.trustProfile.next'));
  if (issuer) {
    for (const did of secondIssuer ? [DID, 'did:web:second.example.test'] : [DID]) {
      fireEvent.change(await screen.findByTestId('wizard.trustProfile.issuerDid'), { target: { value: did } });
      fireEvent.click(screen.getByTestId('wizard.trustProfile.addIssuer'));
    }
  }
  if (registry) {
    fireEvent.click(screen.getByTestId('wizard.trustProfile.tab.registries'));
    fireEvent.click(await screen.findByTestId('wizard.trustProfile.addRegistry'));
    fireEvent.change(await screen.findByTestId('wizard.trustProfile.registrySelect'), { target: { value: REGISTRY_URL } });
    fireEvent.click(screen.getByTestId('wizard.trustProfile.registryDialog.add'));
  }
  fireEvent.click(screen.getByTestId('wizard.trustProfile.next'));
  fireEvent.click(await screen.findByTestId('wizard.trustProfile.skip'));
  await screen.findByTestId('wizard.trustProfile.submit');
  if (!activate) fireEvent.click(screen.getByRole('switch'));
}

function submit() { fireEvent.click(screen.getByTestId('wizard.trustProfile.submit')); }
async function settleSubmission(settle?: () => void) {
  await act(async () => { settle?.(); await submission.pending?.catch(() => undefined); });
}

describe('Trust wizard continuation boundaries', () => {
  it('completes the current issuer, registry and activation chain with native acknowledgments', async () => {
    const chain = installChain();
    renderWithoutRouter(page());
    await prepareWizard({ registry: true }); submit();
    await screen.findByTestId('wizard.trustProfile.success');
    expect(chain.calls.map(call => call.stage)).toEqual(['create', 'issuer-inventory', 'issuer-entity', 'issuer-link', 'registry', 'activate']);
    expect(chain.calls[0].body).toEqual(expect.objectContaining({ organization_id: 'org-1', name: 'Owned trust profile',
      trust_sources: [expect.objectContaining({ url: REGISTRY_URL })] }));
    expect(chain.calls.every(call => call.route === NEW_PATH)).toBe(true);
  });

  it.each<Stage>(['issuer-inventory', 'issuer-entity', 'issuer-link', 'registry', 'activate', 'activation-readback'])(
    'ends every remaining continuation when navigation occurs during %s', async (stage) => {
      const chain = installChain({ delayed: stage, activationNetworkFailure: stage === 'activation-readback' });
      renderWithoutRouter(page());
      await prepareWizard({ registry: true }); submit();
      await waitFor(() => expect(chain.calls.some(call => call.stage === stage)).toBe(true));
      const beforeLeaving = [...chain.calls];
      await act(async () => { await navigateTo(CURRENT_PATH); });
      await settleSubmission(() => chain.settle());
      expect(chain.calls).toEqual(beforeLeaving);
      expect(screen.getByRole('heading', { name: 'Current Trust overview' })).toBeInTheDocument();
      expect(screen.queryByTestId('wizard.trustProfile.error')).not.toBeInTheDocument();
      expect(screen.queryByTestId('wizard.trustProfile.success')).not.toBeInTheDocument();
    },
  );

  it.each<Stage>(['create', 'activate', 'issuer-inventory', 'activation-readback'])('suppresses the nested retry or readback after a departed %s rejects', async (stage) => {
    const chain = installChain({ delayed: stage, activationNetworkFailure: stage === 'activation-readback' });
    renderWithoutRouter(page());
    await prepareWizard(); submit();
    await waitFor(() => expect(chain.calls.some(call => call.stage === stage)).toBe(true));
    const beforeLeaving = [...chain.calls];
    await act(async () => { await navigateTo(CURRENT_PATH); });
    await settleSubmission(() => chain.settle(true));
    expect(chain.calls).toEqual(beforeLeaving);
    expect(screen.getByTestId('current-route')).toHaveTextContent(CURRENT_PATH);
  });

  it('preserves the current create retry with the same idempotency key and exact body', async () => {
    const chain = installChain({ createNetworkFailure: true });
    renderWithoutRouter(page());
    await prepareWizard(); submit();
    await screen.findByTestId('wizard.trustProfile.success');
    const creates = chain.calls.filter(call => call.stage === 'create');
    expect(creates).toHaveLength(2);
    expect(creates[0].key).toBeTruthy();
    expect(creates[1]).toEqual(creates[0]);
    expect(chain.calls.filter(call => call.stage === 'activate')).toHaveLength(1);
  });

  it('preserves current activation readback and validates its ACTIVE result', async () => {
    const chain = installChain({ activationNetworkFailure: true });
    renderWithoutRouter(page());
    await prepareWizard(); submit();
    await screen.findByTestId('wizard.trustProfile.success');
    expect(chain.calls.map(call => call.stage)).toEqual(['create', 'issuer-inventory', 'issuer-entity', 'issuer-link', 'activate', 'activation-readback']);
  });

  it.each(['issuer-inventory', 'activation-readback'] as const)('surfaces a current %s failure without an implicit read retry or recreation', async (stage) => {
    const chain = installChain({ readNetworkFailure: stage, activationNetworkFailure: stage === 'activation-readback' });
    renderWithoutRouter(page()); await prepareWizard(); submit();
    await screen.findByTestId('wizard.trustProfile.error');
    expect(chain.calls.filter(call => call.stage === stage)).toHaveLength(1);
    expect(chain.calls.at(-1)?.stage).toBe(stage);
    expect(screen.getByText(/This trust profile was created/)).toBeInTheDocument();
    expect(screen.getByTestId('wizard.trustProfile.submit')).toBeDisabled();
  });

  it.each(['organization', 'principal', 'permission loading', 'create grant', 'issuer view grant', 'issuer create grant', 'registry view grant', 'activation grant'])(
    'invalidates the old draft continuation on a changed %s', async (change) => {
      const chain = installChain({ delayed: 'create' });
      const view = renderWithoutRouter(page());
      await prepareWizard({ registry: true }); submit();
      await waitFor(() => expect(chain.calls).toHaveLength(1));
      if (change === 'organization') context.activeOrgId = 'org-2';
      if (change === 'principal') auth.user = { id: 'principal-2' };
      if (change === 'permission loading') permission.isLoading = true;
      if (change === 'create grant') grants.delete('trust-profile:create');
      if (change === 'issuer view grant') grants.delete('trusted-issuer:view');
      if (change === 'issuer create grant') grants.delete('trusted-issuer:create');
      if (change === 'registry view grant') grants.delete('trust-profile:view');
      if (change === 'activation grant') grants.delete('trust-profile:activate');
      view.rerender(page());
      await settleSubmission(() => chain.settle());
      expect(chain.calls).toHaveLength(1);
      expect(screen.queryByTestId('wizard.trustProfile.error')).not.toBeInTheDocument();
      expect(screen.queryByTestId('wizard.trustProfile.success')).not.toBeInTheDocument();
      if (change === 'permission loading' || change === 'create grant') {
        expect(screen.queryByTestId('wizard.trustProfile.name')).not.toBeInTheDocument();
        permission.isLoading = false; grants.add('trust-profile:create'); view.rerender(page());
      }
      expect(screen.getByTestId('wizard.trustProfile.name')).toHaveValue('');
    },
  );

  it.each(['same path', 'search', 'hash'])('starts a fresh wizard on a new browser entry with %s', async (entry) => {
    const chain = installChain({ delayed: 'create' });
    renderWithoutRouter(page());
    await prepareWizard(); submit();
    await waitFor(() => expect(chain.calls).toHaveLength(1));
    const oldKey = window.history.state?.key;
    const destination = NEW_PATH + (entry === 'search' ? '?fresh=1' : entry === 'hash' ? '#fresh' : '');
    await act(async () => { await navigateTo(destination); });
    expect(window.history.state?.key).not.toBe(oldKey);
    expect(screen.getByTestId('wizard.trustProfile.name')).toHaveValue('');
    await settleSubmission(() => chain.settle());
    expect(chain.calls).toHaveLength(1);
    expect(screen.getByTestId('wizard.trustProfile.name')).toHaveValue('');
  });

  it('locks the captured review fields and rejects same-turn duplicate submission', async () => {
    const chain = installChain({ delayed: 'create' });
    renderWithoutRouter(page());
    await prepareWizard();
    const activate = screen.getByRole('switch');
    const create = screen.getByTestId('wizard.trustProfile.submit');
    act(() => { fireEvent.click(create); fireEvent.click(create); fireEvent.click(activate); });
    await waitFor(() => expect(chain.calls).toHaveLength(1));
    expect(activate).toBeDisabled(); expect(activate).toBeChecked();
    expect(screen.getByTestId('wizard.trustProfile.back')).toBeDisabled();
    for (const edit of screen.getAllByRole('button', { name: /edit/i })) expect(edit).toBeDisabled();
    await settleSubmission(() => chain.settle());
    expect(chain.calls.filter(call => call.stage === 'create')).toHaveLength(1);
    expect(chain.calls.filter(call => call.stage === 'activate')).toHaveLength(1);
    expect(screen.getByTestId('wizard.trustProfile.success')).toBeInTheDocument();
  });

  it('keeps an ordinary create error editable and permits a current explicit retry', async () => {
    const chain = installChain();
    let attempts = 0;
    server.use(http.post('*/v1/trust-profiles', async ({ request }) => {
      attempts += 1;
      return attempts === 1
        ? HttpResponse.json({ error: { message: 'Name already exists' } }, { status: 409 })
        : HttpResponse.json({ ...await request.json() as object, id: PROFILE_ID, status: 'DRAFT' });
    }));
    renderWithoutRouter(page());
    await prepareWizard({ issuer: false, activate: false }); submit();
    await screen.findByText(/Name already exists/);
    expect(screen.getByRole('switch')).toBeEnabled();
    expect(screen.getByTestId('wizard.trustProfile.submit')).toBeEnabled();
    submit();
    await screen.findByTestId('wizard.trustProfile.success');
    expect(attempts).toBe(2); expect(chain.calls).toHaveLength(0);
  });

  it('retains the acknowledged profile after a follow-up error and prevents recreating it', async () => {
    const chain = installChain({ overrides: { 'issuer-entity': { organization_id: 'another-org' } } });
    renderWithoutRouter(page());
    await prepareWizard(); submit();
    await screen.findByTestId('wizard.trustProfile.error');
    expect(screen.getByText(/This trust profile was created/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'View details' })).toHaveAttribute('href', '/console/org/trust/profiles/' + PROFILE_ID);
    expect(screen.getByTestId('wizard.trustProfile.submit')).toBeDisabled();
    submit();
    expect(chain.calls.map(call => call.stage)).toEqual(['create', 'issuer-inventory', 'issuer-entity']);
  });

  it('ends pending sibling issuer continuations when one issuer fails', async () => {
    const api = await import('../../../../services/presentationPolicyApi');
    const original = api.addTrustProfileIssuer;
    const helpers: Promise<unknown>[] = [];
    const helper = vi.spyOn(api, 'addTrustProfileIssuer').mockImplementation((...args) => {
      const pending = original(...args); helpers.push(pending); return pending;
    });
    const chain = installChain();
    const first = deferred<Response>(); const second = deferred<Response>();
    const entities: Record<string, unknown>[] = [];
    server.use(http.post('*/v1/issuer-entities', async ({ request }) => {
      const body = await request.json() as Record<string, unknown>; entities.push(body);
      return body.issuer_id === DID ? first.promise : second.promise;
    }));
    try {
      renderWithoutRouter(page());
      await prepareWizard({ secondIssuer: true }); submit();
      await waitFor(() => expect(entities).toHaveLength(2));
      await settleSubmission(() => first.resolve(HttpResponse.json({
        ...entities.find(entity => entity.issuer_id === DID), id: ISSUER_ID, organization_id: 'another-org',
      })));
      expect(screen.getByTestId('wizard.trustProfile.error')).toBeInTheDocument();
      await act(async () => {
        second.resolve(HttpResponse.json({
          ...entities.find(entity => entity.issuer_id !== DID), id: ISSUER_ID, is_system_issuer: false,
        }));
        await Promise.allSettled(helpers);
      });
      expect(chain.calls.map(call => call.stage)).toEqual(['create', 'issuer-inventory', 'issuer-inventory']);
      expect(screen.getByTestId('wizard.trustProfile.submit')).toBeDisabled();
    } finally { helper.mockRestore(); }
  });
});

describe('Trust wizard exact grants and acknowledgments', () => {
  it.each([null, '', '   '])('requires a selected organization: %s', (organization) => {
    context.activeOrgId = organization;
    const chain = installChain(); renderWithoutRouter(page());
    expect(screen.getByRole('alert')).toHaveTextContent('Select an organization');
    expect(screen.queryByTestId('wizard.trustProfile.name')).not.toBeInTheDocument();
    expect(chain.calls).toHaveLength(0);
  });

  it('requires create rather than view or edit and waits for settled grants', () => {
    grants.clear(); grants.add('trust-profile:view'); grants.add('trust-profile:edit');
    const view = renderWithoutRouter(page());
    expect(screen.getByRole('alert')).toHaveTextContent('permission to create');
    permission.isLoading = true; grants.add('trust-profile:create'); view.rerender(page());
    expect(screen.getByRole('progressbar')).toBeInTheDocument();
    expect(screen.queryByTestId('wizard.trustProfile.name')).not.toBeInTheDocument();
    permission.isLoading = false; view.rerender(page());
    expect(screen.getByTestId('wizard.trustProfile.name')).toHaveValue('');
  });

  it('allows a draft using only the create grant when no follow-up action is requested', async () => {
    grants.clear(); grants.add('trust-profile:create');
    const chain = installChain(); renderWithoutRouter(page());
    await prepareWizard({ issuer: false });
    expect(screen.getByText(/Turn off immediate activation/)).toBeInTheDocument();
    expect(screen.getByTestId('wizard.trustProfile.submit')).toBeDisabled();
    fireEvent.click(screen.getByRole('switch')); submit();
    await screen.findByTestId('wizard.trustProfile.success');
    expect(chain.calls.map(call => call.stage)).toEqual(['create']);
  });

  it.each(['trusted-issuer:view', 'trusted-issuer:create', 'trust-profile:view', 'trust-profile:activate'])(
    'checks the exact requested follow-up grant %s before creating a profile', async (grant) => {
      grants.delete(grant);
      const chain = installChain(); renderWithoutRouter(page());
      await prepareWizard({ registry: grant === 'trust-profile:view' });
      expect(screen.getByTestId('wizard.trustProfile.submit')).toBeDisabled();
      const explanation = grant.startsWith('trusted-issuer') ? /Adding issuer relationships requires/
        : grant === 'trust-profile:view' ? /Synchronizing registry sources requires/ : /permission to activate trust profiles/;
      expect(screen.getByText(explanation)).toBeInTheDocument();
      submit(); expect(chain.calls).toHaveLength(0);
    },
  );

  it('allows activation without the independent view grant but omits unauthorized readback', async () => {
    grants.delete('trust-profile:view');
    const chain = installChain({ activationNetworkFailure: true }); renderWithoutRouter(page());
    await prepareWizard(); submit();
    await screen.findByTestId('wizard.trustProfile.error');
    expect(chain.calls.map(call => call.stage)).toEqual(['create', 'issuer-inventory', 'issuer-entity', 'issuer-link', 'activate']);
    expect(screen.getByText(/This trust profile was created/)).toBeInTheDocument();
    expect(screen.getByText(new RegExp(PROFILE_ID))).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'View details' })).not.toBeInTheDocument();
  });

  it.each([
    { id: '' }, { id: 123 }, { organization_id: 'another-org' }, { organization_id: undefined },
    { status: 'ACTIVE' }, { status: undefined },
  ])('rejects an invalid create acknowledgment before any downstream request: %j', async (invalid) => {
    const chain = installChain({ overrides: { create: invalid } }); renderWithoutRouter(page());
    await prepareWizard({ registry: true }); submit();
    await screen.findByTestId('wizard.trustProfile.error');
    expect(screen.getByTestId('wizard.trustProfile.error')).toHaveTextContent('did not confirm');
    expect(chain.calls.map(call => call.stage)).toEqual(['create']);
    expect(screen.queryByTestId('wizard.trustProfile.success')).not.toBeInTheDocument();
  });

  it.each([{ trust_profile_id: 'another-profile' }, { sources: [] }, { synchronized_at: undefined }])(
    'rejects an incomplete registry acknowledgment before activation: %j', async (invalid) => {
      const chain = installChain({ overrides: { registry: invalid } }); renderWithoutRouter(page());
      await prepareWizard({ registry: true }); submit();
      await screen.findByTestId('wizard.trustProfile.error');
      expect(chain.calls.map(call => call.stage)).toEqual(['create', 'issuer-inventory', 'issuer-entity', 'issuer-link', 'registry']);
      expect(screen.getByText(/This trust profile was created/)).toBeInTheDocument();
    },
  );

  it.each([{ id: 'another-profile' }, { organization_id: 'another-org' }, { status: 'DRAFT' }])(
    'requires activation acknowledgment identity and ACTIVE status: %j', async (invalid) => {
      const chain = installChain({ overrides: { activate: invalid } }); renderWithoutRouter(page());
      await prepareWizard(); submit();
      await screen.findByTestId('wizard.trustProfile.error');
      expect(chain.calls.filter(call => call.stage === 'activate')).toHaveLength(1);
      expect(screen.queryByTestId('wizard.trustProfile.success')).not.toBeInTheDocument();
      expect(screen.getByText(/This trust profile was created/)).toBeInTheDocument();
    },
  );

  it.each([{ id: 'another-profile' }, { organization_id: 'another-org' }])(
    'validates the activation fallback identity before showing success: %j', async (invalid) => {
      const chain = installChain({ activationNetworkFailure: true, overrides: { 'activation-readback': invalid } });
      renderWithoutRouter(page()); await prepareWizard(); submit();
      await screen.findByTestId('wizard.trustProfile.error');
      expect(chain.calls.at(-1)?.stage).toBe('activation-readback');
      expect(screen.queryByTestId('wizard.trustProfile.success')).not.toBeInTheDocument();
    },
  );
});

describe('Trust wizard browser history before React commit', () => {
  function heldDestination(samePath = false) {
    const transition = deferred<void>();
    let destinationReady = false;
    const initialKey = window.history.state?.key || 'default';
    function CreationEntry() {
      const location = useLocation();
      if (samePath && location.key !== initialKey && !destinationReady) throw transition.promise;
      return <TrustProfileWizard />;
    }
    function Destination() {
      if (!destinationReady) throw transition.promise;
      return <h1>Current Trust overview</h1>;
    }
    renderWithoutRouter(<BrowserRouter><Suspense fallback={<h1>Loading destination</h1>}>
      <CurrentRoute /><Routes>
        <Route path={NEW_PATH} element={<CreationEntry />} />
        <Route path={CURRENT_PATH} element={<Destination />} />
        <Route path="/console/org/templates/credentials" element={<h1>Credential Templates</h1>} />
      </Routes>
    </Suspense></BrowserRouter>);
    return async () => {
      destinationReady = true;
      await act(async () => { transition.resolve(); });
    };
  }

  it.each([
    { stage: 'create' as Stage, reject: false }, { stage: 'create' as Stage, reject: true },
    { stage: 'issuer-inventory' as Stage, reject: false }, { stage: 'issuer-entity' as Stage, reject: false },
    { stage: 'issuer-inventory' as Stage, reject: true },
    { stage: 'registry' as Stage, reject: false },
    { stage: 'activate' as Stage, reject: false }, { stage: 'activate' as Stage, reject: true },
  ])('ends $stage continuation on browser departure before commit (rejection: $reject)', async ({ stage, reject }) => {
    const chain = installChain({ delayed: stage });
    const release = heldDestination();
    await prepareWizard({ registry: stage === 'registry' }); submit();
    await waitFor(() => expect(chain.calls.some(call => call.stage === stage)).toBe(true));
    const beforeLeaving = [...chain.calls];
    const oldKey = screen.getByTestId('current-route').getAttribute('data-entry-key');
    try {
      await act(async () => { navigateTo(CURRENT_PATH); });
      expect(window.location.pathname).toBe(CURRENT_PATH);
      expect(window.history.state?.key).not.toBe(oldKey);
      expect(screen.getByTestId('current-route')).toHaveAttribute('data-entry-key', oldKey);
      expect(screen.getByTestId('wizard.trustProfile.submit')).toBeInTheDocument();
      await settleSubmission(() => chain.settle(reject));
      expect(chain.calls).toEqual(beforeLeaving);
      expect(screen.queryByTestId('wizard.trustProfile.success')).not.toBeInTheDocument();
      expect(screen.queryByTestId('wizard.trustProfile.error')).not.toBeInTheDocument();
      expect(window.location.pathname).toBe(CURRENT_PATH);
    } finally { await release(); }
    expect(screen.getByRole('heading', { name: 'Current Trust overview' })).toBeInTheDocument();
  });

  it('does not dispatch an old visible form after browser history changes', async () => {
    const chain = installChain(); const release = heldDestination();
    await prepareWizard();
    try {
      await act(async () => { navigateTo(CURRENT_PATH); });
      expect(screen.getByTestId('current-route')).toHaveTextContent(NEW_PATH);
      expect(window.location.pathname).toBe(CURRENT_PATH);
      submit();
      expect(submission.pending).toBeNull(); expect(chain.calls).toHaveLength(0);
    } finally { await release(); }
  });

  it('ends the old action when a new history entry uses the identical URL', async () => {
    const chain = installChain({ delayed: 'create' }); const release = heldDestination(true);
    await prepareWizard(); submit();
    await waitFor(() => expect(chain.calls).toHaveLength(1));
    const oldKey = screen.getByTestId('current-route').getAttribute('data-entry-key');
    try {
      await act(async () => { navigateTo(NEW_PATH); });
      expect(window.location.pathname).toBe(NEW_PATH);
      expect(window.history.state?.key).not.toBe(oldKey);
      expect(screen.getByTestId('current-route')).toHaveAttribute('data-entry-key', oldKey);
      await settleSubmission(() => chain.settle());
      expect(chain.calls).toHaveLength(1);
      expect(screen.queryByTestId('wizard.trustProfile.success')).not.toBeInTheDocument();
      expect(screen.queryByTestId('wizard.trustProfile.error')).not.toBeInTheDocument();
    } finally { await release(); }
    expect(screen.getByTestId('wizard.trustProfile.name')).toHaveValue('');
  });

  it('keeps a delayed success redirect from overriding a newer browser navigation', async () => {
    const timers = vi.spyOn(globalThis, 'setTimeout');
    installChain(); const release = heldDestination();
    await prepareWizard(); submit();
    await screen.findByTestId('wizard.trustProfile.success');
    const complete = timers.mock.calls.find(call => call[1] === 1500)?.[0] as (() => void) | undefined;
    expect(complete).toBeTypeOf('function');
    try {
      await act(async () => { navigateTo(CURRENT_PATH); });
      expect(screen.getByTestId('current-route')).toHaveTextContent(NEW_PATH);
      act(() => { complete?.(); });
      expect(window.location.pathname).toBe(CURRENT_PATH);
    } finally { timers.mockRestore(); await release(); }
  });
});
