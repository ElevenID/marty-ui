import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Suspense, useLayoutEffect } from 'react';
import { BrowserRouter, Route, Routes, useLocation, useNavigate } from 'react-router';
import { act, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';

import { renderWithoutRouter, screen } from '@test/utils';
import { server } from '@test/mocks/server';
import { mockDeploymentProfiles, mockTemplates } from '@test/mocks/fixtures';
import { AuthContext } from '../../../../contexts/AuthContext';
import { ConsoleProvider, useConsole } from '../../../../contexts/ConsoleContext';
import FlowDefinitionWizard from '../FlowDefinitionWizard';

const pending = vi.hoisted(() => ({
  creates: [] as Promise<unknown>[],
  capabilities: [] as Promise<unknown>[],
  owners: [] as Array<(() => boolean) | undefined>,
  selection: null as Promise<unknown> | null,
}));
// Observe actual promises and ownership only. Keep the actual wizard, provider,
// API adapter, idempotency helper and installed transport.
vi.mock('../../../../services/flowsApi', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../services/flowsApi')>();
  return { ...actual,
    createFlow: (...args: Parameters<typeof actual.createFlow>) => {
      const options = (args as unknown as [unknown, { isCurrent?: () => boolean }?])[1];
      pending.owners.push(options?.isCurrent);
      const result = actual.createFlow(...args);
      pending.creates.push(result);
      return result;
    },
    getFlowCapabilities: (...args: Parameters<typeof actual.getFlowCapabilities>) => {
      const result = actual.getFlowCapabilities(...args);
      pending.capabilities.push(result);
      return result;
    },
  };
});

const NEW_PATH = '/console/org/flows/definitions/new';
const CURRENT_PATH = '/console/org/trust';
const NAME = 'Flow fixture';
const organizations = ['org-a', 'org-b'].map(id => ({
  id, name: id, display_name: id,
  membership: { status: 'active', roles: [{ name: 'owner' }], has_org_console_access: true },
}));
const auth = {
  user: { user_id: 'flow-fixture-user', roles: ['owner'], capabilities: { 'org:view': true }, organizations },
  isAuthenticated: true, isLoading: false,
};
let navigateTo: ReturnType<typeof useNavigate>;
let preferenceWrites: Array<Record<string, unknown>>;

function ScopeControls() {
  const { activeOrgId, setActiveOrgId } = useConsole();
  const navigate = useNavigate();
  const location = useLocation();
  useLayoutEffect(() => { navigateTo = navigate; }, [navigate]);
  const select = (id: string) => {
    pending.selection = setActiveOrgId(id);
    void pending.selection.catch(() => undefined);
  };
  return <>
    <output data-testid="current-route">{location.pathname}{location.search}{location.hash}</output>
    <output data-testid="current-organization">{activeOrgId}</output>
    <button onClick={() => select('org-a')}>Select organization A</button>
    <button onClick={() => select('org-b')}>Select organization B</button>
  </>;
}
function ReadyRoutes({ destination }: { destination: React.ReactNode }) {
  const { isLoading } = useConsole();
  if (isLoading) return <p>Loading console</p>;
  return <Routes>
    <Route path={NEW_PATH} element={<FlowDefinitionWizard />} />
    <Route path={CURRENT_PATH} element={destination} />
    <Route path="/console/org" element={<h1>Organization home</h1>} />
    <Route path="/console/org/flows/definitions/:id" element={<h1>Saved draft workspace</h1>} />
  </Routes>;
}
function page(destination: React.ReactNode = <h1>Current Trust overview</h1>) {
  return <BrowserRouter><AuthContext.Provider value={auth as any}><ConsoleProvider>
    <Suspense fallback={<h1>Loading destination</h1>}>
      <ScopeControls /><ReadyRoutes destination={destination} />
    </Suspense>
  </ConsoleProvider></AuthContext.Provider></BrowserRouter>;
}
function deferredDestination() {
  let ready = false;
  let resolve!: () => void;
  const waiting = new Promise<void>(done => { resolve = done; });
  function Destination() {
    if (!ready) throw waiting;
    return <h1>Current Trust overview</h1>;
  }
  return { element: <Destination />, async release() {
    await act(async () => { ready = true; resolve(); });
  } };
}
function installRequests(deferFirst = true) {
  const writes: Array<{ body: Record<string, unknown>; key: string | null; route: string }> = [];
  let release!: (response: Response) => void;
  const first = new Promise<Response>(done => { release = done; });
  server.use(http.post('*/v1/flows/definitions', async ({ request }) => {
    const body = await request.json() as Record<string, unknown>;
    writes.push({ body, key: request.headers.get('Idempotency-Key'), route: window.location.pathname });
    if (!body.name || !body.flow_type) {
      return HttpResponse.json({ error: 'validation_error', error_description: 'A flow name and type are required.' }, { status: 400 });
    }
    if (deferFirst && writes.length === 1) return first;
    return HttpResponse.json({ ...body, id: 'flow-created', status: 'DRAFT',
      resolved_steps: ['create_offer', 'token_exchange', 'credential_request', 'issue_credential'] }, { status: 201 });
  }));
  return { writes, release, async settle(response: Response = HttpResponse.error()) {
    await act(async () => {
      release(response);
      await Promise.allSettled(pending.creates);
    });
  } };
}
async function settleCapabilities() {
  let consumed = 0;
  do {
    const batch = pending.capabilities.slice(consumed);
    consumed += batch.length;
    await act(async () => { await Promise.all(batch); });
  } while (consumed < pending.capabilities.length);
}
function holdOrganizationSwitch() {
  let release!: () => void;
  const held = new Promise<void>(done => { release = done; });
  server.use(http.put('/v1/me/preferences', async ({ request }) => {
    const body = await request.json() as Record<string, unknown>;
    preferenceWrites.push(body);
    if (body.last_active_org_id === 'org-b') await held;
    return HttpResponse.json(body);
  }));
  return { async settle() {
    await act(async () => {
      release();
      await pending.selection?.catch(() => undefined);
    });
  } };
}
async function reachReview(user: ReturnType<typeof renderWithoutRouter>['user'], organization = 'org-a') {
  await waitFor(() => expect(screen.getByTestId('current-organization')).toHaveTextContent(organization));
  await user.click(await screen.findByTestId('flow-type-oid4vci_pre_authorized'));
  await user.click(screen.getByTestId('wizard.flow.next'));
  await user.type(await screen.findByLabelText(/Flow name/i), NAME);
  await user.click(screen.getByTestId('wizard.flow.next'));
  await waitFor(() => expect(screen.getByTestId('wizard.flow.next')).toBeEnabled());
  await user.click(screen.getByTestId('wizard.flow.next'));
  expect(await screen.findByRole('heading', { name: 'Review draft' })).toBeInTheDocument();
}
beforeEach(() => {
  pending.creates.length = 0; pending.capabilities.length = 0; pending.owners.length = 0;
  pending.selection = null; preferenceWrites = [];
  window.localStorage.clear();
  window.history.replaceState({}, '', NEW_PATH);
  server.use(
    http.get('/v1/me/preferences', () => HttpResponse.json({ last_view_mode: 'org_admin', last_active_org_id: 'org-a' })),
    http.put('/v1/me/preferences', async ({ request }) => {
      const body = await request.json() as Record<string, unknown>;
      preferenceWrites.push(body);
      return HttpResponse.json(body);
    }),
    http.get('*/v1/organizations/mine', () => HttpResponse.json(organizations)),
    http.get('*/v1/organizations/:organizationId/defaults', () => HttpResponse.json({})),
    http.get('*/v1/deployment-profiles', ({ request }) => {
      const organization = new URL(request.url).searchParams.get('organization_id');
      return HttpResponse.json([{ ...mockDeploymentProfiles.valid, id: 'deploy-' + organization,
        organization_id: organization, trust_profile_id: 'trust-' + organization }]);
    }),
    http.get('*/v1/credential-templates', ({ request }) => {
      const organization = new URL(request.url).searchParams.get('organization_id');
      return HttpResponse.json([{ ...mockTemplates.valid, id: 'template-' + organization,
        organization_id: organization, trust_profile_id: 'trust-' + organization,
        issuance_protocol: 'OID4VCI_PRE_AUTH', credential_payload_format: 'SD_JWT_VC' }]);
    }),
  );
});

describe('standard flow creation ownership', () => {
  it('preserves a current same-key network retry and opens the created draft', async () => {
    const requests = installRequests(); const { user } = renderWithoutRouter(page());
    try {
      await reachReview(user); await user.click(screen.getByTestId('wizard.flow.submit'));
      await waitFor(() => expect(requests.writes).toHaveLength(1));
      await requests.settle();
      expect(requests.writes).toHaveLength(2);
      expect(requests.writes[0].key).toBeTruthy();
      expect(requests.writes[1].key).toBe(requests.writes[0].key);
      expect(requests.writes[1].body).toEqual(requests.writes[0].body);
      expect(requests.writes[0].body).toMatchObject({ organization_id: 'org-a', name: NAME,
        flow_type: 'oid4vci_pre_authorized', credential_template_id: 'template-org-a',
        deployment_profile_ids: ['deploy-org-a'] });
      expect(screen.getByText(/Draft created\. Opening validation workspace/)).toBeInTheDocument();
      await waitFor(() => expect(screen.getByRole('heading', { name: 'Saved draft workspace' })).toBeInTheDocument(), { timeout: 2500 });
    } finally { await requests.settle(); }
  });

  it('does not retry an unconfirmed create after navigation commits', async () => {
    const requests = installRequests(); const { user } = renderWithoutRouter(page());
    try {
      await reachReview(user); await user.click(screen.getByTestId('wizard.flow.submit'));
      await waitFor(() => expect(requests.writes).toHaveLength(1));
      await act(async () => { navigateTo(CURRENT_PATH); });
      expect(screen.getByRole('heading', { name: 'Current Trust overview' })).toBeInTheDocument();
      await requests.settle();
      expect(requests.writes, JSON.stringify(requests.writes)).toHaveLength(1);
      expect(screen.getByTestId('current-route')).toHaveTextContent(CURRENT_PATH);
      expect(screen.queryByText(/Draft created\. Opening validation workspace/)).not.toBeInTheDocument();
    } finally { await requests.settle(); }
  });

  it('does not retry while a changed browser destination is still suspended', async () => {
    const requests = installRequests(); const destination = deferredDestination();
    const { user } = renderWithoutRouter(page(destination.element));
    try {
      await reachReview(user); await user.click(screen.getByTestId('wizard.flow.submit'));
      await waitFor(() => expect(requests.writes).toHaveLength(1));
      await act(async () => { navigateTo(CURRENT_PATH); });
      expect(window.location.pathname).toBe(CURRENT_PATH);
      expect(screen.getByRole('heading', { name: 'Review draft' })).toBeInTheDocument();
      await requests.settle();
      expect(requests.writes, JSON.stringify(requests.writes)).toHaveLength(1);
      expect(screen.queryByText(/Draft created\. Opening validation workspace/)).not.toBeInTheDocument();
    } finally { await requests.settle(); await destination.release(); }
    expect(screen.getByRole('heading', { name: 'Current Trust overview' })).toBeInTheDocument();
  });

  it('does not start a create from an old Review after browser navigation begins', async () => {
    const requests = installRequests(false); const destination = deferredDestination();
    const { user } = renderWithoutRouter(page(destination.element));
    try {
      await reachReview(user);
      await act(async () => { navigateTo(CURRENT_PATH); });
      expect(window.location.pathname).toBe(CURRENT_PATH);
      expect(screen.getByRole('heading', { name: 'Review draft' })).toBeInTheDocument();
      await user.click(screen.getByTestId('wizard.flow.submit'));
      await requests.settle();
      expect(requests.writes, JSON.stringify(requests.writes)).toHaveLength(0);
    } finally { await requests.settle(); await destination.release(); }
  });

  it.each(['before', 'after', 'during'] as const)('returns to a usable fresh form when the old create settles %s Back', async (settlement) => {
    const requests = installRequests(); const destination = deferredDestination();
    const { user } = renderWithoutRouter(page(destination.element));
    const settleDuringBack = () => requests.release(HttpResponse.error());
    const captureObservations: Array<{ path: string; hasOwner: boolean; current: boolean | undefined; oldReviewVisible: boolean }> = [];
    const observeOwnerDuringBack = () => captureObservations.push({
      path: window.location.pathname,
      hasOwner: typeof pending.owners[0] === 'function',
      current: pending.owners[0]?.(),
      oldReviewVisible: Boolean(screen.queryByRole('heading', { name: 'Review draft' })),
    });
    try {
      await reachReview(user); await user.click(screen.getByTestId('wizard.flow.submit'));
      await waitFor(() => expect(requests.writes).toHaveLength(1));
      const originalKey = window.history.state?.key;
      await act(async () => { navigateTo(CURRENT_PATH); });
      expect(window.location.pathname).toBe(CURRENT_PATH);
      if (settlement === 'before') await requests.settle();
      if (settlement === 'during') {
        // Registered after mount: the real child invalidator runs first, and
        // this capture probe runs before any outer bubble remount handler.
        window.addEventListener('popstate', observeOwnerDuringBack, { capture: true, once: true });
        window.addEventListener('popstate', settleDuringBack, { once: true });
      }
      await act(async () => { navigateTo(-1); });
      await waitFor(() => expect(window.location.pathname).toBe(NEW_PATH));
      expect(window.history.state?.key).toBe(originalKey);
      if (settlement === 'during') expect(captureObservations).toEqual([
        { path: NEW_PATH, hasOwner: true, current: false, oldReviewVisible: true },
      ]);
      await destination.release();
      if (settlement !== 'before') await requests.settle();
      expect(requests.writes, JSON.stringify(requests.writes)).toHaveLength(1);
      expect(await screen.findByText('Choose a flow')).toBeInTheDocument();
      expect(screen.getByTestId('wizard.flow.next')).toBeDisabled();
      expect(screen.queryByText(/Draft created\. Opening validation workspace/)).not.toBeInTheDocument();
      await user.click(screen.getByTestId('flow-type-oid4vci_pre_authorized'));
      await user.click(screen.getByTestId('wizard.flow.next'));
      expect(await screen.findByLabelText(/Flow name/i)).toHaveValue('');
    } finally {
      window.removeEventListener('popstate', settleDuringBack);
      window.removeEventListener('popstate', observeOwnerDuringBack, true);
      await requests.settle(); await destination.release();
    }
  });
});

describe('standard flow organization selection', () => {
  it('resets Review and data together while the real organization preference write is pending', async () => {
    const requests = installRequests(false); const selection = holdOrganizationSwitch();
    const { user } = renderWithoutRouter(page());
    try {
      await reachReview(user);
      await user.click(screen.getByRole('button', { name: 'Select organization B' }));
      await waitFor(() => expect(screen.getByTestId('current-organization')).toHaveTextContent('org-b'));
      await waitFor(() => expect(preferenceWrites).toContainEqual({ last_view_mode: 'org_admin', last_active_org_id: 'org-b' }));
      expect(window.location.pathname).toBe(NEW_PATH);
      expect(screen.getByTestId('current-route')).toHaveTextContent(NEW_PATH);
      const submit = screen.queryByTestId('wizard.flow.submit');
      if (submit) await user.click(submit);
      await requests.settle();
      expect(requests.writes, JSON.stringify(requests.writes)).toHaveLength(0);
      expect(await screen.findByText('Choose a flow')).toBeInTheDocument();
      expect(screen.getByTestId('wizard.flow.next')).toBeDisabled();
    } finally { await requests.settle(); await selection.settle(); }
    expect(screen.getByRole('heading', { name: 'Organization home' })).toBeInTheDocument();
  });

  it('invalidates an old pending create during the real organization switch', async () => {
    const requests = installRequests(); const selection = holdOrganizationSwitch();
    const { user } = renderWithoutRouter(page());
    try {
      await reachReview(user); await user.click(screen.getByTestId('wizard.flow.submit'));
      await waitFor(() => expect(requests.writes).toHaveLength(1));
      await user.click(screen.getByRole('button', { name: 'Select organization B' }));
      await waitFor(() => expect(screen.getByTestId('current-organization')).toHaveTextContent('org-b'));
      expect(window.location.pathname).toBe(NEW_PATH);
      await requests.settle();
      expect(requests.writes, JSON.stringify(requests.writes)).toHaveLength(1);
      expect(await screen.findByText('Choose a flow')).toBeInTheDocument();
      expect(screen.getByTestId('wizard.flow.next')).toBeDisabled();
      expect(screen.queryByText(/Draft created\. Opening validation workspace/)).not.toBeInTheDocument();
    } finally { await requests.settle(); await selection.settle(); }
  });

  it('preserves the reviewed form when selecting the current organization', async () => {
    const requests = installRequests(false); const { user } = renderWithoutRouter(page());
    await reachReview(user);
    const writesBefore = preferenceWrites.length;
    await user.click(screen.getByRole('button', { name: 'Select organization A' }));
    await act(async () => { await pending.selection; });
    expect(preferenceWrites).toHaveLength(writesBefore);
    expect(screen.getByRole('heading', { name: 'Review draft' })).toBeInTheDocument();
    await user.click(screen.getByTestId('wizard.flow.submit'));
    await requests.settle();
    expect(requests.writes).toHaveLength(1);
    expect(requests.writes[0].body).toMatchObject({ organization_id: 'org-a', name: NAME, flow_type: 'oid4vci_pre_authorized' });
  });
});

describe('combined standard flow navigation boundaries', () => {
  it('keeps a replacement organization form bound to the retained router entry', async () => {
    const requests = installRequests(false); const selection = holdOrganizationSwitch();
    const destination = deferredDestination(); const { user } = renderWithoutRouter(page(destination.element));
    try {
      await reachReview(user);
      await act(async () => { navigateTo(CURRENT_PATH); });
      expect(window.location.pathname).toBe(CURRENT_PATH);
      expect(screen.getByRole('heading', { name: 'Review draft' })).toBeInTheDocument();
      await user.click(screen.getByRole('button', { name: 'Select organization B' }));
      await waitFor(() => expect(screen.getByTestId('current-organization')).toHaveTextContent('org-b'));
      await waitFor(() => expect(preferenceWrites).toContainEqual({ last_view_mode: 'org_admin', last_active_org_id: 'org-b' }));
      await settleCapabilities();
      expect(window.location.pathname).toBe(CURRENT_PATH);
      const obsoleteSubmit = screen.queryByTestId('wizard.flow.submit');
      if (obsoleteSubmit) await user.click(obsoleteSubmit);
      await requests.settle();
      expect(requests.writes, JSON.stringify(requests.writes)).toHaveLength(0);
      expect(screen.queryByTestId('flow-type-oid4vci_pre_authorized')).not.toBeInTheDocument();
      expect(screen.queryByTestId('wizard.flow.submit')).not.toBeInTheDocument();
      await act(async () => { navigateTo(-1); });
      await waitFor(() => expect(window.location.pathname).toBe(NEW_PATH));
      await destination.release();
      expect(await screen.findByText('Choose a flow')).toBeInTheDocument();
      expect(screen.getByTestId('wizard.flow.next')).toBeDisabled();
      await reachReview(user, 'org-b');
      await user.click(screen.getByTestId('wizard.flow.submit'));
      await requests.settle();
      expect(requests.writes).toHaveLength(1);
      expect(requests.writes[0].body).toMatchObject({ organization_id: 'org-b', name: NAME,
        credential_template_id: 'template-org-b', deployment_profile_ids: ['deploy-org-b'] });
    } finally { await requests.settle(); await selection.settle(); await destination.release(); }
  });

  it('does not let a completed create redirect a later suspended navigation', async () => {
    const requests = installRequests(false); const destination = deferredDestination();
    const { user } = renderWithoutRouter(page(destination.element));
    try {
      await reachReview(user); await user.click(screen.getByTestId('wizard.flow.submit'));
      await requests.settle();
      expect(screen.getByText(/Draft created\. Opening validation workspace/)).toBeInTheDocument();
      await act(async () => { navigateTo(CURRENT_PATH); });
      expect(window.location.pathname).toBe(CURRENT_PATH);
      await act(async () => { await new Promise(resolve => setTimeout(resolve, 1600)); });
      expect(window.location.pathname).toBe(CURRENT_PATH);
      expect(requests.writes).toHaveLength(1);
      expect(screen.queryByRole('heading', { name: 'Saved draft workspace' })).not.toBeInTheDocument();
    } finally { await requests.settle(); await destination.release(); }
    expect(screen.getByRole('heading', { name: 'Current Trust overview' })).toBeInTheDocument();
  });

  it('does not revive a completed create callback before a returned entry remounts', async () => {
    const requests = installRequests(false); const destination = deferredDestination();
    const { user } = renderWithoutRouter(page(destination.element));
    let invokeCompletion: (() => void) | undefined;
    const observations: Array<{ before: string; after: string; hasOwner: boolean; current: boolean | undefined; oldSuccessVisible: boolean }> = [];
    const invokeDuringBack = () => {
      const observation = {
        before: window.location.pathname,
        after: '',
        hasOwner: typeof pending.owners[0] === 'function',
        current: pending.owners[0]?.(),
        oldSuccessVisible: Boolean(screen.queryByText(/Draft created\. Opening validation workspace/)),
      };
      invokeCompletion?.();
      observation.after = window.location.pathname;
      observations.push(observation);
    };
    // The spy calls through. Capture the callback actually scheduled by
    // useWizard; do not replace its hook or the timer's implementation.
    const timerSpy = vi.spyOn(globalThis, 'setTimeout');
    try {
      await reachReview(user);
      timerSpy.mockClear();
      await user.click(screen.getByTestId('wizard.flow.submit'));
      await requests.settle();
      expect(screen.getByText(/Draft created\. Opening validation workspace/)).toBeInTheDocument();
      const completionCalls = timerSpy.mock.calls.filter(([, delay]) => delay === 1500);
      expect(completionCalls).toHaveLength(1);
      expect(typeof completionCalls[0][0]).toBe('function');
      invokeCompletion = completionCalls[0][0] as () => void;
      expect(pending.owners[0]?.()).toBe(true);
      const originalKey = window.history.state?.key;
      await act(async () => { navigateTo(CURRENT_PATH); });
      expect(window.location.pathname).toBe(CURRENT_PATH);
      expect(screen.getByText(/Draft created\. Opening validation workspace/)).toBeInTheDocument();
      window.addEventListener('popstate', invokeDuringBack, { capture: true, once: true });
      await act(async () => { navigateTo(-1); });
      await waitFor(() => expect(observations).toHaveLength(1));
      expect(observations).toEqual([{ before: NEW_PATH, after: NEW_PATH, hasOwner: true,
        current: false, oldSuccessVisible: true }]);
      expect(window.history.state?.key).toBe(originalKey);
      expect(window.location.pathname).toBe(NEW_PATH);
      await destination.release();
      expect(await screen.findByText('Choose a flow')).toBeInTheDocument();
      expect(screen.getByTestId('wizard.flow.next')).toBeDisabled();
      expect(requests.writes).toHaveLength(1);
      expect(screen.queryByRole('heading', { name: 'Saved draft workspace' })).not.toBeInTheDocument();
    } finally {
      window.removeEventListener('popstate', invokeDuringBack, true);
      timerSpy.mockRestore();
      await requests.settle(); await destination.release();
    }
  });

});
