import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Suspense, useLayoutEffect } from 'react';
import { BrowserRouter, Route, Routes, useLocation, useNavigate } from 'react-router';
import { act, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';

import { renderWithoutRouter, screen } from '@test/utils';
import { server } from '@test/mocks/server';
import { AuthContext } from '../../../../contexts/AuthContext';
import { ConsoleProvider, useConsole } from '../../../../contexts/ConsoleContext';
import CustomFlowBuilder from '../CustomFlowBuilder';

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

const NEW_PATH = '/console/org/flows/definitions/new/custom';
const CURRENT_PATH = '/console/org/trust';
const NAME = 'Custom continuation fixture';
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
    <Route path={NEW_PATH} element={<CustomFlowBuilder />} />
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
      resolved_steps: ['collect_input', 'complete'] }, { status: 200 });
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

async function completeForm(user: ReturnType<typeof renderWithoutRouter>['user'], organization = 'org-a') {
  await waitFor(() => expect(screen.getByTestId('current-organization')).toHaveTextContent(organization));
  await user.type(await screen.findByRole('textbox', { name: 'Flow name' }), NAME);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Create draft' })).toBeEnabled());
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
    // Native capabilities advertise custom support separately from standard
    // types. Keep the actual API call and supply the fields this view consumes.
    http.get('*/v1/flows/capabilities', () => HttpResponse.json({
      protocol_version: '0.5.0',
      flow_types: ['custom', 'oid4vci_pre_authorized'],
      standard_flow_types: ['oid4vci_pre_authorized'],
      triggers: ['API_CALL', 'WEBHOOK', 'SCHEDULE', 'APPLICATION_SUBMITTED'],
    })),
  );
});

describe('custom flow creation ownership', () => {
  it('preserves unknown-outcome guidance and the original reference key after both attempts lose confirmation', async () => {
    const writes: Array<{ body: Record<string, unknown>; key: string | null }> = [];
    server.use(http.post('*/v1/flows/definitions', async ({ request }) => {
      writes.push({ body: await request.json() as Record<string, unknown>, key: request.headers.get('Idempotency-Key') });
      return HttpResponse.error();
    }));
    const { user } = renderWithoutRouter(page());
    await completeForm(user);
    await user.click(screen.getByRole('button', { name: 'Create draft' }));
    await act(async () => { await Promise.allSettled(pending.creates); });
    expect(writes).toHaveLength(2);
    expect(writes[0].key).toBeTruthy();
    expect(writes[1]).toEqual(writes[0]);
    const alert = screen.getByRole('alert');
    expect(alert).toHaveTextContent('The request may have completed, but the connection ended before confirmation.');
    expect(alert).toHaveTextContent('Refresh the page before creating another artifact.');
    expect(alert).toHaveTextContent('Reference key: ' + writes[0].key);
    expect(screen.getByRole('textbox', { name: 'Flow name' })).toHaveValue(NAME);
    expect(window.location.pathname).toBe(NEW_PATH);
  });

  it('preserves the current same-key retry and native custom extension payload', async () => {
    const requests = installRequests(); const { user } = renderWithoutRouter(page());
    try {
      await completeForm(user); await user.click(screen.getByRole('button', { name: 'Create draft' }));
      await waitFor(() => expect(requests.writes).toHaveLength(1));
      await requests.settle();
      expect(requests.writes).toHaveLength(2);
      expect(requests.writes[0].key).toBeTruthy();
      expect(requests.writes[1].key).toBe(requests.writes[0].key);
      expect(requests.writes[1].body).toEqual(requests.writes[0].body);
      expect(requests.writes[0].body).toMatchObject({ organization_id: 'org-a', name: NAME,
        flow_type: 'custom', trigger: { trigger_type: 'API_CALL', config: {} },
        extension: { extends_flow_type: 'oid4vci_pre_authorized', entry_step_id: 'collect_input',
          steps: [{ step_id: 'collect_input', action: 'collect_input', config: {} },
            { step_id: 'complete', action: 'complete', config: {} }],
          transitions: [{ from_step_id: 'collect_input', to_step_id: 'complete', outcome: 'SUCCESS' }] } });
      expect(screen.getByRole('heading', { name: 'Saved draft workspace' })).toBeInTheDocument();
    } finally { await requests.settle(); }
  });

  it('does not retry an unconfirmed create after navigation commits', async () => {
    const requests = installRequests(); const { user } = renderWithoutRouter(page());
    try {
      await completeForm(user); await user.click(screen.getByRole('button', { name: 'Create draft' }));
      await waitFor(() => expect(requests.writes).toHaveLength(1));
      await act(async () => { navigateTo(CURRENT_PATH); });
      expect(screen.getByRole('heading', { name: 'Current Trust overview' })).toBeInTheDocument();
      await requests.settle();
      expect(requests.writes, JSON.stringify(requests.writes)).toHaveLength(1);
      expect(window.location.pathname).toBe(CURRENT_PATH);
    } finally { await requests.settle(); }
  });

  it.each(['network error', 'successful response'] as const)('ignores an obsolete %s while navigation is suspended', async (response) => {
    const requests = installRequests(); const destination = deferredDestination();
    const { user } = renderWithoutRouter(page(destination.element));
    try {
      await completeForm(user); await user.click(screen.getByRole('button', { name: 'Create draft' }));
      await waitFor(() => expect(requests.writes).toHaveLength(1));
      await act(async () => { navigateTo(CURRENT_PATH); });
      expect(window.location.pathname).toBe(CURRENT_PATH);
      expect(screen.getByRole('heading', { name: 'Custom flow extension' })).toBeInTheDocument();
      await requests.settle(response === 'network error' ? HttpResponse.error()
        : HttpResponse.json({ ...requests.writes[0].body, id: 'flow-created', status: 'DRAFT' }, { status: 200 }));
      expect(requests.writes, JSON.stringify(requests.writes)).toHaveLength(1);
      expect(window.location.pathname).toBe(CURRENT_PATH);
      expect(screen.queryByRole('heading', { name: 'Saved draft workspace' })).not.toBeInTheDocument();
    } finally { await requests.settle(); await destination.release(); }
  });

  it('does not dispatch from an old form after browser navigation begins', async () => {
    const requests = installRequests(false); const destination = deferredDestination();
    const { user } = renderWithoutRouter(page(destination.element));
    try {
      await completeForm(user);
      await act(async () => { navigateTo(CURRENT_PATH); });
      expect(window.location.pathname).toBe(CURRENT_PATH);
      await user.click(screen.getByRole('button', { name: 'Create draft' }));
      await requests.settle();
      expect(requests.writes, JSON.stringify(requests.writes)).toHaveLength(0);
      expect(window.location.pathname).toBe(CURRENT_PATH);
    } finally { await requests.settle(); await destination.release(); }
  });

  it.each(['before', 'after', 'during'] as const)('returns a fresh form when the old create settles %s Back', async (settlement) => {
    const requests = installRequests(); const destination = deferredDestination();
    const { user } = renderWithoutRouter(page(destination.element));
    const observations: Array<{ current: boolean | undefined; oldName: string; path: string }> = [];
    const observeDuringBack = () => {
      observations.push({ current: pending.owners[0]?.(),
        oldName: (screen.getByRole('textbox', { name: 'Flow name' }) as HTMLInputElement).value,
        path: window.location.pathname });
      requests.release(HttpResponse.error());
    };
    try {
      await completeForm(user); await user.click(screen.getByRole('button', { name: 'Create draft' }));
      await waitFor(() => expect(requests.writes).toHaveLength(1));
      const originalKey = window.history.state?.key;
      await act(async () => { navigateTo(CURRENT_PATH); });
      expect(window.location.pathname).toBe(CURRENT_PATH);
      if (settlement === 'before') {
        await requests.settle();
        expect(requests.writes, JSON.stringify(requests.writes)).toHaveLength(1);
      }
      if (settlement === 'during') window.addEventListener('popstate', observeDuringBack, { capture: true, once: true });
      await act(async () => { navigateTo(-1); });
      await waitFor(() => expect(window.location.pathname).toBe(NEW_PATH));
      if (settlement === 'during') expect(observations).toEqual([{ current: false, oldName: NAME, path: NEW_PATH }]);
      expect(window.history.state?.key).toBe(originalKey);
      await destination.release();
      if (settlement !== 'before') await requests.settle();
      expect(requests.writes, JSON.stringify(requests.writes)).toHaveLength(1);
      expect(await screen.findByRole('textbox', { name: 'Flow name' })).toHaveValue('');
      expect(screen.getByRole('button', { name: 'Create draft' })).toBeDisabled();
      await completeForm(user);
      expect(screen.getByRole('button', { name: 'Create draft' })).toBeEnabled();
    } finally {
      window.removeEventListener('popstate', observeDuringBack, true);
      await requests.settle(); await destination.release();
    }
  });
});

describe('custom flow organization ownership', () => {
  it('invalidates an old create while the real organization preference write is pending', async () => {
    const requests = installRequests(); const selection = holdOrganizationSwitch();
    const { user } = renderWithoutRouter(page());
    try {
      await completeForm(user); await user.click(screen.getByRole('button', { name: 'Create draft' }));
      await waitFor(() => expect(requests.writes).toHaveLength(1));
      await user.click(screen.getByRole('button', { name: 'Select organization B' }));
      await waitFor(() => expect(screen.getByTestId('current-organization')).toHaveTextContent('org-b'));
      await waitFor(() => expect(preferenceWrites).toContainEqual({ last_view_mode: 'org_admin', last_active_org_id: 'org-b' }));
      await requests.settle();
      expect(requests.writes, JSON.stringify(requests.writes)).toHaveLength(1);
      expect(await screen.findByRole('textbox', { name: 'Flow name' })).toHaveValue('');
      expect(screen.getByRole('button', { name: 'Create draft' })).toBeDisabled();
      expect(window.location.pathname).toBe(NEW_PATH);
    } finally { await requests.settle(); await selection.settle(); }
  });

  it('preserves a valid form when selecting the current organization', async () => {
    const requests = installRequests(false); const { user } = renderWithoutRouter(page());
    try {
      await completeForm(user); const writesBefore = preferenceWrites.length;
      await user.click(screen.getByRole('button', { name: 'Select organization A' }));
      await act(async () => { await pending.selection; });
      expect(preferenceWrites).toHaveLength(writesBefore);
      expect(screen.getByRole('textbox', { name: 'Flow name' })).toHaveValue(NAME);
      await user.click(screen.getByRole('button', { name: 'Create draft' }));
      await requests.settle();
      expect(requests.writes).toHaveLength(1);
      expect(requests.writes[0].body).toMatchObject({ organization_id: 'org-a', name: NAME, flow_type: 'custom' });
      expect(screen.getByRole('heading', { name: 'Saved draft workspace' })).toBeInTheDocument();
    } finally { await requests.settle(); }
  });

  it('keeps a replacement organization form out of a suspended destination and permits creation after Back', async () => {
    const requests = installRequests(false); const selection = holdOrganizationSwitch();
    const destination = deferredDestination(); const { user } = renderWithoutRouter(page(destination.element));
    try {
      await completeForm(user);
      await act(async () => { navigateTo(CURRENT_PATH); });
      expect(window.location.pathname).toBe(CURRENT_PATH);
      await user.click(screen.getByRole('button', { name: 'Select organization B' }));
      await waitFor(() => expect(screen.getByTestId('current-organization')).toHaveTextContent('org-b'));
      await waitFor(() => expect(preferenceWrites).toContainEqual({ last_view_mode: 'org_admin', last_active_org_id: 'org-b' }));
      await settleCapabilities();
      expect(window.location.pathname).toBe(CURRENT_PATH);
      if (screen.queryByRole('textbox', { name: 'Flow name' })) {
        await completeForm(user, 'org-b');
        await user.click(screen.getByRole('button', { name: 'Create draft' }));
        await requests.settle();
      }
      expect(requests.writes, JSON.stringify(requests.writes)).toHaveLength(0);
      expect(screen.queryByRole('textbox', { name: 'Flow name' })).not.toBeInTheDocument();
      await act(async () => { navigateTo(-1); });
      await waitFor(() => expect(window.location.pathname).toBe(NEW_PATH));
      await destination.release();
      expect(await screen.findByRole('textbox', { name: 'Flow name' })).toHaveValue('');
      await completeForm(user, 'org-b');
      await user.click(screen.getByRole('button', { name: 'Create draft' }));
      await requests.settle();
      expect(requests.writes).toHaveLength(1);
      expect(requests.writes[0].body).toMatchObject({ organization_id: 'org-b', name: NAME, flow_type: 'custom' });
      expect(requests.writes[0].route).toBe(NEW_PATH);
      expect(screen.getByRole('heading', { name: 'Saved draft workspace' })).toBeInTheDocument();
    } finally { await requests.settle(); await selection.settle(); await destination.release(); }
  });
});
