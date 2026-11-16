import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Suspense, useLayoutEffect } from 'react';
import { BrowserRouter, Route, Routes, useLocation, useNavigate } from 'react-router';
import { act, waitFor } from '@testing-library/react';
import { http, HttpResponse } from 'msw';

import { renderWithoutRouter, screen } from '@test/utils';
import { server } from '@test/mocks/server';
import { AuthContext } from '../../../contexts/AuthContext';
import { ConsoleProvider, useConsole } from '../../../contexts/ConsoleContext';
import { NotificationProvider } from '../../../contexts/NotificationContext';
import KeyManagementServiceWizard from './KeyManagementServiceWizard';

const pending = vi.hoisted(() => ({
  configurations: [] as Promise<unknown>[],
  permissions: [] as Promise<unknown>[],
  validations: [] as Promise<unknown>[],
  writes: [] as Promise<unknown>[],
  selection: null as Promise<unknown> | null,
}));
// Observe actual promise settlement only. The providers, permission hook,
// wizard, action scope, API serialization and installed transport stay real.
vi.mock('../../../services/signingKeysApi', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../services/signingKeysApi')>();
  return { ...actual, default: { ...actual.default,
    getKeyManagementConfig: (...args: Parameters<typeof actual.getKeyManagementConfig>) => {
      const result = actual.getKeyManagementConfig(...args);
      pending.configurations.push(result);
      return result;
    },
    validateKeyManagementService: (...args: Parameters<typeof actual.validateKeyManagementService>) => {
      const result = actual.validateKeyManagementService(...args);
      pending.validations.push(result);
      return result;
    },
    updateKeyManagementConfig: (...args: Parameters<typeof actual.updateKeyManagementConfig>) => {
      const result = actual.updateKeyManagementConfig(...args);
      pending.writes.push(result);
      return result;
    },
  } };
});
vi.mock('../../../services/rbacApi', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../services/rbacApi')>();
  return { ...actual,
    getMyPermissions: (...args: Parameters<typeof actual.getMyPermissions>) => {
      const result = actual.getMyPermissions(...args);
      pending.permissions.push(result);
      return result;
    },
  };
});

const NEW_PATH = '/console/org/operator/key-management/services/new';
const CURRENT_PATH = '/console/org/trust';
const REVISION = '"r-11111111-1111-4111-8111-111111111111"';
const NEXT_REVISION = '"r-22222222-2222-4222-8222-222222222222"';
const NAME = 'Combined continuation fixture';
const KEY = 'arn:aws:kms:us-east-2:123456789012:key/fixture-only';
const organizations = ['org-a', 'org-b'].map(id => ({
  id, name: id, display_name: id,
  membership: { status: 'active', roles: [{ name: 'owner' }], has_org_console_access: true },
}));
const auth = {
  user: { user_id: 'kms-combined-fixture-user', roles: ['owner'],
    capabilities: { 'org:view': true }, organizations },
  isAuthenticated: true, isLoading: false,
};
const registry = () => ({ config_revision: REVISION, default_service_id: null,
  services: [], service_type_catalog: [], key_reference_purposes: {}, type_defaults: {}, format_defaults: {},
});
const liveValidation = () => ({ ok: true, basis: 'live', validated_at: '2026-11-09T19:00:00Z',
  checks: [{ name: 'Provider connectivity', status: 'pass', detail: 'Fixture signer is available.', source: 'live' }],
});
let navigateTo: ReturnType<typeof useNavigate>;
let preferenceWrites: Array<Record<string, unknown>>;
let permissionReads: string[];

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
    <Route path={NEW_PATH} element={<KeyManagementServiceWizard />} />
    <Route path={CURRENT_PATH} element={destination} />
    <Route path="/console/org" element={<h1>Organization home</h1>} />
  </Routes>;
}
function page(destination: React.ReactNode = <h1>Current Trust overview</h1>) {
  return <BrowserRouter><AuthContext.Provider value={auth as any}><ConsoleProvider><NotificationProvider>
    <Suspense fallback={<h1>Loading destination</h1>}>
      <ScopeControls /><ReadyRoutes destination={destination} />
    </Suspense>
  </NotificationProvider></ConsoleProvider></AuthContext.Provider></BrowserRouter>;
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
async function drainActualPromises(read: () => Promise<unknown>[]) {
  const observed = new Set<Promise<unknown>>();
  let batch: Promise<unknown>[];
  do {
    batch = read().filter(promise => !observed.has(promise));
    batch.forEach(promise => observed.add(promise));
    await act(async () => { await Promise.all(batch); });
  } while (read().some(promise => !observed.has(promise)));
}
function installRequests(holdFirstValidation = false) {
  let resolve!: (response: Response) => void;
  const firstValidation = new Promise<Response>(done => { resolve = done; });
  const reads: Array<string | null> = [];
  const validations: Array<{ organization: string | null; body: Record<string, unknown>; route: string }> = [];
  const writes: Array<{ organization: string | null; body: Record<string, unknown>; revision: string | null; route: string }> = [];
  server.use(
    http.get('*/v1/signing-keys/config', ({ request }) => {
      reads.push(new URL(request.url).searchParams.get('organization_id'));
      return HttpResponse.json(registry());
    }),
    http.post('*/v1/signing-keys/config/validate', async ({ request }) => {
      validations.push({ organization: new URL(request.url).searchParams.get('organization_id'),
        body: await request.json() as Record<string, unknown>, route: window.location.pathname });
      if (holdFirstValidation && validations.length === 1) return firstValidation;
      return HttpResponse.json(liveValidation());
    }),
    http.patch('*/v1/signing-keys/config', async ({ request }) => {
      const body = await request.json() as Record<string, unknown>;
      writes.push({ organization: new URL(request.url).searchParams.get('organization_id'), body,
        revision: request.headers.get('If-Match'), route: window.location.pathname });
      return HttpResponse.json({ ...registry(), ...body, config_revision: NEXT_REVISION });
    }),
  );
  const release = () => resolve(HttpResponse.json(liveValidation()));
  return { reads, validations, writes, release,
    async settle() {
      release();
      await drainActualPromises(() => [...pending.validations, ...pending.writes]);
    },
  };
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
    await act(async () => { release(); await pending.selection?.catch(() => undefined); });
  } };
}
async function reachReview(user: ReturnType<typeof renderWithoutRouter>['user'], organization = 'org-a') {
  await waitFor(() => expect(screen.getByTestId('current-organization')).toHaveTextContent(organization));
  await user.click(await screen.findByRole('button', { name: 'AWS KMS key management service' }));
  await user.click(screen.getByRole('button', { name: 'Next' }));
  await user.type(screen.getByRole('textbox', { name: /Service name/i }), NAME);
  await user.type(screen.getByRole('textbox', { name: /Region \/ location/i }), 'us-east-2');
  await user.click(screen.getByRole('button', { name: 'Next' }));
  await user.type(screen.getByRole('textbox', { name: /Key ARN/i }), KEY);
  await user.click(screen.getByRole('button', { name: 'Next' }));
  expect(screen.getByRole('heading', { name: 'Review' })).toBeInTheDocument();
}
beforeEach(() => {
  pending.configurations.length = 0; pending.permissions.length = 0;
  pending.validations.length = 0; pending.writes.length = 0; pending.selection = null;
  preferenceWrites = []; permissionReads = [];
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
    http.get('*/v1/organizations/:organizationId/members/me/permissions', ({ params }) => {
      permissionReads.push(String(params.organizationId));
      return HttpResponse.json({ permissions: ['signing-key:view', 'signing-key:create'], roles: [{ name: 'owner' }] });
    }),
  );
});

describe('KMS combined organization and navigation ownership', () => {
  it('registers a current service through the real provider, grants, validation and revision PATCH', async () => {
    const requests = installRequests(); const { user } = renderWithoutRouter(page());
    try {
      await reachReview(user);
      await user.click(screen.getByRole('button', { name: 'Register service' }));
      await requests.settle();
      expect(await screen.findByRole('heading', { name: 'Signing service registered' })).toBeInTheDocument();
      expect(permissionReads).toContain('org-a');
      expect(requests.validations).toHaveLength(1);
      expect(requests.validations[0]).toMatchObject({ organization: 'org-a', route: NEW_PATH,
        body: { name: NAME, key_reference: KEY, live_probe: true } });
      expect(requests.writes).toHaveLength(1);
      expect(requests.writes[0]).toMatchObject({ organization: 'org-a', route: NEW_PATH, revision: REVISION });
      expect(requests.writes[0].body).not.toHaveProperty('organization_id');
      expect(requests.writes[0].body).not.toHaveProperty('config_revision');
    } finally { await requests.settle(); }
  });

  it('does not admit a new organization registration from a suspended destination browser entry', async () => {
    const requests = installRequests(); const selection = holdOrganizationSwitch();
    const destination = deferredDestination(); const { user } = renderWithoutRouter(page(destination.element));
    try {
      await reachReview(user);
      await act(async () => { navigateTo(CURRENT_PATH); });
      expect(window.location.pathname).toBe(CURRENT_PATH);
      expect(screen.getByRole('heading', { name: 'Review' })).toBeInTheDocument();
      await user.click(screen.getByRole('button', { name: 'Select organization B' }));
      await waitFor(() => expect(screen.getByTestId('current-organization')).toHaveTextContent('org-b'));
      await waitFor(() => expect(preferenceWrites).toContainEqual({ last_view_mode: 'org_admin', last_active_org_id: 'org-b' }));
      await drainActualPromises(() => [...pending.permissions, ...pending.configurations]);
      expect(permissionReads).toContain('org-b');
      expect(window.location.pathname).toBe(CURRENT_PATH);
      expect(screen.getByTestId('current-route')).toHaveTextContent(NEW_PATH);
      if (screen.queryByRole('button', { name: 'AWS KMS key management service' })) {
        await reachReview(user, 'org-b');
        await user.click(screen.getByRole('button', { name: 'Register service' }));
        await requests.settle();
      }
      expect({ validations: requests.validations, writes: requests.writes }).toEqual({ validations: [], writes: [] });
      expect(screen.queryByRole('button', { name: 'AWS KMS key management service' })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: 'Register service' })).not.toBeInTheDocument();
      await act(async () => { navigateTo(-1); });
      await waitFor(() => expect(window.location.pathname).toBe(NEW_PATH));
      await destination.release();
      await reachReview(user, 'org-b');
      await user.click(screen.getByRole('button', { name: 'Register service' }));
      await requests.settle();
      expect(await screen.findByRole('heading', { name: 'Signing service registered' })).toBeInTheDocument();
      expect(requests.validations).toHaveLength(1);
      expect(requests.writes).toHaveLength(1);
      expect(requests.writes[0]).toMatchObject({ organization: 'org-b', route: NEW_PATH, revision: REVISION });
    } finally { await requests.settle(); await selection.settle(); await destination.release(); }
  });

  it('does not continue old registration when validation is released during the actual Back event', async () => {
    const requests = installRequests(true); const destination = deferredDestination();
    const { user } = renderWithoutRouter(page(destination.element));
    const releaseDuringBack = () => requests.release();
    try {
      await reachReview(user);
      await user.click(screen.getByRole('button', { name: 'Register service' }));
      await waitFor(() => expect(requests.validations).toHaveLength(1));
      const originalKey = window.history.state?.key;
      await act(async () => { navigateTo(CURRENT_PATH); });
      expect(window.location.pathname).toBe(CURRENT_PATH);
      expect(screen.getByRole('heading', { name: 'Review' })).toBeInTheDocument();
      window.addEventListener('popstate', releaseDuringBack, { capture: true, once: true });
      await act(async () => { navigateTo(-1); });
      await waitFor(() => expect(window.location.pathname).toBe(NEW_PATH));
      expect(window.history.state?.key).toBe(originalKey);
      await requests.settle();
      await destination.release();
      expect(requests.writes, JSON.stringify(requests.writes)).toHaveLength(0);
      expect(await screen.findByRole('button', { name: 'AWS KMS key management service' })).toBeInTheDocument();
      expect(screen.queryByRole('heading', { name: 'Signing service registered' })).not.toBeInTheDocument();
    } finally {
      window.removeEventListener('popstate', releaseDuringBack, true);
      await requests.settle(); await destination.release();
    }
  });
});
