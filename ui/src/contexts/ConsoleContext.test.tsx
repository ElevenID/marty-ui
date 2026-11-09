import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Suspense } from 'react';
import { Route, Routes, useLocation, useNavigate } from 'react-router';
import { act, renderWithRouter, screen, waitFor } from '@test/utils';

import { AuthContext } from './AuthContext';
import { useAuth } from '../hooks/useAuth';
import { ConsoleProvider, useConsole } from './ConsoleContext';
import { getPreferences, updatePreferences } from '../services/preferencesApi';
import { getMyOrganizations } from '../services/organizationsApi';
import { ApplicantConsoleRoute, OrgConsoleRoute } from '../components/ProtectedRoute';

vi.mock('../services/preferencesApi', () => ({
  getPreferences: vi.fn(),
  updatePreferences: vi.fn(),
}));

vi.mock('../services/organizationsApi', () => ({
  getMyOrganizations: vi.fn(),
}));

function Probe() {
  const {
    mode,
    activeOrgId,
    memberships,
    membershipsLoaded,
    membershipLoadError,
    isOrgBootstrapRequired,
    isLoading,
  } = useConsole();

  return (
    <div>
      <div data-testid="mode">{mode}</div>
      <div data-testid="active-org">{activeOrgId || ''}</div>
      <div data-testid="loading">{isLoading ? 'loading' : 'ready'}</div>
      <div data-testid="loaded">{membershipsLoaded ? 'loaded' : 'not-loaded'}</div>
      <div data-testid="memberships">{memberships.length}</div>
      <div data-testid="bootstrap">{isOrgBootstrapRequired ? 'required' : 'optional'}</div>
      <div data-testid="error">{membershipLoadError?.message || ''}</div>
      <div data-testid="message-id">{membershipLoadError?.messageId || ''}</div>
    </div>
  );
}

function renderProvider(userOverrides = {}) {
  const setActiveOrganizationId = vi.fn();
  const authValue = {
    user: {
      user_id: 'user-1',
      email: 'vendor@example.com',
      roles: ['vendor'],
      capabilities: { 'org:view': true },
      organizations: [],
      ...userOverrides,
    },
    isAuthenticated: true,
    isLoading: false,
    setActiveOrganizationId,
  };

  return {
    setActiveOrganizationId,
    ...renderWithRouter(
    <AuthContext.Provider value={authValue as any}>
      <ConsoleProvider>
        <Probe />
      </ConsoleProvider>
    </AuthContext.Provider>
    ),
  };
}

describe('ConsoleContext', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.localStorage.clear();
    vi.mocked(getPreferences).mockResolvedValue({
      last_view_mode: 'org',
      last_active_org_id: 'org-1',
    });
    vi.mocked(updatePreferences).mockResolvedValue({
      last_view_mode: 'org',
      last_active_org_id: 'org-1',
    });
  });

  it('treats organization membership load failures as errors, not loaded empty memberships', async () => {
    const error = new Error('Service unavailable') as Error & {
      status?: number;
      response?: { message_id?: string; error_description?: string };
    };
    error.status = 503;
    error.response = {
      message_id: 'msg-503',
      error_description: 'Organization service unavailable',
    };
    vi.mocked(getMyOrganizations).mockRejectedValue(error);

    renderProvider();

    await waitFor(() => {
      expect(screen.getByTestId('loading')).toHaveTextContent('ready');
    });

    expect(vi.mocked(getMyOrganizations)).toHaveBeenCalledWith({ retryConfig: { maxRetries: 0 } });
    expect(screen.getByTestId('loaded')).toHaveTextContent('not-loaded');
    expect(screen.getByTestId('memberships')).toHaveTextContent('0');
    expect(screen.getByTestId('bootstrap')).toHaveTextContent('required');
    expect(screen.getByTestId('error')).toHaveTextContent('Organization service unavailable');
    expect(screen.getByTestId('message-id')).toHaveTextContent('msg-503');
  });

  it('preserves the selected fallback org while memberships refresh after org creation', async () => {
    window.localStorage.setItem('activeOrgId', 'org-new');
    vi.mocked(getMyOrganizations).mockResolvedValue([
      {
        id: 'org-old',
        name: 'Old Org',
        membership: {
          roles: [{ name: 'owner' }],
          has_org_console_access: true,
        },
      },
    ]);

    renderProvider({
      organization_id: 'org-new',
      organization_name: 'New Org',
      organizations: [
        {
          id: 'org-new',
          name: 'new-org',
          display_name: 'New Org',
          membership: {
            roles: [{ name: 'owner' }],
            has_org_console_access: true,
          },
        },
      ],
    });

    await waitFor(() => {
      expect(screen.getByTestId('loading')).toHaveTextContent('ready');
    });

    expect(screen.getByTestId('loaded')).toHaveTextContent('loaded');
    expect(screen.getByTestId('memberships')).toHaveTextContent('2');
    expect(screen.getByTestId('mode')).toHaveTextContent('org');
    expect(screen.getByTestId('active-org')).toHaveTextContent('org-new');
  });

  it('does not mutate the applicant organization when no org-console membership is available', async () => {
    window.localStorage.setItem('activeOrgId', 'org-stale');
    vi.mocked(getPreferences).mockResolvedValue({
      last_view_mode: 'org',
      last_active_org_id: 'org-stale',
    });
    vi.mocked(getMyOrganizations).mockResolvedValue([
      {
        id: '00000000-0000-0000-0000-000000000001',
        name: 'Marty',
        display_name: 'Marty Identity Platform',
        membership: {
          roles: [{ name: 'applicant' }],
          has_org_console_access: false,
        },
      },
    ]);

    const { setActiveOrganizationId } = renderProvider({
      organization_id: 'org-stale',
      default_organization_id: '00000000-0000-0000-0000-000000000001',
    });

    await waitFor(() => {
      expect(screen.getByTestId('loading')).toHaveTextContent('ready');
    });

    expect(screen.getByTestId('loaded')).toHaveTextContent('loaded');
    expect(screen.getByTestId('memberships')).toHaveTextContent('0');
    expect(screen.getByTestId('mode')).toHaveTextContent('applicant');
    expect(screen.getByTestId('active-org')).toHaveTextContent('');
    expect(setActiveOrganizationId).not.toHaveBeenCalled();
    expect(vi.mocked(updatePreferences)).toHaveBeenCalledWith({
      last_view_mode: 'applicant',
      last_active_org_id: null,
    });
  });

  it.each(['saved', 'failed'])('switches from an org route to a deferred applicant route when preference persistence %s without a competing setup redirect', async (persistence) => {
    if (persistence === 'failed') vi.mocked(updatePreferences).mockRejectedValue(new Error('Preferences unavailable'));
    vi.mocked(getMyOrganizations).mockResolvedValue([{
      id: 'org-1',
      name: 'Marty',
      membership: { status: 'active', roles: [{ name: 'admin' }], has_org_console_access: true },
    }]);
    const authValue = {
      user: { user_id: 'user-1', roles: ['admin'], capabilities: { 'org:view': true }, organizations: [] },
      isAuthenticated: true,
      isLoading: false,
    };
    let catalogReady = false;
    let resolveCatalog!: () => void;
    const catalogPromise = new Promise<void>((resolve) => { resolveCatalog = resolve; });
    function DeferredCatalog() {
      if (!catalogReady) throw catalogPromise;
      return <div>Applicant catalog</div>;
    }
    function ModeSwitcher() {
      const { setMode, mode, activeOrgId } = useConsole();
      const location = useLocation();
      return <>
        <button onClick={() => setMode('applicant')}>Applicant mode</button>
        <div data-testid="current-path">{location.pathname}</div>
        <div data-testid="current-mode">{mode}</div>
        <div data-testid="current-org">{activeOrgId || ''}</div>
      </>;
    }
    const { user } = renderWithRouter(
      <AuthContext.Provider value={authValue as any}>
        <ConsoleProvider>
          <ModeSwitcher />
          <Suspense fallback={<div>Loading route</div>}>
            <Routes>
              <Route path="/console/org/settings" element={<OrgConsoleRoute><div>Organization settings</div></OrgConsoleRoute>} />
              <Route path="/console/applicant/catalog" element={<ApplicantConsoleRoute><DeferredCatalog /></ApplicantConsoleRoute>} />
              <Route path="/console/org/setup" element={<div>Organization setup</div>} />
            </Routes>
          </Suspense>
        </ConsoleProvider>
      </AuthContext.Provider>,
      { initialEntries: ['/console/org/settings'] },
    );
    expect(await screen.findByText('Organization settings')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Applicant mode' }));
    await act(async () => {
      catalogReady = true;
      resolveCatalog();
    });

    expect(await screen.findByText('Applicant catalog')).toBeInTheDocument();
    expect(screen.getByTestId('current-path')).toHaveTextContent('/console/applicant/catalog');
    expect(screen.getByTestId('current-mode')).toHaveTextContent('applicant');
    expect(screen.getByTestId('current-org')).toBeEmptyDOMElement();
    expect(window.localStorage.getItem('activeOrgId')).toBeNull();
    expect(screen.queryByText('Organization setup')).not.toBeInTheDocument();
    expect(vi.mocked(updatePreferences)).toHaveBeenLastCalledWith({
      last_view_mode: 'applicant',
      last_active_org_id: null,
    });
  });
});

const oldOrg = {
  id: 'private-org-a', display_name: 'Private organization A',
  membership: { status: 'active', roles: [{ name: 'owner' }], has_org_console_access: true },
};
const oldAuth = {
  user: { user_id: 'account-a', roles: ['owner'], capabilities: { 'org:view': true }, organizations: [] },
  isAuthenticated: true, isLoading: false, hasCapability: () => true,
};
const newAuth = {
  user: { user_id: 'account-b', roles: ['applicant'], capabilities: { 'org:view': false }, organizations: [] },
  isAuthenticated: true, isLoading: false, hasCapability: () => false,
};
let oldSetter: null | ((id: string, memberships: any[]) => Promise<void>);
let currentConsole: ReturnType<typeof useConsole>;

function PrincipalProbe() {
  const state = useConsole();
  const { user } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  currentConsole = state;
  if (user?.user_id === 'account-a') oldSetter = state.setActiveOrgId;
  return <>
    <output data-testid="principal">{user?.user_id}</output>
    <output data-testid="loading">{state.isLoading ? 'loading' : 'ready'}</output>
    <output data-testid="selected">{state.activeOrgId}</output>
    <output data-testid="path">{location.pathname}</output>
    <button onClick={() => navigate('/console/org')}>Visit organization route</button>
  </>;
}

function App({ auth }: { auth: any }) {
  return <AuthContext.Provider value={auth}>
    <ConsoleProvider>
      <PrincipalProbe />
      <Routes>
        <Route path="/console/org" element={<OrgConsoleRoute><h1>Organization dashboard</h1></OrgConsoleRoute>} />
        <Route path="/console/org/setup" element={<div>Choose an organization</div>} />
        <Route path="/console/applicant/catalog" element={<div>Applicant catalog</div>} />
      </Routes>
    </ConsoleProvider>
  </AuthContext.Provider>;
}

describe('ConsoleContext session and request lifetime', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    window.localStorage.clear();
    oldSetter = null;
    vi.mocked(updatePreferences).mockResolvedValue({});
  });

  it('does not allow the new applicant into an old account organization after a late membership list', async () => {
    let finishOld!: (organizations: any[]) => void;
    const oldRequest = new Promise<any[]>(resolve => { finishOld = resolve; });
    vi.mocked(getPreferences).mockResolvedValue({ last_view_mode: 'org', last_active_org_id: oldOrg.id });
    vi.mocked(getMyOrganizations).mockReturnValueOnce(oldRequest).mockResolvedValueOnce([]);
    const { user, rerender } = renderWithRouter(<App auth={oldAuth} />, { initialEntries: ['/console/org'] });
    await waitFor(() => expect(getMyOrganizations).toHaveBeenCalledTimes(1));

    rerender(<App auth={newAuth} />);
    await waitFor(() => expect(getMyOrganizations).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.getByTestId('loading')).toHaveTextContent('ready'));
    await act(async () => finishOld([oldOrg]));
    await user.click(screen.getByRole('button', { name: 'Visit organization route' }));

    expect(screen.getByTestId('principal')).toHaveTextContent('account-b');
    expect(screen.queryByRole('heading', { name: 'Organization dashboard' })).not.toBeInTheDocument();
    expect(screen.getByTestId('selected')).toBeEmptyDOMElement();
  });

  it('does not accept a prior account creation callback membership override', async () => {
    vi.mocked(getPreferences).mockResolvedValue({ last_view_mode: 'applicant', last_active_org_id: null });
    vi.mocked(getMyOrganizations).mockResolvedValue([]);
    const { rerender } = renderWithRouter(<App auth={oldAuth} />, { initialEntries: ['/console/org/setup'] });
    await waitFor(() => expect(screen.getByTestId('loading')).toHaveTextContent('ready'));
    const capturedCreationSetter = oldSetter!;
    rerender(<App auth={newAuth} />);
    await waitFor(() => expect(getMyOrganizations).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.getByTestId('loading')).toHaveTextContent('ready'));

    await act(async () => {
      await expect(capturedCreationSetter(oldOrg.id, [oldOrg])).rejects.toMatchObject({ name: 'AbortError' });
    });

    expect(screen.getByTestId('principal')).toHaveTextContent('account-b');
    expect(screen.queryByRole('heading', { name: 'Organization dashboard' })).not.toBeInTheDocument();
    expect(screen.getByTestId('selected')).toBeEmptyDOMElement();
    expect(updatePreferences).not.toHaveBeenCalledWith({ last_view_mode: 'org', last_active_org_id: oldOrg.id });
  });

  it('clears loaded account context before the replacement account membership request finishes', async () => {
    let finishNew!: (organizations: any[]) => void;
    const newRequest = new Promise<any[]>(resolve => { finishNew = resolve; });
    vi.mocked(getPreferences).mockResolvedValue({ last_view_mode: 'org', last_active_org_id: oldOrg.id });
    vi.mocked(getMyOrganizations).mockResolvedValueOnce([oldOrg]).mockReturnValueOnce(newRequest);
    const { rerender } = renderWithRouter(<App auth={oldAuth} />, { initialEntries: ['/console/org'] });
    expect(await screen.findByRole('heading', { name: 'Organization dashboard' })).toBeInTheDocument();

    rerender(<App auth={newAuth} />);

    expect(screen.getByTestId('principal')).toHaveTextContent('account-b');
    expect(screen.getByTestId('selected')).toBeEmptyDOMElement();
    expect(screen.queryByRole('heading', { name: 'Organization dashboard' })).not.toBeInTheDocument();
    expect(window.localStorage.getItem('activeOrgId')).toBeNull();
    await act(async () => finishNew([]));
  });

  it('retains a valid local selection during the initial unknown-to-authenticated bootstrap', async () => {
    const anotherOrg = { ...oldOrg, id: 'another-organization' };
    window.localStorage.setItem('activeOrgId', oldOrg.id);
    vi.mocked(getPreferences).mockResolvedValue({ last_view_mode: 'org', last_active_org_id: anotherOrg.id });
    vi.mocked(getMyOrganizations).mockResolvedValue([anotherOrg, oldOrg]);
    const { rerender } = renderWithRouter(<App auth={{ ...oldAuth, user: null, isAuthenticated: false, isLoading: true }} />,
      { initialEntries: ['/console/org'] });
    expect(getMyOrganizations).not.toHaveBeenCalled();

    rerender(<App auth={oldAuth} />);

    expect(await screen.findByRole('heading', { name: 'Organization dashboard' })).toBeInTheDocument();
    expect(screen.getByTestId('selected')).toHaveTextContent(oldOrg.id);
    expect(window.localStorage.getItem('activeOrgId')).toBe(oldOrg.id);
  });

  it('rejects stale refresh calls and results without starting another-account requests', async () => {
    let finishRefresh!: (organizations: any[]) => void;
    const refresh = new Promise<any[]>(resolve => { finishRefresh = resolve; });
    vi.mocked(getPreferences).mockResolvedValue({ last_view_mode: 'applicant', last_active_org_id: null });
    vi.mocked(getMyOrganizations).mockResolvedValueOnce([]).mockReturnValueOnce(refresh).mockResolvedValueOnce([]);
    const { rerender } = renderWithRouter(<App auth={oldAuth} />, { initialEntries: ['/console/org/setup'] });
    await waitFor(() => expect(screen.getByTestId('loading')).toHaveTextContent('ready'));
    const capturedRefresh = currentConsole.refreshMemberships;
    let outcome!: Promise<unknown>;
    await act(async () => { outcome = capturedRefresh().catch((error: Error) => error); });
    rerender(<App auth={newAuth} />);
    await waitFor(() => expect(getMyOrganizations).toHaveBeenCalledTimes(3));

    await act(async () => finishRefresh([oldOrg]));
    expect(await outcome).toMatchObject({ name: 'AbortError' });
    await expect(capturedRefresh()).rejects.toMatchObject({ name: 'AbortError' });
    expect(getMyOrganizations).toHaveBeenCalledTimes(3);
    expect(screen.getByTestId('selected')).toBeEmptyDOMElement();
    expect(updatePreferences).not.toHaveBeenCalled();
  });

  it('does not revive a prior lifetime after signing out and back in as the same principal', async () => {
    vi.mocked(getPreferences).mockResolvedValue({ last_view_mode: 'applicant', last_active_org_id: null });
    vi.mocked(getMyOrganizations).mockResolvedValue([]);
    const { rerender } = renderWithRouter(<App auth={oldAuth} />, { initialEntries: ['/console/org/setup'] });
    await waitFor(() => expect(screen.getByTestId('loading')).toHaveTextContent('ready'));
    const prior = currentConsole;
    rerender(<App auth={{ ...oldAuth, user: null, isAuthenticated: false }} />);
    rerender(<App auth={oldAuth} />);
    await waitFor(() => expect(getMyOrganizations).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.getByTestId('loading')).toHaveTextContent('ready'));

    await expect(prior.setActiveOrgId(oldOrg.id, [oldOrg])).rejects.toMatchObject({ name: 'AbortError' });
    await expect(prior.setMode('org')).rejects.toMatchObject({ name: 'AbortError' });
    await expect(prior.refreshMemberships()).rejects.toMatchObject({ name: 'AbortError' });
    await expect(prior.reloadConsoleState()).resolves.toBeUndefined();
    expect(getMyOrganizations).toHaveBeenCalledTimes(2);
    expect(screen.getByTestId('selected')).toBeEmptyDOMElement();
    expect(updatePreferences).not.toHaveBeenCalled();
  });

  it.each(['bootstrap', 'refresh'])('keeps a newer same-account selection when an older %s finishes', async operation => {
    let finishRead!: (organizations: any[]) => void;
    const read = new Promise<any[]>(resolve => { finishRead = resolve; });
    vi.mocked(getPreferences).mockResolvedValue({ last_view_mode: 'applicant', last_active_org_id: null });
    if (operation === 'bootstrap') vi.mocked(getMyOrganizations).mockReturnValueOnce(read);
    else vi.mocked(getMyOrganizations).mockResolvedValueOnce([]).mockReturnValueOnce(read);
    renderWithRouter(<App auth={oldAuth} />, { initialEntries: ['/console/org/setup'] });
    await waitFor(() => expect(getMyOrganizations).toHaveBeenCalledTimes(1));
    let refreshOutcome: Promise<unknown> | null = null;
    if (operation === 'refresh') {
      await waitFor(() => expect(screen.getByTestId('loading')).toHaveTextContent('ready'));
      await act(async () => { refreshOutcome = currentConsole.refreshMemberships().catch((error: Error) => error); });
    }
    await act(async () => currentConsole.setActiveOrgId(oldOrg.id, [oldOrg]));
    await act(async () => finishRead([]));

    if (refreshOutcome) expect(await refreshOutcome).toMatchObject({ name: 'AbortError' });
    expect(screen.getByTestId('selected')).toHaveTextContent(oldOrg.id);
    expect(screen.getByTestId('path')).toHaveTextContent(/^\/console\/org$/);
    expect(window.localStorage.getItem('activeOrgId')).toBe(oldOrg.id);
    expect(updatePreferences).toHaveBeenCalledExactlyOnceWith({ last_view_mode: 'org', last_active_org_id: oldOrg.id });
  });

  it('rejects a delayed selection completion after a newer selection without navigating back', async () => {
    let finishFirst!: (value: any) => void;
    const firstPreference = new Promise(resolve => { finishFirst = resolve; });
    const nextOrg = { ...oldOrg, id: 'private-org-next' };
    vi.mocked(getPreferences).mockResolvedValue({ last_view_mode: 'applicant', last_active_org_id: null });
    vi.mocked(getMyOrganizations).mockResolvedValue([oldOrg, nextOrg]);
    renderWithRouter(<App auth={oldAuth} />, { initialEntries: ['/console/org/setup'] });
    await waitFor(() => expect(screen.getByTestId('loading')).toHaveTextContent('ready'));
    vi.mocked(updatePreferences).mockReturnValueOnce(firstPreference).mockResolvedValueOnce({});
    let firstOutcome!: Promise<unknown>;
    await act(async () => { firstOutcome = currentConsole.setActiveOrgId(oldOrg.id).catch((error: Error) => error); });
    await act(async () => currentConsole.setActiveOrgId(nextOrg.id));
    await act(async () => finishFirst({}));

    expect(await firstOutcome).toMatchObject({ name: 'AbortError' });
    expect(screen.getByTestId('selected')).toHaveTextContent(nextOrg.id);
    expect(window.localStorage.getItem('activeOrgId')).toBe(nextOrg.id);
    expect(screen.getByTestId('path')).toHaveTextContent(/^\/console\/org$/);
    expect(updatePreferences).toHaveBeenCalledTimes(2);
  });

  it('does not navigate or heal preferences when an old selection completes after account replacement', async () => {
    let finishPreference!: (value: any) => void;
    const preference = new Promise(resolve => { finishPreference = resolve; });
    vi.mocked(getPreferences).mockResolvedValue({ last_view_mode: 'applicant', last_active_org_id: null });
    vi.mocked(getMyOrganizations).mockResolvedValue([]);
    const { rerender } = renderWithRouter(<App auth={oldAuth} />, { initialEntries: ['/console/org/setup'] });
    await waitFor(() => expect(screen.getByTestId('loading')).toHaveTextContent('ready'));
    vi.mocked(updatePreferences).mockReturnValueOnce(preference);
    let outcome!: Promise<unknown>;
    await act(async () => { outcome = currentConsole.setActiveOrgId(oldOrg.id, [oldOrg]).catch((error: Error) => error); });
    rerender(<App auth={newAuth} />);
    await waitFor(() => expect(getMyOrganizations).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.getByTestId('loading')).toHaveTextContent('ready'));
    await act(async () => finishPreference({}));

    expect(await outcome).toMatchObject({ name: 'AbortError' });
    expect(screen.getByTestId('path')).toHaveTextContent('/console/org/setup');
    expect(screen.getByTestId('selected')).toBeEmptyDOMElement();
    expect(window.localStorage.getItem('activeOrgId')).toBeNull();
    expect(updatePreferences).toHaveBeenCalledTimes(1);
  });
});
