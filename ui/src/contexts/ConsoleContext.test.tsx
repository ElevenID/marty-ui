import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Suspense } from 'react';
import { Route, Routes, useLocation } from 'react-router';
import { act, renderWithRouter, screen, waitFor } from '@test/utils';

import { AuthContext } from './AuthContext';
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
