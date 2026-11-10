import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes, useLocation, useNavigate } from 'react-router';
import { act, renderWithRouter, screen, waitFor } from '@test/utils';

import { AuthContext } from '../../contexts/AuthContext';
import { ConsoleContext, ConsoleProvider, useConsole } from '../../contexts/ConsoleContext';
import { useAuth } from '../../hooks/useAuth';
import { usePermissions } from '../../hooks/usePermissions';
import { createOrganization, getMyOrganizations } from '../../services/organizationsApi';
import { getPreferences, updatePreferences } from '../../services/preferencesApi';
import { getMyPermissions } from '../../services/rbacApi';
import { OrgConsoleRoute } from '../ProtectedRoute';
import OrgSetupPage from '../console/org/OrgSetupPage';
import CreateOrganizationPage from './CreateOrganizationPage';

vi.mock('../../services/organizationsApi', () => ({
  createOrganization: vi.fn(),
  getMyOrganizations: vi.fn(),
  getErrorMessage: (error: Error) => error.message,
}));
vi.mock('../../services/preferencesApi', () => ({ getPreferences: vi.fn(), updatePreferences: vi.fn() }));
vi.mock('../../services/rbacApi', () => ({ getMyPermissions: vi.fn() }));

const applicantOrganization = {
  id: 'marty-org', name: 'marty', display_name: 'Marty Identity Platform',
  membership: { status: 'active', roles: [{ name: 'applicant' }], has_org_console_access: false },
};
const createdOrganization = {
  id: 'org-new', name: 'new-workspace', display_name: 'New Workspace',
  membership: { status: 'active', roles: [{ name: 'owner' }], has_org_console_access: true, is_owner: true },
};
const applicantAuth = {
  isAuthenticated: true,
  isLoading: false,
  hasCapability: () => false,
  user: {
    user_id: 'new-user', roles: ['applicant'], capabilities: { 'org:view': false },
    organization_id: applicantOrganization.id, default_organization_id: applicantOrganization.id,
    organizations: [applicantOrganization],
  },
};

function ContextProbe() {
  const { activeOrgId, mode, memberships, isLoading } = useConsole();
  const { user } = useAuth();
  const location = useLocation();
  return <>
    <output data-testid="path">{location.pathname}</output>
    <output data-testid="mode">{mode}</output>
    <output data-testid="selected-org">{activeOrgId}</output>
    <output data-testid="selected-name">{memberships.find(org => org.id === activeOrgId)?.display_name}</output>
    <output data-testid="applicant-org">{user?.default_organization_id}</output>
    <output data-testid="console-loading">{isLoading ? 'loading' : 'ready'}</output>
  </>;
}

function OrganizationDashboard() {
  const { can } = usePermissions();
  return <>
    <h1>Organization dashboard</h1>
    {can('team', 'manage') && <div>Native owner controls</div>}
  </>;
}

describe('organization creation console handoff', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    window.localStorage.clear();
    (window as any).__MARTY_RUNTIME_CONFIG__ = { organizationCreationEnabled: true };
    vi.mocked(getPreferences).mockResolvedValue({ last_view_mode: 'applicant', last_active_org_id: null });
    vi.mocked(updatePreferences).mockResolvedValue({});
    vi.mocked(getMyPermissions).mockResolvedValue({ permissions: ['team:manage'], roles: [{ id: 'owner', name: 'owner' }] });
  });

  afterEach(() => { delete (window as any).__MARTY_RUNTIME_CONFIG__; });

  it.each(['refreshed', 'lagging', 'unavailable'])('opens the new owner console without reloading applicant auth when the membership list is %s', async (inventory) => {
    let created = false;
    vi.mocked(getMyOrganizations).mockImplementation(async () => {
      if (created && inventory === 'unavailable') throw new Error('Membership list temporarily unavailable');
      return created && inventory === 'refreshed'
        ? [applicantOrganization, createdOrganization] : [applicantOrganization];
    });
    vi.mocked(createOrganization).mockImplementation(async () => {
      created = true;
      return createdOrganization;
    });
    const { user } = renderWithRouter(
      <AuthContext.Provider value={applicantAuth as any}>
        <ConsoleProvider>
          <ContextProbe />
          <Routes>
            <Route path="/console/org" element={<OrgConsoleRoute><OrganizationDashboard /></OrgConsoleRoute>} />
            <Route path="/console/org/setup" element={<OrgSetupPage />} />
            <Route path="/console/organizations/create" element={<CreateOrganizationPage />} />
            <Route path="/console/applicant/catalog" element={<div>Marty applicant catalog</div>} />
          </Routes>
        </ConsoleProvider>
      </AuthContext.Provider>,
      { initialEntries: ['/console/org'] },
    );

    await user.click(await screen.findByRole('button', { name: 'Create Organization' }));
    await user.type(screen.getByLabelText('Organization Slug'), createdOrganization.name);
    await user.type(screen.getByLabelText('Display Name'), createdOrganization.display_name);
    await user.click(screen.getByRole('button', { name: 'Create Organization' }));

    expect(await screen.findByRole('heading', { name: 'Organization dashboard' })).toBeInTheDocument();
    expect(await screen.findByText('Native owner controls')).toBeInTheDocument();
    expect(screen.getByTestId('path')).toHaveTextContent(/^\/console\/org$/);
    expect(screen.getByTestId('mode')).toHaveTextContent('org');
    expect(screen.getByTestId('selected-org')).toHaveTextContent(createdOrganization.id);
    expect(screen.getByTestId('selected-name')).toHaveTextContent(createdOrganization.display_name);
    expect(screen.getByTestId('applicant-org')).toHaveTextContent(applicantOrganization.id);
    expect(screen.queryByText('Marty applicant catalog')).not.toBeInTheDocument();
    expect(getMyPermissions).toHaveBeenCalledWith(createdOrganization.id);
    expect(getMyPermissions).not.toHaveBeenCalledWith(applicantOrganization.id);
    expect(window.localStorage.getItem('activeOrgId')).toBe(createdOrganization.id);
    await waitFor(() => expect(updatePreferences).toHaveBeenLastCalledWith({
      last_view_mode: 'org', last_active_org_id: createdOrganization.id,
    }));
  });

  it.each([
    { label: 'absent selection membership', memberships: [], membershipsLoaded: true },
    { label: 'membership for another organization', memberships: [createdOrganization], membershipsLoaded: true },
    { label: 'applicant-only membership', memberships: [applicantOrganization], membershipsLoaded: true },
    { label: 'unconfirmed membership inventory', memberships: [applicantOrganization], membershipsLoaded: false },
  ])('does not grant an organization route from a login capability with $label', async ({ memberships, membershipsLoaded }) => {
    renderWithRouter(
      <AuthContext.Provider value={{ ...applicantAuth, hasCapability: () => true } as any}>
        <ConsoleContext.Provider value={{
          activeOrgId: applicantOrganization.id, mode: 'org', memberships, membershipsLoaded, isLoading: false,
          membershipLoadError: null, isOrgBootstrapRequired: false,
        } as any}>
          <Routes>
            <Route path="/console/org" element={<OrgConsoleRoute><OrganizationDashboard /></OrgConsoleRoute>} />
            <Route path="/console/org/setup" element={<div>Select an eligible organization</div>} />
            <Route path="/console/applicant/catalog" element={<div>Marty applicant catalog</div>} />
          </Routes>
        </ConsoleContext.Provider>
      </AuthContext.Provider>,
      { initialEntries: ['/console/org'] },
    );

    expect(await screen.findByText('Select an eligible organization')).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Organization dashboard' })).not.toBeInTheDocument();
    expect(getMyPermissions).not.toHaveBeenCalled();
  });

  it('still requires authentication for a selected organization membership', async () => {
    renderWithRouter(
      <AuthContext.Provider value={{ ...applicantAuth, user: null, isAuthenticated: false } as any}>
        <ConsoleContext.Provider value={{
          activeOrgId: createdOrganization.id, mode: 'org', memberships: [createdOrganization],
          membershipsLoaded: true, isLoading: false, membershipLoadError: null, isOrgBootstrapRequired: false,
        } as any}>
          <Routes>
            <Route path="/console/org" element={<OrgConsoleRoute redirectTo="/console/login"><OrganizationDashboard /></OrgConsoleRoute>} />
            <Route path="/console/login" element={<div>Sign in</div>} />
          </Routes>
        </ConsoleContext.Provider>
      </AuthContext.Provider>,
      { initialEntries: ['/console/org'] },
    );

    expect(await screen.findByText('Sign in')).toBeInTheDocument();
    expect(getMyPermissions).not.toHaveBeenCalled();
  });

  it('does not let a creation membership override bypass a Canvas applicant-only session', async () => {
    vi.mocked(getMyOrganizations).mockResolvedValue([createdOrganization]);
    function SelectCreatedOrganization() {
      const { setActiveOrgId } = useConsole();
      return <button onClick={() => setActiveOrgId(createdOrganization.id, [createdOrganization])}>Select created organization</button>;
    }
    const { user } = renderWithRouter(
      <AuthContext.Provider value={{
        ...applicantAuth, user: { ...applicantAuth.user, roles: ['canvas_lti_learner'] },
      } as any}>
        <ConsoleProvider>
          <ContextProbe />
          <SelectCreatedOrganization />
        </ConsoleProvider>
      </AuthContext.Provider>,
      { initialEntries: ['/console/organizations'] },
    );
    await waitFor(() => expect(screen.getByTestId('console-loading')).toHaveTextContent('ready'));

    await user.click(screen.getByRole('button', { name: 'Select created organization' }));

    expect(screen.getByTestId('selected-org')).toBeEmptyDOMElement();
    expect(screen.getByTestId('mode')).toHaveTextContent('applicant');
    expect(screen.getByTestId('path')).toHaveTextContent('/console/organizations');
    expect(window.localStorage.getItem('activeOrgId')).toBeNull();
    expect(updatePreferences).not.toHaveBeenCalled();
    expect(getMyPermissions).not.toHaveBeenCalled();
  });
});

function CreationNavigation() {
  const navigate = useNavigate();
  const location = useLocation();
  return <>
    <button onClick={() => navigate('/console/applicant/catalog')}>Leave creation</button>
    <output data-testid="complete-location">{location.pathname}{location.search}{location.hash}</output>
  </>;
}

function CreationLifetimeApp({ auth }: { auth: any }) {
  return <AuthContext.Provider value={auth}>
    <ConsoleProvider>
      <ContextProbe />
      <CreationNavigation />
      <Routes>
        <Route path="/console/org" element={<OrgConsoleRoute><OrganizationDashboard /></OrgConsoleRoute>} />
        <Route path="/console/org/team" element={<OrgConsoleRoute><div>Created organization team</div></OrgConsoleRoute>} />
        <Route path="/console/org/setup" element={<div>Organization setup</div>} />
        <Route path="/console/organizations/create" element={<CreateOrganizationPage />} />
        <Route path="/console/applicant/catalog" element={<div>Applicant catalog</div>} />
      </Routes>
    </ConsoleProvider>
  </AuthContext.Provider>;
}

describe('organization creation request lifetime', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    window.localStorage.clear();
    (window as any).__MARTY_RUNTIME_CONFIG__ = { organizationCreationEnabled: true };
    vi.mocked(getPreferences).mockResolvedValue({ last_view_mode: 'applicant', last_active_org_id: null });
    vi.mocked(updatePreferences).mockResolvedValue({});
    vi.mocked(getMyOrganizations).mockResolvedValue([applicantOrganization]);
  });
  afterEach(() => { delete (window as any).__MARTY_RUNTIME_CONFIG__; });

  async function submit(user: ReturnType<typeof renderWithRouter>['user']) {
    await waitFor(() => expect(screen.getByTestId('console-loading')).toHaveTextContent('ready'));
    await user.type(screen.getByLabelText('Organization Slug'), createdOrganization.name);
    await user.type(screen.getByLabelText('Display Name'), createdOrganization.display_name);
    await user.click(screen.getByRole('button', { name: 'Create Organization' }));
    await waitFor(() => expect(createOrganization).toHaveBeenCalledTimes(1));
  }

  it.each(['saved', 'failed'])('honors creation returnTo including query and hash when preference persistence %s', async persistence => {
    vi.mocked(createOrganization).mockResolvedValue(createdOrganization);
    if (persistence === 'failed') vi.mocked(updatePreferences).mockRejectedValue(new Error('Preferences temporarily unavailable'));
    const destination = '/console/org/team?invite=1#members';
    const { user } = renderWithRouter(<CreationLifetimeApp auth={applicantAuth} />, {
      initialEntries: ['/console/organizations/create?returnTo=' + encodeURIComponent(destination)],
    });
    await submit(user);

    expect(await screen.findByText('Created organization team')).toBeInTheDocument();
    expect(screen.getByTestId('complete-location')).toHaveTextContent(destination);
    expect(screen.getByTestId('selected-org')).toHaveTextContent(createdOrganization.id);
    expect(updatePreferences).toHaveBeenCalledExactlyOnceWith({ last_view_mode: 'org', last_active_org_id: createdOrganization.id });
  });

  it.each(['create', 'refresh'])('does not let an old account %s completion refresh, select or navigate the replacement session', async phase => {
    let finish!: (value: any) => void;
    const request = new Promise(resolve => { finish = resolve; });
    if (phase === 'create') vi.mocked(createOrganization).mockReturnValueOnce(request);
    else {
      vi.mocked(createOrganization).mockResolvedValue(createdOrganization);
      vi.mocked(getMyOrganizations).mockResolvedValueOnce([applicantOrganization]).mockReturnValueOnce(request)
        .mockResolvedValue([applicantOrganization]);
    }
    const { user, rerender } = renderWithRouter(<CreationLifetimeApp auth={applicantAuth} />,
      { initialEntries: ['/console/organizations/create'] });
    await submit(user);
    if (phase === 'refresh') await waitFor(() => expect(getMyOrganizations).toHaveBeenCalledTimes(2));
    const replacement = { ...applicantAuth, user: { ...applicantAuth.user, user_id: 'replacement-user', organizations: [] } };
    rerender(<CreationLifetimeApp auth={replacement} />);
    await waitFor(() => expect(getMyOrganizations).toHaveBeenCalledTimes(phase === 'create' ? 2 : 3));
    await waitFor(() => expect(screen.getByTestId('console-loading')).toHaveTextContent('ready'));
    const reads = vi.mocked(getMyOrganizations).mock.calls.length;

    await act(async () => finish(phase === 'create' ? createdOrganization : [createdOrganization]));

    expect(screen.getByTestId('path')).toHaveTextContent('/console/organizations/create');
    expect(screen.getByTestId('selected-org')).toBeEmptyDOMElement();
    expect(screen.queryByRole('heading', { name: 'Organization dashboard' })).not.toBeInTheDocument();
    expect(getMyOrganizations).toHaveBeenCalledTimes(reads);
    expect(getMyPermissions).not.toHaveBeenCalled();
    expect(updatePreferences).not.toHaveBeenCalled();
    expect(window.localStorage.getItem('activeOrgId')).toBeNull();
  });

  it.each(['create', 'preference'])('does not navigate back after leaving creation while %s is pending', async phase => {
    let finish!: (value: any) => void;
    const request = new Promise(resolve => { finish = resolve; });
    if (phase === 'create') vi.mocked(createOrganization).mockReturnValueOnce(request);
    else {
      vi.mocked(createOrganization).mockResolvedValue(createdOrganization);
      vi.mocked(updatePreferences).mockReturnValueOnce(request);
    }
    const { user } = renderWithRouter(<CreationLifetimeApp auth={applicantAuth} />,
      { initialEntries: ['/console/organizations/create'] });
    await submit(user);
    if (phase === 'preference') await waitFor(() => expect(updatePreferences).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole('button', { name: 'Leave creation' }));
    const reads = vi.mocked(getMyOrganizations).mock.calls.length;

    await act(async () => finish(phase === 'create' ? createdOrganization : {}));

    expect(screen.getByTestId('path')).toHaveTextContent('/console/applicant/catalog');
    expect(screen.getByText('Applicant catalog')).toBeInTheDocument();
    expect(getMyOrganizations).toHaveBeenCalledTimes(reads);
    expect(getMyPermissions).not.toHaveBeenCalled();
  });
});
