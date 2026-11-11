import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Route, Routes, useLocation } from 'react-router';
import { act, renderWithRouter, screen, waitFor, within } from '@test/utils';
import { AuthContext } from '../../../contexts/AuthContext';
import { ConsoleProvider, useConsole } from '../../../contexts/ConsoleContext';
import { ConsoleHeaderBar } from '../../navigation/ConsoleHeaderBar';
import { OrgSwitcher } from '../../navigation/OrgSwitcher';
import TeamPage from './TeamPage';
import MembershipRequestsPage from './MembershipRequestsPage';
import OrganizationSettingsPage from './OrganizationSettingsPage';

const api = vi.hoisted(() => ({
  getPreferences: vi.fn(), updatePreferences: vi.fn(), getMyOrganizations: vi.fn(),
  getMyPermissions: vi.fn(), listRoles: vi.fn(), setMemberRoles: vi.fn(),
  listMembers: vi.fn(), inviteMember: vi.fn(), removeMember: vi.fn(),
  getPendingRequests: vi.fn(), approveMembershipRequest: vi.fn(),
  loadOrgSettings: vi.fn(), saveOrgSettings: vi.fn(), showNotification: vi.fn(),
}));
vi.mock('../../../services/preferencesApi', () => ({
  getPreferences: api.getPreferences, updatePreferences: api.updatePreferences,
}));
vi.mock('../../../services/organizationsApi', () => ({ getMyOrganizations: api.getMyOrganizations }));
vi.mock('../../../services/rbacApi', () => ({
  getMyPermissions: api.getMyPermissions, listRoles: api.listRoles, setMemberRoles: api.setMemberRoles,
}));
vi.mock('../../../services/teamApi', () => ({ default: {
  listMembers: api.listMembers, inviteMember: api.inviteMember, removeMember: api.removeMember,
} }));
vi.mock('../../../services/membershipApi', () => ({
  getPendingRequests: api.getPendingRequests, approveMembershipRequest: api.approveMembershipRequest,
}));
vi.mock('../../../application/orgSettings', () => ({
  loadOrgSettings: api.loadOrgSettings, saveOrgSettings: api.saveOrgSettings,
}));
vi.mock('../../../hooks/useNotifications', () => ({ useNotifications: () => ({
  showNotification: api.showNotification, showSuccess: api.showNotification,
}) }));
vi.mock('../../../hooks/useBranding', () => ({ useBranding: () => ({ branding: {} }) }));
vi.mock('../../common/NotificationBell', () => ({ default: () => null }));
vi.mock('./OrgDefaultsSection', () => ({ default: () => null }));

const organization = {
  id: 'org-a', name: 'original-name', display_name: 'Original organization',
  membership: { status: 'active', roles: [{ id: 'role-admin', name: 'admin' }], has_org_console_access: true },
};
const otherOrganization = { ...organization, id: 'org-b', name: 'other-name', display_name: 'Other organization' };
const currentMember = {
  id: 'member-a', organization_id: 'org-a', user_id: 'user-a', email: 'current@example.invalid',
  status: 'active', roles: organization.membership.roles, is_owner: false,
};
const profile = {
  name: organization.name, displayName: organization.display_name, description: '',
  website: '', contactEmail: '', contactPhone: '', visibility: 'PRIVATE', joinMechanism: 'invite', requiresApproval: true,
};
const auth = {
  user: { user_id: 'user-a', email: currentMember.email, roles: ['admin'], organizations: [organization, otherOrganization] },
  isAuthenticated: true, isLoading: false, isVendor: true, isApplicant: false,
  isAdministrator: false, organizationId: organization.id, organizationName: organization.display_name,
  hasCapability: () => true,
};

function ContextProbe() {
  const context = useConsole();
  const location = useLocation();
  return <>
    <output data-testid="selected-org">{context.activeOrgId || ''}</output>
    <output data-testid="memberships">{JSON.stringify(context.memberships)}</output>
    <output data-testid="location">{location.pathname}</output>
  </>;
}

function App({ shell = false }: { shell?: boolean }) {
  return <AuthContext.Provider value={auth as any}>
    <ConsoleProvider>
      <ContextProbe />
      {shell && <>
        <div data-testid="console-header"><ConsoleHeaderBar /></div>
        <div data-testid="org-switcher"><OrgSwitcher variant="header" /></div>
      </>}
      <Routes>
        <Route path="/console/org/team" element={<TeamPage />} />
        <Route path="/console/org/membership-requests" element={<MembershipRequestsPage />} />
        <Route path="/console/org/settings" element={<OrganizationSettingsPage />} />
        <Route path="/console/org/setup" element={<h1>Choose an organization</h1>} />
      </Routes>
    </ConsoleProvider>
  </AuthContext.Provider>;
}

describe('organization mutations and permission recovery with real console state', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    Object.values(api).forEach(mock => mock.mockReset());
    window.localStorage.clear();
    vi.stubGlobal('confirm', vi.fn(() => true));
    api.getPreferences.mockResolvedValue({ last_view_mode: 'org', last_active_org_id: organization.id });
    api.updatePreferences.mockResolvedValue({});
    api.getMyOrganizations.mockResolvedValue([organization, otherOrganization]);
    api.getMyPermissions.mockResolvedValue({
      permissions: ['team:view', 'team:manage', 'role:view', 'role:assign', 'organization:view', 'organization:edit'],
      roles: organization.membership.roles,
    });
    api.listRoles.mockResolvedValue({ roles: [] });
    api.listMembers.mockResolvedValue([currentMember]);
    api.removeMember.mockResolvedValue({ success: true });
    api.getPendingRequests.mockResolvedValue({ requests: [{ ...currentMember, status: 'pending' }] });
    api.loadOrgSettings.mockResolvedValue({ org: profile, error: null });
    api.saveOrgSettings.mockResolvedValue({ org: { ...profile, name: 'updated-name', displayName: 'Updated organization' }, error: null });
  });
  afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

  it.each(['team', 'membership-requests'])('offers retry after a %s permission transport failure without fetching protected inventory', async route => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    api.getMyPermissions.mockRejectedValue(new Error('Permissions temporarily unavailable'));
    const { user } = renderWithRouter(<App />, { initialEntries: [`/console/org/${route}`] });
    expect((await screen.findAllByText('Permissions temporarily unavailable')).length).toBeGreaterThan(0);
    expect(screen.queryByText(/You do not have permission to view/)).not.toBeInTheDocument();
    expect(api.listMembers).not.toHaveBeenCalled();
    expect(api.getPendingRequests).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
    let finishRetry!: (value: { permissions: string[]; roles: any[] }) => void;
    api.getMyPermissions.mockReturnValue(new Promise(resolve => { finishRetry = resolve; }));
    const permissionReads = api.getMyPermissions.mock.calls.length;
    await user.click(screen.getByRole('button', { name: /Retry/i }));
    expect(api.getMyPermissions).toHaveBeenCalledTimes(permissionReads + 1);
    expect(api.listMembers).not.toHaveBeenCalled();
    expect(api.getPendingRequests).not.toHaveBeenCalled();
    expect(screen.queryByText(currentMember.email)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Retry/i })).not.toBeInTheDocument();
    await act(async () => finishRetry({ permissions: ['team:view'], roles: [] }));
    expect((await screen.findAllByText(currentMember.email)).length).toBeGreaterThan(0);
    expect(screen.queryByText('Permissions temporarily unavailable')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Approve' })).not.toBeInTheDocument();
  });

  it.each([
    { route: 'team', denial: '403' },
    { route: 'team', denial: 'empty grants' },
    { route: 'membership-requests', denial: '403' },
    { route: 'membership-requests', denial: 'empty grants' },
  ])('keeps a confirmed $route permission denial ($denial) distinct from a load failure', async ({ route, denial }) => {
    if (denial === '403') api.getMyPermissions.mockRejectedValue({ status: 403 });
    else api.getMyPermissions.mockResolvedValue({ permissions: [], roles: [] });
    renderWithRouter(<App />, { initialEntries: [`/console/org/${route}`] });
    expect(await screen.findByText(/You do not have permission to view/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Retry/i })).not.toBeInTheDocument();
    expect(api.listMembers).not.toHaveBeenCalled();
    expect(api.getPendingRequests).not.toHaveBeenCalled();
  });

  it('leaves the removed current membership immediately even if a subsequent inventory or preference request would fail', async () => {
    const { user } = renderWithRouter(<App />, { initialEntries: ['/console/org/team'] });
    const row = (await screen.findAllByText(currentMember.email))[0].closest('tr') as HTMLElement;
    api.getMyOrganizations.mockRejectedValue(new Error('Inventory temporarily unavailable'));
    api.updatePreferences.mockRejectedValue(new Error('Preferences temporarily unavailable'));
    api.listMembers.mockRejectedValue(Object.assign(new Error('Membership removed'), { status: 403 }));
    await user.click(within(row).getByRole('button'));
    await user.click(screen.getByRole('menuitem', { name: 'Remove Member' }));
    expect(await screen.findByRole('heading', { name: 'Choose an organization' })).toBeInTheDocument();
    expect(screen.getByTestId('selected-org')).toBeEmptyDOMElement();
    expect(JSON.parse(screen.getByTestId('memberships').textContent!)).toEqual([otherOrganization]);
    expect(window.localStorage.getItem('activeOrgId')).toBeNull();
    expect(api.removeMember).toHaveBeenCalledExactlyOnceWith(organization.id, currentMember.id);
    expect(api.listMembers).toHaveBeenCalledOnce();
    expect(api.getMyOrganizations).toHaveBeenCalledOnce();
    expect(api.showNotification).toHaveBeenCalledExactlyOnceWith('Member removed from team', 'success');
  });

  it('reconciles saved names in the header and switcher while retaining the selected ID and membership roles', async () => {
    const { user } = renderWithRouter(<App shell />, { initialEntries: ['/console/org/settings'] });
    await screen.findByRole('textbox', { name: 'Organization Name' });
    api.getMyOrganizations.mockRejectedValue(new Error('Inventory temporarily unavailable'));
    await user.click(screen.getByRole('button', { name: 'Edit' }));
    const name = screen.getByRole('textbox', { name: 'Organization Name' });
    const displayName = screen.getByRole('textbox', { name: 'Display Name' });
    await user.clear(name); await user.type(name, 'updated-name');
    await user.clear(displayName); await user.type(displayName, 'Updated organization');
    await user.click(screen.getByRole('button', { name: 'Save Changes' }));
    expect(await screen.findByText('Organization settings saved successfully.')).toBeInTheDocument();
    await waitFor(() => {
      expect(within(screen.getByTestId('console-header')).getByText('Updated organization')).toBeInTheDocument();
      expect(within(screen.getByTestId('org-switcher')).getByText('Updated organization')).toBeInTheDocument();
    });
    expect(screen.getByTestId('selected-org')).toHaveTextContent(organization.id);
    expect(JSON.parse(screen.getByTestId('memberships').textContent!)).toEqual([
      { ...organization, name: 'updated-name', display_name: 'Updated organization' }, otherOrganization,
    ]);
    expect(api.getMyOrganizations).toHaveBeenCalledOnce();
    expect(api.saveOrgSettings).toHaveBeenCalledOnce();
  });
});
