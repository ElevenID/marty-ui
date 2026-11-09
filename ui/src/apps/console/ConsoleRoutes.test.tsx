import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter, Outlet, useLocation } from 'react-router';
import { renderWithoutRouter, screen, waitFor } from '@test/utils';
import type { ReactNode } from 'react';

import ConsoleRoutes from './ConsoleRoutes';
import { TeamSnapshotPanel } from '../../components/console/dashboard/TeamSnapshotPanel';
import { SetupReadinessPanel } from '../../components/console/dashboard/SetupReadinessPanel';

const { mockLogin, mockUseAuth, mockUseConsole, mockUsePermissions } = vi.hoisted(() => ({
  mockUsePermissions: vi.fn(),
  mockLogin: vi.fn(),
  mockUseAuth: vi.fn(),
  mockUseConsole: vi.fn(),
}));

vi.mock('../../hooks/usePermissions', () => ({ usePermissions: () => mockUsePermissions() }));

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => mockUseAuth(),
}));

vi.mock('../../contexts/ConsoleContext', () => ({
  useConsole: () => mockUseConsole(),
  getDefaultLandingPath: () => '/console/applicant/catalog',
}));

vi.mock('../../services/api', () => ({
  get: vi.fn(),
}));

vi.mock('../../services/presentationPolicyApi', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../services/presentationPolicyApi')>(),
  listPresentationPolicies: vi.fn().mockResolvedValue([]),
  listCredentialTemplates: vi.fn().mockResolvedValue([]),
  listTrustProfiles: vi.fn().mockResolvedValue([]),
}));

vi.mock('../../components/vendor/FlowManager', () => ({
  default: () => <div data-testid="flow-manager" />,
}));

vi.mock('../../components/ProtectedRoute', () => {
  const passthrough = ({ children }: { children: ReactNode }) => <>{children}</>;

  return {
    default: passthrough,
    ApplicantConsoleRoute: passthrough,
    OrgConsoleRoute: passthrough,
  };
});

vi.mock('../../components/AuthCallback', () => ({
  default: () => <div data-testid="auth-callback" />,
}));

vi.mock('../../components/ProfilePage', () => ({
  default: () => <div data-testid="profile-page" />,
}));

vi.mock('../../components/applicant', () => ({
  ApplicationForm: () => <div data-testid="application-form" />,
}));

vi.mock('../../components/applicant/CredentialCatalog', () => ({
  default: () => <div data-testid="credential-catalog" />,
}));

vi.mock('../../components/layouts', () => ({
  AuthenticatedLayout: () => <Outlet />,
}));

vi.mock('../../components/pages/MyOrganizationsPage', () => ({
  default: () => <div data-testid="my-organizations-page" />,
}));

vi.mock('../../components/pages/DiscoverOrganizationsPage', () => ({
  default: () => <div data-testid="discover-organizations-page" />,
}));

vi.mock('../../components/pages/JoinOrganizationPage', () => ({
  default: () => <div data-testid="join-organization-page" />,
}));

vi.mock('../../components/organizations/CreateOrganizationPage', () => ({
  default: () => <div data-testid="create-organization-page" />,
}));

vi.mock('../../components/console', async () => ({
  ConsoleDashboard: () => <div data-testid="console-dashboard" />,
  TrustPage: () => <div data-testid="trust-page" />,
  TrustProfilesPage: () => <div data-testid="trust-profiles-page" />,
  RevocationProfilesPage: () => <div data-testid="revocation-profiles-page" />,
  RevocationProfileDetailPage: () => <div data-testid="revocation-profile-detail-page" />,
  RevocationProfileWizard: () => <div data-testid="revocation-profile-wizard" />,
  TrustProfileWizard: () => <div data-testid="trust-profile-wizard" />,
  TrustProfileDetailPage: () => <div data-testid="trust-profile-detail-page" />,
  TrustProfileEditPage: () => <div data-testid="trust-profile-edit-page" />,
  TemplatesPage: () => <div data-testid="templates-page" />,
  CredentialTemplatesPage: () => <div data-testid="credential-templates-page" />,
  CredentialTemplateDetailPage: () => <div data-testid="credential-template-detail-page" />,
  ApplicationTemplatesPage: () => <div data-testid="application-templates-page" />,
  ApplicationTemplateEditorPage: () => <div data-testid="application-template-editor-page" />,
  ApplicationTemplateDetailPage: () => <div data-testid="application-template-detail-page" />,
  CredentialTemplateWizard: () => <div data-testid="credential-template-wizard" />,
  PoliciesPage: () => <div data-testid="policies-page" />,
  PresentationPoliciesPage: (await import('../../components/console/policies/PresentationPoliciesPage')).default,
  ComplianceProfilePage: ({ mode = "view" }: { mode?: string }) => <div data-testid={`compliance-profile-${mode}`} />,
  ComplianceProfilesPage: () => <div data-testid="compliance-profiles-page" />,
  PresentationPolicyWizard: () => <div data-testid="presentation-policy-wizard" />,
  DeployPage: () => <div data-testid="deploy-page" />,
  DeploymentProfilesPage: () => <div data-testid="deployment-profiles-page" />,
  ApiKeysPage: () => <div data-testid="api-keys-page" />,
  DidIdentitiesPage: () => <div data-testid="did-identities-page" />,
  DidIdentityDetailPage: () => <div data-testid="did-identity-detail-page" />,
  CanvasIntegrationsPage: () => <div data-testid="canvas-integrations-page" />,
  DeliveryDestinationsPage: () => <div data-testid="delivery-destinations-page" />,
  LanesDevicesPage: () => <div data-testid="lanes-devices-page" />,
  DeploymentProfileWizard: () => <div data-testid="deployment-profile-wizard" />,
  KeyManagementServiceWizard: () => <div data-testid="key-management-service-wizard" />,
  IssuerIdentityWizard: () => <div data-testid="issuer-identity-wizard" />,
  FlowsPage: () => <div data-testid="flows-page" />,
  FlowDefinitionsPage: (await import('../../components/console/flows/FlowDefinitionsPage')).default,
  FlowInstancesPage: () => <div data-testid="flow-instances-page" />,
  FlowDefinitionWizard: () => <div data-testid="flow-definition-wizard" />,
  CustomFlowBuilder: () => <div data-testid="custom-flow-builder" />,
  PolicySetsPage: () => <div data-testid="policy-sets-page" />,
  PolicySetWizard: () => <div data-testid="policy-set-wizard" />,
  PolicySetDetailPage: () => <div data-testid="policy-set-detail-page" />,
  FlowDetailPage: () => <div data-testid="flow-detail-page" />,
  OperatePage: () => <div data-testid="operate-page" />,
  IssuancePage: () => <div data-testid="issuance-page" />,
  ApplicationsPage: () => <div data-testid="applications-page" />,
  ApplicationReviewPage: () => <div data-testid="application-review-page" />,
  VerificationSessionsPage: () => <div data-testid="verification-sessions-page" />,
  OrganizationSettingsPage: () => <div data-testid="organization-settings-page" />,
  OrgSetupPage: () => <div data-testid="org-setup-page" />,
  TeamPage: () => <div data-testid="team-page" />,
  RolesPage: () => <div data-testid="roles-page" />,
  NotificationsPage: () => <div data-testid="notifications-page" />,
  MembershipRequestsPage: () => <div data-testid="membership-requests-page" />,
  RoleEscalationRequestsPage: (await import('../../components/console/org/RoleEscalationRequestsPage')).default,
  SigningKeysPage: () => <div data-testid="signing-keys-page" />,
  WebhooksPage: () => <div data-testid="webhooks-page" />,
  AuditPage: () => <div data-testid="audit-page" />,
  UsageDashboard: () => <div data-testid="usage-dashboard" />,
  ApplicantDashboard: () => <div data-testid="applicant-dashboard" />,
  MyIdentityPage: () => <div data-testid="my-identity-page" />,
  ApplicantSettingsPage: () => <div data-testid="applicant-settings-page" />,
  DeviceManagementPage: () => <div data-testid="device-management-page" />,
}));

afterEach(() => {
  delete (window as any).__MARTY_RUNTIME_CONFIG__;
});

function CurrentPath() {
  const { pathname, search } = useLocation();
  return <span data-testid="current-path">{pathname}{search}</span>;
}

function renderConsoleRoutes(path: string, navigation?: ReactNode) {
  return renderWithoutRouter(
    <MemoryRouter initialEntries={[path]}>
      {navigation}
      <ConsoleRoutes />
      <CurrentPath />
    </MemoryRouter>
  );
}

describe('resource navigation through the console route table', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUseAuth.mockReturnValue({ isAuthenticated: true, isLoading: false });
    mockUseConsole.mockReturnValue({ mode: 'org', activeOrgId: 'org-1', memberships: [{ id: 'org-1' }], isLoading: false });
    mockUsePermissions.mockReturnValue({ can: () => true, isLoading: false });
  });

  it('keeps the retired Role Requests deep link useful without requiring Team access', async () => {
    mockUsePermissions.mockReturnValue({ can: (resource: string, action: string) => resource === 'role' && action === 'view', isLoading: false });
    const { user } = renderConsoleRoutes('/console/org/role-requests?source=bookmark');

    expect(await screen.findByRole('alert')).toHaveTextContent('Role change requests are not available in this console.');
    expect(screen.getByTestId('current-path')).toHaveTextContent('/console/org/role-requests?source=bookmark');
    expect(screen.queryByRole('link', { name: 'View team' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('link', { name: 'View roles' }));
    expect(await screen.findByTestId('roles-page')).toBeInTheDocument();
    expect(screen.getByTestId('current-path')).toHaveTextContent('/console/org/roles');
  });

  it('opens the operational instances page from the Flow Definitions tab', async () => {
    const { user } = renderConsoleRoutes('/console/org/flows/definitions');

    await user.click(screen.getByRole('tab', { name: 'Flow Instances' }));

    expect(await screen.findByTestId('flow-instances-page')).toBeInTheDocument();
    expect(screen.getByTestId('current-path')).toHaveTextContent('/console/org/operate/flow-instances');
    expect(screen.queryByTestId('console-dashboard')).not.toBeInTheDocument();
  });

  it('uses a translated singular resource label and opens the flow builder', async () => {
    const { user } = renderConsoleRoutes('/console/org/flows/definitions');

    await user.click(screen.getByRole('button', { name: 'Build Flow Definition' }));

    expect(await screen.findByTestId('flow-definition-wizard')).toBeInTheDocument();
    expect(screen.getByTestId('current-path')).toHaveTextContent('/console/org/flows/definitions/new');
  });

  it('opens supported verification sessions from Presentation Policies', async () => {
    const { user } = renderConsoleRoutes('/console/org/policies/presentation');

    expect(screen.queryByRole('link', { name: 'Evaluate VP' })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Start QR Verification' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('link', { name: 'Verification sessions' }));

    expect(await screen.findByTestId('verification-sessions-page')).toBeInTheDocument();
    expect(screen.getByTestId('current-path')).toHaveTextContent('/console/org/operate/verify');
    expect(screen.queryByTestId('flow-definition-wizard')).not.toBeInTheDocument();
    expect(screen.queryByTestId('console-dashboard')).not.toBeInTheDocument();
  });

  it('preserves invitation intent when the dashboard Team action opens Team', async () => {
    const { user } = renderConsoleRoutes('/console/org', <TeamSnapshotPanel teamData={{
      members: [{ id: 'member-1', email: 'operator@example.test' }],
      roleDistribution: { admin: 1 },
    }} />);

    await user.click(screen.getByRole('link', { name: 'Invite' }));

    expect(await screen.findByTestId('team-page')).toBeInTheDocument();
    expect(screen.getByTestId('current-path')).toHaveTextContent('/console/org/team?invite=1');
    expect(screen.queryByTestId('console-dashboard')).not.toBeInTheDocument();
  });

  it('opens Revocation Profiles from the ready lifecycle row itself', async () => {
    const { user } = renderConsoleRoutes('/console/org', <SetupReadinessPanel readiness={{
      activeIntent: 'lifecycle',
      intents: {
        lifecycle: {
          id: 'lifecycle',
          label: 'Revoke or renew credentials',
          order: ['revocation'],
          steps: { revocation: { state: 'ready', message: '1 active Revocation Profile' } },
        },
      },
    }} />);

    await user.click(screen.getByRole('link', { name: /Revocation Profile Ready/ }));

    expect(await screen.findByTestId('revocation-profiles-page')).toBeInTheDocument();
    expect(screen.getByTestId('current-path')).toHaveTextContent('/console/org/trust/revocation');
    expect(screen.queryByTestId('console-dashboard')).not.toBeInTheDocument();
  });
});

describe('ConsoleRoutes login routing', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUsePermissions.mockReturnValue({ can: () => true, isLoading: false });
    mockUseAuth.mockReturnValue({
      isAuthenticated: false,
      isLoading: false,
      login: mockLogin,
    });
    mockUseConsole.mockReturnValue({
      mode: 'applicant',
      activeOrgId: null,
      memberships: [],
      isLoading: false,
    });
  });

  it('centers the console initialization state without forwarding layout props to the DOM', () => {
    mockUseConsole.mockReturnValue({ isLoading: true });

    renderConsoleRoutes('/console');

    const loadingState = screen.getByRole('progressbar').parentElement;
    expect(screen.getByText('Loading console...')).toBeVisible();
    expect(loadingState).toHaveStyle({
      display: 'flex',
      'flex-direction': 'column',
      'align-items': 'center',
      'justify-content': 'center',
      'min-height': `${window.innerHeight / 2}px`,
    });
    for (const attribute of ['display', 'flexDirection', 'alignItems', 'justifyContent', 'minHeight']) {
      expect(loadingState).not.toHaveAttribute(attribute);
    }
    expect(mockLogin).not.toHaveBeenCalled();
  });

  it('keeps login inside the console when public pages are disabled', async () => {
    (window as any).__MARTY_RUNTIME_CONFIG__ = { web: { enabled_sections: ['console'] } };
    renderConsoleRoutes('/console');
    await waitFor(() => expect(mockLogin).toHaveBeenCalledWith('/console'));
    expect(screen.getByTestId('current-path')).toHaveTextContent('/console/login');
    expect(screen.queryByTestId('web-section-unavailable')).not.toBeInTheDocument();
  });

  it('exchanges a shared callback served by the console entry when public pages are disabled', () => {
    (window as any).__MARTY_RUNTIME_CONFIG__ = { web: { enabled_sections: ['console'] } };
    renderConsoleRoutes('/auth/callback?code=code-1&state=state-1');
    expect(screen.getByTestId('auth-callback')).toBeInTheDocument();
    expect(mockLogin).not.toHaveBeenCalled();
  });

  it.each([{ sections: ['public'] }, { sections: [] }])('does not start a console or login excluded at startup: $sections', ({ sections }) => {
    (window as any).__MARTY_RUNTIME_CONFIG__ = { web: { enabled_sections: sections } };
    renderConsoleRoutes('/console/login');
    expect(screen.getByTestId('web-section-unavailable')).toBeVisible();
    expect(mockLogin).not.toHaveBeenCalled();
  });

  it('starts the real login flow from the logged-out console entry route', async () => {
    renderConsoleRoutes('/console');

    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith('/console');
    });

    expect(screen.queryByTestId('browser-redirect')).not.toBeInTheDocument();
    expect(screen.queryByText('Opening login...')).not.toBeInTheDocument();
  });

  it.each(['/login', '/console/login'])('starts the real login flow from %s', async (path) => {
    renderConsoleRoutes(path);

    await waitFor(() => {
      expect(mockLogin).toHaveBeenCalledWith('/console');
    });

    expect(screen.queryByTestId('browser-redirect')).not.toBeInTheDocument();
    expect(screen.queryByText('Opening login...')).not.toBeInTheDocument();
  });

  it('shows org-console unavailable instead of applicant navigation when org bootstrap fails', () => {
    mockUseAuth.mockReturnValue({
      isAuthenticated: true,
      isLoading: false,
      login: mockLogin,
    });
    mockUseConsole.mockReturnValue({
      mode: 'applicant',
      activeOrgId: null,
      memberships: [],
      isLoading: false,
      membershipLoadError: {
        message: 'Organization service unavailable',
        messageId: 'msg-503',
      },
      isOrgBootstrapRequired: true,
      reloadConsoleState: vi.fn(),
    });

    renderConsoleRoutes('/console');

    expect(screen.getByText('Organization console unavailable')).toBeInTheDocument();
    expect(screen.getByText('Organization service unavailable')).toBeInTheDocument();
    expect(screen.getByText('Message ID: msg-503')).toBeInTheDocument();
    expect(screen.queryByTestId('credential-catalog')).not.toBeInTheDocument();
  });

  it('routes org-capable users without org-console memberships to the org access hub, not applicant navigation', async () => {
    mockUseAuth.mockReturnValue({
      isAuthenticated: true,
      isLoading: false,
      login: mockLogin,
    });
    mockUseConsole.mockReturnValue({
      mode: 'applicant',
      activeOrgId: null,
      memberships: [],
      isLoading: false,
      membershipLoadError: null,
      isOrgBootstrapRequired: true,
      reloadConsoleState: vi.fn(),
    });

    renderConsoleRoutes('/console');

    expect(await screen.findByTestId('org-setup-page')).toBeInTheDocument();
    expect(screen.queryByTestId('credential-catalog')).not.toBeInTheDocument();
  });

  it('redirects the retired org setup wizard route to the org dashboard', async () => {
    mockUseAuth.mockReturnValue({
      isAuthenticated: true,
      isLoading: false,
      login: mockLogin,
    });
    mockUseConsole.mockReturnValue({
      mode: 'org',
      activeOrgId: 'org-1',
      memberships: [{ id: 'org-1', name: 'Marty' }],
      isLoading: false,
      isOrgBootstrapRequired: true,
    });

    renderConsoleRoutes('/console/org/setup-wizard');

    expect(await screen.findByTestId('console-dashboard')).toBeInTheDocument();
    expect(screen.queryByTestId('guided-setup-wizard')).not.toBeInTheDocument();
  });

  it('does not resolve the retired audit alias to the audit page', async () => {
    mockUseAuth.mockReturnValue({
      isAuthenticated: true,
      isLoading: false,
      login: mockLogin,
    });
    mockUseConsole.mockReturnValue({
      mode: 'applicant',
      activeOrgId: null,
      memberships: [],
      isLoading: false,
      isOrgBootstrapRequired: false,
    });

    renderConsoleRoutes('/console/audit');

    expect(await screen.findByTestId('credential-catalog')).toBeInTheDocument();
    expect(screen.queryByTestId('audit-page')).not.toBeInTheDocument();
  });

});

// ProtectedRoute is mocked only for authentication; the operator guard is real.
describe('operator key management authorization', () => {
  const canonical = '/console/org/operator/key-management';
  const readPaths = [canonical, canonical + '/services', '/console/org/operator', '/console/org/deploy/key-management', '/console/org/deploy/key-management/services', '/console/org/deploy/signing-keys', '/console/org/deploy/signing-keys/settings'];
  const writePaths = [canonical + '/services/new', '/console/org/deploy/key-management/services/new', '/console/org/deploy/signing-keys/services/new'];
  beforeEach(() => {
    vi.clearAllMocks();
    mockUseAuth.mockReturnValue({ isAuthenticated: true });
    mockUseConsole.mockReturnValue({ mode: 'org', activeOrgId: 'org-1', memberships: [{ id: 'org-1' }] });
    mockUsePermissions.mockReturnValue({ can: (_resource: string, action: string) => action === 'view', isLoading: false });
  });
  it.each(readPaths)('allows metadata readers at %s', async (path) => {
    renderConsoleRoutes(path);
    expect(await screen.findByTestId('signing-keys-page')).toBeInTheDocument();
  });
  it.each(writePaths)('denies configuration to read-only users at %s', async (path) => {
    renderConsoleRoutes(path);
    expect(await screen.findByRole('alert')).toHaveTextContent('permission to configure');
    expect(screen.queryByTestId('key-management-service-wizard')).not.toBeInTheDocument();
  });
  it.each(readPaths)('denies unauthorized readers at %s', async (path) => {
    mockUsePermissions.mockReturnValue({ can: () => false, isLoading: false });
    renderConsoleRoutes(path);
    expect(await screen.findByRole('alert')).toHaveTextContent('permission to view');
    expect(screen.queryByTestId('signing-keys-page')).not.toBeInTheDocument();
  });
  it.each(writePaths)('preserves administrator configuration access at %s', async (path) => {
    mockUsePermissions.mockReturnValue({ can: () => true, isLoading: false });
    renderConsoleRoutes(path);
    expect(await screen.findByTestId('key-management-service-wizard')).toBeInTheDocument();
  });
  it('does not mount an operator page while permissions load even if stale can() grants access', () => {
    mockUsePermissions.mockReturnValue({ can: () => true, isLoading: true });
    renderConsoleRoutes(canonical);
    expect(screen.getByText('Checking operator permissions...')).toBeInTheDocument();
    expect(screen.queryByTestId('signing-keys-page')).not.toBeInTheDocument();
  });
  it('keeps the public issuer inventory in Deploy', () => {
    mockUsePermissions.mockReturnValue({ can: () => false, isLoading: false });
    renderConsoleRoutes('/console/org/deploy/issuer-identity');
    expect(screen.getByTestId('did-identities-page')).toBeInTheDocument();
  });
});


describe('canonical compliance profile routes', () => {
  it.each([['/new', 'create'], ['/profile-one', 'view'], ['/profile-one/edit', 'edit']])('routes %s to the owned consumer page', (suffix, mode) => {
    renderConsoleRoutes('/console/org/policies/compliance' + suffix);
    expect(screen.getByTestId('compliance-profile-' + mode)).toBeInTheDocument();
  });
});
