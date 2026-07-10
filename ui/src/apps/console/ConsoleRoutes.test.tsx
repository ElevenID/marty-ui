import { beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryRouter, Outlet } from 'react-router-dom';
import { renderWithoutRouter, screen, waitFor } from '@test/utils';
import type { ReactNode } from 'react';

import ConsoleRoutes from './ConsoleRoutes';

const { mockLogin, mockUseAuth, mockUseConsole } = vi.hoisted(() => ({
  mockLogin: vi.fn(),
  mockUseAuth: vi.fn(),
  mockUseConsole: vi.fn(),
}));

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

vi.mock('../../components/console', () => ({
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
  CredentialTemplateWizard: () => <div data-testid="credential-template-wizard" />,
  PoliciesPage: () => <div data-testid="policies-page" />,
  PresentationPoliciesPage: () => <div data-testid="presentation-policies-page" />,
  ComplianceProfilesPage: () => <div data-testid="compliance-profiles-page" />,
  PresentationPolicyWizard: () => <div data-testid="presentation-policy-wizard" />,
  DeployPage: () => <div data-testid="deploy-page" />,
  DeploymentProfilesPage: () => <div data-testid="deployment-profiles-page" />,
  ApiKeysPage: () => <div data-testid="api-keys-page" />,
  DidIdentitiesPage: () => <div data-testid="did-identities-page" />,
  CanvasIntegrationsPage: () => <div data-testid="canvas-integrations-page" />,
  LanesDevicesPage: () => <div data-testid="lanes-devices-page" />,
  DeploymentProfileWizard: () => <div data-testid="deployment-profile-wizard" />,
  KeyManagementServiceWizard: () => <div data-testid="key-management-service-wizard" />,
  IssuerIdentityWizard: () => <div data-testid="issuer-identity-wizard" />,
  FlowsPage: () => <div data-testid="flows-page" />,
  FlowDefinitionsPage: () => <div data-testid="flow-definitions-page" />,
  FlowInstancesPage: () => <div data-testid="flow-instances-page" />,
  FlowDefinitionWizard: () => <div data-testid="flow-definition-wizard" />,
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
  RoleEscalationRequestsPage: () => <div data-testid="role-escalation-requests-page" />,
  SigningKeysPage: () => <div data-testid="signing-keys-page" />,
  WebhooksPage: () => <div data-testid="webhooks-page" />,
  AuditPage: () => <div data-testid="audit-page" />,
  UsageDashboard: () => <div data-testid="usage-dashboard" />,
  ApplicantDashboard: () => <div data-testid="applicant-dashboard" />,
  MyIdentityPage: () => <div data-testid="my-identity-page" />,
  ApplicantSettingsPage: () => <div data-testid="applicant-settings-page" />,
  DeviceManagementPage: () => <div data-testid="device-management-page" />,
}));

function renderConsoleRoutes(path: string) {
  return renderWithoutRouter(
    <MemoryRouter initialEntries={[path]}>
      <ConsoleRoutes />
    </MemoryRouter>
  );
}

describe('ConsoleRoutes login routing', () => {
  beforeEach(() => {
    vi.clearAllMocks();
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
});
