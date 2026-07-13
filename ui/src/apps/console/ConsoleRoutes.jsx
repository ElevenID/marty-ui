import { Navigate, Route, Routes } from 'react-router-dom';
import { Box, CircularProgress, Typography } from '@mui/material';

import { get } from '../../services/api';
import ProtectedRoute, { ApplicantConsoleRoute, OrgConsoleRoute } from '../../components/ProtectedRoute';
import AuthCallback from '../../components/AuthCallback';
import LoginPage from '../../components/LoginPage';
import ProfilePage from '../../components/ProfilePage';
import { ApplicationForm } from '../../components/applicant';
import CredentialCatalog from '../../components/applicant/CredentialCatalog';
import { AuthenticatedLayout } from '../../components/layouts';
import MyOrganizationsPage from '../../components/pages/MyOrganizationsPage';
import DiscoverOrganizationsPage from '../../components/pages/DiscoverOrganizationsPage';
import JoinOrganizationPage from '../../components/pages/JoinOrganizationPage';
import CreateOrganizationPage from '../../components/organizations/CreateOrganizationPage';
import OrgConsoleUnavailable from '../../components/console/OrgConsoleUnavailable';
import { useAuth } from '../../hooks/useAuth';
import { useConsole, getDefaultLandingPath } from '../../contexts/ConsoleContext';
import {
  ConsoleDashboard,
  TrustPage,
  TrustProfilesPage,
  RevocationProfilesPage,
  RevocationProfileDetailPage,
  RevocationProfileWizard,
  TrustProfileWizard,
  TrustProfileDetailPage,
  TrustProfileEditPage,
  TemplatesPage,
  CredentialTemplatesPage,
  CredentialTemplateDetailPage,
  ApplicationTemplatesPage,
  ApplicationTemplateEditorPage,
  ApplicationTemplateDetailPage,
  CredentialTemplateWizard,
  PoliciesPage,
  PresentationPoliciesPage,
  ComplianceProfilesPage,
  PresentationPolicyWizard,
  DeployPage,
  DeploymentProfilesPage,
  ApiKeysPage,
  DidIdentitiesPage,
  CanvasIntegrationsPage,
  DeliveryDestinationsPage,
  LanesDevicesPage,
  DeploymentProfileWizard,
  KeyManagementServiceWizard,
  IssuerIdentityWizard,
  FlowsPage,
  FlowDefinitionsPage,
  FlowInstancesPage,
  FlowDefinitionWizard,
  CustomFlowBuilder,
  PolicySetsPage,
  PolicySetWizard,
  PolicySetDetailPage,
  FlowDetailPage,
  IssuancePage,
  ApplicationsPage,
  ApplicationReviewPage,
  VerificationSessionsPage,
  OrganizationSettingsPage,
  OrgSetupPage,
  TeamPage,
  RolesPage,
  NotificationsPage,
  MembershipRequestsPage,
  RoleEscalationRequestsPage,
  SigningKeysPage,
  WebhooksPage,
  AuditPage,
  UsageDashboard,
  ApplicantDashboard,
  MyIdentityPage,
  ApplicantSettingsPage,
  DeviceManagementPage,
} from '../../components/console';

function GuardLoadingState({ message }) {
  return (
    <Box
      display="flex"
      flexDirection="column"
      alignItems="center"
      justifyContent="center"
      minHeight="50vh"
    >
      <CircularProgress size={48} />
      <Typography variant="body1" color="text.secondary" sx={{ mt: 2 }}>
        {message}
      </Typography>
    </Box>
  );
}

function resolveConsoleHomePath({ mode, activeOrgId, memberships, isOrgBootstrapRequired }) {
  if (isOrgBootstrapRequired && (!Array.isArray(memberships) || memberships.length === 0)) {
    return '/console/org/setup';
  }

  if (mode === 'org' && !activeOrgId) {
    return '/console/org/setup';
  }

  return getDefaultLandingPath({ mode, activeOrgId, memberships }, '/console/applicant/catalog');
}

function ConsoleEntryRoute() {
  const { isAuthenticated, isLoading: authLoading } = useAuth();
  const {
    mode,
    activeOrgId,
    memberships,
    isLoading: consoleLoading,
    membershipLoadError,
    isOrgBootstrapRequired,
    reloadConsoleState,
  } = useConsole();

  if (authLoading || consoleLoading) {
    return <GuardLoadingState message="Loading console..." />;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: { pathname: '/console' } }} replace />;
  }

  if (membershipLoadError && isOrgBootstrapRequired) {
    return <OrgConsoleUnavailable error={membershipLoadError} onRetry={reloadConsoleState} />;
  }

  return <Navigate to={resolveConsoleHomePath({ mode, activeOrgId, memberships, isOrgBootstrapRequired })} replace />;
}

function ConsoleRoutes() {
  return (
    <Routes>
      <Route path="/console" element={<ConsoleEntryRoute />} />
      <Route path="/console/login" element={<LoginPage fallbackRedirectTo="/console" />} />
      <Route path="/login" element={<LoginPage fallbackRedirectTo="/console" />} />
      <Route path="/console/auth/callback" element={<AuthCallback />} />
      <Route
        path="/console/org"
        element={
          <OrgConsoleRoute redirectTo="/login">
            <AuthenticatedLayout />
          </OrgConsoleRoute>
        }
      >
        <Route index element={<ConsoleDashboard />} />
        <Route path="design" element={<Navigate to="/console/org/templates/credentials" replace />} />
        <Route path="govern" element={<Navigate to="/console/org/trust/profiles" replace />} />
        <Route path="connect" element={<Navigate to="/console/org/deploy/canvas" replace />} />
        <Route path="setup-wizard" element={<Navigate to="/console/org" replace />} />
        <Route path="profile" element={<ProfilePage />} />
        <Route path="trust" element={<TrustPage />} />
        <Route path="trust/profiles" element={<TrustProfilesPage />} />
        <Route path="trust/profiles/new" element={<TrustProfileWizard />} />
        <Route path="trust/profiles/:id" element={<TrustProfileDetailPage />} />
        <Route path="trust/profiles/:id/edit" element={<TrustProfileEditPage />} />
        <Route path="trust/issuers" element={<Navigate to="/console/org/trust/profiles" replace />} />
        <Route path="trust/revocation" element={<RevocationProfilesPage />} />
        <Route path="trust/revocation/new" element={<RevocationProfileWizard />} />
        <Route path="trust/revocation/:id" element={<RevocationProfileDetailPage />} />
        <Route path="templates" element={<TemplatesPage />} />
        <Route path="templates/credentials" element={<CredentialTemplatesPage />} />
        <Route path="templates/credentials/new" element={<CredentialTemplateWizard />} />
        <Route path="templates/credentials/:templateId" element={<CredentialTemplateDetailPage />} />
        <Route path="templates/applications" element={<ApplicationTemplatesPage />} />
        <Route path="templates/applications/new" element={<ApplicationTemplateEditorPage />} />
        <Route path="templates/applications/:templateId" element={<ApplicationTemplateDetailPage />} />
        <Route path="templates/applications/:templateId/edit" element={<ApplicationTemplateEditorPage />} />
        <Route path="policies" element={<PoliciesPage />} />
        <Route path="policies/presentation" element={<PresentationPoliciesPage />} />
        <Route path="policies/presentation/new" element={<PresentationPolicyWizard />} />
        <Route path="policies/compliance" element={<ComplianceProfilesPage />} />
        <Route path="deploy" element={<DeployPage />} />
        <Route path="deploy/profiles" element={<DeploymentProfilesPage />} />
        <Route path="deploy/profiles/new" element={<DeploymentProfileWizard />} />
        <Route path="deploy/api-keys" element={<Navigate to="/console/org/api-keys" replace />} />
        <Route path="deploy/issuer-identity" element={<DidIdentitiesPage />} />
        <Route path="deploy/canvas" element={<CanvasIntegrationsPage />} />
        <Route path="connect/delivery-destinations" element={<DeliveryDestinationsPage />} />
        <Route path="deploy/issuer-identity/new" element={<IssuerIdentityWizard />} />
        <Route path="deploy/key-management" element={<SigningKeysPage />} />
        <Route path="deploy/key-management/services" element={<Navigate to="/console/org/deploy/key-management" replace />} />
        <Route path="deploy/key-management/services/new" element={<KeyManagementServiceWizard />} />
        {/* Legacy redirects */}
        <Route path="deploy/dids" element={<Navigate to="/console/org/deploy/issuer-identity" replace />} />
        <Route path="deploy/signing-keys" element={<Navigate to="/console/org/deploy/key-management" replace />} />
        <Route path="deploy/signing-keys/settings" element={<Navigate to="/console/org/deploy/key-management/services" replace />} />
        <Route path="deploy/signing-keys/services/new" element={<Navigate to="/console/org/deploy/key-management/services/new" replace />} />
        <Route path="deploy/lanes" element={<LanesDevicesPage />} />
        <Route path="deploy/webhooks" element={<Navigate to="/console/org/webhooks" replace />} />
        <Route path="flows" element={<FlowsPage />} />
        <Route path="flows/definitions" element={<FlowDefinitionsPage />} />
        <Route path="flows/definitions/new" element={<FlowDefinitionWizard />} />
        <Route path="flows/definitions/new/custom" element={<CustomFlowBuilder />} />
        <Route path="flows/definitions/:flowId" element={<FlowDetailPage />} />
        <Route path="policies/sets" element={<PolicySetsPage />} />
        <Route path="policies/sets/new" element={<PolicySetWizard />} />
        <Route path="policies/sets/:policySetId" element={<PolicySetDetailPage />} />
        <Route path="operate" element={<Navigate to="/console/org/operate/flow-instances" replace />} />
        <Route path="operate/issuance" element={<IssuancePage />} />
        <Route path="operate/issuance/:credentialId" element={<IssuancePage />} />
        <Route path="operate/applications" element={<ApplicationsPage />} />
        <Route path="operate/applications/:applicationId" element={<ApplicationReviewPage />} />
        <Route path="operate/flow-instances" element={<FlowInstancesPage />} />
        <Route path="operate/flow-instances/:instanceId" element={<FlowInstancesPage />} />
        <Route path="operate/verify" element={<VerificationSessionsPage />} />
        <Route path="settings" element={<OrganizationSettingsPage />} />
        <Route path="api-keys" element={<ApiKeysPage />} />
        <Route path="webhooks" element={<WebhooksPage />} />
        <Route path="team" element={<TeamPage />} />
        <Route path="roles" element={<RolesPage />} />
        <Route path="notifications" element={<NotificationsPage />} />
        <Route path="membership-requests" element={<MembershipRequestsPage />} />
        <Route path="role-requests" element={<RoleEscalationRequestsPage />} />
        <Route path="audit" element={<AuditPage />} />
        <Route path="billing" element={<UsageDashboard get={get} />} />
      </Route>

      <Route
        path="/console/org/setup"
        element={
          <ProtectedRoute redirectTo="/login">
            <AuthenticatedLayout />
          </ProtectedRoute>
        }
      >
        <Route index element={<OrgSetupPage />} />
      </Route>

      <Route
        path="/console/applicant"
        element={
          <ApplicantConsoleRoute redirectTo="/login">
            <AuthenticatedLayout />
          </ApplicantConsoleRoute>
        }
      >
        <Route index element={<Navigate to="/console/applicant/catalog" replace />} />
        <Route path="dashboard" element={<ApplicantDashboard />} />
        <Route path="identity" element={<MyIdentityPage />} />
        <Route path="credentials" element={<Navigate to="/console/applicant/identity" replace />} />
        <Route path="applications" element={<Navigate to="/console/applicant/identity" replace />} />
        <Route path="catalog" element={<CredentialCatalog />} />
        <Route path="apply/:credentialType" element={<ApplicationForm />} />
        <Route path="devices" element={<DeviceManagementPage />} />
        <Route path="settings" element={<ApplicantSettingsPage />} />
        <Route path="profile" element={<ProfilePage />} />
      </Route>

      <Route
        path="/console/organizations"
        element={
          <ProtectedRoute redirectTo="/login">
            <AuthenticatedLayout />
          </ProtectedRoute>
        }
      >
        <Route
          index
          element={
            <MyOrganizationsPage
              managePath="/console/organizations"
              discoverPath="/console/organizations/discover"
              joinPath="/console/organizations/join"
            />
          }
        />
        <Route path="discover" element={<DiscoverOrganizationsPage joinPath="/console/organizations/join" />} />
        <Route
          path="join"
          element={<JoinOrganizationPage managePath="/console/organizations" discoverPath="/console/organizations/discover" />}
        />
        <Route path="create" element={<CreateOrganizationPage />} />
      </Route>

      <Route
        path="*"
        element={
          <ProtectedRoute redirectTo="/login">
            <Navigate to="/console" replace />
          </ProtectedRoute>
        }
      />
    </Routes>
  );
}

export default ConsoleRoutes;
