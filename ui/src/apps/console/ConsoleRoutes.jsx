import { Navigate, Route, Routes } from 'react-router-dom';
import { Box, CircularProgress, Typography } from '@mui/material';

import { get } from '../../services/api';
import ProtectedRoute, { ApplicantConsoleRoute, OrgConsoleRoute, VendorRoute } from '../../components/ProtectedRoute';
import AuthCallback from '../../components/AuthCallback';
import ProfilePage from '../../components/ProfilePage';
import { ApplicationForm } from '../../components/applicant';
import CredentialCatalog from '../../components/applicant/CredentialCatalog';
import { AuthenticatedLayout } from '../../components/layouts';
import BrowserRedirect from '../../components/BrowserRedirect';
import { useAuth } from '../../hooks/useAuth';
import { useConsole, getDefaultLandingPath } from '../../contexts/ConsoleContext';
import {
  ConsoleDashboard,
  GuidedSetupWizard,
  TrustPage,
  TrustProfilesPage,
  TrustedIssuersPage,
  RevocationProfilesPage,
  TrustProfileWizard,
  TrustProfileDetailPage,
  TemplatesPage,
  CredentialTemplatesPage,
  ApplicationTemplatesPage,
  CredentialTemplateWizard,
  PoliciesPage,
  PresentationPoliciesPage,
  ComplianceProfilesPage,
  PresentationPolicyWizard,
  DeployPage,
  DeploymentProfilesPage,
  ApiKeysPage,
  LanesDevicesPage,
  DeploymentProfileWizard,
  FlowsPage,
  FlowDefinitionsPage,
  FlowInstancesPage,
  FlowDefinitionWizard,
  FlowDetailPage,
  OperatePage,
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

function resolveConsoleHomePath({ mode, activeOrgId, memberships }) {
  if (mode === 'org' && !activeOrgId) {
    return '/console/org/setup';
  }

  return getDefaultLandingPath({ mode, activeOrgId, memberships }, '/console/applicant/catalog');
}

function ConsoleEntryRoute() {
  const { isAuthenticated, isLoading: authLoading } = useAuth();
  const { mode, activeOrgId, memberships, isLoading: consoleLoading } = useConsole();

  if (authLoading || consoleLoading) {
    return <GuardLoadingState message="Loading console..." />;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: { pathname: '/console' } }} replace />;
  }

  return <Navigate to={resolveConsoleHomePath({ mode, activeOrgId, memberships })} replace />;
}

function ConsoleRoutes() {
  return (
    <Routes>
      <Route path="/console" element={<ConsoleEntryRoute />} />
      <Route path="/console/login" element={<BrowserRedirect to="/login" message="Opening login..." />} />
      <Route path="/login" element={<BrowserRedirect to="/login" message="Opening login..." />} />
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
        <Route path="setup-wizard" element={<GuidedSetupWizard />} />
        <Route path="profile" element={<ProfilePage />} />
        <Route path="trust" element={<TrustPage />} />
        <Route path="trust/profiles" element={<TrustProfilesPage />} />
        <Route path="trust/profiles/new" element={<TrustProfileWizard />} />
        <Route path="trust/profiles/:id" element={<TrustProfileDetailPage />} />
        <Route path="trust/issuers" element={<TrustedIssuersPage />} />
        <Route path="trust/revocation" element={<RevocationProfilesPage />} />
        <Route path="templates" element={<TemplatesPage />} />
        <Route path="templates/credentials" element={<CredentialTemplatesPage />} />
        <Route path="templates/credentials/new" element={<CredentialTemplateWizard />} />
        <Route path="templates/applications" element={<ApplicationTemplatesPage />} />
        <Route path="policies" element={<PoliciesPage />} />
        <Route path="policies/presentation" element={<PresentationPoliciesPage />} />
        <Route path="policies/presentation/new" element={<PresentationPolicyWizard />} />
        <Route path="policies/compliance" element={<ComplianceProfilesPage />} />
        <Route path="deploy" element={<DeployPage />} />
        <Route path="deploy/profiles" element={<DeploymentProfilesPage />} />
        <Route path="deploy/profiles/new" element={<DeploymentProfileWizard />} />
        <Route path="deploy/api-keys" element={<ApiKeysPage />} />
        <Route path="deploy/signing-keys" element={<SigningKeysPage />} />
        <Route path="deploy/signing-keys/settings" element={<SigningKeysPage />} />
        <Route path="deploy/lanes" element={<LanesDevicesPage />} />
        <Route path="deploy/webhooks" element={<WebhooksPage />} />
        <Route path="flows" element={<FlowsPage />} />
        <Route path="flows/definitions" element={<FlowDefinitionsPage />} />
        <Route path="flows/definitions/new" element={<FlowDefinitionWizard />} />
        <Route path="flows/definitions/:flowId" element={<FlowDetailPage />} />
        <Route path="operate" element={<OperatePage />} />
        <Route path="operate/issuance" element={<IssuancePage />} />
        <Route path="operate/applications" element={<ApplicationsPage />} />
        <Route path="operate/applications/:applicationId" element={<ApplicationReviewPage />} />
        <Route path="operate/flow-instances" element={<FlowInstancesPage />} />
        <Route path="operate/verify" element={<VerificationSessionsPage />} />
        <Route path="settings" element={<OrganizationSettingsPage />} />
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
          <VendorRoute redirectTo="/login">
            <AuthenticatedLayout />
          </VendorRoute>
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