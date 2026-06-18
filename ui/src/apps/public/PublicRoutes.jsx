import { Navigate, Route, Routes } from 'react-router-dom';

import { useAuth } from '../../hooks/useAuth';
import ProtectedRoute, { ApplicantRoute, VendorRoute } from '../../components/ProtectedRoute';
import LoginPage from '../../components/LoginPage';
import AuthCallback from '../../components/AuthCallback';
import WalletSetup from '../../components/WalletSetup';
import InviteAcceptPage from '../../components/InviteAcceptPage';
import ApplyPage from '../../components/ApplyPage';
import ApiDocumentation from '../../components/ApiDocumentation';
import MyOrganizationsPage from '../../components/pages/MyOrganizationsPage';
import DiscoverOrganizationsPage from '../../components/pages/DiscoverOrganizationsPage';
import JoinOrganizationPage from '../../components/pages/JoinOrganizationPage';
import CanvasLtiExperiencePage from '../../components/pages/CanvasLtiExperiencePage';
import BrowserRedirect from '../../components/BrowserRedirect';
import { getPublicLoginFallback, renderPublicRoot, renderMarketingRoutes } from '@ui-public-routes';
import { PublicLayout } from '../../components/layouts';
import {
  PreviewLayout,
  PreviewCatalogPage,
  PreviewCredentialPage,
  PreviewApplicationPage,
  PreviewFlowPage,
} from '../../components/preview';
import { NotificationPreferencesPage } from '../../components/console';

function PublicRoutes() {
  const auth = useAuth() || {};
  const {
    isAuthenticated = false,
    isAdministrator = false,
    isVendor = false,
    isApplicant = false,
    login = () => {},
  } = auth;
  const loginFallbackRedirect = getPublicLoginFallback({ isAuthenticated, isAdministrator, isVendor, isApplicant });

  return (
    <Routes>
      <Route
        path="/applicant/preview"
        element={
          <VendorRoute>
            <PreviewLayout />
          </VendorRoute>
        }
      >
        <Route path="catalog" element={<PreviewCatalogPage />} />
        <Route path="credentials/:templateId" element={<PreviewCredentialPage />} />
        <Route path="applications/:applicationTemplateId" element={<PreviewApplicationPage />} />
        <Route path="flows/:flowId" element={<PreviewFlowPage />} />
      </Route>

      <Route path="/canvas/lti/experience" element={<CanvasLtiExperiencePage />} />

      <Route element={<PublicLayout />}>
        <Route path="/" element={renderPublicRoot({ isAuthenticated, isAdministrator, isVendor, isApplicant })} />
        <Route path="/login" element={<LoginPage fallbackRedirectTo={loginFallbackRedirect} />} />
        <Route path="/auth/callback" element={<AuthCallback />} />
        <Route path="/apply" element={<ApplyPage />} />
        <Route path="/apply/:credentialType" element={<ApplyPage />} />

        {renderMarketingRoutes({ login })}

        <Route path="/docs" element={<ApiDocumentation />} />
        <Route path="/organizations" element={<MyOrganizationsPage />} />
        <Route path="/organizations/discover" element={<DiscoverOrganizationsPage />} />
        <Route path="/organizations/join" element={<JoinOrganizationPage />} />
        <Route
          path="/console-handoff/org/setup"
          element={<BrowserRedirect to="/console/org/setup" preserveSearch message="Opening console setup..." />}
        />
        <Route
          path="/console-handoff/org/billing"
          element={<BrowserRedirect to="/console/org/billing" preserveSearch message="Opening console billing..." />}
        />

        <Route path="/invite/accept" element={<InviteAcceptPage />} />

        <Route
          path="/credentials"
          element={
            <ApplicantRoute>
              <BrowserRedirect to="/console/applicant/credentials" message="Opening applicant console..." />
            </ApplicantRoute>
          }
        />
        <Route
          path="/catalog"
          element={
            <ApplicantRoute>
              <BrowserRedirect to="/console/applicant/catalog" message="Opening applicant console..." />
            </ApplicantRoute>
          }
        />
        <Route
          path="/my-applications"
          element={
            <ApplicantRoute>
              <BrowserRedirect to="/console/applicant/applications" message="Opening applicant console..." />
            </ApplicantRoute>
          }
        />
        <Route
          path="/my-documents"
          element={
            <ApplicantRoute>
              <BrowserRedirect to="/console/applicant/devices" message="Opening applicant console..." />
            </ApplicantRoute>
          }
        />
        <Route
          path="/wallet/setup"
          element={
            <ProtectedRoute>
              <WalletSetup />
            </ProtectedRoute>
          }
        />
        <Route
          path="/settings/notifications"
          element={
            <ProtectedRoute>
              <NotificationPreferencesPage />
            </ProtectedRoute>
          }
        />

        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

export default PublicRoutes;
