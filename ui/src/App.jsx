import { useState, useMemo, Suspense, useContext } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { AppBar, Toolbar, Typography, Box, Button, Avatar, Chip, Tooltip, IconButton, Menu, MenuItem, ListItemIcon, ListItemText, Divider } from '@mui/material';
import LoginIcon from '@mui/icons-material/Login';
import LogoutIcon from '@mui/icons-material/Logout';
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings';
import PersonIcon from '@mui/icons-material/Person';
import BusinessIcon from '@mui/icons-material/Business';
import StorefrontIcon from '@mui/icons-material/Storefront';
import SettingsIcon from '@mui/icons-material/Settings';
import NotificationsIcon from '@mui/icons-material/Notifications';
import PaymentIcon from '@mui/icons-material/Payment';

import { AuthProvider, AuthContext } from './contexts/AuthContext';
import { ConsoleProvider } from './contexts/ConsoleContext';
import { NotificationProvider } from './contexts/NotificationContext';
import { BrandingProvider, BrandingContext } from './contexts/BrandingContext';
import { PaymentProvider } from './contexts/PaymentContext';
import { TrustProvider } from './components/trust/TrustProvider';
import ErrorBoundary from './components/ErrorBoundary';
import ProtectedRoute, { AdminRoute, ApplicantRoute, ApplicantConsoleRoute, VendorRoute, OrgConsoleRoute } from './components/ProtectedRoute';
import LandingPage from './components/LandingPage';
import Home from './components/Home';
import TravelDocuments from './components/TravelDocuments';
import VerifierDemo from './components/VerifierDemo';
import WalletDemo from './components/WalletDemo';
import EnhancedVerifierDemo from './components/EnhancedVerifierDemo';
import PresentationRequestCreator from './components/verifier/PresentationRequestCreator';
import AdminDashboard from './components/AdminDashboard';
import PassportDemo from './components/PassportDemo';
import CscaManager from './components/CscaManager';
import PkdManager from './components/PkdManager';
import TrustAnchor from './components/TrustAnchor';
import MetricsViewer from './components/MetricsViewer';
import MasterListViewer from './components/MasterListViewer';
import ApplicantVetting from './components/ApplicantVetting';
import LoginPage from './components/LoginPage';
import AuthCallback from './components/AuthCallback';
import WalletSetup from './components/WalletSetup';
import ProfilePage from './components/ProfilePage';
import { ApplicationForm } from './components/applicant';
import CredentialCatalog from './components/applicant/CredentialCatalog';
import InviteAcceptPage from './components/InviteAcceptPage';
import ApplyPage from './components/ApplyPage';
import ApiDocumentation from './components/ApiDocumentation';
import ProductPage from './components/ProductPage';
import StandardsPage from './components/StandardsPage';
import IdentityGuidePage from './components/IdentityGuidePage';
import FromIDVPage from './components/FromIDVPage';
import PricingPage from './components/PricingPage';
import {
  VerifiableCredentialApiPage,
  EudiWalletVerificationPage,
  IsoMdocVerificationPage,
  SdJwtVerificationPage,
  OpenBadgesVerificationPage,
  OpenBadgesIssuancePage,
  TrustRegistryPage,
  MyOrganizationsPage,
  DiscoverOrganizationsPage,
  JoinOrganizationPage,
} from './components/pages';

// New Console Pages with Sidebar Navigation
import { AuthenticatedLayout, PublicLayout } from './components/layouts';
import {
  ConsoleDashboard,
  GuidedSetupWizard,
  // Trust
  TrustPage,
  TrustProfilesPage,
  TrustedIssuersPage,
  RevocationProfilesPage,
  TrustProfileWizard,
  TrustProfileDetailPage,
  // Templates
  TemplatesPage,
  CredentialTemplatesPage,
  ApplicationTemplatesPage,
  CredentialTemplateWizard,
  // Policies
  PoliciesPage,
  PresentationPoliciesPage,
  ComplianceProfilesPage,
  PresentationPolicyWizard,
  // Deploy
  DeployPage,
  DeploymentProfilesPage,
  ApiKeysPage,
  LanesDevicesPage,
  DeploymentProfileWizard,
  // Flows
  FlowsPage,
  FlowDefinitionsPage,
  FlowInstancesPage,
  FlowDefinitionWizard,
  FlowDetailPage,
  // Operate
  OperatePage,
  IssuancePage,
  ApplicationsPage,
  ApplicationReviewPage,
  VerificationSessionsPage,
  // Org
  OrgPage,
  OrganizationSettingsPage,
  OrgSetupPage,
  TeamPage,
  RolesPage,
  NotificationsPage,
  MembershipRequestsPage,
  RoleEscalationRequestsPage,
  NotificationPreferencesPage,
  SigningKeysPage,
  WebhooksPage,
  // Audit
  AuditPage,
  // Applicant
  ApplicantDashboard,
  MyCredentialsPage,
  MyApplicationsPage,
  ApplicantSettingsPage,
  DeviceManagementPage,
} from './components/console';
import { NotificationBell, LanguageSwitcher } from './components/common';
import ImpersonationBanner from './components/ImpersonationBanner';

// Preview Components
import {
  PreviewLayout,
  PreviewCatalogPage,
  PreviewCredentialPage,
  PreviewApplicationPage,
  PreviewFlowPage,
} from './components/preview';

// TODO: Future feature - Dynamic theme from org database settings
// When org profile page is implemented, fetch theme colors from API
// and update theme dynamically based on authenticated user's organization
function createDynamicTheme(branding) {
  return createTheme({
    palette: {
      primary: {
        main: branding.primaryColor || '#1976d2',
      },
      secondary: {
        main: branding.secondaryColor || '#dc004e',
      },
    },
  });
}

function AppContent() {
  const { t } = useTranslation('common');
  const auth = useContext(AuthContext) || {};
  const brandingContext = useContext(BrandingContext);
  const fallbackBranding = useMemo(() => ({
    appName: 'ElevenID LLC',
    primaryColor: '#1976d2',
    secondaryColor: '#dc004e',
    logoUrl: null,
  }), []);

  const {
    isAuthenticated = false,
    isAdministrator = false,
    isApplicant = false,
    isVendor = false,
    organizationName = null,
    user = null,
    login = () => {},
    logout = () => {},
  } = auth;

  const runtimeBranding = brandingContext?.branding;
  const branding = useMemo(
    () => runtimeBranding || fallbackBranding,
    [runtimeBranding, fallbackBranding],
  );

  // Settings menu state
  const [settingsAnchorEl, setSettingsAnchorEl] = useState(null);
  const settingsMenuOpen = Boolean(settingsAnchorEl);

  const handleSettingsClick = (event) => {
    setSettingsAnchorEl(event.currentTarget);
  };

  const handleSettingsClose = () => {
    setSettingsAnchorEl(null);
  };

  // Create theme from branding config
  const theme = useMemo(() => createDynamicTheme(branding), [branding]);

  const getUserDisplayName = () => {
    if (!user) return t('common.user');
    return user.given_name || user.username || user.email || t('common.user');
  };

  const getUserTypeLabel = () => {
    if (isAdministrator) return t('userTypes.administrator');
    if (isVendor) return t('common.organizationMember', 'Organization Member');
    if (isApplicant) return t('common.person', 'Person');
    return t('userTypes.user');
  };

  const getUserTypeIcon = () => {
    if (isAdministrator) return <AdminPanelSettingsIcon />;
    if (isVendor) return <StorefrontIcon />;
    return <PersonIcon />;
  };

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      {isAuthenticated && <ImpersonationBanner />}
      <AppBar position="static">
        <Toolbar>
          {branding.logoUrl && (
            <Box component="img" src={branding.logoUrl} alt={branding.appName} sx={{ height: 32, mr: 2 }} />
          )}
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            {branding.appName}
          </Typography>
          
          {/* Language Switcher */}
          <LanguageSwitcher
            variant="standard"
            sx={{
              mr: 2,
              minWidth: 120,
              '& .MuiInputBase-root': {
                color: 'common.white',
              },
              '& .MuiSelect-select': {
                color: 'common.white',
              },
              '& .MuiSvgIcon-root': {
                color: 'common.white',
              },
              '& .MuiInputAdornment-root .MuiSvgIcon-root': {
                color: 'common.white',
              },
              '& .MuiInput-underline:before': {
                borderBottomColor: 'rgba(255, 255, 255, 0.7)',
              },
              '& .MuiInput-underline:hover:not(.Mui-disabled):before': {
                borderBottomColor: 'rgba(255, 255, 255, 0.9)',
              },
              '& .MuiInput-underline:after': {
                borderBottomColor: 'common.white',
              },
            }}
          />
          
          {/* User Info & Auth Actions */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            {isAuthenticated ? (
              <>
                {/* Organization Badge (for vendors) */}
                {isVendor && organizationName && (
                  <Tooltip title={t('common.yourOrganization')}>
                    <Chip
                      icon={<BusinessIcon />}
                      label={organizationName}
                      size="small"
                      variant="filled"
                      sx={{ bgcolor: 'rgba(255, 255, 255, 0.2)', color: 'white' }}
                    />
                  </Tooltip>
                )}

                {/* User Type Badge */}
                <Chip
                  icon={getUserTypeIcon()}
                  label={getUserTypeLabel()}
                  size="small"
                  variant="outlined"
                  sx={{ borderColor: 'white', color: 'white' }}
                  data-testid="user-type-badge"
                />

                {/* User Avatar & Name */}
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Avatar
                    src={user?.picture || undefined}
                    sx={{ width: 32, height: 32, bgcolor: 'rgba(255, 255, 255, 0.3)' }}
                  >
                    {!user?.picture && getUserDisplayName().charAt(0).toUpperCase()}
                  </Avatar>
                  <Typography variant="body2" sx={{ color: 'white' }}>
                    {getUserDisplayName()}
                  </Typography>
                </Box>

                {/* Notification Bell */}
                {isVendor && <NotificationBell />}

                {/* Settings Menu (Vendor only) */}
                {isVendor && (
                  <>
                    <Tooltip title={t('common.settings')}>
                      <IconButton
                        onClick={handleSettingsClick}
                        size="small"
                        sx={{ color: 'white' }}
                        aria-controls={settingsMenuOpen ? 'settings-menu' : undefined}
                        aria-haspopup="true"
                        aria-expanded={settingsMenuOpen ? 'true' : undefined}
                        data-testid="settings-button"
                      >
                        <SettingsIcon />
                      </IconButton>
                    </Tooltip>
                    <Menu
                      id="settings-menu"
                      anchorEl={settingsAnchorEl}
                      open={settingsMenuOpen}
                      onClose={handleSettingsClose}
                      MenuListProps={{
                        'aria-labelledby': 'settings-button',
                      }}
                      transformOrigin={{ horizontal: 'right', vertical: 'top' }}
                      anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
                    >
                      <MenuItem component="a" href="/console/org/settings" onClick={handleSettingsClose}>
                        <ListItemIcon>
                          <BusinessIcon fontSize="small" />
                        </ListItemIcon>
                        <ListItemText>{t('common.organizationProfile')}</ListItemText>
                      </MenuItem>
                      <MenuItem component="a" href="/console/org/notifications" onClick={handleSettingsClose}>
                        <ListItemIcon>
                          <NotificationsIcon fontSize="small" />
                        </ListItemIcon>
                        <ListItemText>{t('common.notifications')}</ListItemText>
                      </MenuItem>
                      <MenuItem disabled>
                        <ListItemIcon>
                          <PaymentIcon fontSize="small" />
                        </ListItemIcon>
                        <ListItemText>{t('common.billingSubscription')}</ListItemText>
                      </MenuItem>
                      <Divider />
                      <MenuItem disabled>
                        <ListItemText sx={{ color: 'error.main' }}>{t('common.deleteOrganization')}</ListItemText>
                      </MenuItem>
                    </Menu>
                  </>
                )}

                {/* Logout Button */}
                <Button
                  variant="outlined"
                  size="small"
                  startIcon={<LogoutIcon />}
                  onClick={logout}
                  sx={{ borderColor: 'white', color: 'white', '&:hover': { borderColor: 'white', bgcolor: 'rgba(255, 255, 255, 0.1)' } }}
                  data-testid="logout-button"
                >
                  {t('common.logout')}
                </Button>
              </>
            ) : (
              /* Login Button */
              <Button
                variant="contained"
                size="small"
                startIcon={<LoginIcon />}
                onClick={login}
                sx={{ bgcolor: 'white', color: 'primary.main', '&:hover': { bgcolor: 'rgba(255, 255, 255, 0.9)' } }}
                data-testid="login-button"
              >
                {t('common.login')}
              </Button>
            )}
          </Box>
        </Toolbar>
      </AppBar>

      <Routes>
        {/* Organization Console Routes (with Sidebar) - Requires org selection */}
        <Route
          path="/console/org"
          element={
            <OrgConsoleRoute>
              <AuthenticatedLayout />
            </OrgConsoleRoute>
          }
        >
          <Route index element={<ConsoleDashboard />} />
          <Route path="setup-wizard" element={<GuidedSetupWizard />} />
          <Route path="profile" element={<ProfilePage />} />
          {/* Trust */}
          <Route path="trust" element={<TrustPage />} />
          <Route path="trust/profiles" element={<TrustProfilesPage />} />
          <Route path="trust/profiles/new" element={<TrustProfileWizard />} />
          <Route path="trust/profiles/:id" element={<TrustProfileDetailPage />} />
          <Route path="trust/issuers" element={<TrustedIssuersPage />} />
          <Route path="trust/revocation" element={<RevocationProfilesPage />} />
          {/* Templates */}
          <Route path="templates" element={<TemplatesPage />} />
          <Route path="templates/credentials" element={<CredentialTemplatesPage />} />
          <Route path="templates/credentials/new" element={<CredentialTemplateWizard />} />
          <Route path="templates/applications" element={<ApplicationTemplatesPage />} />
          {/* Policies */}
          <Route path="policies" element={<PoliciesPage />} />
          <Route path="policies/presentation" element={<PresentationPoliciesPage />} />
          <Route path="policies/presentation/new" element={<PresentationPolicyWizard />} />
          <Route path="policies/compliance" element={<ComplianceProfilesPage />} />
          {/* Deploy */}
          <Route path="deploy" element={<DeployPage />} />
          <Route path="deploy/profiles" element={<DeploymentProfilesPage />} />
          <Route path="deploy/profiles/new" element={<DeploymentProfileWizard />} />
          <Route path="deploy/api-keys" element={<ApiKeysPage />} />
          <Route path="deploy/signing-keys" element={<SigningKeysPage />} />
          <Route path="deploy/lanes" element={<LanesDevicesPage />} />
          <Route path="deploy/webhooks" element={<WebhooksPage />} />
          {/* Flows */}
          <Route path="flows" element={<FlowsPage />} />
          <Route path="flows/definitions" element={<FlowDefinitionsPage />} />
          <Route path="flows/definitions/new" element={<FlowDefinitionWizard />} />
          <Route path="flows/definitions/:flowId" element={<FlowDetailPage />} />
          {/* Operate */}
          <Route path="operate" element={<OperatePage />} />
          <Route path="operate/issuance" element={<IssuancePage />} />
          <Route path="operate/applications" element={<ApplicationsPage />} />
          <Route path="operate/applications/:applicationId" element={<ApplicationReviewPage />} />
          <Route path="operate/flow-instances" element={<FlowInstancesPage />} />
          <Route path="operate/verify" element={<VerificationSessionsPage />} />
          {/* Org - Settings remain under org path */}
          <Route path="settings" element={<OrganizationSettingsPage />} />
          <Route path="team" element={<TeamPage />} />
          <Route path="roles" element={<RolesPage />} />
          <Route path="notifications" element={<NotificationsPage />} />
          <Route path="membership-requests" element={<MembershipRequestsPage />} />
          <Route path="role-requests" element={<RoleEscalationRequestsPage />} />
          {/* Audit */}
          <Route path="audit" element={<AuditPage />} />
        </Route>

        {/* Organization Setup Route - No org required */}
        <Route
          path="/console/org/setup"
          element={
            <ProtectedRoute>
              <AuthenticatedLayout />
            </ProtectedRoute>
          }
        >
          <Route index element={<OrgSetupPage />} />
        </Route>

        {/* Applicant Console Routes (with Sidebar) */}
        <Route
          path="/console/applicant"
          element={
            <ApplicantConsoleRoute>
              <AuthenticatedLayout />
            </ApplicantConsoleRoute>
          }
        >
          <Route index element={<Navigate to="/console/applicant/catalog" replace />} />
          <Route path="dashboard" element={<ApplicantDashboard />} />
          <Route path="credentials" element={<MyCredentialsPage />} />
          <Route path="applications" element={<MyApplicationsPage />} />
          <Route path="catalog" element={<CredentialCatalog />} />
          <Route path="apply/:credentialType" element={<ApplicationForm />} />
          <Route path="devices" element={<DeviceManagementPage />} />
          <Route path="settings" element={<ApplicantSettingsPage />} />
          <Route path="profile" element={<ProfilePage />} />
        </Route>

        {/* Preview Routes - Vendor auth required, render applicant views in preview mode */}
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

        {/* All other routes use PublicLayout with Container */}
        <Route element={<PublicLayout />}>
          {/* Public Routes */}
          <Route path="/" element={<LandingPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/auth/callback" element={<AuthCallback />} />
          
          {/* Deep Link Entry - Apply for Credentials */}
          <Route path="/apply" element={<ApplyPage />} />
          <Route path="/apply/:credentialType" element={<ApplyPage />} />
          
          <Route path="/product" element={<ProductPage />} />
          <Route path="/verifiable-credential-api" element={<VerifiableCredentialApiPage />} />
          <Route path="/eudi-wallet-verification" element={<EudiWalletVerificationPage />} />
          <Route path="/iso-18013-5-mdoc-verification" element={<IsoMdocVerificationPage />} />
          <Route path="/sd-jwt-verification" element={<SdJwtVerificationPage />} />
          <Route path="/open-badges-verification" element={<OpenBadgesVerificationPage />} />
          <Route path="/open-badges-issuance" element={<OpenBadgesIssuancePage />} />
          <Route path="/trust-registry-infrastructure" element={<TrustRegistryPage />} />
          <Route path="/identity" element={<IdentityGuidePage />} />
          <Route path="/from-idv-to-verifiable-identity" element={<FromIDVPage />} />
          <Route path="/standards" element={<StandardsPage />} />
          <Route path="/pricing" element={<PricingPage />} />
          <Route path="/docs" element={<ApiDocumentation />} />
          <Route path="/organizations" element={<MyOrganizationsPage />} />
          <Route path="/organizations/discover" element={<DiscoverOrganizationsPage />} />
          <Route path="/organizations/join" element={<JoinOrganizationPage />} />

          {/* Admin Dashboard (the original Home component) */}
          <Route
            path="/dashboard"
            element={
              <AdminRoute>
                <Home />
              </AdminRoute>
            }
          />

          {/* Administrator-Only Routes */}
          <Route
            path="/documents"
            element={
              <AdminRoute>
                <TravelDocuments />
              </AdminRoute>
            }
          />
          <Route
            path="/applicants"
            element={
              <AdminRoute>
                <ApplicantVetting />
              </AdminRoute>
            }
          />
          <Route
            path="/verifier"
            element={
              <AdminRoute>
                <VerifierDemo />
              </AdminRoute>
            }
          />
          <Route
            path="/verifier/create-request"
            element={
              <AdminRoute>
                <PresentationRequestCreator />
              </AdminRoute>
            }
          />
          <Route
            path="/wallet"
            element={
              <AdminRoute>
                <WalletDemo />
              </AdminRoute>
            }
          />
          <Route
            path="/enhanced"
            element={
              <AdminRoute>
                <EnhancedVerifierDemo />
              </AdminRoute>
            }
          />
          <Route
            path="/admin"
            element={
              <AdminRoute>
                <AdminDashboard />
              </AdminRoute>
            }
          />
          <Route
            path="/admin/passport"
            element={
              <AdminRoute>
                <PassportDemo />
              </AdminRoute>
            }
          />
          <Route
            path="/admin/csca"
            element={
              <AdminRoute>
                <CscaManager />
              </AdminRoute>
            }
          />
          <Route
            path="/admin/pkd"
            element={
              <AdminRoute>
                <PkdManager />
              </AdminRoute>
            }
          />
          <Route
            path="/admin/trust-anchor"
            element={
              <AdminRoute>
                <TrustAnchor />
              </AdminRoute>
            }
          />
          <Route
            path="/admin/master-lists"
            element={
              <AdminRoute>
                <MasterListViewer />
              </AdminRoute>
            }
          />
          <Route
            path="/admin/metrics"
            element={
              <AdminRoute>
                <MetricsViewer />
              </AdminRoute>
            }
          />

          {/* Public invite accept route */}
          <Route path="/invite/accept" element={<InviteAcceptPage />} />

          {/* Applicant-Only Routes */}
          <Route
            path="/credentials"
            element={
              <ApplicantRoute>
                <Navigate to="/console/applicant/credentials" replace />
              </ApplicantRoute>
            }
          />
          <Route
            path="/catalog"
            element={
              <ApplicantRoute>
                <Navigate to="/console/applicant/catalog" replace />
              </ApplicantRoute>
            }
          />
          <Route
            path="/my-applications"
            element={
              <ApplicantRoute>
                <Navigate to="/console/applicant/applications" replace />
              </ApplicantRoute>
            }
          />
          <Route
            path="/my-documents"
            element={
              <ApplicantRoute>
                <Navigate to="/console/applicant/devices" replace />
              </ApplicantRoute>
            }
          />
          <Route
            path="/apply"
            element={
              <ApplicantRoute>
                <ApplicationForm />
              </ApplicantRoute>
            }
          />
          <Route
            path="/apply/:credentialType"
            element={
              <ApplicantRoute>
                <ApplicationForm />
              </ApplicantRoute>
            }
          />
          {/* Wallet Setup & Notifications */}
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

          {/* Fallback - redirect unknown routes to home */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </ThemeProvider>
  );
}

console.log('[DEBUG] App.jsx - Module loaded');

function App() {
  console.log('[DEBUG] App component rendering');
  return (
    <ErrorBoundary>
      <Suspense fallback={
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
          <Typography>Loading...</Typography>
        </Box>
      }>
        <BrandingProvider>
          <NotificationProvider>
            <TrustProvider>
              <PaymentProvider>
                <Router>
                  <AuthProvider>
                    <ConsoleProvider>
                      <AppContent />
                    </ConsoleProvider>
                  </AuthProvider>
                </Router>
              </PaymentProvider>
            </TrustProvider>
          </NotificationProvider>
        </BrandingProvider>
      </Suspense>
    </ErrorBoundary>
  );
}

export default App;
