import { useState, useMemo } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { AppBar, Toolbar, Typography, Container, Box, Button, Avatar, Chip, Tooltip, IconButton, Menu, MenuItem, ListItemIcon, ListItemText, Divider } from '@mui/material';
import LoginIcon from '@mui/icons-material/Login';
import LogoutIcon from '@mui/icons-material/Logout';
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings';
import PersonIcon from '@mui/icons-material/Person';
import BusinessIcon from '@mui/icons-material/Business';
import StorefrontIcon from '@mui/icons-material/Storefront';
import SettingsIcon from '@mui/icons-material/Settings';
import NotificationsIcon from '@mui/icons-material/Notifications';
import PaymentIcon from '@mui/icons-material/Payment';

import { AuthProvider } from './contexts/AuthContext';
import { NotificationProvider } from './contexts/NotificationContext';
import { BrandingProvider } from './contexts/BrandingContext';
import { PaymentProvider } from './contexts/PaymentContext';
import { TrustProvider } from './components/trust/TrustProvider';
import { useAuth } from './hooks/useAuth';
import { useBranding } from './hooks/useBranding';
import ErrorBoundary from './components/ErrorBoundary';
import ProtectedRoute, { AdminRoute, ApplicantRoute, VendorRoute } from './components/ProtectedRoute';
import LandingPage from './components/LandingPage';
import Home from './components/Home';
import TravelDocuments from './components/TravelDocuments';
import VerifierDemo from './components/VerifierDemo';
import WalletDemo from './components/WalletDemo';
import EnhancedVerifierDemo from './components/EnhancedVerifierDemo';
import PresentationRequestCreator from './components/verifier/PresentationRequestCreator';
import Navigation from './components/Navigation';
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
import OnboardingPage from './components/OnboardingPage';
import MyApplications from './components/MyApplications';
import MyDocuments from './components/MyDocuments';
import ProfilePage from './components/ProfilePage';
import WalletSetup from './components/WalletSetup';
import NotificationPreferences from './components/NotificationPreferences';
import { ApplicationForm, CredentialCatalog } from './components/applicant';
import InviteAcceptPage from './components/InviteAcceptPage';
import ApiDocumentation from './components/ApiDocumentation';
import ProductPage from './components/ProductPage';
import StandardsPage from './components/StandardsPage';
import IdentityGuidePage from './components/IdentityGuidePage';
import FromIDVPage from './components/FromIDVPage';
import PricingPage from './components/PricingPage';

// New Console Pages with Sidebar Navigation
import { AuthenticatedLayout, PublicLayout } from './components/layouts';
import {
  ConsoleDashboard,
  // Trust
  TrustPage,
  TrustProfilesPage,
  TrustedIssuersPage,
  RevocationProfilesPage,
  TrustProfileWizard,
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
  // Operate
  OperatePage,
  IssuancePage,
  ApplicationsPage,
  // Org
  OrgPage,
  OrganizationSettingsPage,
  TeamPage,
  WebhooksPage,
  // Audit
  AuditPage,
  // Applicant
  ApplicantDashboard,
  MyCredentialsPage,
  MyApplicationsPage,
  ApplicantSettingsPage,
} from './components/console';

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
  const { isAuthenticated, isAdministrator, isApplicant, isVendor, organizationName, user, login, logout } = useAuth();
  const { branding } = useBranding();

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
    if (!user) return '';
    return user.name || user.email || 'User';
  };

  const getUserTypeLabel = () => {
    if (isAdministrator) return 'Administrator';
    if (isVendor) return 'Vendor';
    if (isApplicant) return 'Applicant';
    return 'User';
  };

  const getUserTypeIcon = () => {
    if (isAdministrator) return <AdminPanelSettingsIcon />;
    if (isVendor) return <StorefrontIcon />;
    return <PersonIcon />;
  };

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <AppBar position="static">
        <Toolbar>
          {branding.logoUrl && (
            <Box component="img" src={branding.logoUrl} alt={branding.appName} sx={{ height: 32, mr: 2 }} />
          )}
          <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
            {branding.appName}
          </Typography>
          
          {/* User Info & Auth Actions */}
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            {isAuthenticated ? (
              <>
                {/* Organization Badge (for vendors) */}
                {isVendor && organizationName && (
                  <Tooltip title="Your Organization">
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
                  <Avatar sx={{ width: 32, height: 32, bgcolor: 'rgba(255, 255, 255, 0.3)' }}>
                    {getUserDisplayName().charAt(0).toUpperCase()}
                  </Avatar>
                  <Typography variant="body2" sx={{ color: 'white' }}>
                    {getUserDisplayName()}
                  </Typography>
                </Box>

                {/* Settings Menu (Vendor only) */}
                {isVendor && (
                  <>
                    <Tooltip title="Settings">
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
                      <MenuItem component="a" href="/vendor/settings" onClick={handleSettingsClose}>
                        <ListItemIcon>
                          <BusinessIcon fontSize="small" />
                        </ListItemIcon>
                        <ListItemText>Organization Profile</ListItemText>
                      </MenuItem>
                      <MenuItem disabled>
                        <ListItemIcon>
                          <NotificationsIcon fontSize="small" />
                        </ListItemIcon>
                        <ListItemText>Notifications</ListItemText>
                      </MenuItem>
                      <MenuItem disabled>
                        <ListItemIcon>
                          <PaymentIcon fontSize="small" />
                        </ListItemIcon>
                        <ListItemText>Billing & Subscription</ListItemText>
                      </MenuItem>
                      <Divider />
                      <MenuItem disabled>
                        <ListItemText sx={{ color: 'error.main' }}>Delete Organization</ListItemText>
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
                  Logout
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
                Login
              </Button>
            )}
          </Box>
        </Toolbar>
      </AppBar>

      <Routes>
        {/* New Console Routes (Admin/Vendor with Sidebar) - Full width, no Container */}
        <Route
          path="/console"
          element={
            <ProtectedRoute allowedTypes={['administrator', 'vendor']}>
              <AuthenticatedLayout />
            </ProtectedRoute>
          }
        >
          <Route index element={<ConsoleDashboard />} />
          {/* Trust */}
          <Route path="trust" element={<TrustPage />} />
          <Route path="trust/profiles" element={<TrustProfilesPage />} />
          <Route path="trust/profiles/new" element={<TrustProfileWizard />} />
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
          <Route path="deploy/lanes" element={<LanesDevicesPage />} />
          <Route path="deploy/webhooks" element={<WebhooksPage />} />
          {/* Flows */}
          <Route path="flows" element={<FlowsPage />} />
          <Route path="flows/definitions" element={<FlowDefinitionsPage />} />
          <Route path="flows/definitions/new" element={<FlowDefinitionWizard />} />
          {/* Operate */}
          <Route path="operate" element={<OperatePage />} />
          <Route path="operate/issuance" element={<IssuancePage />} />
          <Route path="operate/applications" element={<ApplicationsPage />} />
          <Route path="operate/flow-instances" element={<FlowInstancesPage />} />
          {/* Org */}
          <Route path="org" element={<OrgPage />} />
          <Route path="org/settings" element={<OrganizationSettingsPage />} />
          <Route path="org/team" element={<TeamPage />} />
          {/* Audit */}
          <Route path="audit" element={<AuditPage />} />
        </Route>

        {/* Applicant Console Routes (with Sidebar) - Full width, no Container */}
        <Route
          path="/applicant"
          element={
            <ApplicantRoute>
              <AuthenticatedLayout />
            </ApplicantRoute>
          }
        >
          <Route index element={<ApplicantDashboard />} />
          <Route path="credentials" element={<MyCredentialsPage />} />
          <Route path="applications" element={<MyApplicationsPage />} />
          <Route path="settings" element={<ApplicantSettingsPage />} />
        </Route>

        {/* All other routes use PublicLayout with Container */}
        <Route element={<PublicLayout />}>
          {/* Public Routes */}
          <Route path="/" element={<LandingPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/auth/callback" element={<AuthCallback />} />
          <Route path="/product" element={<ProductPage />} />
          <Route path="/identity" element={<IdentityGuidePage />} />
          <Route path="/from-idv-to-verifiable-identity" element={<FromIDVPage />} />
          <Route path="/standards" element={<StandardsPage />} />
          <Route path="/pricing" element={<PricingPage />} />
          <Route path="/docs" element={<ApiDocumentation />} />
          <Route
            path="/onboarding"
            element={
              <ProtectedRoute>
                <OnboardingPage />
              </ProtectedRoute>
            }
          />

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

          {/* Legacy Vendor Routes - Redirect to new Console routes */}
          <Route path="/vendor" element={<Navigate to="/console" replace />} />
          <Route path="/vendor/api-keys" element={<Navigate to="/console/deploy/api-keys" replace />} />
          <Route path="/vendor/credentials" element={<Navigate to="/console/templates/credentials" replace />} />
          <Route path="/vendor/mdoc-config" element={<Navigate to="/console/templates/credentials" replace />} />
          <Route path="/vendor/settings" element={<Navigate to="/console/org/settings" replace />} />
          <Route path="/vendor/invitations" element={<Navigate to="/console/operate/invitations" replace />} />
          <Route path="/vendor/applications" element={<Navigate to="/console/operate/applications" replace />} />
          <Route path="/vendor/trust" element={<Navigate to="/console/trust/profiles" replace />} />
          <Route path="/vendor/team" element={<Navigate to="/console/org/team" replace />} />
          <Route path="/vendor/logs" element={<Navigate to="/console/audit" replace />} />
          <Route path="/vendor/verification" element={<Navigate to="/console/operate/verification" replace />} />

          {/* Public invite accept route */}
          <Route path="/invite/accept" element={<InviteAcceptPage />} />

          {/* Applicant-Only Routes */}
          <Route
            path="/credentials"
            element={
              <ApplicantRoute>
                <CredentialCatalog />
              </ApplicantRoute>
            }
          />
          <Route
            path="/my-applications"
            element={
              <ApplicantRoute>
                <MyApplications />
              </ApplicantRoute>
            }
          />
          <Route
            path="/my-documents"
            element={
              <ApplicantRoute>
                <MyDocuments />
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
          <Route
            path="/profile"
            element={
              <ProtectedRoute>
                <ProfilePage />
              </ProtectedRoute>
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
                <NotificationPreferences />
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
      <BrandingProvider>
        <NotificationProvider>
          <TrustProvider>
            <PaymentProvider>
              <Router>
                <AuthProvider>
                  <AppContent />
                </AuthProvider>
              </Router>
            </PaymentProvider>
          </TrustProvider>
        </NotificationProvider>
      </BrandingProvider>
    </ErrorBoundary>
  );
}

export default App;
