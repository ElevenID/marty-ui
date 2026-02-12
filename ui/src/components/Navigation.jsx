import { useMemo } from 'react';
import { Tabs, Tab, Box } from '@mui/material';
import { Link, useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { useAuth } from '../hooks/useAuth';

/**
 * Administrator navigation tabs
 */
const ADMIN_TABS = [
  { labelKey: 'navigation.dashboard', defaultLabel: 'Dashboard', path: '/dashboard', exact: true },
  { labelKey: 'navigation.travelDocs', defaultLabel: 'Travel Docs', path: '/documents' },
  { labelKey: 'navigation.applicants', defaultLabel: 'Applicants', path: '/applicants' },
  { labelKey: 'navigation.verify', defaultLabel: 'Verify', path: '/verifier' },
  { labelKey: 'navigation.wallet', defaultLabel: 'Wallet', path: '/wallet' },
  { labelKey: 'navigation.advanced', defaultLabel: 'Advanced', path: '/enhanced' },
  { labelKey: 'navigation.admin', defaultLabel: 'Admin', path: '/admin', prefixes: ['/admin'] },
];

/**
 * Vendor navigation tabs
 */
const VENDOR_TABS = [
  { labelKey: 'navigation.dashboard', defaultLabel: 'Dashboard', path: '/vendor', exact: true },
  { labelKey: 'navigation.applications', defaultLabel: 'Applications', path: '/vendor/applications' },
  { labelKey: 'navigation.trust', defaultLabel: 'Trust', path: '/vendor/trust' },
  { labelKey: 'navigation.verification', defaultLabel: 'Verification', path: '/vendor/verification' },
  { labelKey: 'navigation.auditLogs', defaultLabel: 'Audit Logs', path: '/vendor/logs' },
  { labelKey: 'navigation.team', defaultLabel: 'Team', path: '/vendor/team' },
];

/**
 * Applicant navigation tabs
 */
const APPLICANT_TABS = [
  { labelKey: 'navigation.credentials', defaultLabel: 'Credentials', path: '/credentials', exact: true },
  { labelKey: 'navigation.myApplications', defaultLabel: 'My Applications', path: '/my-applications' },
  { labelKey: 'navigation.myDocuments', defaultLabel: 'My Documents', path: '/my-documents' },
  { labelKey: 'navigation.profile', defaultLabel: 'Profile', path: '/profile' },
];

/**
 * Public navigation tabs (not logged in)
 * Intent-based navigation for product education and conversion
 */
const PUBLIC_TABS = [
  { labelKey: 'navigation.home', defaultLabel: 'Home', path: '/', exact: true },
  { labelKey: 'navigation.product', defaultLabel: 'Product', path: '/product' },
  { labelKey: 'navigation.howItWorks', defaultLabel: 'How It Works', path: '/identity' },
  { labelKey: 'navigation.whyVerifiableIdentity', defaultLabel: 'Why Verifiable Identity', path: '/from-idv-to-verifiable-identity' },
  { labelKey: 'navigation.standards', defaultLabel: 'Standards', path: '/standards' },
  { labelKey: 'navigation.docs', defaultLabel: 'Docs', path: '/docs' },
  { labelKey: 'navigation.pricing', defaultLabel: 'Pricing', path: '/pricing' },
];

function Navigation() {
  const { t } = useTranslation('common');
  const location = useLocation();
  const { isAuthenticated, isAdministrator, isApplicant, isVendor } = useAuth();

  // Select tabs based on user type
  const tabs = useMemo(() => {
    if (!isAuthenticated) return PUBLIC_TABS;
    if (isAdministrator) return ADMIN_TABS;
    if (isVendor) return VENDOR_TABS;
    if (isApplicant) return APPLICANT_TABS;
    return PUBLIC_TABS;
  }, [isAuthenticated, isAdministrator, isVendor, isApplicant]);

  // Find current tab index
  const getCurrentTab = () => {
    const path = location.pathname;

    for (let i = 0; i < tabs.length; i++) {
      const tab = tabs[i];

      // Exact match
      if (tab.exact && path === tab.path) return i;

      // Prefix match (for nested routes like /admin/*)
      if (tab.prefixes) {
        if (tab.prefixes.some((prefix) => path.startsWith(prefix))) return i;
      }

      // Non-exact path match - check if current path starts with tab path
      if (!tab.exact && path.startsWith(tab.path)) return i;
    }

    return false; // Return false instead of 0 to indicate no match
  };

  return (
    <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }} data-testid="navigation-container">
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          px: 2,
          py: 1,
        }}
      >
        {/* Navigation Tabs */}
        <Tabs value={getCurrentTab()} aria-label="navigation" data-testid="navigation-tabs">
          {tabs.map((tab) => (
            <Tab 
              key={tab.path} 
              label={t(tab.labelKey, tab.defaultLabel)} 
              component={Link} 
              to={tab.path}
              data-testid={`nav-tab-${tab.defaultLabel.toLowerCase().replace(/\s+/g, '-')}`}
            />
          ))}
        </Tabs>
      </Box>
    </Box>
  );
}

export default Navigation;
