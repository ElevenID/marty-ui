import React, { useMemo } from 'react';
import { Tabs, Tab, Box } from '@mui/material';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../hooks/useAuth';

/**
 * Administrator navigation tabs
 */
const ADMIN_TABS = [
  { label: 'Dashboard', path: '/dashboard', exact: true },
  { label: 'Travel Docs', path: '/documents' },
  { label: 'Applicants', path: '/applicants' },
  { label: 'Verify', path: '/verifier' },
  { label: 'Wallet', path: '/wallet' },
  { label: 'Advanced', path: '/enhanced' },
  { label: 'Admin', path: '/admin', prefixes: ['/admin'] },
];

/**
 * Vendor navigation tabs
 */
const VENDOR_TABS = [
  { label: 'Dashboard', path: '/vendor', exact: true },
  { label: 'Applications', path: '/vendor/applications' },
  { label: 'Trust', path: '/vendor/trust' },
  { label: 'Verification', path: '/vendor/verification' },
  { label: 'Audit Logs', path: '/vendor/logs' },
  { label: 'Team', path: '/vendor/team' },
];

/**
 * Applicant navigation tabs
 */
const APPLICANT_TABS = [
  { label: 'Credentials', path: '/credentials', exact: true },
  { label: 'My Applications', path: '/my-applications' },
  { label: 'My Documents', path: '/my-documents' },
  { label: 'Profile', path: '/profile' },
];

/**
 * Public navigation tabs (not logged in)
 * Only show Home - the Login button in the nav bar handles authentication
 */
const PUBLIC_TABS = [
  { label: 'Home', path: '/', exact: true },
];

function Navigation() {
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
          {tabs.map((tab, index) => (
            <Tab 
              key={tab.path} 
              label={tab.label} 
              component={Link} 
              to={tab.path}
              data-testid={`nav-tab-${tab.label.toLowerCase().replace(/\s+/g, '-')}`}
            />
          ))}
        </Tabs>
      </Box>
    </Box>
  );
}

export default Navigation;
