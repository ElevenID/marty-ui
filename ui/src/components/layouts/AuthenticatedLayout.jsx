/**
 * AuthenticatedLayout Component
 * 
 * Layout wrapper for authenticated users with sidebar navigation.
 * Handles responsive behavior and role-based layout differences.
 */

import { useState } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { Box, Button, Alert, Typography, useTheme, useMediaQuery } from '@mui/material';
import { SidebarNavigation } from '../navigation/index.js';
import { ConsoleHeaderBar } from '../navigation/ConsoleHeaderBar';
import { useAuth } from '../../hooks/useAuth';
import ErrorBoundary from '../ErrorBoundary';

const HEADER_HEIGHT = 64;

function ConsoleContentFallback({ error, onRetry }) {
  return (
    <Box sx={{ py: 2 }}>
      <Alert
        severity="error"
        sx={{ mb: 2 }}
        action={
          <Button color="inherit" size="small" onClick={onRetry}>
            Retry
          </Button>
        }
      >
        This page hit an unexpected error. You can retry or continue using sidebar navigation.
      </Alert>
      {import.meta.env.DEV && error && (
        <Typography
          variant="body2"
          color="text.secondary"
          sx={{ fontFamily: 'monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}
        >
          {String(error)}
        </Typography>
      )}
    </Box>
  );
}

/**
 * Main layout for authenticated users
 * Renders header bar + sidebar + main content area
 * Uses Outlet for nested routes or children for direct rendering
 */
function AuthenticatedLayout({ children }) {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const { isAdministrator, isVendor, isApplicant } = useAuth();
  const location = useLocation();

  // Mobile drawer state
  const [mobileOpen, setMobileOpen] = useState(false);

  const handleMobileToggle = () => {
    setMobileOpen(!mobileOpen);
  };

  const handleMobileClose = () => {
    setMobileOpen(false);
  };

  // Determine if we should show sidebar (Admin/Vendor get full sidebar, Applicant gets simpler nav)
  const showSidebar = isAdministrator || isVendor || isApplicant;

  if (!showSidebar) {
    // Fallback for unauthenticated or unknown role
    return <Box sx={{ p: 3 }}>{children || <Outlet />}</Box>;
  }

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      {/* Top Header Bar */}
      <ConsoleHeaderBar onMobileMenuToggle={handleMobileToggle} />

      {/* Main content area below header */}
      <Box sx={{ display: 'flex', flexGrow: 1, minWidth: 0, width: '100%', pt: `${HEADER_HEIGHT}px` }}>
        {/* Sidebar Navigation */}
        <SidebarNavigation 
          mobileOpen={mobileOpen} 
          onMobileClose={handleMobileClose} 
        />

        {/* Main Content Area */}
        <Box
          component="main"
          sx={{
            flexGrow: 1,
            minWidth: 0,
            width: '100%',
            p: { xs: 2, sm: 3 },
            minHeight: '100%',
            bgcolor: 'background.default',
          }}
        >
          <ErrorBoundary key={location.pathname} FallbackComponent={ConsoleContentFallback}>
            {children || <Outlet />}
          </ErrorBoundary>
        </Box>
      </Box>
    </Box>
  );
}

export default AuthenticatedLayout;
