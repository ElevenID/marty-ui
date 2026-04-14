/**
 * AuthenticatedLayout Component
 * 
 * Layout wrapper for authenticated users with sidebar navigation.
 * Handles responsive behavior and role-based layout differences.
 */

import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Box, useTheme, useMediaQuery } from '@mui/material';
import { SidebarNavigation } from '../navigation/index.js';
import { ConsoleHeaderBar } from '../navigation/ConsoleHeaderBar';
import { useAuth } from '../../hooks/useAuth';

const DRAWER_WIDTH = 260;
const HEADER_HEIGHT = 64;

/**
 * Main layout for authenticated users
 * Renders header bar + sidebar + main content area
 * Uses Outlet for nested routes or children for direct rendering
 */
function AuthenticatedLayout({ children }) {
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('md'));
  const { isAdministrator, isVendor, isApplicant } = useAuth();

  // Debug logging
  console.log('[AuthenticatedLayout] Rendering');
  console.log('[AuthenticatedLayout] isAdministrator:', isAdministrator, 'isVendor:', isVendor, 'isApplicant:', isApplicant);

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
  console.log('[AuthenticatedLayout] showSidebar:', showSidebar);

  if (!showSidebar) {
    // Fallback for unauthenticated or unknown role
    console.log('[AuthenticatedLayout] No sidebar, rendering fallback');
    return <Box sx={{ p: 3 }}>{children || <Outlet />}</Box>;
  }

  console.log('[AuthenticatedLayout] Rendering main layout with sidebar');
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      {/* Top Header Bar */}
      <ConsoleHeaderBar onMobileMenuToggle={handleMobileToggle} />

      {/* Main content area below header */}
      <Box sx={{ display: 'flex', flexGrow: 1, pt: `${HEADER_HEIGHT}px` }}>
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
            p: 3,
            width: { md: `calc(100% - ${DRAWER_WIDTH}px)` },
            minHeight: '100%',
            bgcolor: 'background.default',
          }}
        >
          {children || <Outlet />}
        </Box>
      </Box>
    </Box>
  );
}

export default AuthenticatedLayout;
