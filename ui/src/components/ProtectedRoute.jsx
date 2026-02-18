/**
 * ProtectedRoute Component
 *
 * Route guard that restricts access based on authentication and capabilities.
 * Redirects to login if not authenticated, or to home if unauthorized.
 */

import { Navigate, useLocation } from 'react-router-dom';
import { CircularProgress, Box, Typography } from '@mui/material';
import { useAuth } from '../hooks/useAuth';
import { useConsole } from '../contexts/ConsoleContext';

/**
 * Protected Route wrapper
 *
 * @param {Object} props
 * @param {React.ReactNode} props.children - Child components to render if authorized
 * @param {string[]} [props.requiredCapabilities] - Required capabilities
 * @param {boolean} [props.requireAllCapabilities=false] - Require all capabilities instead of any
 * @param {string} [props.redirectTo='/login'] - Where to redirect if not authenticated
 * @param {string} [props.unauthorizedRedirect='/'] - Where to redirect if unauthorized
 *
 * @example
 * // Require any authenticated user
 * <ProtectedRoute>
 *   <Dashboard />
 * </ProtectedRoute>
 *
 * @example
 * // Require platform admin capability
 * <ProtectedRoute requiredCapabilities={['admin:platform']}>
 *   <AdminPanel />
 * </ProtectedRoute>
 */
function ProtectedRoute({
  children,
  requiredCapabilities = null,
  requireAllCapabilities = false,
  redirectTo = '/login',
  unauthorizedRedirect = '/',
}) {
  const { isAuthenticated, isLoading, user, hasCapability } = useAuth();
  const location = useLocation();

  // Debug logging
  console.log('[ProtectedRoute] Rendering for path:', location.pathname);
  console.log('[ProtectedRoute] isLoading:', isLoading);
  console.log('[ProtectedRoute] isAuthenticated:', isAuthenticated);
  console.log('[ProtectedRoute] roles:', user?.roles, 'capabilities:', user?.capabilities);
  console.log('[ProtectedRoute] requiredCapabilities:', requiredCapabilities);

  // Show loading spinner while checking auth
  if (isLoading) {
    console.log('[ProtectedRoute] Showing loading spinner');
    return (
      <Box
        display="flex"
        flexDirection="column"
        alignItems="center"
        justifyContent="center"
        minHeight="50vh"
      >
        <CircularProgress size={48} />
        <Typography variant="body1" color="textSecondary" sx={{ mt: 2 }}>
          Checking authentication...
        </Typography>
      </Box>
    );
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    console.log('[ProtectedRoute] Not authenticated, redirecting to:', redirectTo);
    // Save the attempted URL for redirecting after login
    return <Navigate to={redirectTo} state={{ from: location }} replace />;
  }

  // Check capabilities when required
  if (requiredCapabilities && requiredCapabilities.length > 0) {
    const normalizedHasCapability = typeof hasCapability === 'function'
      ? hasCapability
      : (capability) => Boolean(user?.capabilities?.[capability]);

    const isAllowed = requireAllCapabilities
      ? requiredCapabilities.every((capability) => normalizedHasCapability(capability))
      : requiredCapabilities.some((capability) => normalizedHasCapability(capability));

    console.log('[ProtectedRoute] isAllowed:', isAllowed, 'for capabilities:', requiredCapabilities);

    if (!isAllowed) {
      console.log('[ProtectedRoute] Not allowed, redirecting to:', unauthorizedRedirect);
      // User is authenticated but unauthorized
      return <Navigate to={unauthorizedRedirect} replace />;
    }
  }

  // User is authenticated and authorized
  console.log('[ProtectedRoute] Authorized, rendering children');
  return children;
}

/**
 * Admin-only route shorthand
 */
export function AdminRoute({ children, ...props }) {
  return (
    <ProtectedRoute requiredCapabilities={['admin:platform']} {...props}>
      {children}
    </ProtectedRoute>
  );
}

/**
 * Applicant route shorthand
 * Every authenticated person can access applicant capabilities.
 */
export function ApplicantRoute({ children, ...props }) {
  return (
    <ProtectedRoute {...props}>
      {children}
    </ProtectedRoute>
  );
}

/**
 * Applicant console route with membership guard
 * Applicant console should remain accessible even without org memberships.
 */
export function ApplicantConsoleRoute({ children, ...props }) {
  const { isLoading: consoleLoading } = useConsole();

  if (consoleLoading) {
    return (
      <Box
        display="flex"
        flexDirection="column"
        alignItems="center"
        justifyContent="center"
        minHeight="50vh"
      >
        <CircularProgress size={48} />
        <Typography variant="body1" color="textSecondary" sx={{ mt: 2 }}>
          Loading console...
        </Typography>
      </Box>
    );
  }

  return (
    <ProtectedRoute {...props}>
      {children}
    </ProtectedRoute>
  );
}

/**
 * Organization console route shorthand
 * Requires org visibility capability.
 */
export function VendorRoute({ children, ...props }) {
  return (
    <ProtectedRoute requiredCapabilities={['org:view']} {...props}>
      {children}
    </ProtectedRoute>
  );
}

/**
 * Organization console route with org selection guard
 * Requires org:view capability AND an active organization to be selected.
 * Redirects to /console/org/setup if no org is selected.
 */
export function OrgConsoleRoute({ children, ...props }) {
  const { mode, activeOrgId, isLoading: consoleLoading } = useConsole();
  const location = useLocation();

  // Show loading while console context initializes
  if (consoleLoading) {
    return (
      <Box
        display="flex"
        flexDirection="column"
        alignItems="center"
        justifyContent="center"
        minHeight="50vh"
      >
        <CircularProgress size={48} />
        <Typography variant="body1" color="textSecondary" sx={{ mt: 2 }}>
          Loading console...
        </Typography>
      </Box>
    );
  }

  // If in org mode but no org selected, redirect to setup
  if (mode === 'org' && !activeOrgId) {
    console.log('[OrgConsoleRoute] No org selected, redirecting to setup');
    return <Navigate to="/console/org/setup" state={{ from: location }} replace />;
  }

  // Otherwise, apply standard protected route check with org:view capability
  return (
    <ProtectedRoute requiredCapabilities={['org:view']} {...props}>
      {children}
    </ProtectedRoute>
  );
}

export default ProtectedRoute;
