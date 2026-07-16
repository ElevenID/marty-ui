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
import OrgConsoleUnavailable from './console/OrgConsoleUnavailable';
import {
  evaluateApplicantConsolePolicy,
  evaluateOrgConsolePolicy,
  evaluateProtectedRoutePolicy,
} from '../application/routing';

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
      <Typography variant="body1" color="textSecondary" sx={{ mt: 2 }}>
        {message}
      </Typography>
    </Box>
  );
}

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
  const decision = evaluateProtectedRoutePolicy({
    isLoading,
    isAuthenticated,
    user,
    hasCapability,
    requiredCapabilities,
    requireAllCapabilities,
    redirectTo,
    unauthorizedRedirect,
  });

  // Show loading spinner while checking auth
  if (decision.kind === 'loading') {
    return <GuardLoadingState message="Checking authentication..." />;
  }

  // Redirect to login if not authenticated
  if (decision.kind === 'redirect' && decision.reason === 'unauthenticated') {
    // Save the attempted URL for redirecting after login
    return <Navigate to={decision.destination} state={{ from: location }} replace />;
  }

  // Check capabilities when required
  if (decision.kind === 'redirect' && decision.reason === 'unauthorized') {
    // User is authenticated but unauthorized
    return <Navigate to={decision.destination} replace />;
  }

  // User is authenticated and authorized
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
  const {
    isLoading: consoleLoading,
    membershipLoadError,
    isOrgBootstrapRequired,
    reloadConsoleState,
  } = useConsole();
  const decision = evaluateApplicantConsolePolicy({ consoleLoading });

  if (decision.kind === 'loading') {
    return <GuardLoadingState message="Loading console..." />;
  }

  if (membershipLoadError && isOrgBootstrapRequired) {
    return <OrgConsoleUnavailable error={membershipLoadError} onRetry={reloadConsoleState} />;
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
  const {
    mode,
    activeOrgId,
    isLoading: consoleLoading,
    membershipLoadError,
    isOrgBootstrapRequired,
    reloadConsoleState,
  } = useConsole();
  const location = useLocation();
  const decision = evaluateOrgConsolePolicy({
    consoleLoading,
    mode,
    activeOrgId,
  });

  // Show loading while console context initializes
  if (decision.kind === 'loading') {
    return <GuardLoadingState message="Loading console..." />;
  }

  if (membershipLoadError && isOrgBootstrapRequired) {
    return <OrgConsoleUnavailable error={membershipLoadError} onRetry={reloadConsoleState} />;
  }

  // If in org mode but no org selected, redirect to setup
  if (decision.kind === 'redirect' && decision.reason === 'missing-org-selection') {
    return <Navigate to={decision.destination} state={{ from: location }} replace />;
  }

  // Otherwise, apply standard protected route check with org:view capability
  return (
    <ProtectedRoute requiredCapabilities={['org:view']} unauthorizedRedirect="/console/applicant/catalog" {...props}>
      {children}
    </ProtectedRoute>
  );
}

export default ProtectedRoute;
