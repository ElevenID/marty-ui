/**
 * ProtectedRoute Component
 *
 * Route guard that restricts access based on authentication and user type.
 * Redirects to login if not authenticated, or to home if wrong user type.
 */

import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { CircularProgress, Box, Typography } from '@mui/material';
import { useAuth } from '../hooks/useAuth';

/**
 * Protected Route wrapper
 *
 * @param {Object} props
 * @param {React.ReactNode} props.children - Child components to render if authorized
 * @param {string[]} [props.allowedTypes] - Allowed user types (e.g., ['administrator', 'applicant'])
 * @param {string} [props.redirectTo='/login'] - Where to redirect if not authenticated
 * @param {string} [props.unauthorizedRedirect='/'] - Where to redirect if wrong user type
 *
 * @example
 * // Require any authenticated user
 * <ProtectedRoute>
 *   <Dashboard />
 * </ProtectedRoute>
 *
 * @example
 * // Require administrator only
 * <ProtectedRoute allowedTypes={['administrator']}>
 *   <AdminPanel />
 * </ProtectedRoute>
 */
function ProtectedRoute({
  children,
  allowedTypes = null,
  redirectTo = '/login',
  unauthorizedRedirect = '/',
}) {
  const { isAuthenticated, isLoading, checkingOnboarding, user } = useAuth();
  const location = useLocation();

  // Show loading spinner while checking auth or onboarding
  if (isLoading || checkingOnboarding) {
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
    // Save the attempted URL for redirecting after login
    return <Navigate to={redirectTo} state={{ from: location }} replace />;
  }

  // Check user type if allowedTypes specified
  if (allowedTypes && allowedTypes.length > 0) {
    const userType = user?.user_type;

    if (!userType || !allowedTypes.includes(userType)) {
      // User is authenticated but wrong type
      return <Navigate to={unauthorizedRedirect} replace />;
    }
  }

  // User is authenticated and authorized
  return children;
}

/**
 * Admin-only route shorthand
 * Administrators bypass onboarding requirements
 */
export function AdminRoute({ children, ...props }) {
  return (
    <ProtectedRoute allowedTypes={['administrator']} {...props}>
      {children}
    </ProtectedRoute>
  );
}

/**
 * Applicant-only route shorthand
 * Redirects to onboarding if user needs to complete it
 */
export function ApplicantRoute({ children, ...props }) {
  const { user } = useAuth();
  const location = useLocation();

  // Redirect to onboarding if user needs to complete it
  if (user?.needsOnboarding && location.pathname !== '/onboarding') {
    return <Navigate to="/onboarding" replace />;
  }

  return (
    <ProtectedRoute allowedTypes={['applicant']} {...props}>
      {children}
    </ProtectedRoute>
  );
}

/**
 * Vendor-only route shorthand
 * Redirects to onboarding if user needs to complete it
 */
export function VendorRoute({ children, ...props }) {
  const { user } = useAuth();
  const location = useLocation();

  // Redirect to onboarding if user needs to complete it
  if (user?.needsOnboarding && location.pathname !== '/onboarding') {
    return <Navigate to="/onboarding" replace />;
  }

  return (
    <ProtectedRoute allowedTypes={['vendor']} {...props}>
      {children}
    </ProtectedRoute>
  );
}

export default ProtectedRoute;
