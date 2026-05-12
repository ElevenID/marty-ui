/**
 * Login Page Component
 *
 * Landing page for authentication. Redirects already-authenticated users.
 */

import { useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Box,
  CircularProgress,
} from '@mui/material';
import { useAuth } from '../hooks/useAuth';
import { getLoginEntryDecision, getLoginEntryRedirect } from '../application/routing';
import { redirectBrowser, shouldBrowserRedirect } from '../application/routing/appHandoff';

function LoginPage({ fallbackRedirectTo = '/' }) {
  const { isAuthenticated, isLoading, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const redirectTo = getLoginEntryRedirect(location.state, fallbackRedirectTo);

  useEffect(() => {
    const decision = getLoginEntryDecision({
      isAuthenticated,
      isLoading,
      redirectTo,
    });

    if (decision.action === 'navigate' && decision.redirectTo) {
      if (shouldBrowserRedirect({ currentPathname: location.pathname, destination: decision.redirectTo })) {
        redirectBrowser(decision.redirectTo);
        return;
      }

      navigate(decision.redirectTo, { replace: true });
      return;
    }

    if (decision.action === 'login') {
      login(redirectTo);
    }
  }, [isAuthenticated, isLoading, location.pathname, login, navigate, redirectTo]);

  // Show a neutral loading state while auth is checked or SSO redirect is in progress
  return (
    <Box
      display="flex"
      flexDirection="column"
      alignItems="center"
      justifyContent="center"
      minHeight="50vh"
      data-testid="login-page"
    >
      <CircularProgress size={48} />
    </Box>
  );
}

export default LoginPage;
