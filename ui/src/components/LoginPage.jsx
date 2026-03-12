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

function LoginPage() {
  const { isAuthenticated, isLoading, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  // Get the intended destination from state, default to home
  const from = location.state?.from?.pathname || '/';

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated && !isLoading) {
      navigate(from, { replace: true });
    }
  }, [isAuthenticated, isLoading, navigate, from]);

  // Immediately trigger SSO login for unauthenticated users
  useEffect(() => {
    if (!isAuthenticated && !isLoading) {
      login();
    }
  }, [isAuthenticated, isLoading, login]);

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
