/**
 * Login Page Component
 *
 * Landing page for authentication. Redirects already-authenticated users.
 */

import React, { useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Box,
  Card,
  CardContent,
  Typography,
  Button,
  CircularProgress,
} from '@mui/material';
import LoginIcon from '@mui/icons-material/Login';
import { useAuth } from '../hooks/useAuth';
import { useBranding } from '../hooks/useBranding';

function LoginPage() {
  const branding = useBranding();
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

  if (isLoading) {
    return (
      <Box
        display="flex"
        flexDirection="column"
        alignItems="center"
        justifyContent="center"
        minHeight="50vh"
        data-testid="login-loading"
      >
        <CircularProgress size={48} />
        <Typography variant="body1" color="textSecondary" sx={{ mt: 2 }}>
          Checking authentication...
        </Typography>
      </Box>
    );
  }

  return (
    <Box
      display="flex"
      flexDirection="column"
      alignItems="center"
      justifyContent="center"
      minHeight="60vh"
      data-testid="login-page"
    >
      <Card sx={{ maxWidth: 400, width: '100%' }} data-testid="login-card">
        <CardContent sx={{ textAlign: 'center', py: 4 }}>
          <Typography variant="h4" component="h1" gutterBottom data-testid="login-title">
            Welcome to {branding.appName}
          </Typography>

          <Typography variant="body1" color="textSecondary" sx={{ mb: 4 }}>
            Sign in to access the Travel Document Trust Services portal.
          </Typography>

          <Box sx={{ mb: 3 }}>
            <Typography variant="body2" color="textSecondary">
              For <strong>Administrators</strong>: Manage travel documents, applicants, and system
              settings.
            </Typography>
            <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
              For <strong>Applicants</strong>: Submit applications and track your travel document
              status.
            </Typography>
          </Box>

          <Button
            variant="contained"
            size="large"
            startIcon={<LoginIcon />}
            onClick={() => login()}
            fullWidth
            sx={{ py: 1.5 }}
            data-testid="login-sso-btn"
          >
            Sign in with SSO
          </Button>

          <Typography variant="caption" color="textSecondary" sx={{ mt: 3, display: 'block' }}>
            Secured by Keycloak OpenID Connect
          </Typography>
        </CardContent>
      </Card>
    </Box>
  );
}

export default LoginPage;
