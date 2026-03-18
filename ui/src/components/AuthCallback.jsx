/**
 * Auth Callback Component
 *
 * Handles the OIDC callback after Keycloak authentication.
 * Processes the authorization code and redirects to the intended page.
 */

import { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Box, CircularProgress, Typography, Alert } from '@mui/material';
import { useAuth } from '../hooks/useAuth';
import { useConsole, getDefaultLandingPath } from '../contexts/ConsoleContext';
import { completeAuthCallback } from '../application/routing';

function AuthCallback() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { refreshUser } = useAuth();
  const consoleContext = useConsole();
  const [error, setError] = useState(null);

  useEffect(() => {
    const handleCallback = async () => {
      const result = await completeAuthCallback({
        searchParams,
        refreshUser,
        consoleContext,
        getDefaultLandingPath,
      });

      if (result.error) {
        console.error('Auth callback error:', result.error);
        setError(result.error);
        return;
      }

      navigate(result.redirectTo, { replace: true });
    };

    handleCallback();
  }, [searchParams, navigate, refreshUser, consoleContext]);

  if (error) {
    return (
      <Box
        display="flex"
        flexDirection="column"
        alignItems="center"
        justifyContent="center"
        minHeight="50vh"
      >
        <Alert severity="error" sx={{ maxWidth: 400 }}>
          <Typography variant="h6" gutterBottom>
            Authentication Error
          </Typography>
          <Typography variant="body2">{error}</Typography>
        </Alert>
      </Box>
    );
  }

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
        Completing authentication...
      </Typography>
    </Box>
  );
}

export default AuthCallback;
