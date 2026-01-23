/**
 * Auth Callback Component
 *
 * Handles the OIDC callback after Keycloak authentication.
 * Processes the authorization code and redirects to the intended page.
 */

import React, { useEffect, useState } from 'react';
import { useNavigate, useLocation, useSearchParams } from 'react-router-dom';
import { Box, CircularProgress, Typography, Alert } from '@mui/material';
import { useAuth } from '../hooks/useAuth';

function AuthCallback() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const { refreshUser } = useAuth();
  const [error, setError] = useState(null);

  useEffect(() => {
    const handleCallback = async () => {
      // Check for error from Keycloak
      const errorParam = searchParams.get('error');
      const errorDescription = searchParams.get('error_description');

      if (errorParam) {
        setError(errorDescription || errorParam);
        return;
      }

      // Check for authorization code
      const code = searchParams.get('code');
      const state = searchParams.get('state');

      if (!code) {
        setError('No authorization code received');
        return;
      }

      try {
        // Exchange code for tokens via backend
        // The backend /auth/callback endpoint handles the token exchange
        const response = await fetch(
          `/api/auth/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state || '')}`,
          {
            method: 'GET',
            credentials: 'include',
          }
        );

        if (!response.ok) {
          const data = await response.json().catch(() => ({}));
          throw new Error(data.detail || 'Authentication failed');
        }

        // Refresh the user state
        await refreshUser();

        // Get the intended destination from state or default to home
        // The state parameter may contain the original URL
        let redirectTo = '/';
        if (state) {
          try {
            const stateData = JSON.parse(atob(state));
            if (stateData.returnTo) {
              redirectTo = stateData.returnTo;
            }
          } catch {
            // State wasn't our encoded data, ignore
          }
        }

        navigate(redirectTo, { replace: true });
      } catch (err) {
        console.error('Auth callback error:', err);
        setError(err.message || 'Authentication failed');
      }
    };

    handleCallback();
  }, [searchParams, navigate, refreshUser]);

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
