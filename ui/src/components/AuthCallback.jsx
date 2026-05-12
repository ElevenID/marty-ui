/**
 * Auth Callback Component
 *
 * Handles the OIDC callback after Keycloak authentication.
 * Processes the authorization code and redirects to the intended page.
 */

import { useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { Box, CircularProgress, Typography, Alert } from '@mui/material';
import { useAuth } from '../hooks/useAuth';
import { useConsole, getDefaultLandingPath } from '../contexts/ConsoleContext';
import { completeAuthCallback } from '../application/routing';
import { redirectBrowser, shouldBrowserRedirect } from '../application/routing/appHandoff';

function AuthCallback() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const { refreshUser } = useAuth();
  const consoleContext = useConsole();
  const [error, setError] = useState(null);
  const handledCallbackKeyRef = useRef(null);
  const callbackKey = searchParams.toString();

  useEffect(() => {
    if (handledCallbackKeyRef.current === callbackKey) {
      return undefined;
    }

    handledCallbackKeyRef.current = callbackKey;
    let cancelled = false;

    const handleCallback = async () => {
      const result = await completeAuthCallback({
        searchParams,
        refreshUser,
        consoleContext,
        getDefaultLandingPath,
      });

      if (cancelled) {
        return;
      }

      if (result.error) {
        console.error('Auth callback error:', result.error);
        setError(result.error);
        return;
      }

      if (shouldBrowserRedirect({ currentPathname: location.pathname, destination: result.redirectTo })) {
        redirectBrowser(result.redirectTo);
        return;
      }

      navigate(result.redirectTo, { replace: true });
    };

    handleCallback();
    return () => {
      cancelled = true;
    };
  }, [callbackKey, searchParams, navigate, refreshUser, consoleContext, location.pathname]);

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
