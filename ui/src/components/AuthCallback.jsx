/**
 * Auth Callback Component
 *
 * Handles the OIDC callback after Keycloak authentication.
 * Processes the authorization code and redirects to the intended page.
 */

import { useEffect, useState } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router';
import { Box, CircularProgress, Typography, Alert } from '@mui/material';
import { useAuth } from '../hooks/useAuth';
import { useConsole, getDefaultLandingPath } from '../contexts/ConsoleContext';
import {
  getAuthCallbackCodeState,
  getAuthCallbackErrorFromParams,
  resolveAuthCallbackRedirect,
} from '../application/routing/authCallback';
import { redirectBrowser, shouldBrowserRedirect } from '../application/routing/appHandoff';

function AuthCallback() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const { completeLoginCallback, user, isAuthenticated, isLoading: authLoading } = useAuth();
  const consoleContext = useConsole();
  const [error, setError] = useState(null);
  const [completed, setCompleted] = useState(null);
  const callbackKey = searchParams.toString();
  const principalId = user?.user_id || user?.sub || user?.id;

  useEffect(() => {
    let cancelled = false;
    setError(null);
    setCompleted(null);
    const handleCallback = async () => {
      const params = new URLSearchParams(callbackKey);
      const parameterError = getAuthCallbackErrorFromParams(params);
      if (parameterError) {
        setError(parameterError);
        return;
      }
      try {
        const { code, state } = getAuthCallbackCodeState(params);
        const result = await completeLoginCallback({ code, state, routeKey: location.key });
        if (!cancelled) setCompleted({ ...result, callbackKey, routeKey: location.key, state });
      } catch (error) {
        if (!cancelled) {
          setError(error?.name === 'AbortError'
            ? 'Authentication changed before sign-in completed. Please sign in again.'
            : error?.message || 'Authentication failed');
        }
      }
    };

    handleCallback();
    return () => {
      cancelled = true;
    };
  }, [callbackKey, completeLoginCallback, location.key]);

  // Use the replacement session's current memberships and preferences. A
  // captured console value cannot observe the provider finishing its bootstrap.
  useEffect(() => {
    if (!completed || completed.callbackKey !== callbackKey || completed.routeKey !== location.key
      || authLoading || consoleContext.isLoading) return;
    if (!isAuthenticated || completed.principalId !== principalId) {
      setError('Authentication changed before sign-in completed. Please sign in again.');
      return;
    }
    const destination = resolveAuthCallbackRedirect({
      state: completed.state, consoleContext, getDefaultLandingPath,
    });
    if (shouldBrowserRedirect({ currentPathname: location.pathname, destination })) {
      redirectBrowser(destination);
      return;
    }
    navigate(destination, { replace: true });
  }, [completed, callbackKey, location.key, location.pathname, authLoading, isAuthenticated,
    principalId, consoleContext, navigate]);

  if (error) {
    return (
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          minHeight: '50vh',
        }}
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
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '50vh',
      }}
    >
      <CircularProgress size={48} />
      <Typography variant="body1" color="textSecondary" sx={{ mt: 2 }}>
        Completing authentication...
      </Typography>
    </Box>
  );
}

export default AuthCallback;
