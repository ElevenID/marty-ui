/**
 * ApplyPage - Deep Link Entry Point for Applicants
 * 
 * Handles direct links like:
 * - /apply
 * - /apply/mdl
 * - /apply/mdl?org_id=123
 * - /apply?org_id=123
 * 
 * This page:
 * 1. Checks authentication status
 * 2. Stores context (credential type, org_id) in session storage
 * 3. Redirects to login if not authenticated
 * 4. After login, auto-navigates to the application or org join flow
 */

import { useEffect } from 'react';
import { useParams, useSearchParams, useNavigate, useLocation } from 'react-router-dom';
import { Box, CircularProgress, Typography, Container, Paper, Alert } from '@mui/material';
import { useAuth } from '../hooks/useAuth';
import {
  APPLY_CONTEXT_STORAGE_KEY,
  getApplyEntryDecision,
} from '../application/routing';

const ApplyPage = () => {
  const { credentialType } = useParams();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const location = useLocation();
  const { user, isAuthenticated, isLoading: authLoading } = useAuth();

  useEffect(() => {
    if (authLoading) {
      return;
    }

    const orgId = searchParams.get('org_id');
    const decision = getApplyEntryDecision({
      isAuthenticated,
      user,
      credentialType,
      orgId,
      pathname: window.location.pathname,
      search: window.location.search,
      locationState: location.state,
    });

    sessionStorage.setItem(APPLY_CONTEXT_STORAGE_KEY, JSON.stringify(decision.context));
    Object.entries(decision.storage || {}).forEach(([key, value]) => {
      if (value !== null && value !== undefined) {
        sessionStorage.setItem(key, value);
      }
    });

    if (decision.kind === 'redirect-browser') {
      window.location.href = decision.loginUrl;
      return;
    }

    navigate(decision.destination, decision.navigationState ? { state: decision.navigationState } : undefined);
  }, [authLoading, isAuthenticated, user, credentialType, searchParams, navigate, location.state]);

  // Show loading state while checking auth or redirecting
  return (
    <Container maxWidth="sm" sx={{ mt: 8 }}>
      <Paper elevation={3} sx={{ p: 4 }}>
        <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3 }}>
          <CircularProgress size={60} />
          <Typography variant="h5" textAlign="center">
            Loading Application...
          </Typography>
          <Typography variant="body2" color="text.secondary" textAlign="center">
            {authLoading ? 'Checking authentication...' : 'Redirecting you...'}
          </Typography>
          
          {searchParams.get('org_id') && (
            <Alert severity="info" sx={{ width: '100%' }}>
              You&apos;ll be directed to join the organization before applying.
            </Alert>
          )}
        </Box>
      </Paper>
    </Container>
  );
};

export default ApplyPage;
