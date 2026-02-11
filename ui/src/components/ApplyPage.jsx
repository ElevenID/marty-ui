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
import { useParams, useSearchParams, useNavigate } from 'react-router-dom';
import { Box, CircularProgress, Typography, Container, Paper, Alert } from '@mui/material';
import { useAuth } from '../hooks/useAuth';

const ApplyPage = () => {
  const { credentialType } = useParams();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { user, isAuthenticated, loading: authLoading } = useAuth();

  useEffect(() => {
    if (authLoading) {
      // Still checking auth status
      return;
    }

    // Extract org_id from URL query params
    const orgId = searchParams.get('org_id');

    // Store context in session storage for post-login routing
    const context = {
      credentialType: credentialType || null,
      orgId: orgId || null,
      timestamp: Date.now(),
      returnUrl: window.location.pathname + window.location.search,
    };
    sessionStorage.setItem('applyContext', JSON.stringify(context));

    if (!isAuthenticated) {
      // Not authenticated - redirect to login
      // The context will be picked up after successful login via AuthCallback
      const loginUrl = `/login?return_to=${encodeURIComponent(window.location.pathname + window.location.search)}`;
      window.location.href = loginUrl;
      return;
    }

    // User is authenticated - route them appropriately

    // If org_id is specified and user isn't a member yet, go to onboarding with context
    if (orgId && user?.organization_id !== orgId) {
      // Store the join intent
      sessionStorage.setItem('joinOrgId', orgId);
      
      // If user hasn't completed onboarding, they'll be routed through onboarding flow
      if (user?.needsOnboarding) {
        navigate('/onboarding');
        return;
      }

      // If already onboarded, check if they need to join this specific org
      // For now, redirect to applicant dashboard with a notice
      navigate('/applicant?org_required=' + orgId);
      return;
    }

    // User is authenticated and in the right org (or no org specified)
    if (credentialType) {
      // Navigate to specific credential application
      navigate(`/credentials?type=${credentialType}`);
    } else {
      // No specific credential type - go to catalog
      navigate('/credentials');
    }
  }, [authLoading, isAuthenticated, user, credentialType, searchParams, navigate]);

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
