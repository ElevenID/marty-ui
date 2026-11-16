import { useLayoutEffect, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router';
import { Alert, Box, Button, CircularProgress, Container, Paper, Typography } from '@mui/material';

import { createOrganization, getErrorMessage } from '../../services/organizationsApi';
import { useConsole } from '../../contexts/ConsoleContext';
import OrgConsoleUnavailable from '../console/OrgConsoleUnavailable';
import CreateOrganizationForm from './CreateOrganizationForm';
import { ENABLE_ORGANIZATION_CREATION } from '@ui-public-config';
import { isOrganizationCreationEnabled } from '../../utils/runtimeConfig';

const SHOULD_LOG_CREATE_ORG_DIAGNOSTICS = import.meta.env.DEV && import.meta.env.MODE !== 'test';

function logCreateOrgError(...args) {
  if (SHOULD_LOG_CREATE_ORG_DIAGNOSTICS) {
    console.error(...args);
  }
}

function getMessageId(error) {
  return error?.response?.message_id
    || error?.response?.request_id
    || error?.requestId
    || null;
}

function formatCreateOrganizationError(error) {
  const messageId = getMessageId(error);
  const detail = error?.response?.error_description
    || error?.response?.error?.message
    || error?.message
    || '';
  const disabledByBackend = error?.status === 403 && detail.toLowerCase().includes('disabled');
  const message = disabledByBackend
    ? 'Organization creation is disabled by this deployment configuration.'
    : getErrorMessage(error) || 'Failed to create organization';

  return messageId ? `${message} Message ID: ${messageId}` : message;
}

function normalizeCreatedOrganization(response) {
  const organization = response?.organization || response;
  if (!organization) {
    return null;
  }

  const id = organization.id || organization.organization_id;
  if (!id) {
    return null;
  }

  return {
    ...organization,
    id,
    name: organization.name || organization.display_name || organization.displayName || null,
    display_name: organization.display_name || organization.displayName || organization.name || null,
    membership: organization.membership || response?.membership || null,
  };
}

function includeCreatedOrganization(memberships, createdOrganization) {
  if (!createdOrganization?.id) {
    return memberships;
  }

  const safeMemberships = Array.isArray(memberships) ? memberships : [];
  if (safeMemberships.some((organization) => organization.id === createdOrganization.id)) {
    return safeMemberships;
  }

  return [...safeMemberships, createdOrganization];
}

function CreateOrganizationPage() {
  const organizationCreationEnabled = isOrganizationCreationEnabled(ENABLE_ORGANIZATION_CREATION);
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const {
    refreshMemberships,
    setActiveOrgId,
    membershipLoadError,
    isOrgBootstrapRequired,
    isLoading: consoleLoading,
    reloadConsoleState,
  } = useConsole();
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const active = useRef(false);
  const requestGeneration = useRef(0);
  useLayoutEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
      requestGeneration.current += 1;
    };
  }, []);
  const returnTo = searchParams.get('returnTo');

  const handleCreateOrganization = async (payload) => {
    if (!active.current) return;
    if (!organizationCreationEnabled) {
      setError('Organization creation is disabled for this deployment.');
      return;
    }

    setSubmitting(true);
    setError(null);
    const generation = ++requestGeneration.current;
    const applies = () => active.current && requestGeneration.current === generation;

    try {
      const organizationResponse = await createOrganization(payload);
      if (!applies()) return;
      const organization = normalizeCreatedOrganization(organizationResponse);

      const refreshedMemberships = await refreshMemberships?.();
      if (!applies()) return;
      const membershipsForSelection = includeCreatedOrganization(refreshedMemberships, organization);

      if (organization?.id) {
        // This action owns returnTo; avoid a competing central navigation that
        // would unmount the form before its guarded final handoff.
        await setActiveOrgId?.(organization.id, membershipsForSelection, { navigate: false });
      }

      if (applies()) navigate(returnTo || '/console/org');
    } catch (err) {
      if (!applies() || err?.name === 'AbortError') return;
      logCreateOrgError('[CreateOrganizationPage] Failed to create organization:', err);
      setError(formatCreateOrganizationError(err));
    } finally {
      if (applies()) setSubmitting(false);
    }
  };

  if (consoleLoading && isOrgBootstrapRequired) {
    return (
      <Box
        display="flex"
        flexDirection="column"
        alignItems="center"
        justifyContent="center"
        minHeight="50vh"
      >
        <CircularProgress size={48} />
        <Typography variant="body1" color="text.secondary" sx={{ mt: 2 }}>
          Loading organization access...
        </Typography>
      </Box>
    );
  }

  if (membershipLoadError && isOrgBootstrapRequired) {
    return <OrgConsoleUnavailable error={membershipLoadError} onRetry={reloadConsoleState} />;
  }

  if (!organizationCreationEnabled) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Box sx={{ mb: 3 }}>
          <Typography variant="h4" gutterBottom fontWeight={600}>
            Organization creation is disabled
          </Typography>
          <Typography variant="body1" color="text.secondary">
            This deployment uses managed organization membership. Join an existing organization or contact an administrator for access.
          </Typography>
        </Box>

        <Paper sx={{ p: 3 }}>
          <Alert severity="info" sx={{ mb: 3 }}>
            New organizations cannot be created from this self-hosted production console.
          </Alert>
          <Button variant="contained" onClick={() => navigate('/console/organizations')}>
            Back to organizations
          </Button>
        </Paper>
      </Container>
    );
  }

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h4" gutterBottom fontWeight={600}>
          Create an Organization
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Create a workspace for issuing credentials, managing applicants, and configuring membership access.
        </Typography>
      </Box>

      <Paper sx={{ p: 3 }}>
        <CreateOrganizationForm
          error={error}
          submitting={submitting}
          onSubmit={handleCreateOrganization}
          onCancel={() => navigate('/console/organizations')}
          submitLabel="Create Organization"
        />
      </Paper>
    </Container>
  );
}

export default CreateOrganizationPage;
