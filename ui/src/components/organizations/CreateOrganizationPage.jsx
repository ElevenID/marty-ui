import { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Alert, Box, Button, CircularProgress, Container, Paper, Typography } from '@mui/material';

import { createOrganization, getErrorMessage } from '../../services/organizationsApi';
import { useConsole } from '../../contexts/ConsoleContext';
import OrgConsoleUnavailable from '../console/OrgConsoleUnavailable';
import CreateOrganizationForm from './CreateOrganizationForm';
import { ENABLE_ORGANIZATION_CREATION } from '@ui-public-config';

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
  const returnTo = searchParams.get('returnTo');

  const handleCreateOrganization = async (payload) => {
    if (!ENABLE_ORGANIZATION_CREATION) {
      setError('Organization creation is disabled for this deployment.');
      return;
    }

    setSubmitting(true);
    setError(null);

    try {
      const organizationResponse = await createOrganization(payload);
      const organization = normalizeCreatedOrganization(organizationResponse);

      const refreshedMemberships = await refreshMemberships?.();
      const membershipsForSelection = includeCreatedOrganization(refreshedMemberships, organization);

      if (organization?.id) {
        await setActiveOrgId?.(organization.id, membershipsForSelection);
      }

      navigate(returnTo || '/console/org');
    } catch (err) {
      logCreateOrgError('[CreateOrganizationPage] Failed to create organization:', err);
      setError(formatCreateOrganizationError(err));
    } finally {
      setSubmitting(false);
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

  if (!ENABLE_ORGANIZATION_CREATION) {
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
