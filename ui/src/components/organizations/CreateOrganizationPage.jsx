import { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Box, Container, Paper, Typography } from '@mui/material';

import { createOrganization } from '../../services/organizationsApi';
import { useConsole } from '../../contexts/ConsoleContext';
import CreateOrganizationForm from './CreateOrganizationForm';

function CreateOrganizationPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { refreshMemberships, setActiveOrgId } = useConsole();
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const returnTo = searchParams.get('returnTo');

  const handleCreateOrganization = async (payload) => {
    setSubmitting(true);
    setError(null);

    try {
      const organization = await createOrganization(payload);

      await refreshMemberships?.();

      if (organization?.id) {
        await setActiveOrgId?.(organization.id);
      }

      navigate(returnTo || '/console/org');
    } catch (err) {
      console.error('[CreateOrganizationPage] Failed to create organization:', err);
      setError(err?.message || 'Failed to create organization');
    } finally {
      setSubmitting(false);
    }
  };

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