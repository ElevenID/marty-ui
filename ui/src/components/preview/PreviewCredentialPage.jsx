/**
 * Preview Credential Page
 * 
 * Shows the credential detail view that applicants see before applying.
 */

import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { PreviewProvider, usePreview } from '../../contexts/PreviewContext';
import { Box, Container, Paper, Typography, CircularProgress, Alert } from '@mui/material';
import PreviewNotFound from './PreviewNotFound';

const API_URL = import.meta.env.VITE_API_URL || '';

function PreviewCredentialContent() {
  const { templateId } = useParams();
  const { updateContextLabel } = usePreview();
  const [template, setTemplate] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchTemplate = async () => {
      try {
        // Fetch template with preview flag to get applicant-ready data
        const response = await fetch(
          `${API_URL}/api/credential-templates/${templateId}?preview=true`,
          { credentials: 'include' }
        );

        if (!response.ok) {
          throw new Error('Template not found');
        }

        const data = await response.json();
        setTemplate(data);
        updateContextLabel(`Credential: ${data.name || data.credential_type || 'Unknown'}`);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchTemplate();
  }, [templateId, updateContextLabel]);

  if (loading) {
    return (
      <Container maxWidth="md" sx={{ py: 4, textAlign: 'center' }}>
        <CircularProgress />
        <Typography sx={{ mt: 2 }}>Loading credential preview...</Typography>
      </Container>
    );
  }

  if (error) {
    return (
      <PreviewNotFound 
        resourceType="credential" 
        returnUrl="/console/org/templates/credentials"
      />
    );
  }

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Paper elevation={2} sx={{ p: 4 }}>
        <Typography variant="h4" gutterBottom>
          {template?.name || template?.credential_type || 'Credential'}
        </Typography>
        <Typography variant="body1" color="text.secondary" paragraph>
          {template?.description || 'No description available.'}
        </Typography>

        {/* Check for incomplete/draft state */}
        {template?.status === 'draft' && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            <strong>Draft Status:</strong> This credential template is in draft status and has not been published. 
            The applicant experience may differ when published.
          </Alert>
        )}

        {(!template?.required_fields || template.required_fields.length === 0) &&
          (!template?.optional_fields || template.optional_fields.length === 0) && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            <strong>Missing Configuration:</strong> This template has no configured fields. 
            Complete the template configuration before publishing.
          </Alert>
        )}

        {!template?.hasArtifacts && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            <strong>Missing Artifacts:</strong> Required artifacts (schemas, proofs) are not configured. 
            The applicant will not be able to complete applications until these are added.
          </Alert>
        )}

        <Typography variant="h6" sx={{ mt: 3, mb: 2 }}>
          Required Information
        </Typography>
        {template?.required_fields?.length > 0 ? (
          <Box component="ul" sx={{ pl: 3 }}>
            {template.required_fields.map((field) => (
              <Typography component="li" key={field} variant="body2">
                {field.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase())}
              </Typography>
            ))}
          </Box>
        ) : (
          <Typography variant="body2" color="text.secondary">
            No specific requirements configured.
          </Typography>
        )}
      </Paper>
    </Container>
  );
}

function PreviewCredentialPage() {
  const { templateId } = useParams();

  return (
    <PreviewProvider 
      resourceType="credential" 
      resourceId={templateId}
      returnUrl="/console/org/templates/credentials"
    >
      <PreviewCredentialContent />
    </PreviewProvider>
  );
}

export default PreviewCredentialPage;
