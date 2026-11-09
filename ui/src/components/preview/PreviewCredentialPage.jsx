/**
 * Preview Credential Page
 * 
 * Shows the credential detail view that applicants see before applying.
 */

import { useEffect, useState } from 'react';
import { useLocation, useParams, useSearchParams } from 'react-router';
import { useAuth } from '../../hooks/useAuth';
import { useAsyncActionScope } from '../../hooks/useAsyncActionScope';
import { PreviewProvider, usePreview } from '../../contexts/PreviewContext';
import { Box, Container, Paper, Typography, CircularProgress, Alert } from '@mui/material';
import PreviewNotFound from './PreviewNotFound';
import { fetchPreviewCredentialTemplate } from '../../application/vendor';

function PreviewCredentialContent({ templateId, organizationId }) {
  const { updateContextLabel } = usePreview();
  const beginLoad = useAsyncActionScope();
  const [loaded, setLoaded] = useState(null);

  useEffect(() => {
    const action = beginLoad();
    (async () => {
      try {
        const template = await action.run(fetchPreviewCredentialTemplate, { templateId });
        if (template?.id !== templateId || !template.organization_id
          || (organizationId != null && template.organization_id !== organizationId)) {
          throw new Error('This Credential Template is not available in the selected organization.');
        }
        updateContextLabel(`Credential: ${template.name || template.credential_type || 'Unknown'}`);
        setLoaded({ template });
      } catch (error) {
        if (action.isCurrent()) setLoaded({ error });
      }
    })();
  }, [beginLoad, templateId, organizationId, updateContextLabel]);

  if (!loaded) {
    return (
      <Container maxWidth="md" sx={{ py: 4, textAlign: 'center' }}>
        <CircularProgress />
        <Typography sx={{ mt: 2 }}>Loading credential preview...</Typography>
      </Container>
    );
  }

  if (loaded.error?.status === 404) {
    return (
      <PreviewNotFound 
        resourceType="credential" 
        returnUrl="/console/org/templates/credentials"
      />
    );
  }
  if (loaded.error) {
    return <Container maxWidth="md" sx={{ py: 4 }}>
      <Alert severity="error">{loaded.error.message || 'Credential preview could not be loaded.'}</Alert>
    </Container>;
  }

  const { template } = loaded;
  const status = String(template.status || '').toUpperCase();
  const claims = Array.isArray(template.claims)
    ? template.claims.filter((claim) => typeof claim?.name === 'string' && claim.name)
    : [];
  const requiredClaims = claims.filter((claim) => claim.required === true);
  const optionalClaims = claims.filter((claim) => claim.required !== true);
  const claimLabel = (claim) => claim.display?.label || claim.name.replace(/_/g, ' ').replace(/\b\w/g, (letter) => letter.toUpperCase());

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Paper elevation={2} sx={{ p: 4 }}>
        <Typography variant="h4" gutterBottom>
          {template?.name || template?.credential_type || 'Credential'}
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
          {template?.description || 'No description available.'}
        </Typography>

        {/* Check for incomplete/draft state */}
        {status === 'DRAFT' && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            <strong>Draft Status:</strong> This credential template is in draft status and has not been published. 
            The applicant experience may differ when published.
          </Alert>
        )}
        {['DEPRECATED', 'ARCHIVED'].includes(status) && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            <strong>{status}:</strong> This credential template is no longer active. Its preview shows the saved configuration.
          </Alert>
        )}

        {claims.length === 0 && (
          <Alert severity="warning" sx={{ mb: 2 }}>
            <strong>Missing Configuration:</strong> This template has no configured fields. 
            Complete the template configuration before publishing.
          </Alert>
        )}

        <Typography variant="h6" sx={{ mt: 3, mb: 2 }}>
          Required Information
        </Typography>
        {requiredClaims.length > 0 ? (
          <Box component="ul" aria-label="Required information" sx={{ pl: 3 }}>
            {requiredClaims.map((claim) => (
              <Typography component="li" key={claim.name} variant="body2">
                {claimLabel(claim)}
              </Typography>
            ))}
          </Box>
        ) : (
          <Typography variant="body2" color="text.secondary">
            No specific requirements configured.
          </Typography>
        )}
        {optionalClaims.length > 0 && <>
          <Typography variant="h6" sx={{ mt: 3, mb: 2 }}>Optional Information</Typography>
          <Box component="ul" aria-label="Optional information" sx={{ pl: 3 }}>
            {optionalClaims.map((claim) => (
              <Typography component="li" key={claim.name} variant="body2">{claimLabel(claim)}</Typography>
            ))}
          </Box>
        </>}
      </Paper>
    </Container>
  );
}

function PreviewCredentialPage() {
  const { templateId } = useParams();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const { user } = useAuth();
  const organizationId = searchParams.get('organization_id');
  const scope = JSON.stringify([
    user?.user_id || user?.sub || user?.id || null,
    templateId, organizationId, location.key, location.search,
  ]);

  return (
    <PreviewProvider
      key={scope}
      resourceType="credential" 
      resourceId={templateId}
      returnUrl="/console/org/templates/credentials"
    >
      <PreviewCredentialContent templateId={templateId} organizationId={organizationId} />
    </PreviewProvider>
  );
}

export default PreviewCredentialPage;
