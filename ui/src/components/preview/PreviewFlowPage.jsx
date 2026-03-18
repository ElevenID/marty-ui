/**
 * Preview Flow Page
 * 
 * Shows the complete applicant flow experience from initial landing
 * through application submission.
 */

import { useAsyncData } from '../../hooks/useAsyncData';
import { useParams } from 'react-router-dom';
import { PreviewProvider, usePreview } from '../../contexts/PreviewContext';
import { Container, Alert, CircularProgress, Typography, Box } from '@mui/material';
import ApplicationForm from '../applicant/ApplicationForm';
import PreviewNotFound from './PreviewNotFound';
import { fetchPreviewFlow } from '../../application/vendor';

function PreviewFlowContent() {
  const { flowId } = useParams();
  const { updateContextLabel } = usePreview();
  const { data: flow, loading, error } = useAsyncData(async () => {
    const data = await fetchPreviewFlow({ flowId });
    updateContextLabel(`Issuance Flow: ${data.name || flowId}`);
    return data;
  }, [flowId]);

  if (loading) {
    return (
      <Container maxWidth="md" sx={{ py: 4, textAlign: 'center' }}>
        <CircularProgress />
        <Typography sx={{ mt: 2 }}>Loading flow preview...</Typography>
      </Container>
    );
  }

  if (error) {
    return (
      <PreviewNotFound 
        resourceType="flow" 
        returnUrl="/console/org/flows/definitions"
      />
    );
  }

  return (
    <Box>
      {flow?.status === 'draft' && (
        <Container maxWidth="md" sx={{ py: 2 }}>
          <Alert severity="info">
            <strong>Draft Status:</strong> This flow is in draft status and not yet published to applicants. 
            Publish this flow to make it available for applications.
          </Alert>
        </Container>
      )}
      {flow?.status === 'disabled' && (
        <Container maxWidth="md" sx={{ py: 2 }}>
          <Alert severity="warning">
            <strong>Disabled:</strong> This flow is currently disabled and not accepting new applications.
          </Alert>
        </Container>
      )}
      {flow?.credential_template_id && (
        <ApplicationForm credentialType={flow.credential_template_id} />
      )}
    </Box>
  );
}

function PreviewFlowPage() {
  const { flowId } = useParams();

  return (
    <PreviewProvider 
      resourceType="flow" 
      resourceId={flowId}
      returnUrl="/console/org/flows/definitions"
    >
      <PreviewFlowContent />
    </PreviewProvider>
  );
}

export default PreviewFlowPage;
