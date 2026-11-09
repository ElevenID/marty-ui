/**
 * Preview Flow Page
 * 
 * Simulates the applicant form linked to an existing Flow Definition.
 */

import { useEffect, useState } from 'react';
import { useLocation, useParams, useSearchParams } from 'react-router';
import { useAuth } from '../../hooks/useAuth';
import { useAsyncActionScope } from '../../hooks/useAsyncActionScope';
import { usePreview } from '../../contexts/PreviewContext';
import PreviewPage from './PreviewPage';
import { Container, Alert, CircularProgress, Typography, Box } from '@mui/material';
import ApplicationForm from '../applicant/ApplicationForm';
import PreviewNotFound from './PreviewNotFound';
import { fetchPreviewFlow } from '../../application/vendor';
import { getApplicationTemplate } from '../../services/applicationTemplatesApi';
import { get } from '../../services/api';
import { normalizeTemplateToFormConfig } from '../../application/applications';

function PreviewFlowContent({ flowId, organizationId }) {
  const { updateContextLabel } = usePreview();
  const beginLoad = useAsyncActionScope();
  const [loaded, setLoaded] = useState(null);

  useEffect(() => {
    const action = beginLoad();
    (async () => {
      try {
        const flow = await action.run(fetchPreviewFlow, { flowId });
        if (flow?.id !== flowId || !flow.organization_id
          || (organizationId != null && flow.organization_id !== organizationId)) {
          throw new Error('This Flow is not available in the selected organization.');
        }

        let applicationTemplate = null;
        let credentialId = flow.credential_template_id;
        if (flow.application_template_id) {
          applicationTemplate = await action.run(getApplicationTemplate, flow.application_template_id, flow.organization_id);
          if (applicationTemplate?.id !== flow.application_template_id
            || applicationTemplate.organization_id !== flow.organization_id
            || !applicationTemplate.credential_template_id
            || (credentialId && credentialId !== applicationTemplate.credential_template_id)) {
            throw new Error('The Application Template does not belong to this Flow.');
          }
          credentialId = applicationTemplate.credential_template_id;
        }

        let context = null;
        if (credentialId) {
          const credential = await action.run(get,
            `/v1/credential-templates/${encodeURIComponent(credentialId)}?organization_id=${encodeURIComponent(flow.organization_id)}`);
          if (credential?.id !== credentialId || credential.organization_id !== flow.organization_id) {
            throw new Error('The Credential Template does not belong to this Flow.');
          }
          context = { applicationTemplate, credential: normalizeTemplateToFormConfig(credential) };
        }
        updateContextLabel(`Flow: ${flow.name || flowId}`);
        setLoaded({ flow, context });
      } catch (error) {
        if (action.isCurrent()) setLoaded({ error });
      }
    })();
  }, [beginLoad, flowId, organizationId, updateContextLabel]);

  if (!loaded) {
    return (
      <Container maxWidth="md" sx={{ py: 4, textAlign: 'center' }}>
        <CircularProgress />
        <Typography sx={{ mt: 2 }}>Loading flow preview...</Typography>
      </Container>
    );
  }

  if (loaded.error?.status === 404) {
    return (
      <PreviewNotFound 
        resourceType="flow" 
        returnUrl="/console/org/flows/definitions"
      />
    );
  }
  if (loaded.error) {
    return <Container maxWidth="md" sx={{ py: 4 }}>
      <Alert severity="error">{loaded.error.message || 'Flow preview could not be loaded.'}</Alert>
    </Container>;
  }

  const status = String(loaded.flow.status || '').toUpperCase();

  return (
    <Box>
      {status === 'DRAFT' && (
        <Container maxWidth="md" sx={{ py: 2 }}>
          <Alert severity="info">
            <strong>Draft Status:</strong> This flow is in draft status and not yet published to applicants. 
            Publish this flow to make it available for applications.
          </Alert>
        </Container>
      )}
      {['PAUSED', 'ARCHIVED', 'DISABLED'].includes(status) && (
        <Container maxWidth="md" sx={{ py: 2 }}>
          <Alert severity="warning">
            <strong>{status}:</strong> This flow is not accepting new applications. You can still preview its form.
          </Alert>
        </Container>
      )}
      {loaded.context
        ? <ApplicationForm previewContext={loaded.context} />
        : <Container maxWidth="md" sx={{ py: 2 }}>
          <Alert severity="info">This flow has no applicant application to preview.</Alert>
        </Container>}
    </Box>
  );
}

function PreviewFlowPage() {
  const { flowId } = useParams();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const { user } = useAuth();
  // AuthContext's organization is the profile default, not the console's
  // current selection. Without an explicit URL constraint, the authorized
  // native definition supplies the owner for every linked preview read.
  const organizationId = searchParams.get('organization_id');
  const scope = JSON.stringify([
    user?.user_id || user?.sub || user?.id || null,
    flowId, organizationId, location.key, location.search,
  ]);

  return (
    <PreviewPage
      key={scope}
      resourceType="flow" 
      resourceId={flowId}
      returnUrl="/console/org/flows/definitions"
    >
      <PreviewFlowContent flowId={flowId} organizationId={organizationId} />
    </PreviewPage>
  );
}

export default PreviewFlowPage;
