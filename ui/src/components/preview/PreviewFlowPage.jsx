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

const VERIFICATION_FLOW_TYPES = new Set(['oid4vp_presentation', 'mdl_presentation', 'siopv2']);

function isVerificationFlow(flow) {
  const flowType = String(flow.flow_type || '').trim().toLowerCase();
  const effectiveType = flowType === 'custom' ? flow.extension?.extends_flow_type : flowType;
  return String(flow.flow_category || '').trim().toUpperCase() === 'VERIFICATION'
    || VERIFICATION_FLOW_TYPES.has(String(effectiveType || '').trim().toLowerCase());
}

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

        // A verification flow can reference the credential it checks without
        // offering an application to issue that credential.
        if (isVerificationFlow(flow)) {
          updateContextLabel(`Flow: ${flow.name || flowId}`);
          setLoaded({ flow, verification: true });
          return;
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

  if (loaded.verification) {
    return <Container maxWidth="md" sx={{ py: 4 }}>
      <Typography variant="h5" component="h1" gutterBottom>Credential verification preview</Typography>
      <Alert severity="info">
        This flow requests presentation of existing credentials. Interactive verification preview is unavailable here. No verification has been started.
      </Alert>
    </Container>;
  }

  const status = String(loaded.flow.status || '').toUpperCase();

  return (
    <Box>
      {status === 'DRAFT' && (
        <Container maxWidth="md" sx={{ py: 2 }}>
          <Alert severity="info">
            <strong>Draft Status:</strong> Activate this flow before it can start new instances.
          </Alert>
        </Container>
      )}
      {['PAUSED', 'ARCHIVED', 'DISABLED'].includes(status) && (
        <Container maxWidth="md" sx={{ py: 2 }}>
          <Alert severity="warning">
            <strong>{status}:</strong> This flow cannot start new instances.
            {loaded.context && ' You can still preview its linked application form.'}
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
