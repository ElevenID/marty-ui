/**
 * Preview Application Page
 * 
 * Wraps the ApplicationForm component in preview mode so admins can
 * walk through the application process without submitting real data.
 */

import { useEffect, useState } from 'react';
import { useParams, useSearchParams } from 'react-router';
import { Alert, CircularProgress } from '@mui/material';
import { PreviewProvider, usePreview } from '../../contexts/PreviewContext';
import ApplicationForm from '../applicant/ApplicationForm';
import { getApplicationTemplate } from '../../services/applicationTemplatesApi';
import { get } from '../../services/api';
import { normalizeTemplateToFormConfig } from '../../application/applications';

function PreviewApplicationContent() {
  const { applicationTemplateId } = useParams();
  const [searchParams] = useSearchParams();
  const organizationId = searchParams.get('organization_id');
  const { updateContextLabel } = usePreview();
  const [loaded, setLoaded] = useState(null);
  const scope = `${applicationTemplateId}:${organizationId || ''}`;

  useEffect(() => {
    let current = true;
    updateContextLabel(`Application Template: ${applicationTemplateId}`);
    (async () => {
      try {
        const template = await getApplicationTemplate(applicationTemplateId, organizationId);
        if (template?.id !== applicationTemplateId || !template.organization_id || !template.credential_template_id
          || (organizationId && template.organization_id !== organizationId)) {
          throw new Error('This Application Template is not available in the selected organization.');
        }
        const credential = await get(`/v1/credential-templates/${encodeURIComponent(template.credential_template_id)}?organization_id=${encodeURIComponent(template.organization_id)}`);
        if (credential?.id !== template.credential_template_id || credential.organization_id !== template.organization_id) {
          throw new Error('The Credential Template does not belong to this Application Template.');
        }
        if (current) setLoaded({ scope, context: { applicationTemplate: template, credential: normalizeTemplateToFormConfig(credential) } });
      } catch (error) {
        if (current) setLoaded({ scope, error: error.message || String(error) });
      }
    })();
    return () => { current = false; };
  }, [applicationTemplateId, organizationId, scope, updateContextLabel]);

  if (loaded?.scope !== scope) return <CircularProgress />;
  if (loaded.error) return <Alert severity="error">{loaded.error}</Alert>;
  return <ApplicationForm key={scope} previewContext={loaded.context} />;
}

function PreviewApplicationPage() {
  const { applicationTemplateId } = useParams();

  return (
    <PreviewProvider 
      resourceType="application" 
      resourceId={applicationTemplateId}
      returnUrl="/console/org/templates/applications"
    >
      <PreviewApplicationContent />
    </PreviewProvider>
  );
}

export default PreviewApplicationPage;
