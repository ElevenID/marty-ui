/**
 * Preview Application Page
 * 
 * Wraps the ApplicationForm component in preview mode so admins can
 * walk through the application process without submitting real data.
 */

import { useEffect, useState } from 'react';
import { useLocation, useParams, useSearchParams } from 'react-router';
import { Alert, CircularProgress } from '@mui/material';
import { useAuth } from '../../hooks/useAuth';
import { useAsyncActionScope } from '../../hooks/useAsyncActionScope';
import { usePreview } from '../../contexts/PreviewContext';
import PreviewPage from './PreviewPage';
import ApplicationForm from '../applicant/ApplicationForm';
import { getApplicationTemplate } from '../../services/applicationTemplatesApi';
import { get } from '../../services/api';
import { normalizeTemplateToFormConfig } from '../../application/applications';

function PreviewApplicationContent() {
  const { applicationTemplateId } = useParams();
  const [searchParams] = useSearchParams();
  const organizationId = searchParams.get('organization_id');
  const { updateContextLabel } = usePreview();
  const beginLoad = useAsyncActionScope();
  const [loaded, setLoaded] = useState(null);
  const scope = `${applicationTemplateId}:${organizationId || ''}`;

  useEffect(() => {
    const action = beginLoad();
    updateContextLabel(`Application Template: ${applicationTemplateId}`);
    (async () => {
      try {
        const template = await action.run(getApplicationTemplate, applicationTemplateId, organizationId);
        if (template?.id !== applicationTemplateId || !template.organization_id || !template.credential_template_id
          || (organizationId && template.organization_id !== organizationId)) {
          throw new Error('This Application Template is not available in the selected organization.');
        }
        const credential = await action.run(get, `/v1/credential-templates/${encodeURIComponent(template.credential_template_id)}?organization_id=${encodeURIComponent(template.organization_id)}`);
        if (credential?.id !== template.credential_template_id || credential.organization_id !== template.organization_id) {
          throw new Error('The Credential Template does not belong to this Application Template.');
        }
        setLoaded({ scope, context: { applicationTemplate: template, credential: normalizeTemplateToFormConfig(credential) } });
      } catch (error) {
        if (action.isCurrent()) setLoaded({ scope, error: error.message || String(error) });
      }
    })();
  }, [applicationTemplateId, organizationId, scope, updateContextLabel, beginLoad]);

  if (loaded?.scope !== scope) return <CircularProgress />;
  if (loaded.error) return <Alert severity="error">{loaded.error}</Alert>;
  return <ApplicationForm key={scope} previewContext={loaded.context} />;
}

function PreviewApplicationPage() {
  const { applicationTemplateId } = useParams();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const { user } = useAuth();
  const scope = JSON.stringify([
    user?.user_id || user?.sub || user?.id || null,
    applicationTemplateId, searchParams.get('organization_id'), location.key, location.search,
  ]);

  return (
    <PreviewPage
      key={scope}
      resourceType="application" 
      resourceId={applicationTemplateId}
      returnUrl="/console/org/templates/applications"
    >
      <PreviewApplicationContent />
    </PreviewPage>
  );
}

export default PreviewApplicationPage;
