/**
 * Preview Application Page
 * 
 * Wraps the ApplicationForm component in preview mode so admins can
 * walk through the application process without submitting real data.
 */

import { useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { PreviewProvider, usePreview } from '../../contexts/PreviewContext';
import ApplicationForm from '../applicant/ApplicationForm';

function PreviewApplicationContent() {
  const { applicationTemplateId } = useParams();
  const { updateContextLabel } = usePreview();

  useEffect(() => {
    updateContextLabel(`Application Template: ${applicationTemplateId}`);
  }, [applicationTemplateId, updateContextLabel]);

  return <ApplicationForm />;
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
