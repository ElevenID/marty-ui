/**
 * Preview Catalog Page
 * 
 * Wraps the CredentialCatalog component in preview mode so admins
 * can see what applicants see when browsing available credentials.
 */

import { useEffect } from 'react';
import { usePreview } from '../../contexts/PreviewContext';
import PreviewPage from './PreviewPage';
import CredentialCatalog from '../applicant/CredentialCatalog';
import { Box } from '@mui/material';

function PreviewCatalogContent() {
  const { updateContextLabel } = usePreview();

  useEffect(() => {
    updateContextLabel('Credential Catalog');
  }, [updateContextLabel]);

  return (
    <Box>
      <CredentialCatalog />
    </Box>
  );
}

function PreviewCatalogPage() {
  return (
    <PreviewPage resourceType="catalog" returnUrl="/console/org/templates/credentials">
      <PreviewCatalogContent />
    </PreviewPage>
  );
}

export default PreviewCatalogPage;
