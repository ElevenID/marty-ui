/**
 * Preview Catalog Page
 * 
 * Wraps the CredentialCatalog component in preview mode so admins
 * can see what applicants see when browsing available credentials.
 */

import { useEffect } from 'react';
import { useLocation } from 'react-router';
import { useAuth } from '../../hooks/useAuth';
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
  const location = useLocation();
  const { user } = useAuth();
  const scope = JSON.stringify([
    user?.user_id || user?.sub || user?.id || null,
    location.key, location.pathname, location.search,
  ]);
  return (
    <PreviewPage key={scope} resourceType="catalog" returnUrl="/console/org/templates/credentials">
      <PreviewCatalogContent />
    </PreviewPage>
  );
}

export default PreviewCatalogPage;
