import { useTranslation } from 'react-i18next';
import { Alert, Box, Tab, Tabs } from '@mui/material';
import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import VerificationSessionManager from '../../vendor/verification/VerificationSessionManager';
import CanvasMirrorProvenanceLookup from '../../canvas/CanvasMirrorProvenanceLookup';
import { ResourcePage } from '../../common';
import { useAuth } from '../../../hooks/useAuth';

const getOperateTabs = (t) => [
  { label: t('operate.tabs.issuance'),    path: '/console/org/operate/issuance' },
  { label: t('operate.tabs.applications'), path: '/console/org/operate/applications' },
  { label: t('operate.tabs.verify'),      path: '/console/org/operate/verify' },
];

const getBreadcrumbs = (t) => [
  { label: t('operate.breadcrumbs.console'), path: '/console' },
  { label: t('operate.breadcrumbs.operate'),  path: '/console/org/operate' },
  { label: 'Verification',                    path: '/console/org/operate/verify' },
];

function canvasLookupParamsFromSearch(searchParams) {
  return {
    externalCredentialId: searchParams.get('external_credential_id') || '',
    credentialId: searchParams.get('credential_id') || '',
    deliveryRecordId: searchParams.get('delivery_record_id') || '',
    canvasAccountId: searchParams.get('canvas_account_id') || '',
    organizationId: searchParams.get('organization_id') || '',
  };
}

function hasCanvasLookupParams(params) {
  return Boolean(params.externalCredentialId || params.credentialId || params.deliveryRecordId);
}

function VerificationSessionsPage() {
  const { t } = useTranslation('console');
  const { organizationId } = useAuth();
  const [searchParams] = useSearchParams();
  const canvasLookupParams = useMemo(() => canvasLookupParamsFromSearch(searchParams), [searchParams]);
  const hasCanvasLookup = hasCanvasLookupParams(canvasLookupParams);
  const [activeSection, setActiveSection] = useState(hasCanvasLookup ? 'canvas-provenance' : 'sessions');

  useEffect(() => {
    if (hasCanvasLookup) {
      setActiveSection('canvas-provenance');
    }
  }, [hasCanvasLookup]);

  return (
    <ResourcePage
      title="Credential Verification"
      description="Start OID4VP verification sessions and resolve supporting provenance for mirrored credentials."
      tabs={getOperateTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
    >
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={activeSection} onChange={(_event, value) => setActiveSection(value)}>
          <Tab value="sessions" label="OID4VP Sessions" />
          <Tab value="canvas-provenance" label="Canvas Provenance" />
        </Tabs>
      </Box>

      {activeSection === 'sessions' ? (
        <VerificationSessionManager />
      ) : (
        <Box data-testid="verification-canvas-provenance-section">
          <Alert severity="info" sx={{ mb: 2 }}>
            Use this support lookup when a Canvas Credentials mirror ID needs to be tied back to a canonical ElevenID issuance record.
            Employer-facing verification should use an OID4VP session whenever the holder can present from a wallet.
          </Alert>
          <CanvasMirrorProvenanceLookup
            initialParams={canvasLookupParams}
            organizationId={organizationId}
            showOrganizationField={!organizationId}
            title="Canvas mirror provenance"
            description="Resolve a Canvas Credentials mirror, delivery record, or canonical credential ID to the ElevenID issuance, issuer DID, trust basis, and revocation status."
          />
        </Box>
      )}
    </ResourcePage>
  );
}

export default VerificationSessionsPage;
