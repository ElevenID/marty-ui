/**
 * Flow Definitions Page
 * 
 * Manages flow definitions - reusable verification and issuance workflows.
 * Embeds the existing FlowManager component with console layout.
 */

import { Box } from '@mui/material';
import { useTranslation } from 'react-i18next';
import FlowManager from '../../vendor/FlowManager';
import { ResourcePage } from '../../common';

const getFlowsTabs = (t) => [
  { label: t('flows.flowDefinitions'), path: '/console/org/flows/definitions' },
  { label: t('flows.flowInstances'), path: '/console/org/flows/instances' },
];

const getBreadcrumbs = (t) => [
  { label: t('flows.breadcrumbs.console'), path: '/console' },
  { label: t('flows.breadcrumbs.flows'), path: '/console/org/flows' },
  { label: t('flows.breadcrumbs.flowDefinitions'), path: '/console/org/flows/definitions' },
];

function FlowDefinitionsPage() {
  const { t } = useTranslation('console');
  
  return (
    <ResourcePage
      title={t('flows.flowDefinitions')}
      description={t('flows.flowDefinitionsDescription')}
      tabs={getFlowsTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
    >
      <Box sx={{ mx: -3, mt: -2 }}>
        <FlowManager />
      </Box>
    </ResourcePage>
  );
}

export default FlowDefinitionsPage;
