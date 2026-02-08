/**
 * Flow Definitions Page
 * 
 * Manages flow definitions - reusable verification and issuance workflows.
 * Embeds the existing FlowManager component with console layout.
 */

import { Box } from '@mui/material';
import FlowManager from '../../vendor/FlowManager';
import { ResourcePage } from '../../common';

const FLOWS_TABS = [
  { label: 'Flow Definitions', path: '/console/flows/definitions' },
  { label: 'Flow Instances', path: '/console/flows/instances' },
];

const BREADCRUMBS = [
  { label: 'Console', path: '/console' },
  { label: 'Flows', path: '/console/flows' },
  { label: 'Flow Definitions', path: '/console/flows/definitions' },
];

function FlowDefinitionsPage() {
  return (
    <ResourcePage
      title="Flow Definitions"
      description="Create and manage verification and issuance workflows."
      tabs={FLOWS_TABS}
      breadcrumbs={BREADCRUMBS}
    >
      <Box sx={{ mx: -3, mt: -2 }}>
        <FlowManager />
      </Box>
    </ResourcePage>
  );
}

export default FlowDefinitionsPage;
