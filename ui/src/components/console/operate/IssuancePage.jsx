/**
 * Issuance Page
 * 
 * Issue and manage credentials.
 * Embeds the existing Issuance component.
 */

import { Box } from '@mui/material';
import Issuance from '../../vendor/Issuance';
import { ResourcePage } from '../../common';

const OPERATE_TABS = [
  { label: 'Issuance', path: '/console/operate/issuance' },
  { label: 'Applications', path: '/console/operate/applications' },
];

const BREADCRUMBS = [
  { label: 'Console', path: '/console' },
  { label: 'Operate', path: '/console/operate' },
  { label: 'Issuance', path: '/console/operate/issuance' },
];

function IssuancePage() {
  return (
    <ResourcePage
      title="Issuance"
      description="Issue and manage digital credentials."
      tabs={OPERATE_TABS}
      breadcrumbs={BREADCRUMBS}
    >
      <Box sx={{ mx: -3, mt: -2 }}>
        <Issuance />
      </Box>
    </ResourcePage>
  );
}

export default IssuancePage;
