/**
 * Issuance Page
 * 
 * Issue and manage credentials.
 * Embeds the existing Issuance component.
 */

import { Box } from '@mui/material';
import { useTranslation } from 'react-i18next';
import Issuance from '../../vendor/Issuance';
import { ResourcePage } from '../../common';

const getOperateTabs = (t) => [
  { label: t('operate.tabs.issuance'), path: '/console/operate/issuance' },
  { label: t('operate.tabs.applications'), path: '/console/operate/applications' },
];

const getBreadcrumbs = (t) => [
  { label: t('operate.breadcrumbs.console'), path: '/console' },
  { label: t('operate.breadcrumbs.operate'), path: '/console/operate' },
  { label: t('operate.breadcrumbs.issuance'), path: '/console/operate/issuance' },
];

function IssuancePage() {
  const { t } = useTranslation('console');

  return (
    <ResourcePage
      title={t('operate.issuance.title')}
      description={t('operate.issuance.description')}
      tabs={getOperateTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
    >
      <Box sx={{ mx: -3, mt: -2 }}>
        <Issuance />
      </Box>
    </ResourcePage>
  );
}

export default IssuancePage;
