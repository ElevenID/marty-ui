/**
 * Deployment Profiles Page
 * 
 * Manages deployment profiles for API integrations, kiosks, lanes/devices,
 * and both online and offline environments.
 * Embeds the existing DeploymentProfileManager component.
 */

import { Box } from '@mui/material';
import { useTranslation } from 'react-i18next';
import DeploymentProfileManager from '../../vendor/DeploymentProfileManager';
import { ResourcePage } from '../../common';

const getDeployTabs = (t) => [
  { label: t('deploy.deploymentProfiles'), path: '/console/deploy/profiles' },
  { label: t('deploy.apiKeys'), path: '/console/deploy/api-keys' },
  { label: t('deploy.lanesDevices'), path: '/console/deploy/lanes' },
  { label: t('deploy.webhooks'), path: '/console/deploy/webhooks' },
];

const getBreadcrumbs = (t) => [
  { label: t('deploy.breadcrumbs.console'), path: '/console' },
  { label: t('deploy.breadcrumbs.deploy'), path: '/console/deploy' },
  { label: t('deploy.breadcrumbs.deploymentProfiles'), path: '/console/deploy/profiles' },
];

function DeploymentProfilesPage() {
  const { t } = useTranslation('console');
  
  return (
    <ResourcePage
      title={t('deploy.deploymentProfiles')}
      description={t('deploy.deploymentProfilesDescription')}
      tabs={getDeployTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
    >
      <Box sx={{ mx: -3, mt: -2 }}>
        <DeploymentProfileManager />
      </Box>
    </ResourcePage>
  );
}

export default DeploymentProfilesPage;
