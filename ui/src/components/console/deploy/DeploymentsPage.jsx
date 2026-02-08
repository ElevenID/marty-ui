/**
 * Deployment Profiles Page
 * 
 * Manages deployment profiles for API integrations, kiosks, lanes/devices,
 * and both online and offline environments.
 * Embeds the existing DeploymentProfileManager component.
 */

import { Box } from '@mui/material';
import DeploymentProfileManager from '../../vendor/DeploymentProfileManager';
import { ResourcePage } from '../../common';

const DEPLOY_TABS = [
  { label: 'Deployment Profiles', path: '/console/deploy/profiles' },
  { label: 'API Keys', path: '/console/deploy/api-keys' },
  { label: 'Lanes & Devices', path: '/console/deploy/lanes' },
  { label: 'Webhooks', path: '/console/deploy/webhooks' },
];

const BREADCRUMBS = [
  { label: 'Console', path: '/console' },
  { label: 'Deploy', path: '/console/deploy' },
  { label: 'Deployment Profiles', path: '/console/deploy/profiles' },
];

function DeploymentProfilesPage() {
  return (
    <ResourcePage
      title="Deployment Profiles"
      description="Configure deployment profiles for APIs, kiosks, lanes/devices, and both online and offline environments."
      tabs={DEPLOY_TABS}
      breadcrumbs={BREADCRUMBS}
    >
      <Box sx={{ mx: -3, mt: -2 }}>
        <DeploymentProfileManager />
      </Box>
    </ResourcePage>
  );
}

export default DeploymentProfilesPage;
