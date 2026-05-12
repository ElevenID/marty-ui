/**
 * Deployment Profiles Page
 * 
 * Manages deployment profiles for API integrations, kiosks, lanes/devices,
 * and both online and offline environments.
 * Embeds the existing DeploymentProfileManager component.
 */

import { useTranslation } from 'react-i18next';
import DeploymentProfileManager from '../../vendor/DeploymentProfileManager';
import { ResourcePage } from '../../common';

const getDeployTabs = (t) => [
  { label: t('deploy.deploymentProfiles'), path: '/console/org/deploy/profiles' },
  { label: t('deploy.apiKeys'), path: '/console/org/deploy/api-keys' },
  { label: t('deploy.lanesDevices'), path: '/console/org/deploy/lanes' },
  { label: t('deploy.webhooks'), path: '/console/org/deploy/webhooks' },
];

const getBreadcrumbs = (t) => [
  { label: t('deploy.breadcrumbs.console'), path: '/console' },
  { label: t('deploy.breadcrumbs.deploy'), path: '/console/org/deploy' },
  { label: t('deploy.breadcrumbs.deploymentProfiles'), path: '/console/org/deploy/profiles' },
];

function DeploymentProfilesPage() {
  const { t } = useTranslation('console');
  
  return (
    <ResourcePage
      title={t('deploy.deploymentProfiles')}
      description={t('deploy.deploymentProfilesDescription')}
      tabs={getDeployTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
      buildPath="/console/org/deploy/profiles/new"
      resourceName={t('deploy.deploymentProfile')}
    >
      <DeploymentProfileManager hideHeader />
    </ResourcePage>
  );
}

export default DeploymentProfilesPage;
