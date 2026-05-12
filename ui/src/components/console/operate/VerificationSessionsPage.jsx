import { useTranslation } from 'react-i18next';
import VerificationSessionManager from '../../vendor/verification/VerificationSessionManager';
import { ResourcePage } from '../../common';

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

function VerificationSessionsPage() {
  const { t } = useTranslation('console');

  return (
    <ResourcePage
      title="Credential Verification"
      description="Start and manage OID4VP credential verification sessions"
      tabs={getOperateTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
    >
      <VerificationSessionManager />
    </ResourcePage>
  );
}

export default VerificationSessionsPage;
