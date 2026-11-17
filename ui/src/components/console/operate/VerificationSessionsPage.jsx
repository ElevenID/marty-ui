import { useTranslation } from 'react-i18next';
import VerificationSessionManager from '../../vendor/verification/VerificationSessionManager';
import { ResourcePage } from '../../common';
import { useConsole } from '../../../contexts/ConsoleContext';
import { getOperateTabs } from '../../../config/operateTabs';

const getBreadcrumbs = (t) => [
  { label: t('operate.breadcrumbs.console'), path: '/console' },
  { label: t('operate.breadcrumbs.operate'),  path: '/console/org/operate' },
  { label: 'Verification',                    path: '/console/org/operate/verify' },
];

function VerificationSessionsPage() {
  const { t } = useTranslation('console');
  const { activeOrgId: organizationId } = useConsole();
  return (
    <ResourcePage
      title="Credential Verification"
      description="Start OID4VP verification sessions for credentials presented by holders."
      tabs={getOperateTabs(t)}
      breadcrumbs={getBreadcrumbs(t)}
    >
      <VerificationSessionManager organizationId={organizationId} />
    </ResourcePage>
  );
}

export default VerificationSessionsPage;
