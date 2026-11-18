import { Alert, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import ResourcePage from '../common/ResourcePage';

/** Preserve the existing URL without presenting a preference editor the API cannot save. */
export default function NotificationPreferencesPage() {
  const { t } = useTranslation('console');
  return <ResourcePage title={t('notificationPreferencesPage.title')}>
    <Alert severity="info">{t('notificationPreferencesPage.messages.unsupported')}</Alert>
    <Typography sx={{ mt: 2 }}>{t('notificationPreferencesPage.messages.unsupportedDetails')}</Typography>
  </ResourcePage>;
}
