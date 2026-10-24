import { Alert, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import ResourcePage from '../common/ResourcePage';

/** Preserve the existing URL without presenting a preference editor the API cannot save. */
export default function NotificationPreferencesPage() {
  const { t } = useTranslation('console');
  return <ResourcePage title={t('notificationPreferencesPage.title')}>
    <Alert severity="info">Notification preferences are not supported by the notification API.</Alert>
    <Typography sx={{ mt: 2 }}>This deployment has no notification preference read or update operation. No preference changes have been saved.</Typography>
  </ResourcePage>;
}
