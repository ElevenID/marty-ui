import { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  FormControl,
  FormLabel,
  RadioGroup,
  FormControlLabel,
  Radio,
  Switch,
  Button,
  Alert,
  Divider,
  Stack,
} from '@mui/material';
import NotificationsIcon from '@mui/icons-material/Notifications';
import EmailIcon from '@mui/icons-material/Email';
import PhoneAndroidIcon from '@mui/icons-material/PhoneAndroid';
import { useTranslation } from 'react-i18next';
import ResourcePage from '../common/ResourcePage';
import notificationsApi from '../../services/notificationsApi';

/**
 * Notification Preferences Page
 * 
 * Allows users to configure how they receive notifications (push, email, or both).
 */
export default function NotificationPreferencesPage() {
  const { t } = useTranslation('console');
  const [preferences, setPreferences] = useState({
    method: 'both',
    email_for_applications: true,
    email_for_credentials: true,
    email_for_membership: true,
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const [successMessage, setSuccessMessage] = useState(null);

  useEffect(() => {
    loadPreferences();
  }, []);

  const loadPreferences = async () => {
    try {
      setLoading(true);
      setError(null);
      const prefs = await notificationsApi.getNotificationPreferences();
      setPreferences(prefs);
    } catch (err) {
      console.error('Failed to load notification preferences:', err);
      setError(err.message || t('notificationPreferencesPage.messages.loadFailed'));
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    try {
      setSaving(true);
      setError(null);
      setSuccessMessage(null);
      
      await notificationsApi.updateNotificationPreferences(preferences);
      setSuccessMessage(t('notificationPreferencesPage.messages.saveSuccess'));
    } catch (err) {
      console.error('Failed to save notification preferences:', err);
      setError(err.message || t('notificationPreferencesPage.messages.saveFailed'));
    } finally {
      setSaving(false);
    }
  };

  const handleMethodChange = (event) => {
    setPreferences({
      ...preferences,
      method: event.target.value,
    });
  };

  const handleToggleChange = (field) => (event) => {
    setPreferences({
      ...preferences,
      [field]: event.target.checked,
    });
  };

  const isEmailEnabled = preferences.method === 'email' || preferences.method === 'both';

  return (
    <ResourcePage
      title={t('notificationPreferencesPage.title')}
      subtitle={t('notificationPreferencesPage.subtitle')}
      icon={<NotificationsIcon />}
    >
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {successMessage && (
        <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccessMessage(null)}>
          {successMessage}
        </Alert>
      )}

      <Paper sx={{ p: 3 }}>
        {loading ? (
          <Typography variant="body2" color="text.secondary">
            {t('notificationPreferencesPage.loading')}
          </Typography>
        ) : (
          <Stack spacing={3}>
            {/* Notification Method */}
            <Box>
              <FormControl component="fieldset">
                <FormLabel component="legend" sx={{ mb: 2, fontWeight: 'medium' }}>
                  {t('notificationPreferencesPage.sections.notificationMethod')}
                </FormLabel>
                <RadioGroup value={preferences.method} onChange={handleMethodChange}>
                  <FormControlLabel
                    value="push"
                    control={<Radio />}
                    label={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <PhoneAndroidIcon fontSize="small" />
                        <Box>
                          <Typography variant="body2">{t('notificationPreferencesPage.methods.pushOnly.title')}</Typography>
                          <Typography variant="caption" color="text.secondary">
                            {t('notificationPreferencesPage.methods.pushOnly.description')}
                          </Typography>
                        </Box>
                      </Box>
                    }
                  />
                  <FormControlLabel
                    value="email"
                    control={<Radio />}
                    label={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <EmailIcon fontSize="small" />
                        <Box>
                          <Typography variant="body2">{t('notificationPreferencesPage.methods.emailOnly.title')}</Typography>
                          <Typography variant="caption" color="text.secondary">
                            {t('notificationPreferencesPage.methods.emailOnly.description')}
                          </Typography>
                        </Box>
                      </Box>
                    }
                  />
                  <FormControlLabel
                    value="both"
                    control={<Radio />}
                    label={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <NotificationsIcon fontSize="small" />
                        <Box>
                          <Typography variant="body2">{t('notificationPreferencesPage.methods.both.title')}</Typography>
                          <Typography variant="caption" color="text.secondary">
                            {t('notificationPreferencesPage.methods.both.description')}
                          </Typography>
                        </Box>
                      </Box>
                    }
                  />
                </RadioGroup>
              </FormControl>
            </Box>

            <Divider />

            {/* Email Notification Categories */}
            <Box>
              <Typography variant="subtitle1" fontWeight="medium" sx={{ mb: 2 }}>
                {t('notificationPreferencesPage.sections.emailCategories')}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                {t('notificationPreferencesPage.sections.emailCategoriesDescription')}
                {!isEmailEnabled && (
                  <Typography component="span" color="warning.main" sx={{ display: 'block', mt: 1 }}>
                    {t('notificationPreferencesPage.messages.emailDisabledNote')}
                  </Typography>
                )}
              </Typography>

              <Stack spacing={2}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={preferences.email_for_applications}
                      onChange={handleToggleChange('email_for_applications')}
                      disabled={!isEmailEnabled}
                    />
                  }
                  label={
                    <Box>
                      <Typography variant="body2">{t('notificationPreferencesPage.categories.applicationUpdates.title')}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        {t('notificationPreferencesPage.categories.applicationUpdates.description')}
                      </Typography>
                    </Box>
                  }
                />

                <FormControlLabel
                  control={
                    <Switch
                      checked={preferences.email_for_credentials}
                      onChange={handleToggleChange('email_for_credentials')}
                      disabled={!isEmailEnabled}
                    />
                  }
                  label={
                    <Box>
                      <Typography variant="body2">{t('notificationPreferencesPage.categories.credentialIssuance.title')}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        {t('notificationPreferencesPage.categories.credentialIssuance.description')}
                      </Typography>
                    </Box>
                  }
                />

                <FormControlLabel
                  control={
                    <Switch
                      checked={preferences.email_for_membership}
                      onChange={handleToggleChange('email_for_membership')}
                      disabled={!isEmailEnabled}
                    />
                  }
                  label={
                    <Box>
                      <Typography variant="body2">{t('notificationPreferencesPage.categories.membershipUpdates.title')}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        {t('notificationPreferencesPage.categories.membershipUpdates.description')}
                      </Typography>
                    </Box>
                  }
                />
              </Stack>
            </Box>

            <Divider />

            {/* Save Button */}
            <Box sx={{ display: 'flex', justifyContent: 'flex-end' }}>
              <Button
                variant="contained"
                onClick={handleSave}
                disabled={saving || loading}
              >
                {saving ? t('notificationPreferencesPage.actions.saving') : t('notificationPreferencesPage.actions.save')}
              </Button>
            </Box>
          </Stack>
        )}
      </Paper>
    </ResourcePage>
  );
}
