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
import ResourcePage from '../common/ResourcePage';
import {
  getNotificationPreferences,
  updateNotificationPreferences,
} from '../../services/notificationPreferencesApi';

/**
 * Notification Preferences Page
 * 
 * Allows users to configure how they receive notifications (push, email, or both).
 */
export default function NotificationPreferencesPage() {
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
      const prefs = await getNotificationPreferences();
      setPreferences(prefs);
    } catch (err) {
      console.error('Failed to load notification preferences:', err);
      setError(err.message || 'Failed to load notification preferences');
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    try {
      setSaving(true);
      setError(null);
      setSuccessMessage(null);
      
      await updateNotificationPreferences(preferences);
      setSuccessMessage('Notification preferences updated successfully');
    } catch (err) {
      console.error('Failed to save notification preferences:', err);
      setError(err.message || 'Failed to save notification preferences');
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
      title="Notification Preferences"
      subtitle="Configure how you receive notifications for applications, credentials, and membership updates"
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
            Loading preferences...
          </Typography>
        ) : (
          <Stack spacing={3}>
            {/* Notification Method */}
            <Box>
              <FormControl component="fieldset">
                <FormLabel component="legend" sx={{ mb: 2, fontWeight: 'medium' }}>
                  Notification Method
                </FormLabel>
                <RadioGroup value={preferences.method} onChange={handleMethodChange}>
                  <FormControlLabel
                    value="push"
                    control={<Radio />}
                    label={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <PhoneAndroidIcon fontSize="small" />
                        <Box>
                          <Typography variant="body2">Push Notifications Only</Typography>
                          <Typography variant="caption" color="text.secondary">
                            Receive notifications in the Marty Authenticator app
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
                          <Typography variant="body2">Email Only</Typography>
                          <Typography variant="caption" color="text.secondary">
                            Receive notifications via email
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
                          <Typography variant="body2">Both Push and Email</Typography>
                          <Typography variant="caption" color="text.secondary">
                            Get notifications in both the app and via email (recommended)
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
                Email Notification Categories
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                Choose which types of events should trigger email notifications.
                {!isEmailEnabled && (
                  <Typography component="span" color="warning.main" sx={{ display: 'block', mt: 1 }}>
                    Note: Email is currently disabled in your notification method above.
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
                      <Typography variant="body2">Application Updates</Typography>
                      <Typography variant="caption" color="text.secondary">
                        Status changes for credential applications you&apos;ve submitted
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
                      <Typography variant="body2">Credential Issuance</Typography>
                      <Typography variant="caption" color="text.secondary">
                        When new credentials are issued to your wallet
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
                      <Typography variant="body2">Membership Updates</Typography>
                      <Typography variant="caption" color="text.secondary">
                        Organization membership approvals and role changes
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
                {saving ? 'Saving...' : 'Save Preferences'}
              </Button>
            </Box>
          </Stack>
        )}
      </Paper>
    </ResourcePage>
  );
}
