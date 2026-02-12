/**
 * Applicant Settings Page
 * 
 * Profile and preferences for applicants.
 */

import { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  TextField,
  Button,
  Grid,
  Alert,
  Switch,
  FormControlLabel,
  Divider,
} from '@mui/material';
import SaveIcon from '@mui/icons-material/Save';
import { useTranslation } from 'react-i18next';

import { useAuth } from '../../../hooks/useAuth';
import { getApplicantByUser, updateApplicantProfile } from '../../../services/applicantApi';

function ApplicantSettingsPage() {
  const { t } = useTranslation('applicant');
  const { user } = useAuth();
  const [saving, setSaving] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState(null);
  const [applicantId, setApplicantId] = useState(null);
  const [profile, setProfile] = useState({
    name: user?.name || '',
    email: user?.email || '',
    phone: '',
  });
  const [notifications, setNotifications] = useState({
    emailAlerts: true,
    applicationUpdates: true,
    expirationReminders: true,
  });

  // Load applicant profile on mount
  useEffect(() => {
    const loadProfile = async () => {
      if (user?.user_id) {
        try {
          const applicant = await getApplicantByUser(user.user_id);
          if (applicant) {
            setApplicantId(applicant.id);
            setProfile({
              name: applicant.full_name || user.name || '',
              email: applicant.email || user.email || '',
              phone: applicant.phone_number || '',
            });
          }
        } catch (err) {
          console.error('Error loading applicant profile:', err);
        }
      }
    };
    loadProfile();
  }, [user]);

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    setSuccess(false);
    try {
      if (!applicantId) {
        throw new Error(t('settings.errorNotFound'));
      }
      
      // Split name into given_name and family_name
      const nameParts = profile.name.trim().split(' ');
      const given_name = nameParts[0] || '';
      const family_name = nameParts.slice(1).join(' ') || '';
      
      await updateApplicantProfile(applicantId, {
        given_name,
        family_name,
        phone_number: profile.phone,
      });
      
      setSuccess(true);
      setTimeout(() => setSuccess(false), 3000);
    } catch (err) {
      console.error('Error saving settings:', err);
      setError(err.message || 'Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  const handleProfileChange = (field) => (event) => {
    setProfile((prev) => ({ ...prev, [field]: event.target.value }));
  };

  const handleNotificationChange = (field) => (event) => {
    setNotifications((prev) => ({ ...prev, [field]: event.target.checked }));
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        {t('settings.title')}
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        {t('settings.description')}
      </Typography>

      {success && (
        <Alert severity="success" sx={{ mb: 3 }}>
          {t('settings.successMessage')}
        </Alert>
      )}

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Profile Settings */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          {t('settings.profile.title')}
        </Typography>
        <Grid container spacing={3}>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label={t('settings.profile.fullName')}
              value={profile.name}
              onChange={handleProfileChange('name')}
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label={t('settings.profile.email')}
              value={profile.email}
              onChange={handleProfileChange('email')}
              disabled
              helperText={t('settings.profile.emailHelp')}
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label={t('settings.profile.phone')}
              value={profile.phone}
              onChange={handleProfileChange('phone')}
            />
          </Grid>
        </Grid>
      </Paper>

      {/* Notification Settings */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          {t('settings.notifications.title')}
        </Typography>
        <FormControlLabel
          control={
            <Switch
              checked={notifications.emailAlerts}
              onChange={handleNotificationChange('emailAlerts')}
            />
          }
          label={t('settings.notifications.emailAlerts')}
        />
        <Typography variant="body2" color="text.secondary" paragraph sx={{ ml: 6 }}>
          {t('settings.notifications.emailAlertsDescription')}
        </Typography>

        <Divider sx={{ my: 2 }} />

        <FormControlLabel
          control={
            <Switch
              checked={notifications.applicationUpdates}
              onChange={handleNotificationChange('applicationUpdates')}
            />
          }
          label={t('settings.notifications.applicationUpdates')}
        />
        <Typography variant="body2" color="text.secondary" paragraph sx={{ ml: 6 }}>
          {t('settings.notifications.applicationUpdatesDescription')}
        </Typography>

        <Divider sx={{ my: 2 }} />

        <FormControlLabel
          control={
            <Switch
              checked={notifications.expirationReminders}
              onChange={handleNotificationChange('expirationReminders')}
            />
          }
          label={t('settings.notifications.expirationReminders')}
        />
        <Typography variant="body2" color="text.secondary" paragraph sx={{ ml: 6 }}>
          {t('settings.notifications.expirationRemindersDescription')}
        </Typography>
      </Paper>

      <Button
        variant="contained"
        startIcon={<SaveIcon />}
        onClick={handleSave}
        disabled={saving}
      >
        {saving ? t('settings.actions.saving') : t('settings.actions.save')}
      </Button>
    </Box>
  );
}

export default ApplicantSettingsPage;
