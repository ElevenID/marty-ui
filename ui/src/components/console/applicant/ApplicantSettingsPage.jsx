/**
 * Applicant Settings Page
 * 
 * Profile and preferences for applicants.
 */

import { useState } from 'react';
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

import { useAuth } from '../../../hooks/useAuth';

function ApplicantSettingsPage() {
  const { user } = useAuth();
  const [saving, setSaving] = useState(false);
  const [success, setSuccess] = useState(false);
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

  const handleSave = async () => {
    setSaving(true);
    try {
      // TODO: Save to API
      await new Promise((resolve) => setTimeout(resolve, 500));
      setSuccess(true);
      setTimeout(() => setSuccess(false), 3000);
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
        Settings
      </Typography>
      <Typography variant="body1" color="text.secondary" paragraph>
        Manage your profile and preferences.
      </Typography>

      {success && (
        <Alert severity="success" sx={{ mb: 3 }}>
          Settings saved successfully.
        </Alert>
      )}

      {/* Profile Settings */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Profile
        </Typography>
        <Grid container spacing={3}>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="Full Name"
              value={profile.name}
              onChange={handleProfileChange('name')}
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="Email"
              value={profile.email}
              onChange={handleProfileChange('email')}
              disabled
              helperText="Contact support to change your email"
            />
          </Grid>
          <Grid item xs={12} sm={6}>
            <TextField
              fullWidth
              label="Phone Number"
              value={profile.phone}
              onChange={handleProfileChange('phone')}
            />
          </Grid>
        </Grid>
      </Paper>

      {/* Notification Settings */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" gutterBottom>
          Notifications
        </Typography>
        <FormControlLabel
          control={
            <Switch
              checked={notifications.emailAlerts}
              onChange={handleNotificationChange('emailAlerts')}
            />
          }
          label="Email Alerts"
        />
        <Typography variant="body2" color="text.secondary" paragraph sx={{ ml: 6 }}>
          Receive important updates via email
        </Typography>

        <Divider sx={{ my: 2 }} />

        <FormControlLabel
          control={
            <Switch
              checked={notifications.applicationUpdates}
              onChange={handleNotificationChange('applicationUpdates')}
            />
          }
          label="Application Updates"
        />
        <Typography variant="body2" color="text.secondary" paragraph sx={{ ml: 6 }}>
          Get notified when your application status changes
        </Typography>

        <Divider sx={{ my: 2 }} />

        <FormControlLabel
          control={
            <Switch
              checked={notifications.expirationReminders}
              onChange={handleNotificationChange('expirationReminders')}
            />
          }
          label="Expiration Reminders"
        />
        <Typography variant="body2" color="text.secondary" paragraph sx={{ ml: 6 }}>
          Remind me before credentials expire
        </Typography>
      </Paper>

      <Button
        variant="contained"
        startIcon={<SaveIcon />}
        onClick={handleSave}
        disabled={saving}
      >
        {saving ? 'Saving...' : 'Save Settings'}
      </Button>
    </Box>
  );
}

export default ApplicantSettingsPage;
