/**
 * NotificationPreferences Component
 *
 * Allows users to manage their push notification settings:
 * - Enable/disable push notifications
 * - Configure notification categories
 * - Test push notifications
 */

import React, { useState, useEffect } from 'react';
import {
  Container,
  Paper,
  Typography,
  Button,
  Box,
  Alert,
  Card,
  CardContent,
  Switch,
  FormControlLabel,
  FormGroup,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  CircularProgress,
  Snackbar,
} from '@mui/material';
import {
  Notifications as NotificationsIcon,
  NotificationsOff as NotificationsOffIcon,
  Send as SendIcon,
  Check as CheckIcon,
  Close as CloseIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material';
import { useAuth } from '../hooks/useAuth';
import { useBranding } from '../hooks/useBranding';

const API_BASE_URL = process.env.REACT_APP_API_URL || '/api';

/**
 * Notification category configuration
 */
const NOTIFICATION_CATEGORIES = [
  {
    id: 'credential_offers',
    label: 'Credential Offers',
    description: 'Receive alerts when new credentials are available',
    default: true,
  },
  {
    id: 'verification_requests',
    label: 'Verification Requests',
    description: 'Get notified when someone requests to verify your credentials',
    default: true,
  },
  {
    id: 'credential_updates',
    label: 'Credential Updates',
    description: 'Alerts about credential renewals or revocations',
    default: true,
  },
  {
    id: 'security_alerts',
    label: 'Security Alerts',
    description: 'Important security-related notifications',
    default: true,
  },
  {
    id: 'promotional',
    label: 'Updates & News',
    description: 'Product updates and announcements',
    default: false,
  },
];

/**
 * NotificationPreferences Component
 */
const NotificationPreferences = () => {
  const branding = useBranding();
  const { user, organizationId } = useAuth();
  // State
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [snackbarOpen, setSnackbarOpen] = useState(false);

  // Permission state
  const [notificationPermission, setNotificationPermission] = useState('default');
  const [pushEnabled, setPushEnabled] = useState(false);

  // Category preferences
  const [preferences, setPreferences] = useState(() =>
    NOTIFICATION_CATEGORIES.reduce((acc, cat) => {
      acc[cat.id] = cat.default;
      return acc;
    }, {})
  );

  // Test notification state
  const [testSending, setTestSending] = useState(false);

  // Check permission on mount
  useEffect(() => {
    checkNotificationStatus();
    loadPreferences();
  }, []);

  const checkNotificationStatus = () => {
    if ('Notification' in window) {
      setNotificationPermission(Notification.permission);
      setPushEnabled(Notification.permission === 'granted');
    }
  };

  const loadPreferences = async () => {
    try {
      // Load from localStorage or backend
      const stored = localStorage.getItem('notification_preferences');
      if (stored) {
        setPreferences(JSON.parse(stored));
      }
    } catch (err) {
      console.error('Failed to load preferences:', err);
    }
  };

  const savePreferences = async (newPrefs) => {
    try {
      localStorage.setItem('notification_preferences', JSON.stringify(newPrefs));
      setSuccess('Preferences saved!');
      setSnackbarOpen(true);
    } catch (err) {
      setError('Failed to save preferences');
    }
  };

  const requestPermission = async () => {
    setLoading(true);
    setError(null);

    try {
      if (!('Notification' in window)) {
        throw new Error('Notifications not supported in this browser');
      }

      const permission = await Notification.requestPermission();
      setNotificationPermission(permission);
      setPushEnabled(permission === 'granted');

      if (permission === 'granted') {
        setSuccess('Push notifications enabled!');
        setSnackbarOpen(true);
        await registerPushToken();
      } else if (permission === 'denied') {
        setError('Permission denied. Please enable in browser settings.');
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const registerPushToken = async () => {
    try {
      const mockToken = `fcm_web_${Date.now()}`;

      if (!user?.user_id) {
        throw new Error('Missing user context');
      }

      const prefix = organizationId ? `${organizationId}:` : '';
      const storageKey = `wallet_device_id:${prefix || 'default'}`;
      let deviceId = localStorage.getItem(storageKey);
      if (!deviceId) {
        deviceId = `${prefix}web-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        localStorage.setItem(storageKey, deviceId);
      }

      await fetch(`${API_BASE_URL}/devices/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-User-ID': user.user_id },
        credentials: 'include',
        body: JSON.stringify({
          device_id: deviceId,
          fcm_token: mockToken,
          platform: 'web',
          app_version: 'web-1.0.0',
        }),
      });
    } catch (err) {
      console.error('Failed to register push token:', err);
    }
  };

  const handleCategoryChange = (categoryId) => (event) => {
    const newPrefs = {
      ...preferences,
      [categoryId]: event.target.checked,
    };
    setPreferences(newPrefs);
    savePreferences(newPrefs);
  };

  const handleMasterToggle = async () => {
    if (pushEnabled) {
      // Can't programmatically disable, just update state
      setPushEnabled(false);
      setSuccess('Notifications disabled locally');
      setSnackbarOpen(true);
    } else {
      await requestPermission();
    }
  };

  const sendTestNotification = async () => {
    setTestSending(true);
    setError(null);

    try {
      if (Notification.permission === 'granted') {
        new Notification('Test Notification', {
          body: `This is a test notification from ${branding.appName}`,
          icon: '/favicon.ico',
        });
        setSuccess('Test notification shown!');
        setSnackbarOpen(true);
      } else {
        setError('Please enable notifications first');
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setTestSending(false);
    }
  };

  return (
    <Container maxWidth="md" data-testid="notification-preferences-page">
      <Paper sx={{ p: 4, mt: 4 }}>
        <Typography variant="h4" gutterBottom data-testid="notification-settings-title">
          <NotificationsIcon sx={{ mr: 1, verticalAlign: 'middle' }} />
          Notification Settings
        </Typography>

        <Typography variant="body1" color="text.secondary" paragraph>
          Manage how and when you receive push notifications.
        </Typography>

        {error && (
          <Alert severity="error" sx={{ mb: 2 }} data-testid="notification-error">
            {error}
          </Alert>
        )}

        {/* Master Toggle */}
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                {pushEnabled ? (
                  <NotificationsIcon color="primary" fontSize="large" />
                ) : (
                  <NotificationsOffIcon color="disabled" fontSize="large" />
                )}
                <Box>
                  <Typography variant="h6" data-testid="push-status-label">
                    Push Notifications
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    {pushEnabled ? 'Enabled' : 'Disabled'}
                    {notificationPermission === 'denied' && ' (blocked in browser)'}
                  </Typography>
                </Box>
              </Box>

              <FormControlLabel
                control={
                  <Switch
                    checked={pushEnabled}
                    onChange={handleMasterToggle}
                    disabled={loading || notificationPermission === 'denied'}
                    data-testid="push-master-toggle"
                  />
                }
                label=""
              />
            </Box>

            {notificationPermission === 'denied' && (
              <Alert severity="warning" sx={{ mt: 2 }}>
                Notifications are blocked by your browser. Please update your browser settings to enable.
              </Alert>
            )}

            {notificationPermission === 'default' && (
              <Button
                variant="contained"
                onClick={requestPermission}
                disabled={loading}
                startIcon={loading ? <CircularProgress size={20} /> : <NotificationsIcon />}
                sx={{ mt: 2 }}
                data-testid="request-permission-button"
              >
                {loading ? 'Requesting...' : 'Enable Notifications'}
              </Button>
            )}
          </CardContent>
        </Card>

        {/* Category Preferences */}
        <Typography variant="h6" gutterBottom>
          Notification Categories
        </Typography>

        <Card sx={{ mb: 3 }}>
          <List data-testid="notification-categories-list">
            {NOTIFICATION_CATEGORIES.map((category, index) => (
              <React.Fragment key={category.id}>
                {index > 0 && <Divider />}
                <ListItem>
                  <ListItemText
                    primary={category.label}
                    secondary={category.description}
                    data-testid={`category-${category.id}`}
                  />
                  <ListItemSecondaryAction>
                    <Switch
                      edge="end"
                      checked={preferences[category.id] || false}
                      onChange={handleCategoryChange(category.id)}
                      disabled={!pushEnabled}
                      data-testid={`category-toggle-${category.id}`}
                    />
                  </ListItemSecondaryAction>
                </ListItem>
              </React.Fragment>
            ))}
          </List>
        </Card>

        {/* Test Notification */}
        <Typography variant="h6" gutterBottom>
          Test Notifications
        </Typography>

        <Card>
          <CardContent>
            <Typography variant="body2" color="text.secondary" paragraph>
              Send a test notification to verify your settings are working correctly.
            </Typography>

            <Button
              variant="outlined"
              startIcon={testSending ? <CircularProgress size={20} /> : <SendIcon />}
              onClick={sendTestNotification}
              disabled={testSending || !pushEnabled}
              data-testid="send-test-notification-button"
            >
              {testSending ? 'Sending...' : 'Send Test Notification'}
            </Button>
          </CardContent>
        </Card>
      </Paper>

      {/* Success Snackbar */}
      <Snackbar
        open={snackbarOpen}
        autoHideDuration={3000}
        onClose={() => setSnackbarOpen(false)}
        message={success}
        action={
          <IconButton size="small" color="inherit" onClick={() => setSnackbarOpen(false)}>
            <CloseIcon fontSize="small" />
          </IconButton>
        }
        data-testid="notification-snackbar"
      />
    </Container>
  );
};

export default NotificationPreferences;
