/**
 * Integration Step - Deployment Profile Wizard
 * 
 * Configure webhooks, feature flags, and UX settings.
 * This step is optional.
 */

import {
  Box,
  Typography,
  TextField,
  FormGroup,
  FormControlLabel,
  Checkbox,
  Alert,
  Divider,
  Grid,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormHelperText,
} from '@mui/material';
import InfoIcon from '@mui/icons-material/Info';

const IntegrationStep = ({ data, onChange }) => {
  const webhooks = data.webhooks || { url: '', events: [] };
  const featureFlags = data.feature_flags || { qr_code: true, nfc: false, ble: false };
  const uxConfig = data.ux_config || { theme: 'default', language: 'en' };

  const handleWebhookChange = (key, value) => {
    onChange({ webhooks: { ...webhooks, [key]: value } });
  };

  const handleFeatureFlagChange = (key, value) => {
    onChange({ feature_flags: { ...featureFlags, [key]: value } });
  };

  const handleUxConfigChange = (key, value) => {
    onChange({ ux_config: { ...uxConfig, [key]: value } });
  };

  const WEBHOOK_EVENTS = [
    'credential.issued',
    'credential.verified',
    'credential.revoked',
    'verification.failed',
  ];

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Integration (Optional)
      </Typography>
      <Typography color="text.secondary" paragraph>
        Configure webhooks, feature flags, and user experience settings. You can skip this step and configure later.
      </Typography>

      <Alert severity="info" icon={<InfoIcon />} sx={{ mb: 3 }}>
        These settings are optional. Skip this step to use defaults.
      </Alert>

      {/* Webhooks */}
      <Typography variant="subtitle2" gutterBottom>
        Webhooks
      </Typography>
      <Typography variant="body2" color="text.secondary" paragraph>
        Receive real-time notifications about events
      </Typography>

      <TextField
        fullWidth
        label="Webhook URL"
        placeholder="https://your-app.com/webhooks"
        value={webhooks.url || ''}
        onChange={(e) => handleWebhookChange('url', e.target.value)}
        sx={{ mb: 2 }}
        helperText="POST requests will be sent to this URL for selected events"
      />

      {webhooks.url && (
        <FormGroup sx={{ mb: 3 }}>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            Webhook Events
          </Typography>
          {WEBHOOK_EVENTS.map((event) => (
            <FormControlLabel
              key={event}
              control={
                <Checkbox
                  checked={(webhooks.events || []).includes(event)}
                  onChange={(e) => {
                    const events = webhooks.events || [];
                    const updated = e.target.checked
                      ? [...events, event]
                      : events.filter((ev) => ev !== event);
                    handleWebhookChange('events', updated);
                  }}
                />
              }
              label={event}
            />
          ))}
        </FormGroup>
      )}

      <Divider sx={{ my: 3 }} />

      {/* Feature Flags */}
      <Typography variant="subtitle2" gutterBottom>
        Feature Flags
      </Typography>
      <Typography variant="body2" color="text.secondary" paragraph>
        Enable or disable specific features for this deployment
      </Typography>

      <FormGroup sx={{ mb: 3 }}>
        <FormControlLabel
          control={
            <Checkbox
              checked={featureFlags.qr_code !== false}
              onChange={(e) => handleFeatureFlagChange('qr_code', e.target.checked)}
            />
          }
          label="QR Code Support"
        />
        <FormHelperText sx={{ ml: 4, mt: -1, mb: 2 }}>
          Enable QR code scanning for credential exchange
        </FormHelperText>

        <FormControlLabel
          control={
            <Checkbox
              checked={featureFlags.nfc || false}
              onChange={(e) => handleFeatureFlagChange('nfc', e.target.checked)}
            />
          }
          label="NFC Support"
        />
        <FormHelperText sx={{ ml: 4, mt: -1, mb: 2 }}>
          Enable Near Field Communication for contactless exchange
        </FormHelperText>

        <FormControlLabel
          control={
            <Checkbox
              checked={featureFlags.ble || false}
              onChange={(e) => handleFeatureFlagChange('ble', e.target.checked)}
            />
          }
          label="Bluetooth Low Energy (BLE) Support"
        />
        <FormHelperText sx={{ ml: 4, mt: -1 }}>
          Enable Bluetooth for proximity-based exchange
        </FormHelperText>
      </FormGroup>

      <Divider sx={{ my: 3 }} />

      {/* UX Configuration */}
      <Typography variant="subtitle2" gutterBottom>
        User Experience
      </Typography>
      <Typography variant="body2" color="text.secondary" paragraph>
        Customize the look and feel of this deployment
      </Typography>

      <Grid container spacing={2}>
        <Grid item xs={12} md={6}>
          <FormControl fullWidth>
            <InputLabel>Theme</InputLabel>
            <Select
              value={uxConfig.theme || 'default'}
              onChange={(e) => handleUxConfigChange('theme', e.target.value)}
              label="Theme"
            >
              <MenuItem value="default">Default</MenuItem>
              <MenuItem value="light">Light</MenuItem>
              <MenuItem value="dark">Dark</MenuItem>
              <MenuItem value="high-contrast">High Contrast</MenuItem>
            </Select>
            <FormHelperText>Visual theme for user interfaces</FormHelperText>
          </FormControl>
        </Grid>

        <Grid item xs={12} md={6}>
          <FormControl fullWidth>
            <InputLabel>Language</InputLabel>
            <Select
              value={uxConfig.language || 'en'}
              onChange={(e) => handleUxConfigChange('language', e.target.value)}
              label="Language"
            >
              <MenuItem value="en">English</MenuItem>
              <MenuItem value="es">Español</MenuItem>
              <MenuItem value="fr">Français</MenuItem>
              <MenuItem value="de">Deutsch</MenuItem>
            </Select>
            <FormHelperText>Default language for user interfaces</FormHelperText>
          </FormControl>
        </Grid>
      </Grid>
    </Box>
  );
};

export default IntegrationStep;
