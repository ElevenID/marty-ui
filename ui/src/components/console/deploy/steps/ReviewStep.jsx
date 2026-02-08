/**
 * Review Step - Deployment Profile Wizard
 * 
 * Final review of all configuration before submission.
 * Includes API key generation option.
 */

import {
  Box,
  Typography,
  Card,
  CardContent,
  Button,
  Chip,
  Grid,
  FormControlLabel,
  Switch,
  Divider,
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import SettingsIcon from '@mui/icons-material/Settings';
import WebhookIcon from '@mui/icons-material/Webhook';

const ENV_TYPE_LABELS = {
  api: 'API Service',
  kiosk: 'Kiosk',
  mobile: 'Mobile Verifier',
};

const NETWORK_MODE_LABELS = {
  ONLINE: 'Online',
  OFFLINE: 'Offline',
  HYBRID: 'Hybrid',
};

const ReviewStep = ({ data, onChange, onEdit }) => {
  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Review & Activate
      </Typography>
      <Typography color="text.secondary" paragraph>
        Review all configuration details before creating the deployment profile.
      </Typography>

      {/* Environment */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <CheckCircleIcon color="primary" />
              Environment
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(0)}>
              Edit
            </Button>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary">
                Profile Name
              </Typography>
              <Typography variant="body1" gutterBottom>
                {data.name || <em>Not set</em>}
              </Typography>
            </Grid>

            {data.description && (
              <Grid item xs={12}>
                <Typography variant="subtitle2" color="text.secondary">
                  Description
                </Typography>
                <Typography variant="body1" gutterBottom>
                  {data.description}
                </Typography>
              </Grid>
            )}

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Environment Type
              </Typography>
              <Typography variant="body1">
                {ENV_TYPE_LABELS[data.environment_type] || data.environment_type}
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Network Mode
              </Typography>
              <Typography variant="body1">
                {NETWORK_MODE_LABELS[data.network_mode] || data.network_mode}
              </Typography>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Runtime Settings */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <CloudUploadIcon color="primary" />
              Runtime Settings
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(1)}>
              Edit
            </Button>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary">
                Default Presentation Policy
              </Typography>
              <Typography variant="body1" gutterBottom>
                {data.default_policy_id ? `ID: ${data.default_policy_id}` : <em>Not selected</em>}
              </Typography>
            </Grid>

            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                Enabled Flows
              </Typography>
              {data.enabled_flows && data.enabled_flows.length > 0 ? (
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  {data.enabled_flows.map((flow) => (
                    <Chip key={flow} label={flow} color="primary" variant="outlined" />
                  ))}
                </Box>
              ) : (
                <Typography variant="body2" color="text.secondary">
                  No flows enabled
                </Typography>
              )}
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Integration */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <SettingsIcon color="primary" />
              Integration
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(2)}>
              Edit
            </Button>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary">
                Webhook
              </Typography>
              {data.webhooks?.url ? (
                <Box>
                  <Typography variant="body2" sx={{ fontFamily: 'monospace', mb: 1 }}>
                    {data.webhooks.url}
                  </Typography>
                  {data.webhooks.events && data.webhooks.events.length > 0 && (
                    <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                      {data.webhooks.events.map((event) => (
                        <Chip key={event} label={event} size="small" />
                      ))}
                    </Box>
                  )}
                </Box>
              ) : (
                <Typography variant="body2" color="text.secondary">
                  Not configured
                </Typography>
              )}
            </Grid>

            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                Feature Flags
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                {data.feature_flags?.qr_code && <Chip label="QR Code" size="small" />}
                {data.feature_flags?.nfc && <Chip label="NFC" size="small" />}
                {data.feature_flags?.ble && <Chip label="BLE" size="small" />}
                {!data.feature_flags?.qr_code && !data.feature_flags?.nfc && !data.feature_flags?.ble && (
                  <Typography variant="body2" color="text.secondary">
                    No features enabled
                  </Typography>
                )}
              </Box>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Theme
              </Typography>
              <Typography variant="body1">
                {data.ux_config?.theme || 'default'}
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                Language
              </Typography>
              <Typography variant="body1">
                {data.ux_config?.language || 'en'}
              </Typography>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      <Divider sx={{ my: 3 }} />

      {/* Activation Options */}
      <Box sx={{ p: 2, bgcolor: 'action.hover', borderRadius: 1, mb: 2 }}>
        <FormControlLabel
          control={
            <Switch
              checked={data.generate_api_key !== false}
              onChange={(e) => onChange({ generate_api_key: e.target.checked })}
            />
          }
          label={
            <Box>
              <Typography variant="subtitle2">
                Generate API key automatically
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Create an API key for programmatic access to this deployment
              </Typography>
            </Box>
          }
        />
      </Box>

      <Box sx={{ p: 2, bgcolor: 'action.hover', borderRadius: 1 }}>
        <FormControlLabel
          control={
            <Switch
              checked={data.activate_immediately !== false}
              onChange={(e) => onChange({ activate_immediately: e.target.checked })}
            />
          }
          label={
            <Box>
              <Typography variant="subtitle2">
                Activate immediately
              </Typography>
              <Typography variant="body2" color="text.secondary">
                Make this deployment profile active and ready to use
              </Typography>
            </Box>
          }
        />
      </Box>
    </Box>
  );
};

export default ReviewStep;
