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
import { useTranslation } from 'react-i18next';

const ReviewStep = ({ data, onChange, onEdit }) => {
  const { t } = useTranslation('console');

  const ENV_TYPE_LABELS = {
    api: t('wizards.deploymentProfile.reviewStep.environmentTypeLabels.api'),
    kiosk: t('wizards.deploymentProfile.reviewStep.environmentTypeLabels.kiosk'),
    mobile: t('wizards.deploymentProfile.reviewStep.environmentTypeLabels.mobile'),
  };

  const NETWORK_MODE_LABELS = {
    ONLINE: t('wizards.deploymentProfile.reviewStep.networkModeLabels.ONLINE'),
    OFFLINE: t('wizards.deploymentProfile.reviewStep.networkModeLabels.OFFLINE'),
    HYBRID: t('wizards.deploymentProfile.reviewStep.networkModeLabels.HYBRID'),
  };

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        {t('wizards.deploymentProfile.reviewStep.title')}
      </Typography>
      <Typography color="text.secondary" paragraph>
        {t('wizards.deploymentProfile.reviewStep.description')}
      </Typography>

      {/* Environment */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <CheckCircleIcon color="primary" />
              {t('wizards.deploymentProfile.reviewStep.sections.environment')}
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(0)}>
              {t('wizards.deploymentProfile.reviewStep.actions.edit')}
            </Button>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.deploymentProfile.reviewStep.fields.profileName')}
              </Typography>
              <Typography variant="body1" gutterBottom>
                {data.name || <em>{t('wizards.deploymentProfile.reviewStep.values.notSet')}</em>}
              </Typography>
            </Grid>

            {data.description && (
              <Grid item xs={12}>
                <Typography variant="subtitle2" color="text.secondary">
                  {t('wizards.deploymentProfile.reviewStep.fields.description')}
                </Typography>
                <Typography variant="body1" gutterBottom>
                  {data.description}
                </Typography>
              </Grid>
            )}

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.deploymentProfile.reviewStep.fields.environmentType')}
              </Typography>
              <Typography variant="body1">
                {ENV_TYPE_LABELS[data.environment_type] || data.environment_type}
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.deploymentProfile.reviewStep.fields.networkMode')}
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
              {t('wizards.deploymentProfile.reviewStep.sections.runtimeSettings')}
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(1)}>
              {t('wizards.deploymentProfile.reviewStep.actions.edit')}
            </Button>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.deploymentProfile.reviewStep.fields.defaultPolicy')}
              </Typography>
              <Typography variant="body1" gutterBottom>
                {data.default_policy_id
                  ? t('wizards.deploymentProfile.reviewStep.fields.policyId', { id: data.default_policy_id })
                  : <em>{t('wizards.deploymentProfile.reviewStep.values.notSelected')}</em>}
              </Typography>
            </Grid>

            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                {t('wizards.deploymentProfile.reviewStep.fields.enabledFlows')}
              </Typography>
              {data.enabled_flows && data.enabled_flows.length > 0 ? (
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  {data.enabled_flows.map((flow) => (
                    <Chip key={flow} label={flow} color="primary" variant="outlined" />
                  ))}
                </Box>
              ) : (
                <Typography variant="body2" color="text.secondary">
                  {t('wizards.deploymentProfile.reviewStep.values.noFlowsEnabled')}
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
              {t('wizards.deploymentProfile.reviewStep.sections.integration')}
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(2)}>
              {t('wizards.deploymentProfile.reviewStep.actions.edit')}
            </Button>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.deploymentProfile.reviewStep.fields.webhook')}
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
                  {t('wizards.deploymentProfile.reviewStep.values.notConfigured')}
                </Typography>
              )}
            </Grid>

            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                {t('wizards.deploymentProfile.reviewStep.fields.featureFlags')}
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                {data.feature_flags?.qr_code && <Chip label={t('wizards.deploymentProfile.reviewStep.featureChips.qrCode')} size="small" />}
                {data.feature_flags?.nfc && <Chip label={t('wizards.deploymentProfile.reviewStep.featureChips.nfc')} size="small" />}
                {data.feature_flags?.ble && <Chip label={t('wizards.deploymentProfile.reviewStep.featureChips.ble')} size="small" />}
                {!data.feature_flags?.qr_code && !data.feature_flags?.nfc && !data.feature_flags?.ble && (
                  <Typography variant="body2" color="text.secondary">
                    {t('wizards.deploymentProfile.reviewStep.values.noFeaturesEnabled')}
                  </Typography>
                )}
              </Box>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.deploymentProfile.reviewStep.fields.theme')}
              </Typography>
              <Typography variant="body1">
                {data.ux_config?.theme || t('wizards.deploymentProfile.reviewStep.values.defaultTheme')}
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.deploymentProfile.reviewStep.fields.language')}
              </Typography>
              <Typography variant="body1">
                {data.ux_config?.language || t('wizards.deploymentProfile.reviewStep.values.defaultLanguage')}
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
                {t('wizards.deploymentProfile.reviewStep.activationOptions.generateApiKey.label')}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {t('wizards.deploymentProfile.reviewStep.activationOptions.generateApiKey.description')}
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
                {t('wizards.deploymentProfile.reviewStep.activationOptions.activateImmediately.label')}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {t('wizards.deploymentProfile.reviewStep.activationOptions.activateImmediately.description')}
              </Typography>
            </Box>
          }
        />
      </Box>
    </Box>
  );
};

export default ReviewStep;
