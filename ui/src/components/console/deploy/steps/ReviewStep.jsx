/**
 * Review Step - Deployment Profile Wizard
 * 
 * Final review of all configuration before submission.
 * Includes API key generation option.
 */

import {
  Box,
  Typography,
  Chip,
  Grid,
  Divider,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import SettingsIcon from '@mui/icons-material/Settings';
import { useTranslation } from 'react-i18next';
import { ReviewSectionCard, ReviewToggleOption, ReviewField } from '../../../common';

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
      <ReviewSectionCard
        sx={{ mb: 2 }}
        title={t('wizards.deploymentProfile.reviewStep.sections.environment')}
        icon={<CheckCircleIcon color="primary" />}
        onEdit={() => onEdit(0)}
        editLabel={t('wizards.deploymentProfile.reviewStep.actions.edit')}
      >
          <Grid container spacing={2}>
            <Grid item xs={12}>
              <ReviewField
                label={t('wizards.deploymentProfile.reviewStep.fields.profileName')}
                value={data.name}
                placeholder={t('wizards.deploymentProfile.reviewStep.values.notSet')}
                gutterBottom
              />
            </Grid>

            {data.description && (
              <Grid item xs={12}>
                <ReviewField
                  label={t('wizards.deploymentProfile.reviewStep.fields.description')}
                  value={data.description}
                  gutterBottom
                />
              </Grid>
            )}

            <Grid item xs={12} md={6}>
              <ReviewField
                label={t('wizards.deploymentProfile.reviewStep.fields.environmentType')}
                value={ENV_TYPE_LABELS[data.environment_type] || data.environment_type}
              />
            </Grid>

            <Grid item xs={12} md={6}>
              <ReviewField
                label={t('wizards.deploymentProfile.reviewStep.fields.networkMode')}
                value={NETWORK_MODE_LABELS[data.network_mode] || data.network_mode}
              />
            </Grid>
          </Grid>
      </ReviewSectionCard>

      {/* Runtime Settings */}
      <ReviewSectionCard
        sx={{ mb: 2 }}
        title={t('wizards.deploymentProfile.reviewStep.sections.runtimeSettings')}
        icon={<CloudUploadIcon color="primary" />}
        onEdit={() => onEdit(1)}
        editLabel={t('wizards.deploymentProfile.reviewStep.actions.edit')}
      >
          <Grid container spacing={2}>
            <Grid item xs={12}>
              <ReviewField
                label={t('wizards.deploymentProfile.reviewStep.fields.defaultPolicy')}
                value={data.default_policy_id
                  ? t('wizards.deploymentProfile.reviewStep.fields.policyId', { id: data.default_policy_id })
                  : undefined}
                placeholder={t('wizards.deploymentProfile.reviewStep.values.notSelected')}
                gutterBottom
              />
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
      </ReviewSectionCard>

      {/* Integration */}
      <ReviewSectionCard
        sx={{ mb: 3 }}
        title={t('wizards.deploymentProfile.reviewStep.sections.integration')}
        icon={<SettingsIcon color="primary" />}
        onEdit={() => onEdit(2)}
        editLabel={t('wizards.deploymentProfile.reviewStep.actions.edit')}
      >
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
              <ReviewField
                label={t('wizards.deploymentProfile.reviewStep.fields.theme')}
                value={data.ux_config?.theme || t('wizards.deploymentProfile.reviewStep.values.defaultTheme')}
              />
            </Grid>

            <Grid item xs={12} md={6}>
              <ReviewField
                label={t('wizards.deploymentProfile.reviewStep.fields.language')}
                value={data.ux_config?.language || t('wizards.deploymentProfile.reviewStep.values.defaultLanguage')}
              />
            </Grid>
          </Grid>
      </ReviewSectionCard>

      <Divider sx={{ my: 3 }} />

      {/* Activation Options */}
      <ReviewToggleOption
        sx={{ mb: 2 }}
        checked={data.generate_api_key !== false}
        onChange={(e) => onChange({ generate_api_key: e.target.checked })}
        title={t('wizards.deploymentProfile.reviewStep.activationOptions.generateApiKey.label')}
        description={t('wizards.deploymentProfile.reviewStep.activationOptions.generateApiKey.description')}
      />

      <ReviewToggleOption
        checked={data.activate_immediately !== false}
        onChange={(e) => onChange({ activate_immediately: e.target.checked })}
        title={t('wizards.deploymentProfile.reviewStep.activationOptions.activateImmediately.label')}
        description={t('wizards.deploymentProfile.reviewStep.activationOptions.activateImmediately.description')}
      />
    </Box>
  );
};

export default ReviewStep;
