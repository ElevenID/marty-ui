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
import { useTranslation } from 'react-i18next';

const IntegrationStep = ({ data, onChange }) => {
  const { t } = useTranslation('console');
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
        {t('wizards.deploymentProfile.integrationStep.title')}
      </Typography>
      <Typography color="text.secondary" paragraph>
        {t('wizards.deploymentProfile.integrationStep.description')}
      </Typography>

      <Alert severity="info" icon={<InfoIcon />} sx={{ mb: 3 }}>
        {t('wizards.deploymentProfile.integrationStep.defaultsInfo')}
      </Alert>

      {/* Webhooks */}
      <Typography variant="subtitle2" gutterBottom>
        {t('wizards.deploymentProfile.integrationStep.sections.webhooks')}
      </Typography>
      <Typography variant="body2" color="text.secondary" paragraph>
        {t('wizards.deploymentProfile.integrationStep.helpers.webhooks')}
      </Typography>

      <TextField
        fullWidth
        label={t('wizards.deploymentProfile.integrationStep.fields.webhookUrl')}
        placeholder={t('wizards.deploymentProfile.integrationStep.placeholders.webhookUrl')}
        value={webhooks.url || ''}
        onChange={(e) => handleWebhookChange('url', e.target.value)}
        sx={{ mb: 2 }}
        helperText={t('wizards.deploymentProfile.integrationStep.helpers.webhookUrl')}
      />

      {webhooks.url && (
        <FormGroup sx={{ mb: 3 }}>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            {t('wizards.deploymentProfile.integrationStep.helpers.webhookEvents')}
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
        {t('wizards.deploymentProfile.integrationStep.sections.featureFlags')}
      </Typography>
      <Typography variant="body2" color="text.secondary" paragraph>
        {t('wizards.deploymentProfile.integrationStep.helpers.featureFlags')}
      </Typography>

      <FormGroup sx={{ mb: 3 }}>
        <FormControlLabel
          control={
            <Checkbox
              checked={featureFlags.qr_code !== false}
              onChange={(e) => handleFeatureFlagChange('qr_code', e.target.checked)}
            />
          }
          label={t('wizards.deploymentProfile.integrationStep.featureFlags.qrCode')}
        />
        <FormHelperText sx={{ ml: 4, mt: -1, mb: 2 }}>
          {t('wizards.deploymentProfile.integrationStep.helpers.qrCode')}
        </FormHelperText>

        <FormControlLabel
          control={
            <Checkbox
              checked={featureFlags.nfc || false}
              onChange={(e) => handleFeatureFlagChange('nfc', e.target.checked)}
            />
          }
          label={t('wizards.deploymentProfile.integrationStep.featureFlags.nfc')}
        />
        <FormHelperText sx={{ ml: 4, mt: -1, mb: 2 }}>
          {t('wizards.deploymentProfile.integrationStep.helpers.nfc')}
        </FormHelperText>

        <FormControlLabel
          control={
            <Checkbox
              checked={featureFlags.ble || false}
              onChange={(e) => handleFeatureFlagChange('ble', e.target.checked)}
            />
          }
          label={t('wizards.deploymentProfile.integrationStep.featureFlags.ble')}
        />
        <FormHelperText sx={{ ml: 4, mt: -1 }}>
          {t('wizards.deploymentProfile.integrationStep.helpers.ble')}
        </FormHelperText>
      </FormGroup>

      <Divider sx={{ my: 3 }} />

      {/* UX Configuration */}
      <Typography variant="subtitle2" gutterBottom>
        {t('wizards.deploymentProfile.integrationStep.sections.userExperience')}
      </Typography>
      <Typography variant="body2" color="text.secondary" paragraph>
        {t('wizards.deploymentProfile.integrationStep.helpers.ux')}
      </Typography>

      <Grid container spacing={2}>
        <Grid item xs={12} md={6}>
          <FormControl fullWidth>
            <InputLabel>{t('wizards.deploymentProfile.integrationStep.fields.theme')}</InputLabel>
            <Select
              value={uxConfig.theme || 'default'}
              onChange={(e) => handleUxConfigChange('theme', e.target.value)}
              label={t('wizards.deploymentProfile.integrationStep.fields.theme')}
            >
              <MenuItem value="default">{t('wizards.deploymentProfile.integrationStep.themes.default')}</MenuItem>
              <MenuItem value="light">{t('wizards.deploymentProfile.integrationStep.themes.light')}</MenuItem>
              <MenuItem value="dark">{t('wizards.deploymentProfile.integrationStep.themes.dark')}</MenuItem>
              <MenuItem value="high-contrast">{t('wizards.deploymentProfile.integrationStep.themes.highContrast')}</MenuItem>
            </Select>
            <FormHelperText>{t('wizards.deploymentProfile.integrationStep.helpers.theme')}</FormHelperText>
          </FormControl>
        </Grid>

        <Grid item xs={12} md={6}>
          <FormControl fullWidth>
            <InputLabel>{t('wizards.deploymentProfile.integrationStep.fields.language')}</InputLabel>
            <Select
              value={uxConfig.language || 'en'}
              onChange={(e) => handleUxConfigChange('language', e.target.value)}
              label={t('wizards.deploymentProfile.integrationStep.fields.language')}
            >
              <MenuItem value="en">{t('wizards.deploymentProfile.integrationStep.languages.en')}</MenuItem>
              <MenuItem value="es">{t('wizards.deploymentProfile.integrationStep.languages.es')}</MenuItem>
              <MenuItem value="fr">{t('wizards.deploymentProfile.integrationStep.languages.fr')}</MenuItem>
              <MenuItem value="de">{t('wizards.deploymentProfile.integrationStep.languages.de')}</MenuItem>
            </Select>
            <FormHelperText>{t('wizards.deploymentProfile.integrationStep.helpers.language')}</FormHelperText>
          </FormControl>
        </Grid>
      </Grid>
    </Box>
  );
};

export default IntegrationStep;
