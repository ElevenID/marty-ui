/**
 * Review Step - Trust Profile Wizard
 * 
 * Final review of all configuration before submission.
 * Allows editing via back navigation and activation toggle.
 */

import {
  Box,
  Typography,
  Chip,
  Grid,
  Divider,
  List,
  ListItem,
  ListItemText,
  Alert,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import SecurityIcon from '@mui/icons-material/Security';
import InfoIcon from '@mui/icons-material/Info';
import { useTranslation } from 'react-i18next';
import { ReviewSectionCard, ReviewToggleOption, ReviewField } from '../../../common';

const getFrameworkLabel = (t, frameworkType) => {
  const key = `wizards.trustProfile.frameworkLabels.${frameworkType}`;
  return t(key, { defaultValue: frameworkType });
};

const getFormatLabel = (t, format) => {
  const key = `wizards.trustProfile.formatLabels.${format}`;
  return t(key, { defaultValue: format });
};

const getRevocationLabel = (t, mode) => {
  const normalizedMode = String(mode || 'HARD_FAIL').toUpperCase();
  const key = `wizards.trustProfile.reviewStep.values.revocation.${normalizedMode.toLowerCase()}`;
  return t(key, { defaultValue: normalizedMode.replaceAll('_', ' ') });
};

const formatSeconds = (seconds) => {
  const value = Number(seconds || 0);

  if (value % 86400 === 0) {
    const days = value / 86400;
    return `${days} day${days === 1 ? '' : 's'}`;
  }

  if (value % 3600 === 0) {
    const hours = value / 3600;
    return `${hours} hour${hours === 1 ? '' : 's'}`;
  }

  if (value % 60 === 0) {
    const minutes = value / 60;
    return `${minutes} minute${minutes === 1 ? '' : 's'}`;
  }

  return `${value} seconds`;
};

const ReviewStep = ({ data, onChange, onEdit }) => {
  const { t } = useTranslation('console');
  const allowAllIssuers = data.allow_all_issuers === true;
  const hasTrustSourcesConfigured = (data.trusted_issuers?.length || 0) > 0 || (data.trust_sources?.length || 0) > 0;
  const activeProfileMissingTrustSources = data.activate_immediately && !allowAllIssuers && !hasTrustSourcesConfigured;
  const emptyTrustSummaryKey = allowAllIssuers
    ? 'wizards.trustProfile.reviewStep.trustSourcesSummary.noneConfiguredAllowAll'
    : activeProfileMissingTrustSources
      ? 'wizards.trustProfile.reviewStep.trustSourcesSummary.noneConfiguredActive'
      : 'wizards.trustProfile.reviewStep.trustSourcesSummary.noneConfigured';
  const emptyTrustSummaryDefault = allowAllIssuers
    ? 'No trust sources are configured. This profile is explicitly set to trust any issuer that passes cryptographic validation.'
    : activeProfileMissingTrustSources
      ? 'This profile is set to activate immediately, but no trust sources are configured. Add a trusted issuer or explicitly allow any issuer before activating.'
      : 'No trust sources are configured. This profile will trust no issuers until trust sources are added.';
  const timePolicy = {
    clock_skew_seconds: 300,
    require_freshness: false,
    freshness_window_seconds: 86400,
    ...(data.time_policy || {}),
  };
  const supportedWallets = data.supported_wallet_ids || [];

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        {t('wizards.trustProfile.reviewStep.title')}
      </Typography>
      <Typography color="text.secondary" paragraph>
        {t('wizards.trustProfile.reviewStep.description')}
      </Typography>

      {!hasTrustSourcesConfigured && (
        <Alert severity={activeProfileMissingTrustSources ? 'error' : allowAllIssuers ? 'warning' : 'info'} sx={{ mb: 2 }}>
          <Typography variant="body2">
            {t(emptyTrustSummaryKey, { defaultValue: emptyTrustSummaryDefault })}
          </Typography>
        </Alert>
      )}

      {/* Basic Information */}
      <ReviewSectionCard
        sx={{ mb: 2 }}
        title={t('wizards.trustProfile.reviewStep.sections.basicInformation')}
        icon={<CheckCircleIcon color="primary" />}
        onEdit={() => onEdit(0)}
        editLabel={t('wizards.trustProfile.reviewStep.actions.edit')}
      >
          <Grid container spacing={2}>
            <Grid item xs={12}>
              <ReviewField
                label={t('wizards.trustProfile.reviewStep.fields.profileName')}
                value={data.name}
                placeholder={t('wizards.trustProfile.reviewStep.values.notSet')}
                gutterBottom
              />
            </Grid>

            {data.description && (
              <Grid item xs={12}>
                <ReviewField
                  label={t('wizards.trustProfile.reviewStep.fields.description')}
                  value={data.description}
                  gutterBottom
                />
              </Grid>
            )}

            <Grid item xs={12} md={6}>
              <ReviewField
                label={t('wizards.trustProfile.reviewStep.fields.frameworkType')}
                value={getFrameworkLabel(t, data.framework_type)}
              />
            </Grid>

            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                {t('wizards.trustProfile.reviewStep.fields.supportedFormats')}
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                {(data.supported_formats || []).map((format) => (
                  <Chip
                    key={format}
                    label={getFormatLabel(t, format)}
                    size="small"
                    color="primary"
                    variant="outlined"
                  />
                ))}
              </Box>
            </Grid>
          </Grid>
      </ReviewSectionCard>

      {/* Trust Sources */}
      <ReviewSectionCard
        sx={{ mb: 2 }}
        title={t('wizards.trustProfile.reviewStep.sections.trustSources')}
        icon={<SecurityIcon color="primary" />}
        onEdit={() => onEdit(1)}
        editLabel={t('wizards.trustProfile.reviewStep.actions.edit')}
      >
          {data.trusted_issuers && data.trusted_issuers.length > 0 ? (
            <Box>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                {t('wizards.trustProfile.reviewStep.trustSourcesSummary.trustedIssuersConfigured', {
                  count: data.trusted_issuers.length,
                })}
              </Typography>
              <List dense>
                {data.trusted_issuers.slice(0, 3).map((issuer, index) => (
                  <ListItem key={index} sx={{ px: 0 }}>
                    <ListItemText
                      primary={
                        issuer.certificate_pem ? (
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <Chip label="X.509" size="small" color="warning" />
                            <Typography variant="body2">{issuer.name || 'Root CA Certificate'}</Typography>
                          </Box>
                        ) : (
                          <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                            {issuer.did}
                          </Typography>
                        )
                      }
                    />
                  </ListItem>
                ))}
                {data.trusted_issuers.length > 3 && (
                  <Typography variant="body2" color="text.secondary">
                    {t('wizards.trustProfile.reviewStep.trustSourcesSummary.andMore', {
                      count: data.trusted_issuers.length - 3,
                    })}
                  </Typography>
                )}
              </List>
            </Box>
          ) : (
            <Typography variant="body2" color="text.secondary">
              {t(emptyTrustSummaryKey, { defaultValue: emptyTrustSummaryDefault })}
            </Typography>
          )}
      </ReviewSectionCard>

      {/* Validation Rules */}
      <ReviewSectionCard
        sx={{ mb: 3 }}
        title={t('wizards.trustProfile.reviewStep.sections.validationRules')}
        onEdit={() => onEdit(2)}
        editLabel={t('wizards.trustProfile.reviewStep.actions.edit')}
      >
          <Grid container spacing={2}>
            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                {t('wizards.trustProfile.reviewStep.fields.allowedAlgorithms')}
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                {(data.validation_rules?.allowed_algorithms || []).map((alg) => (
                  <Chip key={alg} label={alg} size="small" />
                ))}
              </Box>
            </Grid>

            <Grid item xs={12} md={6}>
              <ReviewField
                label={t('wizards.trustProfile.reviewStep.fields.selfSignedCredentials')}
                value={data.validation_rules?.allow_self_signed
                  ? t('wizards.trustProfile.reviewStep.values.allowed')
                  : t('wizards.trustProfile.reviewStep.values.notAllowed')}
              />
            </Grid>

            <Grid item xs={12} md={6}>
              <ReviewField
                label={t('wizards.trustProfile.reviewStep.fields.minimumKeySize')}
                value={`${data.validation_rules?.min_key_size || 2048} ${t('wizards.trustProfile.reviewStep.values.bits')}`}
              />
            </Grid>

            <Grid item xs={12} md={6}>
              <ReviewField
                label={t('wizards.trustProfile.reviewStep.fields.keyUsageValidation')}
                value={data.validation_rules?.require_key_usage !== false
                  ? t('wizards.trustProfile.reviewStep.values.required')
                  : t('wizards.trustProfile.reviewStep.values.notRequired')}
              />
            </Grid>

            <Grid item xs={12} md={6}>
              <ReviewField
                label={t(
                  'wizards.trustProfile.reviewStep.fields.revocationStrategy',
                  { defaultValue: 'Revocation strategy' },
                )}
                value={getRevocationLabel(t, data.revocation_policy?.check_mode)}
              />
            </Grid>

            <Grid item xs={12} md={6}>
              <ReviewField
                label={t(
                  'wizards.trustProfile.reviewStep.fields.clockSkew',
                  { defaultValue: 'Clock skew tolerance' },
                )}
                value={formatSeconds(timePolicy.clock_skew_seconds)}
              />
            </Grid>

            <Grid item xs={12} md={6}>
              <ReviewField
                label={t(
                  'wizards.trustProfile.reviewStep.fields.credentialFreshness',
                  { defaultValue: 'Credential freshness' },
                )}
                value={timePolicy.require_freshness
                  ? `${t('wizards.trustProfile.reviewStep.values.required')} (${formatSeconds(timePolicy.freshness_window_seconds)})`
                  : t('wizards.trustProfile.reviewStep.values.notRequired')}
              />
            </Grid>

            <Grid item xs={12}>
              <ReviewField
                label={t(
                  'wizards.trustProfile.reviewStep.fields.issuanceProtocol',
                  { defaultValue: 'Issuance protocol' },
                )}
                value={String(data.issuance_protocol || 'oid4vci').toUpperCase()}
              />
            </Grid>

            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                {t(
                  'wizards.trustProfile.reviewStep.fields.supportedWallets',
                  { defaultValue: 'Supported wallets' },
                )}
              </Typography>
              {supportedWallets.length > 0 ? (
                <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                  {supportedWallets.map((walletId) => (
                    <Chip key={walletId} label={walletId} size="small" />
                  ))}
                </Box>
              ) : (
                <Typography variant="body2" color="text.secondary">
                  {t(
                    'wizards.trustProfile.reviewStep.values.allCompatibleWallets',
                    { defaultValue: 'No wallet targeting configured' },
                  )}
                </Typography>
              )}
            </Grid>
          </Grid>
      </ReviewSectionCard>

      <Divider sx={{ my: 3 }} />

      {/* Activation Explanation */}
      <Alert severity="info" icon={<InfoIcon />} sx={{ mb: 2 }}>
        <Typography variant="body2" gutterBottom>
          <strong>{t('wizards.trustProfile.reviewStep.activationExplanation.title')}</strong>
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {t('wizards.trustProfile.reviewStep.activationExplanation.description')}
        </Typography>
      </Alert>

      {/* Activation Toggle */}
      <ReviewToggleOption
        checked={data.activate_immediately !== false}
        onChange={(e) => onChange({ activate_immediately: e.target.checked })}
        title={t('wizards.trustProfile.reviewStep.activateImmediately.label')}
        description={t('wizards.trustProfile.reviewStep.activateImmediately.description')}
      />
    </Box>
  );
};

export default ReviewStep;
