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

const ReviewStep = ({ data, onChange, onEdit }) => {
  const { t } = useTranslation('console');

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        {t('wizards.trustProfile.reviewStep.title')}
      </Typography>
      <Typography color="text.secondary" paragraph>
        {t('wizards.trustProfile.reviewStep.description')}
      </Typography>

      {(data.trusted_issuers?.length || 0) === 0 && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          <Typography variant="body2">
            {t('wizards.trustProfile.reviewStep.trustSourcesRequired', {
              defaultValue: 'Add at least one trusted issuer before creating this trust profile.',
            })}
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
                        <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: '0.875rem' }}>
                          {issuer.did}
                        </Typography>
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
              {t('wizards.trustProfile.reviewStep.trustSourcesSummary.noneConfigured')}
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
