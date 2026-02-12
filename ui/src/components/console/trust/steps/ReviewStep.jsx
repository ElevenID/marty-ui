/**
 * Review Step - Trust Profile Wizard
 * 
 * Final review of all configuration before submission.
 * Allows editing via back navigation and activation toggle.
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
  List,
  ListItem,
  ListItemText,
  Alert,
} from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import SecurityIcon from '@mui/icons-material/Security';
import InfoIcon from '@mui/icons-material/Info';
import { useTranslation } from 'react-i18next';

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

      {/* Basic Information */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <CheckCircleIcon color="primary" />
              {t('wizards.trustProfile.reviewStep.sections.basicInformation')}
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(0)}>
              {t('wizards.trustProfile.reviewStep.actions.edit')}
            </Button>
          </Box>

          <Grid container spacing={2}>
            <Grid item xs={12}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.trustProfile.reviewStep.fields.profileName')}
              </Typography>
              <Typography variant="body1" gutterBottom>
                {data.name || <em>{t('wizards.trustProfile.reviewStep.values.notSet')}</em>}
              </Typography>
            </Grid>

            {data.description && (
              <Grid item xs={12}>
                <Typography variant="subtitle2" color="text.secondary">
                  {t('wizards.trustProfile.reviewStep.fields.description')}
                </Typography>
                <Typography variant="body1" gutterBottom>
                  {data.description}
                </Typography>
              </Grid>
            )}

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.trustProfile.reviewStep.fields.frameworkType')}
              </Typography>
              <Typography variant="body1">
                {getFrameworkLabel(t, data.framework_type)}
              </Typography>
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
        </CardContent>
      </Card>

      {/* Trust Sources */}
      <Card sx={{ mb: 2 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <SecurityIcon color="primary" />
              {t('wizards.trustProfile.reviewStep.sections.trustSources')}
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(1)}>
              {t('wizards.trustProfile.reviewStep.actions.edit')}
            </Button>
          </Box>

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
        </CardContent>
      </Card>

      {/* Validation Rules */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
            <Typography variant="h6">
              {t('wizards.trustProfile.reviewStep.sections.validationRules')}
            </Typography>
            <Button size="small" startIcon={<EditIcon />} onClick={() => onEdit(2)}>
              {t('wizards.trustProfile.reviewStep.actions.edit')}
            </Button>
          </Box>

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
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.trustProfile.reviewStep.fields.selfSignedCredentials')}
              </Typography>
              <Typography variant="body1">
                {data.validation_rules?.allow_self_signed
                  ? t('wizards.trustProfile.reviewStep.values.allowed')
                  : t('wizards.trustProfile.reviewStep.values.notAllowed')}
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.trustProfile.reviewStep.fields.minimumKeySize')}
              </Typography>
              <Typography variant="body1">
                {(data.validation_rules?.min_key_size || 2048)} {t('wizards.trustProfile.reviewStep.values.bits')}
              </Typography>
            </Grid>

            <Grid item xs={12} md={6}>
              <Typography variant="subtitle2" color="text.secondary">
                {t('wizards.trustProfile.reviewStep.fields.keyUsageValidation')}
              </Typography>
              <Typography variant="body1">
                {data.validation_rules?.require_key_usage !== false
                  ? t('wizards.trustProfile.reviewStep.values.required')
                  : t('wizards.trustProfile.reviewStep.values.notRequired')}
              </Typography>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

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
                {t('wizards.trustProfile.reviewStep.activateImmediately.label')}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {t('wizards.trustProfile.reviewStep.activateImmediately.description')}
              </Typography>
            </Box>
          }
        />
      </Box>
    </Box>
  );
};

export default ReviewStep;
