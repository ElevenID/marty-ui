/**
 * Freshness & Binding Step
 * 
 * Configure freshness requirements and holder binding methods.
 * Includes standard version tracking for compliance.
 */

import {
  Box,
  Typography,
  TextField,
  Card,
  CardContent,
  FormControl,
  RadioGroup,
  FormControlLabel,
  Radio,
  Switch,
  InputAdornment,
  Alert,
  Chip,
} from '@mui/material';
import TimerIcon from '@mui/icons-material/Timer';
import FingerprintIcon from '@mui/icons-material/Fingerprint';
import SecurityIcon from '@mui/icons-material/Security';
import VerifiedIcon from '@mui/icons-material/Verified';
import { useTranslation } from 'react-i18next';

const FreshnessBindingStep = ({ policyConfig, onConfigChange }) => {
  const { t } = useTranslation('console');

  const HOLDER_BINDING_OPTIONS = [
    {
      value: 'device_key',
      label: t('wizards.presentationPolicy.freshnessBindingStep.bindingOptions.device_key.label'),
      description: t('wizards.presentationPolicy.freshnessBindingStep.bindingOptions.device_key.description'),
      icon: <SecurityIcon />,
    },
    {
      value: 'session_nonce',
      label: t('wizards.presentationPolicy.freshnessBindingStep.bindingOptions.session_nonce.label'),
      description: t('wizards.presentationPolicy.freshnessBindingStep.bindingOptions.session_nonce.description'),
      icon: <TimerIcon />,
    },
    {
      value: 'biometric',
      label: t('wizards.presentationPolicy.freshnessBindingStep.bindingOptions.biometric.label'),
      description: t('wizards.presentationPolicy.freshnessBindingStep.bindingOptions.biometric.description'),
      icon: <FingerprintIcon />,
    },
    {
      value: 'none',
      label: t('wizards.presentationPolicy.freshnessBindingStep.bindingOptions.none.label'),
      description: t('wizards.presentationPolicy.freshnessBindingStep.bindingOptions.none.description'),
      icon: null,
    },
  ];

  const handleFieldChange = (field, value) => {
    onConfigChange({
      ...policyConfig,
      [field]: value,
    });
  };

  const handleFreshnessChange = (field, value) => {
    onConfigChange({
      ...policyConfig,
      freshness_requirements: {
        ...policyConfig.freshness_requirements,
        [field]: value,
      },
    });
  };

  const handleMetadataChange = (field, value) => {
    onConfigChange({
      ...policyConfig,
      metadata: {
        ...policyConfig.metadata,
        [field]: value,
      },
    });
  };

  // Convert seconds to days for display
  const secondsToDays = (seconds) => {
    return Math.floor(seconds / 86400);
  };

  // Convert days to seconds
  const daysToSeconds = (days) => {
    return days * 86400;
  };

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        {t('wizards.presentationPolicy.freshnessBindingStep.title')}
      </Typography>
      
      <Typography color="text.secondary" paragraph>
        {t('wizards.presentationPolicy.freshnessBindingStep.description')}
      </Typography>

      {/* Holder Binding */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600 }}>
            {t('wizards.presentationPolicy.freshnessBindingStep.sections.holderBinding')}
          </Typography>

          <Typography variant="body2" color="text.secondary" paragraph>
            {t('wizards.presentationPolicy.freshnessBindingStep.helpers.holderBinding')}
          </Typography>

          <FormControl component="fieldset" fullWidth>
            <RadioGroup
              value={policyConfig.holder_binding}
              onChange={(e) => handleFieldChange('holder_binding', e.target.value)}
            >
              {HOLDER_BINDING_OPTIONS.map((option) => (
                <Card
                  key={option.value}
                  variant="outlined"
                  sx={{
                    mb: 1,
                    border: 2,
                    borderColor: policyConfig.holder_binding === option.value ? 'primary.main' : 'transparent',
                    cursor: 'pointer',
                    '&:hover': {
                      borderColor: 'primary.light',
                    },
                  }}
                  onClick={() => handleFieldChange('holder_binding', option.value)}
                >
                  <CardContent sx={{ py: 1.5 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center' }}>
                      <FormControlLabel
                        value={option.value}
                        control={<Radio />}
                        label=""
                        sx={{ mr: 1 }}
                      />
                      {option.icon && (
                        <Box sx={{ mr: 1.5, display: 'flex', color: 'primary.main' }}>
                          {option.icon}
                        </Box>
                      )}
                      <Box sx={{ flex: 1 }}>
                        <Typography variant="body1" sx={{ fontWeight: 500 }}>
                          {option.label}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {option.description}
                        </Typography>
                      </Box>
                      {option.value === 'device_key' && (
                        <Chip label={t('wizards.presentationPolicy.freshnessBindingStep.recommendedChip')} size="small" color="success" />
                      )}
                    </Box>
                  </CardContent>
                </Card>
              ))}
            </RadioGroup>
          </FormControl>
        </CardContent>
      </Card>

      {/* Freshness Requirements */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600 }}>
            {t('wizards.presentationPolicy.freshnessBindingStep.sections.freshness')}
          </Typography>

          <Typography variant="body2" color="text.secondary" paragraph>
            {t('wizards.presentationPolicy.freshnessBindingStep.helpers.freshness')}
          </Typography>

          <TextField
            fullWidth
            type="number"
            label={t('wizards.presentationPolicy.freshnessBindingStep.fields.maxCredentialAge')}
            value={secondsToDays(policyConfig.freshness_requirements.max_credential_age_seconds)}
            onChange={(e) => handleFreshnessChange('max_credential_age_seconds', daysToSeconds(parseInt(e.target.value) || 0))}
            InputProps={{
              endAdornment: <InputAdornment position="end">{t('wizards.presentationPolicy.freshnessBindingStep.units.days')}</InputAdornment>,
            }}
            helperText={t('wizards.presentationPolicy.freshnessBindingStep.helpers.maxCredentialAge')}
            sx={{ mb: 2 }}
          />

          <TextField
            fullWidth
            type="number"
            label={t('wizards.presentationPolicy.freshnessBindingStep.fields.maxProofAge')}
            value={Math.floor(policyConfig.freshness_requirements.max_proof_age_seconds / 60)}
            onChange={(e) => handleFreshnessChange('max_proof_age_seconds', parseInt(e.target.value) * 60 || 300)}
            InputProps={{
              endAdornment: <InputAdornment position="end">{t('wizards.presentationPolicy.freshnessBindingStep.units.minutes')}</InputAdornment>,
            }}
            helperText={t('wizards.presentationPolicy.freshnessBindingStep.helpers.maxProofAge')}
            sx={{ mb: 2 }}
          />

          <FormControlLabel
            control={
              <Switch
                checked={policyConfig.freshness_requirements.require_revocation_check}
                onChange={(e) => handleFreshnessChange('require_revocation_check', e.target.checked)}
              />
            }
            label={
              <Box sx={{ display: 'flex', alignItems: 'center' }}>
                <VerifiedIcon sx={{ mr: 1, fontSize: 20 }} />
                <Typography variant="body2">{t('wizards.presentationPolicy.freshnessBindingStep.fields.requireRevocationCheck')}</Typography>
              </Box>
            }
          />
          <Typography variant="caption" color="text.secondary" display="block" sx={{ ml: 4 }}>
            {t('wizards.presentationPolicy.freshnessBindingStep.helpers.revocationCheck')}
          </Typography>
        </CardContent>
      </Card>

      {/* Standard Version Tracking */}
      <Card>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600 }}>
            {t('wizards.presentationPolicy.freshnessBindingStep.sections.compliance')}
          </Typography>

          <Typography variant="body2" color="text.secondary" paragraph>
            {t('wizards.presentationPolicy.freshnessBindingStep.helpers.compliance')}
          </Typography>

          <TextField
            fullWidth
            label={t('wizards.presentationPolicy.freshnessBindingStep.fields.standardReference')}
            value={policyConfig.metadata?.standard_reference || ''}
            onChange={(e) => handleMetadataChange('standard_reference', e.target.value)}
            placeholder={t('wizards.presentationPolicy.freshnessBindingStep.standardReferencePlaceholder')}
            helperText={t('wizards.presentationPolicy.freshnessBindingStep.helpers.standardReference')}
            sx={{ mb: 2 }}
          />

          {policyConfig.metadata?.standard_reference && (
            <Alert severity="info" icon={<VerifiedIcon />}>
              <Typography variant="body2">
                {t('wizards.presentationPolicy.freshnessBindingStep.standardReferenceInfo', {
                  standard: policyConfig.metadata.standard_reference,
                })}
              </Typography>
            </Alert>
          )}
        </CardContent>
      </Card>
    </Box>
  );
};

export default FreshnessBindingStep;
