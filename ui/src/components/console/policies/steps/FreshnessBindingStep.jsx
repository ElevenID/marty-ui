/**
 * Freshness & Binding Step
 * 
 * Configure freshness requirements and holder binding methods.
 */

import { useId } from 'react';
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
  Chip,
} from '@mui/material';
import TimerIcon from '@mui/icons-material/Timer';
import KeyIcon from '@mui/icons-material/Key';
import SecurityIcon from '@mui/icons-material/Security';
import VerifiedIcon from '@mui/icons-material/Verified';
import { useTranslation } from 'react-i18next';
import { isValidPolicyCredentialAge } from '../policyFreshnessValidation';

const FreshnessBindingStep = ({ policyConfig, onConfigChange }) => {
  const { t } = useTranslation('console');
  const bindingId = useId();
  const credentialAge = policyConfig.freshness_requirements?.max_credential_age_seconds ?? '';
  const validCredentialAge = isValidPolicyCredentialAge(credentialAge);

  const HOLDER_BINDING_OPTIONS = [
    {
      value: 'device_key',
      label: t('wizards.presentationPolicy.freshnessBindingStep.bindingOptions.device_key.label'),
      description: t('wizards.presentationPolicy.freshnessBindingStep.bindingOptions.device_key.description'),
      icon: <SecurityIcon />,
    },
    {
      value: 'session_binding',
      label: t('wizards.presentationPolicy.freshnessBindingStep.bindingOptions.session_binding.label'),
      description: t('wizards.presentationPolicy.freshnessBindingStep.bindingOptions.session_binding.description'),
      icon: <TimerIcon />,
    },
    {
      value: 'credential_key',
      label: t('wizards.presentationPolicy.freshnessBindingStep.bindingOptions.credential_key.label'),
      description: t('wizards.presentationPolicy.freshnessBindingStep.bindingOptions.credential_key.description'),
      icon: <KeyIcon />,
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

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        {t('wizards.presentationPolicy.freshnessBindingStep.title')}
      </Typography>
      <Typography color="text.secondary" component="p" sx={{ mb: "16px" }}>
        {t('wizards.presentationPolicy.freshnessBindingStep.description')}
      </Typography>
      {/* Holder Binding */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography id={`${bindingId}-label`} variant="subtitle1" gutterBottom sx={{ fontWeight: 600 }}>
            {t('wizards.presentationPolicy.freshnessBindingStep.sections.holderBinding')}
          </Typography>

          <Typography id={`${bindingId}-description`} variant="body2" color="text.secondary" component="p" sx={{ mb: "16px" }}>
            {t('wizards.presentationPolicy.freshnessBindingStep.helpers.holderBinding')}
          </Typography>

          <FormControl component="fieldset" fullWidth>
            <RadioGroup
              aria-labelledby={`${bindingId}-label`}
              aria-describedby={`${bindingId}-description`}
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
                >
                  <FormControlLabel
                    value={option.value}
                    control={<Radio slotProps={{ input: {
                      'aria-labelledby': `${bindingId}-${option.value}-label`,
                      'aria-describedby': `${bindingId}-${option.value}-description`,
                    } }} />}
                    disableTypography
                    label={
                      <Box component="span" sx={{ display: 'flex', alignItems: 'center', flex: 1, minWidth: 0, flexWrap: 'wrap', gap: 1 }}>
                        {option.icon && (
                          <Box component="span" sx={{ display: 'flex', color: 'primary.main' }}>
                            {option.icon}
                          </Box>
                        )}
                        <Box component="span" sx={{ flex: '1 1 140px', minWidth: 0 }}>
                          <Typography id={`${bindingId}-${option.value}-label`} component="span" variant="body1" sx={{ display: 'block', fontWeight: 500 }}>
                            {option.label}
                          </Typography>
                          <Typography id={`${bindingId}-${option.value}-description`} component="span" variant="caption" color="text.secondary">
                            {option.description}
                          </Typography>
                        </Box>
                        {option.value === 'device_key' && (
                          <Chip label={t('wizards.presentationPolicy.freshnessBindingStep.recommendedChip')} component="span" size="small" color="success" />
                        )}
                      </Box>
                    }
                    sx={{ m: 0, px: 2, py: 1.5, width: '100%', boxSizing: 'border-box' }}
                  />
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

          <Typography variant="body2" color="text.secondary" component="p" sx={{ mb: "16px" }}>
            {t('wizards.presentationPolicy.freshnessBindingStep.helpers.freshness')}
          </Typography>

          <TextField
            fullWidth
            type="number"
            label={t('wizards.presentationPolicy.freshnessBindingStep.fields.maxCredentialAge')}
            value={credentialAge}
            onChange={(e) => handleFreshnessChange('max_credential_age_seconds', e.target.value)}
            error={!validCredentialAge}
            helperText={t(validCredentialAge
              ? 'wizards.presentationPolicy.freshnessBindingStep.helpers.maxCredentialAge'
              : 'wizards.presentationPolicy.freshnessBindingStep.validation.maxCredentialAge')}
            sx={{ mb: 2 }}
            slotProps={{
              input: {
                endAdornment: <InputAdornment position="end">{t('wizards.presentationPolicy.freshnessBindingStep.units.seconds')}</InputAdornment>,
              },
              htmlInput: { min: 0, step: 1, inputMode: 'numeric' },
            }}
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
          <Typography variant="caption" color="text.secondary" sx={{ display: "block", ml: 4 }}>
            {t('wizards.presentationPolicy.freshnessBindingStep.helpers.revocationCheck')}
          </Typography>
        </CardContent>
      </Card>
    </Box>
  );
};

export default FreshnessBindingStep;
