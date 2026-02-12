/**
 * Validation Rules Step - Trust Profile Wizard
 * 
 * Configure cryptographic and validation requirements.
 * This step is optional with sensible defaults.
 */

import { useState } from 'react';
import {
  Box,
  Typography,
  FormControl,
  FormGroup,
  FormControlLabel,
  Checkbox,
  InputLabel,
  Select,
  MenuItem,
  FormHelperText,
  Alert,
  Divider,
  Button,
  Chip,
  Collapse,
} from '@mui/material';
import SecurityIcon from '@mui/icons-material/Security';
import RestartAltIcon from '@mui/icons-material/RestartAlt';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import { useTranslation } from 'react-i18next';

const ALGORITHMS = [
  { value: 'ES256', label: 'ES256 (ECDSA P-256)' },
  { value: 'ES384', label: 'ES384 (ECDSA P-384)' },
  { value: 'ES512', label: 'ES512 (ECDSA P-521)' },
  { value: 'EdDSA', label: 'EdDSA (Ed25519)' },
  { value: 'RS256', label: 'RS256 (RSA 2048+)' },
  { value: 'RS384', label: 'RS384 (RSA 2048+)' },
  { value: 'RS512', label: 'RS512 (RSA 2048+)' },
  { value: 'PS256', label: 'PS256 (RSA-PSS)' },
  { value: 'PS384', label: 'PS384 (RSA-PSS)' },
  { value: 'PS512', label: 'PS512 (RSA-PSS)' },
];

const KEY_SIZES = [
  { value: 2048, label: '2048 bits' },
  { value: 3072, label: '3072 bits' },
  { value: 4096, label: '4096 bits' },
];

const ValidationRulesStep = ({ data, onChange }) => {
  const { t } = useTranslation('console');
  const [showAdvanced, setShowAdvanced] = useState(false);
  
  const DEFAULT_RULES = {
    allowed_algorithms: ['ES256', 'ES384', 'ES512', 'EdDSA'],
    allow_self_signed: false,
    min_key_size: 2048,
    require_key_usage: true,
  };
  
  const rules = data.validation_rules || DEFAULT_RULES;

  const handleAlgorithmToggle = (algorithm) => {
    const current = rules.allowed_algorithms || [];
    const updated = current.includes(algorithm)
      ? current.filter((a) => a !== algorithm)
      : [...current, algorithm];
    onChange({ validation_rules: { ...rules, allowed_algorithms: updated } });
  };

  const handleRuleChange = (key, value) => {
    onChange({ validation_rules: { ...rules, [key]: value } });
  };

  const handleResetDefaults = () => {
    onChange({ validation_rules: DEFAULT_RULES });
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
        <SecurityIcon />
        <Typography variant="h6">
          {t('wizards.trustProfile.validationRulesStep.title')}
        </Typography>
        <Chip
          label={t('wizards.trustProfile.validationRulesStep.optionalChip')}
          size="small"
          color="default"
          variant="outlined"
        />
      </Box>
      <Typography color="text.secondary" paragraph>
        {t('wizards.trustProfile.validationRulesStep.description')}
      </Typography>

      <Alert severity="success" sx={{ mb: 3 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Box>
            <Typography variant="body2" gutterBottom>
              <strong>{t('wizards.trustProfile.validationRulesStep.defaultsAlert.title')}</strong>
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {t('wizards.trustProfile.validationRulesStep.defaultsAlert.description')}
            </Typography>
          </Box>
          <Button
            size="small"
            startIcon={<RestartAltIcon />}
            onClick={handleResetDefaults}
          >
            {t('wizards.trustProfile.validationRulesStep.resetDefaults')}
          </Button>
        </Box>
      </Alert>

      {/* Allowed Algorithms */}
      <FormControl component="fieldset" fullWidth sx={{ mb: 3 }}>
        <Typography variant="subtitle2" gutterBottom>
          {t('wizards.trustProfile.validationRulesStep.allowedAlgorithms.title')}
        </Typography>
        <FormHelperText sx={{ mt: 0, mb: 1 }}>
          {t('wizards.trustProfile.validationRulesStep.allowedAlgorithms.helper')}
        </FormHelperText>
        <FormGroup>
          <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 1 }}>
            {ALGORITHMS.map((alg) => (
              <FormControlLabel
                key={alg.value}
                control={
                  <Checkbox
                    checked={(rules.allowed_algorithms || []).includes(alg.value)}
                    onChange={() => handleAlgorithmToggle(alg.value)}
                  />
                }
                label={alg.label}
              />
            ))}
          </Box>
        </FormGroup>
      </FormControl>

      {/* Advanced Options Toggle */}
      <Box sx={{ mt: 3 }}>
        <Button
          fullWidth
          variant="outlined"
          onClick={() => setShowAdvanced(!showAdvanced)}
          endIcon={showAdvanced ? <ExpandLessIcon /> : <ExpandMoreIcon />}
        >
          {t('wizards.trustProfile.validationRulesStep.advanced.toggle', {
            action: showAdvanced
              ? t('wizards.trustProfile.validationRulesStep.advanced.hide')
              : t('wizards.trustProfile.validationRulesStep.advanced.show'),
          })}
        </Button>

        <Collapse in={showAdvanced}>
          <Box sx={{ mt: 2 }}>
            <Divider sx={{ my: 3 }} />

            {/* Key Size Constraints */}
            <FormControl fullWidth sx={{ mb: 3 }}>
              <InputLabel>{t('wizards.trustProfile.validationRulesStep.keySize.label')}</InputLabel>
              <Select
                value={rules.min_key_size || 2048}
                onChange={(e) => handleRuleChange('min_key_size', e.target.value)}
                label={t('wizards.trustProfile.validationRulesStep.keySize.label')}
              >
                {KEY_SIZES.map((size) => (
                  <MenuItem key={size.value} value={size.value}>
                    {size.label}
                  </MenuItem>
                ))}
              </Select>
              <FormHelperText>
                {t('wizards.trustProfile.validationRulesStep.keySize.helper')}
              </FormHelperText>
            </FormControl>

            <Divider sx={{ my: 3 }} />

            {/* Additional Options */}
            <Typography variant="subtitle2" gutterBottom>
              {t('wizards.trustProfile.validationRulesStep.additionalSecurity.title')}
            </Typography>
            
            <FormGroup>
              <FormControlLabel
                control={
                  <Checkbox
                    checked={rules.allow_self_signed || false}
                    onChange={(e) => handleRuleChange('allow_self_signed', e.target.checked)}
                  />
                }
                label={t('wizards.trustProfile.validationRulesStep.additionalSecurity.allowSelfSigned.label')}
              />
              <FormHelperText sx={{ ml: 4, mt: -1, mb: 2 }}>
                {t('wizards.trustProfile.validationRulesStep.additionalSecurity.allowSelfSigned.helper')}
              </FormHelperText>

              <FormControlLabel
                control={
                  <Checkbox
                    checked={rules.require_key_usage !== false}
                    onChange={(e) => handleRuleChange('require_key_usage', e.target.checked)}
                  />
                }
                label={t('wizards.trustProfile.validationRulesStep.additionalSecurity.requireKeyUsage.label')}
              />
              <FormHelperText sx={{ ml: 4, mt: -1 }}>
                {t('wizards.trustProfile.validationRulesStep.additionalSecurity.requireKeyUsage.helper')}
              </FormHelperText>
            </FormGroup>
          </Box>
        </Collapse>
      </Box>
    </Box>
  );
};

export default ValidationRulesStep;
