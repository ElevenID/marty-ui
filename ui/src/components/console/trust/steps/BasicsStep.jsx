/**
 * Basics Step - Trust Profile Wizard
 * 
 * Core information: name, description, framework type, and supported formats.
 */

import {
  Box,
  Typography,
  TextField,
  Chip,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormGroup,
  FormControlLabel,
  Checkbox,
  FormHelperText,
} from '@mui/material';
import { useTranslation } from 'react-i18next';

import {
  TRUST_PROFILE_SUPPORTED_FORMATS,
  getAllowedAlgorithmsForFramework,
  getSupportedFormatsForFramework,
  isFrameworkFormatSelectionLocked,
} from '../trustProfileFormatCatalog';

const getFrameworkTypes = (t) => [
  { value: 'icao', label: t('wizards.trustProfile.frameworkLabels.icao') },
  { value: 'aamva', label: t('wizards.trustProfile.frameworkLabels.aamva') },
  { value: 'eudi', label: t('wizards.trustProfile.frameworkLabels.eudi') },
  { value: 'custom', label: t('wizards.trustProfile.frameworkLabels.custom') },
];

const BasicsStep = ({ data, onChange }) => {
  const { t } = useTranslation('console');
  const frameworkType = data.framework_type || 'custom';
  const supportedFormatsLabel = t('wizards.trustProfile.basicsStep.fields.supportedFormats').replace(/\s*\*$/, '');
  const supportedFormats = TRUST_PROFILE_SUPPORTED_FORMATS.map((format) => ({
    ...format,
    label: t(format.labelKey),
  }));
  const formatSelectionLocked = isFrameworkFormatSelectionLocked(frameworkType);

  const handleFrameworkChange = (nextFrameworkType) => {
    const currentValidationRules = data.validation_rules || {};

    onChange({
      framework_type: nextFrameworkType,
      supported_formats: getSupportedFormatsForFramework(nextFrameworkType, data.supported_formats),
      validation_rules: {
        ...currentValidationRules,
        allowed_algorithms: getAllowedAlgorithmsForFramework(
          nextFrameworkType,
          currentValidationRules.allowed_algorithms,
        ),
      },
    });
  };

  const handleFormatToggle = (format) => {
    if (formatSelectionLocked) {
      return;
    }

    const formats = getSupportedFormatsForFramework('custom', data.supported_formats);
    const newFormats = formats.includes(format)
      ? formats.filter((f) => f !== format)
      : [...formats, format];
    onChange({ supported_formats: newFormats });
  };

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        {t('wizards.trustProfile.basicsStep.title')}
      </Typography>
      <Typography color="text.secondary" paragraph>
        {t('wizards.trustProfile.basicsStep.description')}
      </Typography>

      {/* Name */}
      <TextField
        fullWidth
        required
        label={t('wizards.trustProfile.basicsStep.fields.name')}
        value={data.name || ''}
        onChange={(e) => onChange({ name: e.target.value })}
        placeholder={t('wizards.trustProfile.basicsStep.placeholders.name')}
        sx={{ mb: 3 }}
        helperText={t('wizards.trustProfile.basicsStep.helpers.name')}
        slotProps={{ htmlInput: { 'data-testid': 'wizard.trustProfile.name' } }}
      />

      {/* Description */}
      <TextField
        fullWidth
        multiline
        rows={3}
        label={t('wizards.trustProfile.basicsStep.fields.description')}
        value={data.description || ''}
        onChange={(e) => onChange({ description: e.target.value })}
        sx={{ mb: 3 }}
        helperText={t('wizards.trustProfile.basicsStep.helpers.description')}
        slotProps={{ htmlInput: { 'data-testid': 'wizard.trustProfile.description' } }}
      />

      {/* Framework Type */}
      <FormControl fullWidth sx={{ mb: 3 }} data-testid="wizard.trustProfile.frameworkTypeField">
        <InputLabel>{t('wizards.trustProfile.basicsStep.fields.frameworkType')}</InputLabel>
        <Select
          value={frameworkType}
          onChange={(e) => handleFrameworkChange(e.target.value)}
          label={t('wizards.trustProfile.basicsStep.fields.frameworkType')}
          data-testid="wizard.trustProfile.frameworkType"
        >
          {getFrameworkTypes(t).map((type) => (
            <MenuItem key={type.value} value={type.value}>
              {type.label}
            </MenuItem>
          ))}
        </Select>
        <FormHelperText>
          {t('wizards.trustProfile.basicsStep.helpers.frameworkType')}
        </FormHelperText>
      </FormControl>

      {/* Supported Formats */}
      <FormControl component="fieldset" fullWidth sx={{ mb: 2 }}>
        <Typography variant="subtitle2" gutterBottom>
          {supportedFormatsLabel}
        </Typography>
        <FormHelperText sx={{ mt: 0, mb: 1 }}>
          {formatSelectionLocked
            ? t('wizards.trustProfile.basicsStep.helpers.supportedFormatsLocked', {
                defaultValue: 'This framework uses pre-configured credential formats. Choose Custom to edit them.',
              })
            : t('wizards.trustProfile.basicsStep.helpers.supportedFormats')}
        </FormHelperText>
        <FormGroup>
          {supportedFormats.map((format) => (
            <FormControlLabel
              key={format.value}
              control={
                <Checkbox
                  checked={(data.supported_formats || []).includes(format.value)}
                  onChange={() => handleFormatToggle(format.value)}
                  disabled={formatSelectionLocked}
                  slotProps={{ input: { 'data-testid': `wizard.trustProfile.format.${format.value}` } }}
                />
              }
              label={
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  {format.label}
                  {format.recommended && (
                    <Chip
                      label={t('wizards.trustProfile.basicsStep.recommendedChip')}
                      size="small"
                      color="primary"
                      variant="outlined"
                    />
                  )}
                </Box>
              }
            />
          ))}
        </FormGroup>
      </FormControl>
    </Box>
  );
};

export default BasicsStep;
