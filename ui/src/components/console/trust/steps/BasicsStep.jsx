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

const getFrameworkTypes = (t) => [
  { value: 'icao', label: t('wizards.trustProfile.frameworkLabels.icao') },
  { value: 'aamva', label: t('wizards.trustProfile.frameworkLabels.aamva') },
  { value: 'eudi', label: t('wizards.trustProfile.frameworkLabels.eudi') },
  { value: 'custom', label: t('wizards.trustProfile.frameworkLabels.custom') },
];

const getSupportedFormats = (t) => [
  { value: 'jwt_vc', label: t('wizards.trustProfile.basicsStep.formatOptions.jwt_vc'), recommended: true },
  { value: 'sd_jwt_vc', label: t('wizards.trustProfile.basicsStep.formatOptions.sd_jwt_vc'), recommended: true },
  { value: 'mdoc', label: t('wizards.trustProfile.basicsStep.formatOptions.mdoc'), recommended: true },
  { value: 'ldp_vc', label: t('wizards.trustProfile.basicsStep.formatOptions.ldp_vc'), recommended: false },
];

const BasicsStep = ({ data, onChange }) => {
  const { t } = useTranslation('console');

  const handleFormatToggle = (format) => {
    const formats = data.supported_formats || [];
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
        inputProps={{ 'data-testid': 'wizard.trustProfile.name' }}
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
        inputProps={{ 'data-testid': 'wizard.trustProfile.description' }}
      />

      {/* Framework Type */}
      <FormControl fullWidth sx={{ mb: 3 }}>
        <InputLabel>{t('wizards.trustProfile.basicsStep.fields.frameworkType')}</InputLabel>
        <Select
          value={data.framework_type || 'custom'}
          onChange={(e) => onChange({ framework_type: e.target.value })}
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
          {t('wizards.trustProfile.basicsStep.fields.supportedFormats')}
        </Typography>
        <FormHelperText sx={{ mt: 0, mb: 1 }}>
          {t('wizards.trustProfile.basicsStep.helpers.supportedFormats')}
        </FormHelperText>
        <FormGroup>
          {getSupportedFormats(t).map((format) => (
            <FormControlLabel
              key={format.value}
              control={
                <Checkbox
                  checked={(data.supported_formats || []).includes(format.value)}
                  onChange={() => handleFormatToggle(format.value)}
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
