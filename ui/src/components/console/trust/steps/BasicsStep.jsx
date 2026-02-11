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

const FRAMEWORK_TYPES = [
  { value: 'icao', label: 'ICAO 9303 (eMRTD/ePassport)' },
  { value: 'aamva', label: 'AAMVA (mDL - ISO 18013-5)' },
  { value: 'eudi', label: 'EUDI (EU Digital Identity Wallet)' },
  { value: 'custom', label: 'Custom' },
];

const SUPPORTED_FORMATS = [
  { value: 'jwt_vc', label: 'JWT VC (JSON Web Token Verifiable Credential)', recommended: true },
  { value: 'sd_jwt_vc', label: 'SD-JWT VC (Selective Disclosure)', recommended: true },
  { value: 'mdoc', label: 'mDoc (ISO 18013-5 Mobile Document)', recommended: true },
  { value: 'ldp_vc', label: 'LDP VC (Linked Data Proof)', recommended: false },
];

const BasicsStep = ({ data, onChange }) => {
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
        Basic Information
      </Typography>
      <Typography color="text.secondary" paragraph>
        Trust Profiles define which credential issuers your organization trusts and what validation rules apply. They're the foundation for secure credential verification across your organization.
      </Typography>

      {/* Name */}
      <TextField
        fullWidth
        required
        label="Trust Profile Name"
        value={data.name || ''}
        onChange={(e) => onChange({ name: e.target.value })}
        placeholder="Default Trust Profile"
        sx={{ mb: 3 }}
        helperText="You can change this later"
        inputProps={{ 'data-testid': 'wizard.trustProfile.name' }}
      />

      {/* Description */}
      <TextField
        fullWidth
        multiline
        rows={3}
        label="Description"
        value={data.description || ''}
        onChange={(e) => onChange({ description: e.target.value })}
        sx={{ mb: 3 }}
        helperText="Optional: Explain the purpose and scope of this trust profile"
        inputProps={{ 'data-testid': 'wizard.trustProfile.description' }}
      />

      {/* Framework Type */}
      <FormControl fullWidth sx={{ mb: 3 }}>
        <InputLabel>Framework Type</InputLabel>
        <Select
          value={data.framework_type || 'custom'}
          onChange={(e) => onChange({ framework_type: e.target.value })}
          label="Framework Type"
          data-testid="wizard.trustProfile.frameworkType"
        >
          {FRAMEWORK_TYPES.map((type) => (
            <MenuItem key={type.value} value={type.value}>
              {type.label}
            </MenuItem>
          ))}
        </Select>
        <FormHelperText>
          Select the trust framework or standard this profile implements
        </FormHelperText>
      </FormControl>

      {/* Supported Formats */}
      <FormControl component="fieldset" fullWidth sx={{ mb: 2 }}>
        <Typography variant="subtitle2" gutterBottom>
          Supported Credential Formats *
        </Typography>
        <FormHelperText sx={{ mt: 0, mb: 1 }}>
          Select which credential formats this trust profile accepts
        </FormHelperText>
        <FormGroup>
          {SUPPORTED_FORMATS.map((format) => (
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
                    <Chip label="Recommended" size="small" color="primary" variant="outlined" />
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
