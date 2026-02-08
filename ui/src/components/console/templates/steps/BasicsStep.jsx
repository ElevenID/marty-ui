/**
 * Basics Step - Credential Template Wizard
 * 
 * Core information: name, credential type, VCT, and description.
 */

import {
  Box,
  Typography,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormHelperText,
} from '@mui/material';

const CREDENTIAL_TYPES = [
  { value: 'VerifiableCredential', label: 'Verifiable Credential (W3C)' },
  { value: 'VerifiableAttestation', label: 'Verifiable Attestation' },
  { value: 'mdoc', label: 'Mobile Document (ISO 18013-5)' },
  { value: 'OpenBadgeCredential', label: 'Open Badge Credential' },
];

const BasicsStep = ({ data, onChange }) => {
  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Basic Information
      </Typography>
      <Typography color="text.secondary" paragraph>
        Provide core details about this credential template.
      </Typography>

      {/* Name */}
      <TextField
        fullWidth
        required
        label="Template Name"
        value={data.name || ''}
        onChange={(e) => onChange({ name: e.target.value })}
        sx={{ mb: 3 }}
        helperText="A descriptive name for this credential template (e.g., 'Driver License', 'Diploma')"
      />

      {/* Credential Type */}
      <FormControl fullWidth required sx={{ mb: 3 }}>
        <InputLabel>Credential Type</InputLabel>
        <Select
          value={data.credential_type || 'VerifiableCredential'}
          onChange={(e) => onChange({ credential_type: e.target.value })}
          label="Credential Type"
        >
          {CREDENTIAL_TYPES.map((type) => (
            <MenuItem key={type.value} value={type.value}>
              {type.label}
            </MenuItem>
          ))}
        </Select>
        <FormHelperText>
          The type of credential this template represents
        </FormHelperText>
      </FormControl>

      {/* VCT (Verifiable Credential Type) */}
      <TextField
        fullWidth
        required
        label="VCT (Verifiable Credential Type)"
        value={data.vct || ''}
        onChange={(e) => onChange({ vct: e.target.value })}
        sx={{ mb: 3 }}
        placeholder="https://example.com/credentials/DriversLicense"
        helperText="A unique URI identifying this credential type (often a URL or URN)"
      />

      {/* Description */}
      <TextField
        fullWidth
        multiline
        rows={4}
        label="Description"
        value={data.description || ''}
        onChange={(e) => onChange({ description: e.target.value })}
        helperText="Optional: Describe the purpose and usage of this credential template"
      />
    </Box>
  );
};

export default BasicsStep;
