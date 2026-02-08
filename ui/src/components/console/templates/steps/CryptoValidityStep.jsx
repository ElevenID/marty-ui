/**
 * Crypto & Validity Step - Credential Template Wizard
 * 
 * Configure signing algorithm, validity periods, and revocation settings.
 * This step is optional with sensible defaults.
 */

import { useState } from 'react';
import {
  Box,
  Typography,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  TextField,
  FormHelperText,
  Alert,
  Divider,
  Grid,
  Button,
  Collapse,
} from '@mui/material';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import InfoIcon from '@mui/icons-material/Info';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';

const SIGNING_ALGORITHMS = [
  { value: 'ES256', label: 'ES256 (ECDSA P-256) - Recommended', recommended: true },
  { value: 'ES384', label: 'ES384 (ECDSA P-384)' },
  { value: 'ES512', label: 'ES512 (ECDSA P-521)' },
  { value: 'EdDSA', label: 'EdDSA (Ed25519)' },
  { value: 'RS256', label: 'RS256 (RSA 2048+)' },
];

const CryptoValidityStep = ({ data, onChange }) => {
  const [showAdvanced, setShowAdvanced] = useState(false);
  
  const validity = data.validity_rules || {
    ttl_seconds: 31536000,
    not_before_offset: 0,
    max_validity_seconds: 63072000,
  };

  const handleValidityChange = (key, value) => {
    onChange({
      validity_rules: {
        ...validity,
        [key]: parseInt(value, 10) || 0,
      },
    });
  };

  // Helper to convert seconds to days
  const secondsToDays = (seconds) => Math.floor(seconds / 86400);
  const daysToSeconds = (days) => days * 86400;

  return (
    <Box>
      <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <VpnKeyIcon />
        Cryptography & Validity (Optional)
      </Typography>
      <Typography color="text.secondary" paragraph>
        Configure signing and validity settings. Defaults are pre-selected based on best practices.
      </Typography>

      <Alert severity="success" sx={{ mb: 3 }}>
        <Typography variant="body2" gutterBottom>
          <strong>Defaults are secure and ready to use.</strong>
        </Typography>
        <Typography variant="caption" color="text.secondary">
          Skip this step or use defaults for most use cases. Advanced users can customize crypto and validity settings below.
        </Typography>
      </Alert>

      {/* Validity Period Configuration */}
      <Typography variant="subtitle2" gutterBottom>
        Validity Period
      </Typography>
      <Typography variant="body2" color="text.secondary" paragraph>
        Configure how long credentials remain valid after issuance
      </Typography>

      <Grid container spacing={3}>
        {/* TTL (Time to Live) */}
        <Grid item xs={12} md={6}>
          <TextField
            fullWidth
            type="number"
            label="Default Validity (days)"
            value={secondsToDays(validity.ttl_seconds)}
            onChange={(e) => handleValidityChange('ttl_seconds', daysToSeconds(parseInt(e.target.value, 10)))}
            helperText="How long credentials are valid by default (e.g., 365 days = 1 year)"
            inputProps={{ min: 1 }}
          />
        </Grid>

        {/* Max Validity */}
        <Grid item xs={12} md={6}>
          <TextField
            fullWidth
            type="number"
            label="Maximum Validity (days)"
            value={secondsToDays(validity.max_validity_seconds)}
            onChange={(e) => handleValidityChange('max_validity_seconds', daysToSeconds(parseInt(e.target.value, 10)))}
            helperText="Maximum allowed validity period (e.g., 730 days = 2 years)"
            inputProps={{ min: 1 }}
          />
        </Grid>

        {/* Not Before Offset */}
        <Grid item xs={12} md={6}>
          <TextField
            fullWidth
            type="number"
            label="Not Before Offset (seconds)"
            value={validity.not_before_offset}
            onChange={(e) => handleValidityChange('not_before_offset', e.target.value)}
            helperText="Delay before credential becomes valid (usually 0)"
            inputProps={{ min: 0 }}
          />
        </Grid>
      </Grid>

      <Box sx={{ mt: 3, p: 2, bgcolor: 'action.hover', borderRadius: 1 }}>
        <Typography variant="body2" color="text.secondary">
          <strong>Example:</strong> With a default validity of {secondsToDays(validity.ttl_seconds)} days,
          a credential issued today will expire on{' '}
          {new Date(Date.now() + validity.ttl_seconds * 1000).toLocaleDateString()}.
        </Typography>
      </Box>

      {/* Advanced Options Toggle */}
      <Box sx={{ mt: 3 }}>
        <Button
          fullWidth
          variant="outlined"
          onClick={() => setShowAdvanced(!showAdvanced)}
          endIcon={showAdvanced ? <ExpandLessIcon /> : <ExpandMoreIcon />}
        >
          {showAdvanced ? 'Hide' : 'Show'} Advanced Cryptographic Options
        </Button>

        <Collapse in={showAdvanced}>
          <Box sx={{ mt: 3 }}>
            <Divider sx={{ mb: 3 }} />

            {/* Signing Algorithm */}
            <FormControl fullWidth sx={{ mb: 3 }}>
              <InputLabel>Signing Algorithm</InputLabel>
              <Select
                value={data.signing_algorithm || 'ES256'}
                onChange={(e) => onChange({ signing_algorithm: e.target.value })}
                label="Signing Algorithm"
              >
                {SIGNING_ALGORITHMS.map((alg) => (
                  <MenuItem key={alg.value} value={alg.value}>
                    {alg.label}
                  </MenuItem>
                ))}
              </Select>
              <FormHelperText>
                The cryptographic algorithm used to sign credentials from this template
              </FormHelperText>
            </FormControl>

            <Divider sx={{ my: 3 }} />

            {/* Revocation Profile */}
            <FormControl fullWidth>
              <InputLabel>Revocation Profile</InputLabel>
              <Select
                value={data.revocation_profile_id || ''}
                onChange={(e) => onChange({ revocation_profile_id: e.target.value || null })}
                label="Revocation Profile"
              >
                <MenuItem value="">
                  <em>None (no revocation)</em>
                </MenuItem>
                {/* TODO: Load actual revocation profiles when available */}
                <MenuItem value="status-list" disabled>
                  Status List 2021 (Coming Soon)
                </MenuItem>
              </Select>
              <FormHelperText>
                Optional: Select a revocation mechanism for credentials issued from this template
              </FormHelperText>
            </FormControl>
          </Box>
        </Collapse>
      </Box>
    </Box>
  );
};

export default CryptoValidityStep;
