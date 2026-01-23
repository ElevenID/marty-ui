/**
 * Freshness & Binding Step
 * 
 * Configure freshness requirements and holder binding methods.
 * Includes standard version tracking for compliance.
 */

import React from 'react';
import {
  Box,
  Typography,
  TextField,
  Card,
  CardContent,
  FormControl,
  FormLabel,
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

const HOLDER_BINDING_OPTIONS = [
  {
    value: 'device_key',
    label: 'Device Key',
    description: 'Bind to device cryptographic key (recommended)',
    icon: <SecurityIcon />,
  },
  {
    value: 'session_nonce',
    label: 'Session Nonce',
    description: 'One-time session binding (less secure)',
    icon: <TimerIcon />,
  },
  {
    value: 'biometric',
    label: 'Biometric',
    description: 'Biometric authentication required',
    icon: <FingerprintIcon />,
  },
  {
    value: 'none',
    label: 'None',
    description: 'No holder binding (least secure)',
    icon: null,
  },
];

const FreshnessBindingStep = ({ policyConfig, onConfigChange }) => {
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
        Freshness & Security Settings
      </Typography>
      
      <Typography color="text.secondary" paragraph>
        Configure how recent credentials must be and how to bind presentations to holders.
      </Typography>

      {/* Holder Binding */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600 }}>
            Holder Binding Method
          </Typography>

          <Typography variant="body2" color="text.secondary" paragraph>
            How should the presentation be bound to the credential holder?
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
                        <Chip label="Recommended" size="small" color="success" />
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
            Freshness Requirements
          </Typography>

          <Typography variant="body2" color="text.secondary" paragraph>
            Control how recent credentials and proofs must be.
          </Typography>

          <TextField
            fullWidth
            type="number"
            label="Maximum Credential Age"
            value={secondsToDays(policyConfig.freshness_requirements.max_credential_age_seconds)}
            onChange={(e) => handleFreshnessChange('max_credential_age_seconds', daysToSeconds(parseInt(e.target.value) || 0))}
            InputProps={{
              endAdornment: <InputAdornment position="end">days</InputAdornment>,
            }}
            helperText="How old can the credential be? (1 year = 365 days)"
            sx={{ mb: 2 }}
          />

          <TextField
            fullWidth
            type="number"
            label="Maximum Proof Age"
            value={Math.floor(policyConfig.freshness_requirements.max_proof_age_seconds / 60)}
            onChange={(e) => handleFreshnessChange('max_proof_age_seconds', parseInt(e.target.value) * 60 || 300)}
            InputProps={{
              endAdornment: <InputAdornment position="end">minutes</InputAdornment>,
            }}
            helperText="How old can the proof be? (typically 5-10 minutes)"
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
                <Typography variant="body2">Require Revocation Check</Typography>
              </Box>
            }
          />
          <Typography variant="caption" color="text.secondary" display="block" sx={{ ml: 4 }}>
            Verify that credentials have not been revoked (recommended)
          </Typography>
        </CardContent>
      </Card>

      {/* Standard Version Tracking */}
      <Card>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600 }}>
            Compliance & Standards
          </Typography>

          <Typography variant="body2" color="text.secondary" paragraph>
            Track which standard version this policy targets for compliance audits.
          </Typography>

          <TextField
            fullWidth
            label="Standard Reference"
            value={policyConfig.metadata?.standard_reference || ''}
            onChange={(e) => handleMetadataChange('standard_reference', e.target.value)}
            placeholder="e.g., ISO 18013-5:2021, ARF 1.4.0, ICAO 9303 Ed. 8"
            helperText="Optional: Specify the standard version this policy conforms to"
            sx={{ mb: 2 }}
          />

          {policyConfig.metadata?.standard_reference && (
            <Alert severity="info" icon={<VerifiedIcon />}>
              <Typography variant="body2">
                This policy will be marked as targeting: <strong>{policyConfig.metadata.standard_reference}</strong>
              </Typography>
            </Alert>
          )}
        </CardContent>
      </Card>
    </Box>
  );
};

export default FreshnessBindingStep;
