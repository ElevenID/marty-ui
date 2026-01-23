/**
 * Key Location Selector Component
 * 
 * Radio group for selecting where signing keys are stored:
 * - Customer KMS (AWS/Azure/GCP)
 * - Signing Agent (remote signer)
 * - Marty Generated (hosted by platform)
 * - Skip (configure later)
 * 
 * With conditional fields for URL/ARN configuration.
 */

import React, { useState, useCallback } from 'react';
import {
  Box,
  Typography,
  FormControl,
  FormControlLabel,
  RadioGroup,
  Radio,
  TextField,
  Button,
  Alert,
  Paper,
  Collapse,
  CircularProgress,
  Select,
  MenuItem,
  InputLabel,
} from '@mui/material';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import CloudIcon from '@mui/icons-material/Cloud';
import RouterIcon from '@mui/icons-material/Router';
import AutoAwesomeIcon from '@mui/icons-material/AutoAwesome';
import SkipNextIcon from '@mui/icons-material/SkipNext';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import { IssuerKeySource } from '../ports/types';

/**
 * Key source option configuration.
 */
const KEY_SOURCE_OPTIONS = [
  {
    value: IssuerKeySource.KMS,
    label: 'Customer Key Vault (recommended)',
    description: 'Use AWS KMS / Azure Key Vault / GCP KMS / HSM',
    icon: <CloudIcon />,
    recommended: true,
  },
  {
    value: IssuerKeySource.SIGNING_AGENT,
    label: 'Signing Agent (recommended)',
    description: 'Run a small service on your network that signs requests',
    icon: <RouterIcon />,
    recommended: true,
  },
  {
    value: IssuerKeySource.MARTY_GENERATED,
    label: 'Platform Managed',
    description: 'We generate and manage the signing key for you',
    icon: <AutoAwesomeIcon />,
    recommended: false,
  },
  {
    value: 'skip',
    label: 'Configure later',
    description: 'Skip key configuration for now',
    icon: <SkipNextIcon />,
    recommended: false,
  },
];

/**
 * Signing algorithm options.
 */
const ALGORITHM_OPTIONS = [
  { value: 'ES256', label: 'ES256 (P-256, recommended)' },
  { value: 'ES384', label: 'ES384 (P-384)' },
  { value: 'EdDSA', label: 'EdDSA (Ed25519)' },
];

/**
 * Key Location Selector Component.
 * 
 * @param {Object} props
 * @param {import('../ports/types').KeyLocationConfig} [props.value] - Current config
 * @param {function} props.onChange - Callback when config changes
 * @param {function} [props.onTestConnection] - Test connection callback
 * @param {boolean} [props.disabled] - Disable inputs
 * @param {string} [props.error] - Error message
 * @param {string} [props.label] - Section label
 * @param {boolean} [props.showAlgorithm] - Show algorithm selector
 */
const KeyLocationSelector = ({
  value,
  onChange,
  onTestConnection,
  disabled = false,
  error,
  label = 'Where your signing key lives',
  showAlgorithm = true,
}) => {
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState(null);

  const currentSource = value?.source || '';

  const handleSourceChange = useCallback((e) => {
    const newSource = e.target.value;
    onChange({
      source: newSource,
      kmsArn: newSource === IssuerKeySource.KMS ? (value?.kmsArn || '') : undefined,
      kmsRegion: newSource === IssuerKeySource.KMS ? (value?.kmsRegion || '') : undefined,
      signingAgentUrl: newSource === IssuerKeySource.SIGNING_AGENT ? (value?.signingAgentUrl || '') : undefined,
      signingAgentAuth: newSource === IssuerKeySource.SIGNING_AGENT ? (value?.signingAgentAuth || 'mtls') : undefined,
      algorithm: value?.algorithm || 'ES256',
    });
    setTestResult(null);
  }, [onChange, value]);

  const handleFieldChange = useCallback((field) => (e) => {
    onChange({
      ...value,
      [field]: e.target.value,
    });
    setTestResult(null);
  }, [onChange, value]);

  const handleTestConnection = useCallback(async () => {
    if (!onTestConnection) return;
    
    setTesting(true);
    setTestResult(null);
    
    try {
      const result = await onTestConnection(value);
      setTestResult(result);
    } catch (err) {
      setTestResult({
        success: false,
        message: err.message,
      });
    } finally {
      setTesting(false);
    }
  }, [onTestConnection, value]);

  const canTest = (currentSource === IssuerKeySource.KMS && value?.kmsArn) ||
                  (currentSource === IssuerKeySource.SIGNING_AGENT && value?.signingAgentUrl);

  return (
    <Box>
      <Typography variant="body2" fontWeight="medium" sx={{ mb: 0.5 }}>
        {label}
      </Typography>
      <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mb: 2 }}>
        Your private key stays with you. We only need a way to request a signature when needed.
      </Typography>

      <FormControl component="fieldset" disabled={disabled} fullWidth>
        <RadioGroup value={currentSource} onChange={handleSourceChange}>
          {KEY_SOURCE_OPTIONS.map((option) => (
            <Paper
              key={option.value}
              variant="outlined"
              sx={{
                mb: 1,
                p: 0,
                borderColor: currentSource === option.value ? 'primary.main' : 'divider',
                bgcolor: currentSource === option.value ? 'action.selected' : 'background.paper',
              }}
            >
              <FormControlLabel
                value={option.value}
                control={<Radio />}
                sx={{ 
                  m: 0, 
                  p: 2, 
                  width: '100%',
                  alignItems: 'flex-start',
                }}
                label={
                  <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 1.5, ml: 1 }}>
                    <Box sx={{ color: 'text.secondary', mt: 0.5 }}>
                      {option.icon}
                    </Box>
                    <Box>
                      <Typography variant="body2" fontWeight="medium">
                        {option.label}
                        {option.recommended && (
                          <Typography 
                            component="span" 
                            variant="caption" 
                            color="primary.main"
                            sx={{ ml: 1 }}
                          >
                            Recommended
                          </Typography>
                        )}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {option.description}
                      </Typography>
                    </Box>
                  </Box>
                }
              />

              {/* KMS Fields */}
              <Collapse in={currentSource === IssuerKeySource.KMS && option.value === IssuerKeySource.KMS}>
                <Box sx={{ px: 2, pb: 2, pl: 7 }}>
                  <TextField
                    fullWidth
                    size="small"
                    label="Key reference / Key ID"
                    placeholder="e.g., arn:aws:kms:... or https://vault..."
                    value={value?.kmsArn || ''}
                    onChange={handleFieldChange('kmsArn')}
                    disabled={disabled}
                    sx={{ mb: 2 }}
                  />
                  {showAlgorithm && (
                    <FormControl size="small" sx={{ minWidth: 200 }}>
                      <InputLabel>Signing algorithm</InputLabel>
                      <Select
                        value={value?.algorithm || 'ES256'}
                        onChange={handleFieldChange('algorithm')}
                        label="Signing algorithm"
                        disabled={disabled}
                      >
                        {ALGORITHM_OPTIONS.map((alg) => (
                          <MenuItem key={alg.value} value={alg.value}>
                            {alg.label}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  )}
                </Box>
              </Collapse>

              {/* Signing Agent Fields */}
              <Collapse in={currentSource === IssuerKeySource.SIGNING_AGENT && option.value === IssuerKeySource.SIGNING_AGENT}>
                <Box sx={{ px: 2, pb: 2, pl: 7 }}>
                  <TextField
                    fullWidth
                    size="small"
                    label="Agent URL"
                    placeholder="https://signer.yourorg.com"
                    value={value?.signingAgentUrl || ''}
                    onChange={handleFieldChange('signingAgentUrl')}
                    disabled={disabled}
                    sx={{ mb: 2 }}
                  />
                  <FormControl size="small" sx={{ minWidth: 200 }}>
                    <InputLabel>Authentication</InputLabel>
                    <Select
                      value={value?.signingAgentAuth || 'mtls'}
                      onChange={handleFieldChange('signingAgentAuth')}
                      label="Authentication"
                      disabled={disabled}
                    >
                      <MenuItem value="mtls">mTLS (recommended)</MenuItem>
                      <MenuItem value="api_token">API token</MenuItem>
                    </Select>
                  </FormControl>
                </Box>
              </Collapse>
            </Paper>
          ))}
        </RadioGroup>
      </FormControl>

      {/* Test Connection Button */}
      {canTest && onTestConnection && (
        <Box sx={{ mt: 2 }}>
          <Button
            variant="outlined"
            size="small"
            onClick={handleTestConnection}
            disabled={disabled || testing}
            startIcon={testing ? <CircularProgress size={16} /> : <VpnKeyIcon />}
          >
            {testing ? 'Testing...' : 'Test connection'}
          </Button>

          {testResult && (
            <Alert 
              severity={testResult.success ? 'success' : 'error'} 
              sx={{ mt: 1 }}
              icon={testResult.success ? <CheckCircleIcon /> : undefined}
            >
              {testResult.message}
              {testResult.latencyMs && ` (${testResult.latencyMs}ms)`}
            </Alert>
          )}
        </Box>
      )}

      {error && (
        <Alert severity="error" sx={{ mt: 2 }}>
          {error}
        </Alert>
      )}
    </Box>
  );
};

export default KeyLocationSelector;
