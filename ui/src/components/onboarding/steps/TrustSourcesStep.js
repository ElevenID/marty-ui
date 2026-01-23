/**
 * Trust Sources Step Component
 * 
 * Step 4 of trust setup: Configure what issuers to trust.
 * - Trusted list source toggle
 * - Country/region filters
 * - Document type filters
 * - Revocation policy
 */

import React, { useCallback } from 'react';
import {
  Box,
  Typography,
  Fade,
  Paper,
  FormControlLabel,
  Switch,
  Checkbox,
  FormGroup,
  Chip,
  Autocomplete,
  TextField,
} from '@mui/material';
import PolicyIcon from '@mui/icons-material/Policy';
import PublicIcon from '@mui/icons-material/Public';
import DescriptionIcon from '@mui/icons-material/Description';
import SecurityIcon from '@mui/icons-material/Security';
import { RevocationPolicy } from '../../trust/ports/types';

/**
 * Available countries for filtering.
 */
const COUNTRIES = [
  { code: 'US', name: 'United States' },
  { code: 'DE', name: 'Germany' },
  { code: 'FR', name: 'France' },
  { code: 'IT', name: 'Italy' },
  { code: 'ES', name: 'Spain' },
  { code: 'NL', name: 'Netherlands' },
  { code: 'BE', name: 'Belgium' },
  { code: 'AT', name: 'Austria' },
  { code: 'SE', name: 'Sweden' },
  { code: 'PL', name: 'Poland' },
  { code: 'GB', name: 'United Kingdom' },
  { code: 'CA', name: 'Canada' },
  { code: 'AU', name: 'Australia' },
  { code: 'JP', name: 'Japan' },
];

/**
 * Document type options.
 */
const DOCUMENT_TYPES = [
  { id: 'pid', label: 'Personal ID (PID)', description: 'European personal identity' },
  { id: 'mdl', label: 'Mobile Driver\'s License (mDL)', description: 'ISO 18013-5 driver\'s license' },
  { id: 'passport', label: 'Passport-derived / travel document', description: 'ICAO ePassport data' },
  { id: 'other', label: 'Other credentials', description: 'Custom or regional credentials' },
];

/**
 * Revocation policy options.
 */
const REVOCATION_OPTIONS = [
  { 
    value: RevocationPolicy.HARD_FAIL, 
    label: 'Check certificate revocation', 
    description: 'Reject credentials if revocation check fails' 
  },
  { 
    value: RevocationPolicy.SOFT_FAIL, 
    label: 'Require valid time (not expired)', 
    description: 'Ensure credential is within validity period' 
  },
  { 
    value: RevocationPolicy.OFFLINE_GRACE, 
    label: 'Block unknown issuers', 
    description: 'Reject credentials from issuers not in trusted list' 
  },
];

/**
 * Trust Sources Step Component.
 * 
 * @param {Object} props
 * @param {Object} props.trustSettings - Current trust settings
 * @param {function} props.onSettingsChange - Callback when settings change
 * @param {string} props.selectedProfile - Selected trust profile
 * @param {boolean} [props.disabled] - Disable inputs
 */
const TrustSourcesStep = ({
  trustSettings,
  onSettingsChange,
  selectedProfile,
  disabled = false,
}) => {
  const handleToggleChange = useCallback((field) => (e) => {
    onSettingsChange({
      ...trustSettings,
      [field]: e.target.checked,
    });
  }, [trustSettings, onSettingsChange]);

  const handleCountriesChange = useCallback((_, newValue) => {
    onSettingsChange({
      ...trustSettings,
      trustedCountries: newValue.map(c => c.code),
    });
  }, [trustSettings, onSettingsChange]);

  const handleDocTypeChange = useCallback((docType) => (e) => {
    const current = trustSettings?.acceptedDocTypes || [];
    const updated = e.target.checked
      ? [...current, docType]
      : current.filter(d => d !== docType);
    
    onSettingsChange({
      ...trustSettings,
      acceptedDocTypes: updated,
    });
  }, [trustSettings, onSettingsChange]);

  const handleRevocationChange = useCallback((policy) => (e) => {
    const current = trustSettings?.revocationChecks || [];
    const updated = e.target.checked
      ? [...current, policy]
      : current.filter(p => p !== policy);
    
    onSettingsChange({
      ...trustSettings,
      revocationChecks: updated,
    });
  }, [trustSettings, onSettingsChange]);

  const isDocTypeChecked = (docType) => {
    return trustSettings?.acceptedDocTypes?.includes(docType) ?? true;
  };

  const isRevocationChecked = (policy) => {
    return trustSettings?.revocationChecks?.includes(policy) ?? true;
  };

  const selectedCountries = COUNTRIES.filter(c => 
    trustSettings?.trustedCountries?.includes(c.code)
  );

  const useOfficialList = trustSettings?.useOfficialTrustList ?? true;

  return (
    <Fade in>
      <Box data-testid="trust-sources-step">
        <Typography variant="h5" gutterBottom textAlign="center">
          Choose what you trust
        </Typography>
        <Typography
          variant="body1"
          color="text.secondary"
          textAlign="center"
          sx={{ mb: 4 }}
        >
          This controls which issuers and document types your organization will accept.
        </Typography>

        <Box sx={{ maxWidth: 700, mx: 'auto' }}>
          {/* Section: Trusted List Source */}
          <Paper variant="outlined" sx={{ p: 3, mb: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
              <PolicyIcon color="primary" />
              <Typography variant="subtitle1" fontWeight="bold">
                Trusted list source
              </Typography>
            </Box>

            <FormControlLabel
              control={
                <Switch
                  checked={useOfficialList}
                  onChange={handleToggleChange('useOfficialTrustList')}
                  disabled={disabled}
                />
              }
              label={
                <Box>
                  <Typography variant="body2">
                    Use EU Trusted Lists (recommended)
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    We automatically keep trust anchors up to date.
                  </Typography>
                </Box>
              }
            />

            {!useOfficialList && (
              <Box sx={{ mt: 2, p: 2, bgcolor: 'action.hover', borderRadius: 1 }}>
                <Typography variant="body2" color="text.secondary">
                  Manual trust anchor management enabled. You can add individual issuers in Settings.
                </Typography>
              </Box>
            )}
          </Paper>

          {/* Section: Country Filters */}
          <Paper variant="outlined" sx={{ p: 3, mb: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
              <PublicIcon color="primary" />
              <Typography variant="subtitle1" fontWeight="bold">
                Limit by country (optional)
              </Typography>
            </Box>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Only accept credentials from selected countries. Leave empty to accept all.
            </Typography>

            <Autocomplete
              multiple
              options={COUNTRIES}
              getOptionLabel={(option) => option.name}
              value={selectedCountries}
              onChange={handleCountriesChange}
              disabled={disabled}
              renderInput={(params) => (
                <TextField
                  {...params}
                  label="Allowed countries"
                  placeholder="Select countries..."
                />
              )}
              renderTags={(value, getTagProps) =>
                value.map((option, index) => (
                  <Chip
                    label={option.name}
                    size="small"
                    {...getTagProps({ index })}
                    key={option.code}
                  />
                ))
              }
            />
          </Paper>

          {/* Section: Document Types */}
          <Paper variant="outlined" sx={{ p: 3, mb: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
              <DescriptionIcon color="primary" />
              <Typography variant="subtitle1" fontWeight="bold">
                Accepted document types
              </Typography>
            </Box>

            <FormGroup>
              {DOCUMENT_TYPES.map((docType) => (
                <FormControlLabel
                  key={docType.id}
                  control={
                    <Checkbox
                      checked={isDocTypeChecked(docType.id)}
                      onChange={handleDocTypeChange(docType.id)}
                      disabled={disabled}
                    />
                  }
                  label={
                    <Box>
                      <Typography variant="body2">{docType.label}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        {docType.description}
                      </Typography>
                    </Box>
                  }
                />
              ))}
            </FormGroup>
          </Paper>

          {/* Section: Safety Checks / Revocation */}
          <Paper variant="outlined" sx={{ p: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
              <SecurityIcon color="primary" />
              <Typography variant="subtitle1" fontWeight="bold">
                Safety checks
              </Typography>
            </Box>

            <FormGroup>
              {REVOCATION_OPTIONS.map((option) => (
                <FormControlLabel
                  key={option.value}
                  control={
                    <Checkbox
                      checked={isRevocationChecked(option.value)}
                      onChange={handleRevocationChange(option.value)}
                      disabled={disabled}
                    />
                  }
                  label={
                    <Box>
                      <Typography variant="body2">{option.label}</Typography>
                      <Typography variant="caption" color="text.secondary">
                        {option.description}
                      </Typography>
                    </Box>
                  }
                />
              ))}
            </FormGroup>

            <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 2 }}>
              Tip: Revocation means a certificate was cancelled before its expiration date.
            </Typography>
          </Paper>
        </Box>
      </Box>
    </Fade>
  );
};

export default TrustSourcesStep;
