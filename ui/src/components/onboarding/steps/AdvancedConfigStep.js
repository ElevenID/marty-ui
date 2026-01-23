/**
 * Advanced Configuration Step Component
 * 
 * Escape hatch for technical users who want manual control over trust profiles.
 * Collapsed by default - only shown when user clicks "Advanced Configuration".
 */

import React, { useState } from 'react';
import {
  Box,
  Typography,
  Button,
  Collapse,
  Paper,
  Grid,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  IconButton,
  Alert,
  Divider,
  Fade,
} from '@mui/material';
import {
  ExpandMore as ExpandIcon,
  ExpandLess as CollapseIcon,
  Add as AddIcon,
  Delete as DeleteIcon,
  Settings as SettingsIcon,
} from '@mui/icons-material';

const TRUST_PROFILE_TYPES = [
  { value: 'ICAO', label: 'ICAO PKD (Passports)', description: 'ICAO 9303 for eMRTD/ePassport verification' },
  { value: 'AAMVA', label: 'AAMVA (mDL)', description: 'ISO 18013-5 mobile driving licenses' },
  { value: 'EUDI', label: 'EUDI (EU Wallets)', description: 'European Digital Identity Wallet' },
  { value: 'CUSTOM', label: 'Custom X.509', description: 'Custom certificate-based trust' },
];

/**
 * Manual Trust Profile Editor
 */
const TrustProfileEditor = ({ profile, onChange, onDelete }) => {
  const handleFieldChange = (field, value) => {
    onChange({ ...profile, [field]: value });
  };

  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
        <Typography variant="subtitle1" sx={{ flexGrow: 1 }}>
          Trust Profile Configuration
        </Typography>
        <IconButton
          size="small"
          color="error"
          onClick={onDelete}
          data-testid="delete-profile"
        >
          <DeleteIcon />
        </IconButton>
      </Box>

      <Grid container spacing={2}>
        <Grid item xs={12} sm={6}>
          <TextField
            fullWidth
            label="Profile Name"
            value={profile.name || ''}
            onChange={(e) => handleFieldChange('name', e.target.value)}
            placeholder="e.g., Passports-ICAO"
            helperText="User-friendly name for this profile"
            data-testid="profile-name"
          />
        </Grid>

        <Grid item xs={12} sm={6}>
          <FormControl fullWidth>
            <InputLabel>Trust Framework</InputLabel>
            <Select
              value={profile.profile_type || ''}
              onChange={(e) => handleFieldChange('profile_type', e.target.value)}
              label="Trust Framework"
              data-testid="profile-type"
            >
              {TRUST_PROFILE_TYPES.map((type) => (
                <MenuItem key={type.value} value={type.value}>
                  {type.label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
        </Grid>

        <Grid item xs={12}>
          <TextField
            fullWidth
            multiline
            rows={2}
            label="Description"
            value={profile.description || ''}
            onChange={(e) => handleFieldChange('description', e.target.value)}
            placeholder="Optional description"
            data-testid="profile-description"
          />
        </Grid>

        {profile.profile_type === 'ICAO' && (
          <Grid item xs={12}>
            <TextField
              fullWidth
              label="ICAO PKD URL"
              value={profile.pkd_url || ''}
              onChange={(e) => handleFieldChange('pkd_url', e.target.value)}
              placeholder="https://pkddownloadsg.icao.int"
              helperText="ICAO Public Key Directory endpoint"
              data-testid="pkd-url"
            />
          </Grid>
        )}

        {profile.profile_type === 'AAMVA' && (
          <Grid item xs={12}>
            <TextField
              fullWidth
              label="AAMVA Trust Anchor"
              value={profile.trust_anchor || ''}
              onChange={(e) => handleFieldChange('trust_anchor', e.target.value)}
              placeholder="AAMVA root certificate URL"
              helperText="AAMVA certificate trust chain root"
              data-testid="trust-anchor"
            />
          </Grid>
        )}

        {profile.profile_type === 'EUDI' && (
          <Grid item xs={12}>
            <TextField
              fullWidth
              label="EUDI Trust List URL"
              value={profile.trust_list_url || ''}
              onChange={(e) => handleFieldChange('trust_list_url', e.target.value)}
              placeholder="https://eudi.example.com/trust-list"
              helperText="EU Digital Identity Trust List endpoint"
              data-testid="trust-list-url"
            />
          </Grid>
        )}

        {profile.profile_type === 'CUSTOM' && (
          <>
            <Grid item xs={12}>
              <TextField
                fullWidth
                multiline
                rows={4}
                label="Root Certificate (PEM)"
                value={profile.root_certificate || ''}
                onChange={(e) => handleFieldChange('root_certificate', e.target.value)}
                placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                helperText="Paste your root CA certificate in PEM format"
                data-testid="root-certificate"
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label="Certificate Validation URL"
                value={profile.validation_url || ''}
                onChange={(e) => handleFieldChange('validation_url', e.target.value)}
                placeholder="https://pki.example.com/validate"
                helperText="Optional OCSP or certificate validation endpoint"
                data-testid="validation-url"
              />
            </Grid>
          </>
        )}
      </Grid>
    </Paper>
  );
};

/**
 * Advanced Configuration Step Component
 */
const AdvancedConfigStep = ({
  manualProfiles = [],
  onManualProfilesChange,
  disabled = false,
}) => {
  const [expanded, setExpanded] = useState(false);

  const handleAddProfile = () => {
    const newProfile = {
      id: `manual-${Date.now()}`,
      name: '',
      profile_type: 'CUSTOM',
      description: '',
      manually_configured: true,
    };
    onManualProfilesChange([...manualProfiles, newProfile]);
  };

  const handleUpdateProfile = (index, updatedProfile) => {
    const updated = [...manualProfiles];
    updated[index] = updatedProfile;
    onManualProfilesChange(updated);
  };

  const handleDeleteProfile = (index) => {
    const updated = manualProfiles.filter((_, i) => i !== index);
    onManualProfilesChange(updated);
  };

  return (
    <Fade in>
      <Box data-testid="advanced-config-step">
        <Divider sx={{ my: 4 }} />

        {/* Collapsible Advanced Section */}
        <Box sx={{ textAlign: 'center' }}>
          <Button
            variant="text"
            color="primary"
            startIcon={<SettingsIcon />}
            endIcon={expanded ? <CollapseIcon /> : <ExpandIcon />}
            onClick={() => setExpanded(!expanded)}
            disabled={disabled}
            data-testid="advanced-toggle"
          >
            Advanced Configuration
          </Button>
          <Typography variant="caption" display="block" color="text.secondary" sx={{ mt: 1 }}>
            For technical users: Manually configure trust profiles
          </Typography>
        </Box>

        <Collapse in={expanded} timeout="auto">
          <Box sx={{ mt: 3, maxWidth: 900, mx: 'auto' }}>
            <Alert severity="info" sx={{ mb: 3 }}>
              <Typography variant="subtitle2" gutterBottom>
                Manual Configuration Mode
              </Typography>
              <Typography variant="body2">
                By configuring profiles manually, you'll bypass the automatic setup. 
                Make sure you understand ICAO, AAMVA, EUDI, or X.509 certificate standards 
                before proceeding.
              </Typography>
            </Alert>

            {/* Manual Profile Editors */}
            {manualProfiles.map((profile, index) => (
              <TrustProfileEditor
                key={profile.id || index}
                profile={profile}
                onChange={(updated) => handleUpdateProfile(index, updated)}
                onDelete={() => handleDeleteProfile(index)}
              />
            ))}

            {/* Add Profile Button */}
            <Button
              variant="outlined"
              startIcon={<AddIcon />}
              onClick={handleAddProfile}
              disabled={disabled}
              fullWidth
              sx={{ mt: 2 }}
              data-testid="add-profile"
            >
              Add Trust Profile
            </Button>

            {manualProfiles.length === 0 && (
              <Paper variant="outlined" sx={{ p: 3, mt: 2, textAlign: 'center' }}>
                <Typography variant="body2" color="text.secondary">
                  No manual profiles configured. Click "Add Trust Profile" to create one.
                </Typography>
              </Paper>
            )}
          </Box>
        </Collapse>
      </Box>
    </Fade>
  );
};

export default AdvancedConfigStep;
export { TRUST_PROFILE_TYPES };
