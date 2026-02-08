/**
 * Trust & Compliance Step - Credential Template Wizard
 * 
 * Select the trust profile and optional compliance profile.
 * Trust Profile is required; blocks if none active.
 */

import { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormHelperText,
  Alert,
  CircularProgress,
  Button,
  Chip,
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import SecurityIcon from '@mui/icons-material/Security';
import WarningIcon from '@mui/icons-material/Warning';
import AddCircleOutlineIcon from '@mui/icons-material/AddCircleOutline';

import { listTrustProfiles } from '../../../../services/presentationPolicyApi';

const TrustComplianceStep = ({ data, onChange }) => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [trustProfiles, setTrustProfiles] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadTrustProfiles();
  }, []);

  const loadTrustProfiles = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await listTrustProfiles();
      const profiles = response.data || response || [];
      // Filter to only active profiles
      const activeProfiles = profiles.filter((p) => p.status === 'active');
      setTrustProfiles(activeProfiles);

      // Auto-select if only one active profile
      if (activeProfiles.length === 1 && !data.trust_profile_id) {
        onChange({ trust_profile_id: activeProfiles[0].id });
      }
    } catch (err) {
      console.error('Failed to load trust profiles:', err);
      setError('Failed to load trust profiles');
    } finally {
      setLoading(false);
    }
  };

  const handleGoToTrustProfiles = () => {
    navigate('/console/trust/profiles/new');
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
        <CircularProgress />
      </Box>
    );
  }

  // No active trust profiles - block progression
  if (trustProfiles.length === 0) {
    return (
      <Box sx={{ textAlign: 'center', py: 4 }}>
        <SecurityIcon sx={{ fontSize: 80, color: 'warning.main', mb: 3 }} />
        
        <Typography variant="h5" gutterBottom>
          Trust Profile Required
        </Typography>
        
        <Typography color="text.secondary" paragraph sx={{ maxWidth: 600, mx: 'auto' }}>
          Before creating a credential template, you need at least one active Trust Profile.
          Trust Profiles define which issuers are trusted and validation rules for credentials.
        </Typography>

        <Alert severity="warning" sx={{ maxWidth: 600, mx: 'auto', mb: 3 }}>
          <Typography variant="body2">
            You cannot proceed with credential template creation until an active Trust Profile exists.
            Create one now to continue.
          </Typography>
        </Alert>

        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center' }}>
          <Button
            variant="contained"
            startIcon={<AddCircleOutlineIcon />}
            onClick={handleGoToTrustProfiles}
          >
            Create Trust Profile
          </Button>
          <Button
            variant="outlined"
            onClick={() => window.location.reload()}
          >
            Refresh
          </Button>
        </Box>
      </Box>
    );
  }

  return (
    <Box>
      <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <SecurityIcon />
        Trust & Compliance
      </Typography>
      <Typography color="text.secondary" paragraph>
        Select which trust profile and compliance rules apply to this credential template.
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Trust Profile Selection */}
      <FormControl fullWidth required sx={{ mb: 3 }}>
        <InputLabel>Trust Profile</InputLabel>
        <Select
          value={data.trust_profile_id || ''}
          onChange={(e) => onChange({ trust_profile_id: e.target.value })}
          label="Trust Profile"
        >
          {trustProfiles.map((profile) => (
            <MenuItem key={profile.id} value={profile.id}>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, width: '100%' }}>
                <span>{profile.name}</span>
                {profile.framework_type && (
                  <Chip
                    label={profile.framework_type.toUpperCase()}
                    size="small"
                    sx={{ ml: 'auto' }}
                  />
                )}
              </Box>
            </MenuItem>
          ))}
        </Select>
        <FormHelperText>
          The trust profile that defines validation rules for this credential ({trustProfiles.length} active profile{trustProfiles.length !== 1 ? 's' : ''} available)
        </FormHelperText>
      </FormControl>

      {/* Show selected trust profile */}
      {data.trust_profile_id && (
        <Box sx={{ mb: 3, p: 2, bgcolor: 'action.hover', borderRadius: 1 }}>
          <Typography variant="caption" color="text.secondary" gutterBottom display="block">
            Selected Trust Profile
          </Typography>
          <Chip
            label={trustProfiles.find((p) => p.id === data.trust_profile_id)?.name || 'Unknown'}
            color="primary"
            icon={<SecurityIcon />}
          />
        </Box>
      )}

      {/* Compliance Profile Selection (Optional) */}
      <FormControl fullWidth sx={{ mb: 2 }}>
        <InputLabel>Compliance Profile</InputLabel>
        <Select
          value={data.compliance_profile_id || ''}
          onChange={(e) => onChange({ compliance_profile_id: e.target.value || null })}
          label="Compliance Profile"
        >
          <MenuItem value="">
            <em>None (recommended for most use cases)</em>
          </MenuItem>
          {/* TODO: Load actual compliance profiles when available */}
          <MenuItem value="gdpr" disabled>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              GDPR Compliance
              <Chip label="Coming Soon" size="small" />
            </Box>
          </MenuItem>
        </Select>
        <FormHelperText>
          Optional: Select only if you need specific regulatory requirements (GDPR, HIPAA, etc.)
        </FormHelperText>
      </FormControl>

      <Alert severity="info" sx={{ mb: 3 }}>
        <Typography variant="body2" gutterBottom>
          <strong>Most users don't need compliance profiles.</strong>
        </Typography>
        <Typography variant="caption" color="text.secondary">
          Compliance profiles add extra validation layers for regulated industries. Leave this as "None" unless you have specific regulatory requirements.
        </Typography>
      </Alert>

      <Alert severity="info" icon={<SecurityIcon />}>
        <Typography variant="body2">
          The selected Trust Profile will determine which cryptographic algorithms and validation rules
          apply to credentials issued from this template.
        </Typography>
      </Alert>
    </Box>
  );
};

export default TrustComplianceStep;
