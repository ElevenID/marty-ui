/**
 * Trust Profile Prerequisite Step
 * 
 * Ensures the organization has at least one Trust Profile before proceeding.
 * If none exist, shows a message with a redirect to Trust Profile management.
 */

import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Alert,
  Button,
  Card,
  CardContent,
  Radio,
  RadioGroup,
  FormControlLabel,
  CircularProgress,
  Chip,
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import SecurityIcon from '@mui/icons-material/Security';
import AddCircleOutlineIcon from '@mui/icons-material/AddCircleOutline';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';

import { listTrustProfiles } from '../../../../services/presentationPolicyApi';

const FRAMEWORK_LABELS = {
  icao: { label: 'ICAO', icon: '✈️', description: 'ICAO 9303 for eMRTD/ePassport' },
  aamva: { label: 'AAMVA', icon: '🚗', description: 'ISO 18013-5 for mDL' },
  eudi: { label: 'EUDI', icon: '🇪🇺', description: 'EU Digital Identity Wallet' },
  custom: { label: 'Custom', icon: '🔧', description: 'Custom trust configuration' },
};

const TrustProfilePrerequisiteStep = ({ selectedTrustProfile, onSelectTrustProfile }) => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [trustProfiles, setTrustProfiles] = useState([]);

  useEffect(() => {
    fetchTrustProfiles();
  }, []);

  const fetchTrustProfiles = async () => {
    setLoading(true);
    setError(null);

    try {
      const response = await listTrustProfiles();
      setTrustProfiles(response.data || response || []);

      // Auto-select if only one profile exists
      if (response.data?.length === 1 && !selectedTrustProfile) {
        onSelectTrustProfile(response.data[0]);
      }
    } catch (err) {
      console.error('Failed to fetch trust profiles:', err);
      setError('Failed to load trust profiles');
    } finally {
      setLoading(false);
    }
  };

  const handleGoToTrustProfiles = () => {
    navigate('/vendor/trust-profiles');
  };

  const handleSelectProfile = (profile) => {
    onSelectTrustProfile(profile);
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
        <CircularProgress />
      </Box>
    );
  }

  // No trust profiles exist - block progression
  if (trustProfiles.length === 0) {
    return (
      <Box sx={{ textAlign: 'center', py: 4 }}>
        <SecurityIcon sx={{ fontSize: 80, color: 'warning.main', mb: 3 }} />
        
        <Typography variant="h5" gutterBottom>
          Trust Profile Required
        </Typography>
        
        <Typography color="text.secondary" paragraph sx={{ maxWidth: 600, mx: 'auto' }}>
          Before creating a presentation policy, you need to configure at least one Trust Profile.
          Trust Profiles define which credential issuers your organization trusts and the validation
          rules for verifying credentials.
        </Typography>

        <Alert severity="info" sx={{ maxWidth: 600, mx: 'auto', mb: 3 }}>
          <Typography variant="body2">
            Trust Profiles determine which standards (ICAO, AAMVA, EUDI, etc.) and certificate
            authorities are trusted for credential verification.
          </Typography>
        </Alert>

        <Button
          variant="contained"
          size="large"
          startIcon={<AddCircleOutlineIcon />}
          onClick={handleGoToTrustProfiles}
          sx={{ mt: 2 }}
        >
          Create Trust Profile
        </Button>
      </Box>
    );
  }

  // Trust profiles exist - allow selection
  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Select Trust Profile
      </Typography>
      
      <Typography color="text.secondary" paragraph>
        Choose which Trust Profile this presentation policy will use for credential validation.
        The Trust Profile determines which issuers are trusted and what validation rules apply.
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      <RadioGroup
        value={selectedTrustProfile?.id || ''}
        onChange={(e) => {
          const profile = trustProfiles.find(p => p.id === e.target.value);
          handleSelectProfile(profile);
        }}
      >
        {trustProfiles.map((profile) => {
          const framework = FRAMEWORK_LABELS[profile.trust_framework_type] || FRAMEWORK_LABELS.custom;
          
          return (
            <Card
              key={profile.id}
              sx={{
                mb: 2,
                border: 2,
                borderColor: selectedTrustProfile?.id === profile.id ? 'primary.main' : 'transparent',
                cursor: 'pointer',
                transition: 'all 0.2s',
                '&:hover': {
                  borderColor: 'primary.light',
                  boxShadow: 2,
                },
              }}
              onClick={() => handleSelectProfile(profile)}
            >
              <CardContent>
                <Box sx={{ display: 'flex', alignItems: 'flex-start' }}>
                  <FormControlLabel
                    value={profile.id}
                    control={<Radio />}
                    label=""
                    sx={{ mr: 2 }}
                  />
                  
                  <Box sx={{ flex: 1 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                      <Typography variant="h6" component="span" sx={{ mr: 1 }}>
                        {framework.icon}
                      </Typography>
                      <Typography variant="h6" component="span">
                        {profile.name}
                      </Typography>
                      {profile.is_default && (
                        <Chip
                          label="Default"
                          size="small"
                          color="primary"
                          sx={{ ml: 1 }}
                        />
                      )}
                    </Box>

                    <Typography variant="body2" color="text.secondary" paragraph>
                      {profile.description || framework.description}
                    </Typography>

                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                      <Chip
                        icon={<VerifiedUserIcon />}
                        label={framework.label}
                        size="small"
                        variant="outlined"
                      />
                      {profile.revocation_settings?.check_revocation && (
                        <Chip
                          label="Revocation Check"
                          size="small"
                          variant="outlined"
                          color="success"
                        />
                      )}
                      {profile.supported_formats?.map((format) => (
                        <Chip
                          key={format}
                          label={format}
                          size="small"
                          variant="outlined"
                        />
                      ))}
                    </Box>
                  </Box>
                </Box>
              </CardContent>
            </Card>
          );
        })}
      </RadioGroup>

      <Box sx={{ mt: 3, textAlign: 'center' }}>
        <Button
          variant="outlined"
          startIcon={<AddCircleOutlineIcon />}
          onClick={handleGoToTrustProfiles}
        >
          Create New Trust Profile
        </Button>
      </Box>
    </Box>
  );
};

export default TrustProfilePrerequisiteStep;
