/**
 * Trust Profile Prerequisite Step
 * 
 * Ensures the organization has at least one Trust Profile before proceeding.
 * If none exist, shows a message with a redirect to Trust Profile management.
 */

import { useState, useEffect, useCallback } from 'react';
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
import { useTranslation } from 'react-i18next';

import { listTrustProfiles } from '../../../../services/presentationPolicyApi';

const FRAMEWORK_LABELS = {
  icao: { key: 'icao', icon: '✈️' },
  aamva: { key: 'aamva', icon: '🚗' },
  eudi: { key: 'eudi', icon: '🇪🇺' },
  custom: { key: 'custom', icon: '🔧' },
};

const TrustProfileStep = ({ selectedTrustProfile, onSelectTrustProfile }) => {
  const { t } = useTranslation('console');
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [trustProfiles, setTrustProfiles] = useState([]);

  const fetchTrustProfiles = useCallback(async () => {
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
      setError(t('wizards.presentationPolicy.trustProfileStep.errors.failedToLoadTrustProfiles'));
    } finally {
      setLoading(false);
    }
  }, [selectedTrustProfile, onSelectTrustProfile, t]);

  useEffect(() => {
    fetchTrustProfiles();
  }, [fetchTrustProfiles]);

  const handleGoToTrustProfiles = () => {
    navigate('/console/trust/profiles/new');
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
          {t('wizards.presentationPolicy.trustProfileStep.blocked.title')}
        </Typography>
        
        <Typography color="text.secondary" paragraph sx={{ maxWidth: 600, mx: 'auto' }}>
          {t('wizards.presentationPolicy.trustProfileStep.blocked.description')}
        </Typography>

        <Alert severity="info" sx={{ maxWidth: 600, mx: 'auto', mb: 3 }}>
          <Typography variant="body2">
            {t('wizards.presentationPolicy.trustProfileStep.blocked.info')}
          </Typography>
        </Alert>

        <Button
          variant="contained"
          size="large"
          startIcon={<AddCircleOutlineIcon />}
          onClick={handleGoToTrustProfiles}
          sx={{ mt: 2 }}
        >
          {t('wizards.presentationPolicy.trustProfileStep.blocked.createButton')}
        </Button>
      </Box>
    );
  }

  // Trust profiles exist - allow selection
  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        {t('wizards.presentationPolicy.trustProfileStep.title')}
      </Typography>
      
      <Typography color="text.secondary" paragraph>
        {t('wizards.presentationPolicy.trustProfileStep.description')}
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
                          label={t('wizards.presentationPolicy.trustProfileStep.defaultChip')}
                          size="small"
                          color="primary"
                          sx={{ ml: 1 }}
                        />
                      )}
                    </Box>

                    <Typography variant="body2" color="text.secondary" paragraph>
                      {profile.description || t(`wizards.presentationPolicy.trustProfileStep.frameworkDescriptions.${framework.key}`)}
                    </Typography>

                    <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                      <Chip
                        icon={<VerifiedUserIcon />}
                        label={t(`wizards.presentationPolicy.trustProfileStep.frameworkLabels.${framework.key}`)}
                        size="small"
                        variant="outlined"
                      />
                      {profile.revocation_settings?.check_revocation && (
                        <Chip
                          label={t('wizards.presentationPolicy.trustProfileStep.revocationCheckChip')}
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
          {t('wizards.presentationPolicy.trustProfileStep.createNewButton')}
        </Button>
      </Box>
    </Box>
  );
};

export default TrustProfileStep;
