/**
 * Deployment Binding Step
 * 
 * Optionally bind the flow to a deployment profile and set default policy
 */

import { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Radio,
  RadioGroup,
  FormControlLabel,
  CircularProgress,
  Chip,
  Alert,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
} from '@mui/material';
import DeployIcon from '@mui/icons-material/RocketLaunch';
import ApiIcon from '@mui/icons-material/Api';
import { useTranslation } from 'react-i18next';

import { listDeploymentProfiles } from '../../../../services/deploymentProfilesApi';
import { listPresentationPolicies } from '../../../../services/presentationPolicyApi';

const DeploymentBindingStep = ({ selectedDeployment, defaultPolicyId, onUpdate }) => {
  const { t } = useTranslation('console');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [deploymentProfiles, setDeploymentProfiles] = useState([]);
  const [policies, setPolicies] = useState([]);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const [deploymentsResponse, policiesResponse] = await Promise.all([
        listDeploymentProfiles(),
        listPresentationPolicies(),
      ]);

      setDeploymentProfiles(deploymentsResponse.data || deploymentsResponse || []);
      setPolicies(policiesResponse.data || policiesResponse || []);
    } catch (err) {
      console.error('Failed to fetch data:', err);
      setError(t('wizards.flowDefinition.deploymentBindingStep.errors.failedToLoad'));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleSelectDeployment = (profile) => {
    onUpdate({ selectedDeployment: profile });
  };

  const handleSelectPolicy = (policyId) => {
    onUpdate({ defaultPolicyId: policyId });
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        {t('wizards.flowDefinition.deploymentBindingStep.title')}
      </Typography>
      
      <Typography color="text.secondary" paragraph>
        {t('wizards.flowDefinition.deploymentBindingStep.description')}
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Deployment Profile Selection */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600 }}>
            <DeployIcon sx={{ verticalAlign: 'middle', mr: 1 }} />
            {t('wizards.flowDefinition.deploymentBindingStep.sections.deploymentProfile')}
          </Typography>

          {deploymentProfiles.length === 0 ? (
            <Alert severity="info">
              {t('wizards.flowDefinition.deploymentBindingStep.deployment.empty')}
            </Alert>
          ) : (
            <>
              <Typography variant="body2" color="text.secondary" paragraph>
                {t('wizards.flowDefinition.deploymentBindingStep.deployment.helper')}
              </Typography>

              <RadioGroup
                value={selectedDeployment?.id || ''}
                onChange={(e) => {
                  const profile = deploymentProfiles.find(p => p.id === e.target.value);
                  handleSelectDeployment(profile);
                }}
              >
                <FormControlLabel
                  value=""
                  control={<Radio />}
                  label={t('wizards.flowDefinition.deploymentBindingStep.deployment.none')}
                  sx={{ mb: 1 }}
                />
                
                {deploymentProfiles.map((profile) => (
                  <Card
                    key={profile.id}
                    sx={{
                      mb: 1,
                      border: 2,
                      borderColor: selectedDeployment?.id === profile.id ? 'primary.main' : 'transparent',
                      cursor: 'pointer',
                      '&:hover': {
                        borderColor: 'primary.light',
                      },
                    }}
                    onClick={() => handleSelectDeployment(profile)}
                  >
                    <CardContent sx={{ py: 1.5 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center' }}>
                        <FormControlLabel
                          value={profile.id}
                          control={<Radio />}
                          label=""
                          sx={{ mr: 2 }}
                        />
                        
                        <Box sx={{ flex: 1 }}>
                          <Typography variant="body1" sx={{ fontWeight: 500 }}>
                            {profile.name}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {profile.description}
                          </Typography>
                          <Box sx={{ mt: 0.5 }}>
                            <Chip
                              label={profile.network_mode || t('wizards.flowDefinition.deploymentBindingStep.deployment.onlineFallback')}
                              size="small"
                              variant="outlined"
                              sx={{ mr: 0.5 }}
                            />
                            {profile.is_active && (
                              <Chip
                                label={t('wizards.flowDefinition.deploymentBindingStep.deployment.activeChip')}
                                size="small"
                                color="success"
                                variant="outlined"
                              />
                            )}
                          </Box>
                        </Box>
                      </Box>
                    </CardContent>
                  </Card>
                ))}
              </RadioGroup>
            </>
          )}
        </CardContent>
      </Card>

      {/* Default Policy Selection */}
      <Card>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600 }}>
            <ApiIcon sx={{ verticalAlign: 'middle', mr: 1 }} />
            {t('wizards.flowDefinition.deploymentBindingStep.sections.defaultPolicy')}
          </Typography>

          {policies.length === 0 ? (
            <Alert severity="info">
              {t('wizards.flowDefinition.deploymentBindingStep.policy.empty')}
            </Alert>
          ) : (
            <>
              <Typography variant="body2" color="text.secondary" paragraph>
                {t('wizards.flowDefinition.deploymentBindingStep.policy.helper')}
              </Typography>

              <FormControl fullWidth>
                <InputLabel>{t('wizards.flowDefinition.deploymentBindingStep.policy.label')}</InputLabel>
                <Select
                  value={defaultPolicyId || ''}
                  onChange={(e) => handleSelectPolicy(e.target.value)}
                  label={t('wizards.flowDefinition.deploymentBindingStep.policy.label')}
                >
                  <MenuItem value="">
                    <em>{t('wizards.flowDefinition.deploymentBindingStep.policy.none')}</em>
                  </MenuItem>
                  {policies.map((policy) => (
                    <MenuItem key={policy.id} value={policy.id}>
                      {policy.name}
                      {policy.is_active && (
                        <Chip
                          label={t('wizards.flowDefinition.deploymentBindingStep.policy.activeChip')}
                          size="small"
                          color="success"
                          variant="outlined"
                          sx={{ ml: 1 }}
                        />
                      )}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </>
          )}
        </CardContent>
      </Card>
    </Box>
  );
};

export default DeploymentBindingStep;
