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
import { listCredentialTemplates, listPresentationPolicies } from '../../../../services/presentationPolicyApi';
import { useAuth } from '../../../../hooks/useAuth';
import { useConsole } from '../../../../contexts/ConsoleContext';

const ISSUANCE_FLOW_TYPES = new Set(['issuance', 'issuance_oid4vci', 'combined']);
const PRESENTATION_FLOW_TYPES = new Set(['verification', 'combined']);

function logDeploymentBindingError(message, error) {
  if (import.meta.env?.DEV && import.meta.env?.MODE !== 'test') {
    console.error(message, error);
  }
}

function isActiveResource(resource) {
  return String(resource?.status || resource?.state || '').toLowerCase() === 'active'
    || resource?.is_active === true
    || resource?.enabled === true;
}

const DeploymentBindingStep = ({
  selectedDeployment,
  defaultPolicyId,
  credentialTemplateId,
  flowType,
  onUpdate,
}) => {
  const { t } = useTranslation('console');
  const { organizationId: authOrganizationId } = useAuth();
  const { activeOrgId } = useConsole();
  const organizationId = activeOrgId || authOrganizationId;
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [deploymentProfiles, setDeploymentProfiles] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [credentialTemplates, setCredentialTemplates] = useState([]);

  const requiresCredentialTemplate = ISSUANCE_FLOW_TYPES.has(flowType);
  const requiresPresentationPolicy = PRESENTATION_FLOW_TYPES.has(flowType);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      if (!organizationId) {
        throw new Error('Select an organization before loading flow prerequisites.');
      }

      const [deploymentsResponse, policiesResponse, templatesResponse] = await Promise.all([
        listDeploymentProfiles({ organization_id: organizationId }),
        listPresentationPolicies({ organization_id: organizationId }),
        listCredentialTemplates({ organization_id: organizationId }),
      ]);

      setDeploymentProfiles((deploymentsResponse.data || deploymentsResponse || []).filter(isActiveResource));
      setPolicies((policiesResponse.data || policiesResponse || []).filter(isActiveResource));
      setCredentialTemplates((templatesResponse.data || templatesResponse || []).filter(isActiveResource));
    } catch (err) {
      logDeploymentBindingError('Failed to fetch data:', err);
      setError(err?.message || t('wizards.flowDefinition.deploymentBindingStep.errors.failedToLoad'));
    } finally {
      setLoading(false);
    }
  }, [organizationId, t]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  useEffect(() => {
    const updates = {};
    if (!selectedDeployment && deploymentProfiles.length === 1) {
      updates.selectedDeployment = deploymentProfiles[0];
    }
    if (!defaultPolicyId && policies.length === 1) {
      updates.defaultPolicyId = policies[0].id;
      updates.trustProfileId = policies[0].trust_profile_id || updates.trustProfileId || null;
    }
    if (!credentialTemplateId && credentialTemplates.length === 1) {
      updates.credentialTemplateId = credentialTemplates[0].id;
      updates.trustProfileId = credentialTemplates[0].trust_profile_id || updates.trustProfileId || null;
    }
    if (Object.keys(updates).length > 0) {
      onUpdate(updates);
    }
  }, [
    credentialTemplateId,
    credentialTemplates,
    defaultPolicyId,
    deploymentProfiles,
    onUpdate,
    policies,
    selectedDeployment,
  ]);

  const handleSelectDeployment = (profile) => {
    onUpdate({
      selectedDeployment: profile,
      defaultPolicyId: profile?.default_policy_id || profile?.default_presentation_policy_id || defaultPolicyId || null,
      trustProfileId: profile?.trust_profile_id || null,
    });
  };

  const handleSelectPolicy = (policyId) => {
    const policy = policies.find((candidate) => candidate.id === policyId);
    onUpdate({
      defaultPolicyId: policyId,
      trustProfileId: policy?.trust_profile_id || null,
    });
  };

  const handleSelectTemplate = (templateId) => {
    const template = credentialTemplates.find((candidate) => candidate.id === templateId);
    onUpdate({
      credentialTemplateId: templateId,
      trustProfileId: template?.trust_profile_id || null,
    });
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
            <Alert severity="warning">
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
                            {isActiveResource(profile) && (
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

      {/* Credential Template Selection */}
      {requiresCredentialTemplate && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600 }}>
              {t('wizards.credentialTemplate.title', 'Credential Template')}
            </Typography>

            {credentialTemplates.length === 0 ? (
              <Alert severity="warning">
                No active credential templates are available for this organization.
              </Alert>
            ) : (
              <FormControl fullWidth required>
                <InputLabel>Credential Template</InputLabel>
                <Select
                  value={credentialTemplateId || ''}
                  onChange={(e) => handleSelectTemplate(e.target.value)}
                  label="Credential Template"
                  SelectDisplayProps={{ 'data-testid': 'flow-binding-template-select' }}
                >
                  {credentialTemplates.map((template) => (
                    <MenuItem key={template.id} value={template.id}>
                      {template.name}
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            )}
          </CardContent>
        </Card>
      )}

      {/* Default Policy Selection */}
      {requiresPresentationPolicy && (
      <Card>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600 }}>
            <ApiIcon sx={{ verticalAlign: 'middle', mr: 1 }} />
            {t('wizards.flowDefinition.deploymentBindingStep.sections.defaultPolicy')}
          </Typography>

          {policies.length === 0 ? (
            <Alert severity="warning">
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
                  SelectDisplayProps={{ 'data-testid': 'flow-binding-policy-select' }}
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
      )}
    </Box>
  );
};

export default DeploymentBindingStep;
