/**
 * Runtime Settings Step - Deployment Profile Wizard
 * 
 * Configure default presentation policy and enabled flows.
 */

import { useEffect } from 'react';
import { useAsyncData } from '../../../../hooks/useAsyncData';
import {
  Box,
  Typography,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormHelperText,
  FormGroup,
  FormControlLabel,
  Checkbox,
  Alert,
  CircularProgress,
  Button,
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import AddCircleOutlineIcon from '@mui/icons-material/AddCircleOutline';
import PolicyIcon from '@mui/icons-material/Policy';
import { useTranslation } from 'react-i18next';

import { listPresentationPolicies } from '../../../../services/presentationPolicyApi';
import { useConsole } from '../../../../contexts/ConsoleContext';

const getFlowTypes = (t) => [
  {
    value: 'verification',
    label: t('wizards.deploymentProfile.runtimeSettingsStep.flowTypes.verification.label'),
    description: t('wizards.deploymentProfile.runtimeSettingsStep.flowTypes.verification.description'),
  },
  {
    value: 'issuance',
    label: t('wizards.deploymentProfile.runtimeSettingsStep.flowTypes.issuance.label'),
    description: t('wizards.deploymentProfile.runtimeSettingsStep.flowTypes.issuance.description'),
  },
  {
    value: 'combined',
    label: t('wizards.deploymentProfile.runtimeSettingsStep.flowTypes.combined.label'),
    description: t('wizards.deploymentProfile.runtimeSettingsStep.flowTypes.combined.description'),
  },
];

const isActivePolicy = (policy) => (
  String(policy?.status || '').trim().toLowerCase() === 'active'
  || policy?.is_active === true
);

const RuntimeSettingsStep = ({ data, onChange }) => {
  const { t } = useTranslation('console');
  const navigate = useNavigate();
  const { activeOrgId } = useConsole();
  const { data: rawPolicies, loading, error, reload } = useAsyncData(
    async () => {
      if (!activeOrgId) {
        throw new Error('Select an organization before loading presentation policies.');
      }
      const response = await listPresentationPolicies({ organization_id: activeOrgId });
      return response.filter(isActivePolicy);
    },
    [activeOrgId]
  );
  const policies = rawPolicies || [];

  // Auto-select if only one policy and none already selected (mirrors original mount-only behavior)
  useEffect(() => {
    if (policies.length === 1 && !data.default_policy_id) {
      onChange({
        default_policy_id: policies[0].id,
        trust_profile_id: policies[0].trust_profile_id || null,
      });
    }
  }, [policies]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleFlowToggle = (flowValue) => {
    const flows = data.enabled_flows || [];
    const updated = flows.includes(flowValue)
      ? flows.filter((f) => f !== flowValue)
      : [...flows, flowValue];
    onChange({ enabled_flows: updated });
  };

  const handleGoToPolicies = () => {
    navigate('/console/org/policies/presentation/new');
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ py: 4 }}>
        <Alert severity="error" sx={{ mb: 3 }}>
          {error?.message || t('wizards.deploymentProfile.runtimeSettingsStep.errors.failedToLoadPolicies')}
        </Alert>
        <Button
          variant="outlined"
          onClick={reload}
        >
          {t('wizards.deploymentProfile.runtimeSettingsStep.blocked.refreshButton')}
        </Button>
      </Box>
    );
  }

  // No policies - block progression
  if (policies.length === 0) {
    return (
      <Box sx={{ textAlign: 'center', py: 4 }}>
        <PolicyIcon sx={{ fontSize: 80, color: 'warning.main', mb: 3 }} />
        
        <Typography variant="h5" gutterBottom>
          {t('wizards.deploymentProfile.runtimeSettingsStep.blocked.title')}
        </Typography>
        
        <Typography color="text.secondary" paragraph sx={{ maxWidth: 600, mx: 'auto' }}>
          {t('wizards.deploymentProfile.runtimeSettingsStep.blocked.description')}
        </Typography>

        <Alert severity="warning" sx={{ maxWidth: 600, mx: 'auto', mb: 3 }}>
          <Typography variant="body2">
            {t('wizards.deploymentProfile.runtimeSettingsStep.blocked.alert')}
          </Typography>
        </Alert>

        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center' }}>
          <Button
            variant="contained"
            startIcon={<AddCircleOutlineIcon />}
            onClick={handleGoToPolicies}
          >
            {t('wizards.deploymentProfile.runtimeSettingsStep.blocked.createButton')}
          </Button>
          <Button
            variant="outlined"
            onClick={reload}
          >
            {t('wizards.deploymentProfile.runtimeSettingsStep.blocked.refreshButton')}
          </Button>
        </Box>
      </Box>
    );
  }

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        {t('wizards.deploymentProfile.runtimeSettingsStep.title')}
      </Typography>
      <Typography color="text.secondary" paragraph>
        {t('wizards.deploymentProfile.runtimeSettingsStep.description')}
      </Typography>

      {/* Default Presentation Policy */}
      <FormControl fullWidth required sx={{ mb: 4 }}>
        <InputLabel>{t('wizards.deploymentProfile.runtimeSettingsStep.fields.defaultPolicy')}</InputLabel>
        <Select
          value={data.default_policy_id || ''}
          onChange={(e) => {
            const selectedPolicy = policies.find((policy) => policy.id === e.target.value);
            onChange({
              default_policy_id: e.target.value,
              trust_profile_id: selectedPolicy?.trust_profile_id || null,
            });
          }}
          label={t('wizards.deploymentProfile.runtimeSettingsStep.fields.defaultPolicy')}
          SelectDisplayProps={{ 'data-testid': 'deployment-default-policy-select' }}
        >
          {policies.map((policy) => (
            <MenuItem key={policy.id} value={policy.id}>
              {policy.name}
            </MenuItem>
          ))}
        </Select>
        <FormHelperText>
          {t('wizards.deploymentProfile.runtimeSettingsStep.helpers.defaultPolicy', {
            count: policies.length,
          })}
        </FormHelperText>
      </FormControl>

      {/* Enabled Flows */}
      <Typography variant="subtitle2" gutterBottom>
        {t('wizards.deploymentProfile.runtimeSettingsStep.fields.enabledFlows')}
      </Typography>
      <Typography variant="body2" color="text.secondary" paragraph>
        {t('wizards.deploymentProfile.runtimeSettingsStep.helpers.enabledFlows')}
      </Typography>
      
      <FormGroup>
        {getFlowTypes(t).map((flow) => (
          <FormControlLabel
            key={flow.value}
            control={
              <Checkbox
                checked={(data.enabled_flows || []).includes(flow.value)}
                onChange={() => handleFlowToggle(flow.value)}
              />
            }
            label={
              <Box>
                <Typography variant="body1">{flow.label}</Typography>
                <Typography variant="body2" color="text.secondary">
                  {flow.description}
                </Typography>
              </Box>
            }
          />
        ))}
      </FormGroup>

      {data.enabled_flows && data.enabled_flows.length === 0 && (
        <Alert severity="info" sx={{ mt: 2 }}>
          {t('wizards.deploymentProfile.runtimeSettingsStep.emptyFlows')}
        </Alert>
      )}
    </Box>
  );
};

export default RuntimeSettingsStep;
