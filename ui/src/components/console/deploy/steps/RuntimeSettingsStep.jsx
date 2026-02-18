/**
 * Runtime Settings Step - Deployment Profile Wizard
 * 
 * Configure default presentation policy and enabled flows.
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

const RuntimeSettingsStep = ({ data, onChange }) => {
  const { t } = useTranslation('console');
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [policies, setPolicies] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadPolicies();
  }, []);

  const loadPolicies = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await listPresentationPolicies();
      const items = response.data || response || [];
      // Filter to active policies
      const activePolicies = items.filter((p) => p.status === 'active');
      setPolicies(activePolicies);

      // Auto-select if only one policy
      if (activePolicies.length === 1 && !data.default_policy_id) {
        onChange({ default_policy_id: activePolicies[0].id });
      }
    } catch (err) {
      console.error('Failed to load policies:', err);
      setError(t('wizards.deploymentProfile.runtimeSettingsStep.errors.failedToLoadPolicies'));
    } finally {
      setLoading(false);
    }
  };

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
            onClick={() => window.location.reload()}
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

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Default Presentation Policy */}
      <FormControl fullWidth required sx={{ mb: 4 }}>
        <InputLabel>{t('wizards.deploymentProfile.runtimeSettingsStep.fields.defaultPolicy')}</InputLabel>
        <Select
          value={data.default_policy_id || ''}
          onChange={(e) => onChange({ default_policy_id: e.target.value })}
          label={t('wizards.deploymentProfile.runtimeSettingsStep.fields.defaultPolicy')}
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
