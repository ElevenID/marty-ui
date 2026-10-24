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
import { useNavigate } from 'react-router';
import AddCircleOutlineIcon from '@mui/icons-material/AddCircleOutlined';
import PolicyIcon from '@mui/icons-material/Policy';
import { useTranslation } from 'react-i18next';

import { listPresentationPolicies, listCredentialTemplates } from '../../../../services/presentationPolicyApi';
import { listFlows } from '../../../../services/flowsApi';
import { useConsole } from '../../../../contexts/ConsoleContext';

const isActivePolicy = (policy) => (
  String(policy?.status || '').trim().toLowerCase() === 'active'
  || policy?.is_active === true
);

const RuntimeSettingsStep = ({ data, onChange }) => {
  const { t } = useTranslation('console');
  const navigate = useNavigate();
  const { activeOrgId } = useConsole();
  const { data: catalog, loading, error, reload } = useAsyncData(
    async () => {
      if (!activeOrgId) {
        throw new Error('Select an organization before loading presentation policies.');
      }
      const scope = { organization_id: activeOrgId };
      const [policies, templates, flows] = await Promise.all([
        listPresentationPolicies(scope), listCredentialTemplates(scope), listFlows(scope),
      ]);
      const ownedActive = (items, label) => {
        if (!Array.isArray(items) || items.some((item) => !item || !item.id || item.organization_id !== activeOrgId)) {
          throw new Error(`${label} catalog is malformed or outside the selected organization.`);
        }
        return items.filter(isActivePolicy);
      };
      return { policies: ownedActive(policies, 'Policy'), templates: ownedActive(templates, 'Credential template'), flows: ownedActive(flows, 'Flow') };
    },
    [activeOrgId]
  );
  const policies = catalog?.policies || [];
  const templates = catalog?.templates || [];
  const flows = catalog?.flows || [];
  const selectedPolicy = policies.find((policy) => policy.id === data.default_policy_id);
  const compatibleFlow = (flow) => (!flow.trust_profile_id || flow.trust_profile_id === selectedPolicy?.trust_profile_id)
    && (!flow.presentation_policy_id || flow.presentation_policy_id === selectedPolicy?.id)
    && (!flow.credential_template_id || (data.credential_template_ids || []).includes(flow.credential_template_id));

  // Reconcile selections against the current scoped catalogs before allowing review.
  useEffect(() => {
    const updates = {};
    const ready = Boolean(!loading && !error && catalog);
    if (data.runtime_catalog_ready !== ready) updates.runtime_catalog_ready = ready;
    if (ready) {
      if (data.runtime_catalog !== catalog) updates.runtime_catalog = catalog;
      const policy = selectedPolicy || (policies.length === 1 ? policies[0] : null);
      if (data.default_policy_id !== (policy?.id || null)) updates.default_policy_id = policy?.id || null;
      if (data.trust_profile_id !== (policy?.trust_profile_id || null)) updates.trust_profile_id = policy?.trust_profile_id || null;
      const selectedTemplates = (data.credential_template_ids || []).filter((id) => templates.some((template) => template.id === id));
      if (JSON.stringify(selectedTemplates) !== JSON.stringify(data.credential_template_ids)) updates.credential_template_ids = selectedTemplates;
      const selectedFlows = (data.enabled_flows || []).filter((id) => flows.some((flow) => flow.id === id && compatibleFlow(flow)));
      if (JSON.stringify(selectedFlows) !== JSON.stringify(data.enabled_flows)) updates.enabled_flows = selectedFlows;
    }
    if (Object.keys(updates).length) onChange(updates);
  });

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
        <InputLabel id="deployment-default-policy-label">{t('wizards.deploymentProfile.runtimeSettingsStep.fields.defaultPolicy')}</InputLabel>
        <Select
          labelId="deployment-default-policy-label"
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

      <Typography variant="subtitle2" gutterBottom>Credential templates</Typography>
      <Typography variant="body2" color="text.secondary">Select active credential templates to bind to this deployment.</Typography>
      <FormGroup>
        {templates.map((template) => <FormControlLabel key={template.id} label={template.name}
          control={<Checkbox checked={(data.credential_template_ids || []).includes(template.id)}
            onChange={() => onChange({ credential_template_ids: (data.credential_template_ids || []).includes(template.id)
              ? data.credential_template_ids.filter((id) => id !== template.id) : [...(data.credential_template_ids || []), template.id] })} />} />)}
      </FormGroup>
      {!templates.length && <Alert severity="info">No active credential templates are available. A verification-only deployment can continue without one.</Alert>}

      {/* Enabled Flows */}
      <Typography variant="subtitle2" gutterBottom>
        {t('wizards.deploymentProfile.runtimeSettingsStep.fields.enabledFlows')}
      </Typography>
      <Typography variant="body2" color="text.secondary" paragraph>
        Select active flow definitions. Issuance flows require their credential template to be selected; verification flows must use the selected policy and trust profile.
      </Typography>
      
      <FormGroup>
        {flows.map((flow) => (
          <FormControlLabel
            key={flow.id}
            control={
              <Checkbox
                disabled={!compatibleFlow(flow)}
                checked={(data.enabled_flows || []).includes(flow.id)}
                onChange={() => handleFlowToggle(flow.id)}
              />
            }
            label={
              <Box>
                <Typography variant="body1">{flow.name}</Typography>
                <Typography variant="body2" color="text.secondary">
                  {flow.flow_type}
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
