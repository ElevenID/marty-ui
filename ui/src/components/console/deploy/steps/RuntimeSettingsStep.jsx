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
import { useOrganizationDefaults } from '../../../../hooks/useOrganizationDefaults';
import { findOrganizationDefault, matchesTrust } from '../../organizationDefaultSelection';

const isActivePolicy = (policy) => (
  String(policy?.status || '').trim().toLowerCase() === 'active'
  || policy?.is_active === true
);

const PAGE_SIZE = 100;
const MAX_CATALOG_PAGES = 100;
async function loadCatalog(fetchPage, organizationId, label) {
  const items = [];
  const seen = new Set();
  for (let page = 0; page < MAX_CATALOG_PAGES; page += 1) {
    const batch = await fetchPage({ organization_id: organizationId, limit: PAGE_SIZE, offset: page * PAGE_SIZE });
    if (!Array.isArray(batch) || batch.length > PAGE_SIZE
      || batch.some((item) => !item || !item.id || item.organization_id !== organizationId)) {
      throw new Error(`${label} catalog is malformed or outside the selected organization.`);
    }
    for (const item of batch) {
      if (seen.has(item.id)) throw new Error(`${label} catalog changed while loading. Refresh before selecting resources.`);
      seen.add(item.id); items.push(item);
    }
    if (batch.length < PAGE_SIZE) return items.filter(isActivePolicy);
  }
  throw new Error(`${label} catalog exceeds the console's 10,000-resource discovery limit. No partial catalog was selected.`);
}

const RuntimeSettingsStep = ({ data, onChange }) => {
  const { t } = useTranslation('console');
  const navigate = useNavigate();
  const { activeOrgId } = useConsole();
  const { defaults, loading: defaultsLoading } = useOrganizationDefaults(activeOrgId);
  const { data: catalog, loading, error, reload } = useAsyncData(
    async () => {
      if (!activeOrgId) {
        throw new Error('Select an organization before loading presentation policies.');
      }
      const [policies, templates, flows] = await Promise.all([
        loadCatalog(listPresentationPolicies, activeOrgId, 'Policy'),
        loadCatalog(listCredentialTemplates, activeOrgId, 'Credential template'),
        loadCatalog(listFlows, activeOrgId, 'Flow'),
      ]);
      return { organizationId: activeOrgId, policies, templates, flows };
    },
    [activeOrgId]
  );
  const currentCatalog = activeOrgId && catalog?.organizationId === activeOrgId ? catalog : null;
  const policies = currentCatalog?.policies || [];
  const templates = currentCatalog?.templates || [];
  const flows = currentCatalog?.flows || [];
  const selectedPolicy = policies.find((policy) => policy.id === data.default_policy_id);
  const compatibleFlow = (flow) => (!flow.trust_profile_id || flow.trust_profile_id === selectedPolicy?.trust_profile_id)
    && (!flow.presentation_policy_id || flow.presentation_policy_id === selectedPolicy?.id)
    && (!flow.credential_template_id || (data.credential_template_ids || []).includes(flow.credential_template_id));

  // Reconcile selections against the current scoped catalogs before allowing review.
  useEffect(() => {
    const updates = {};
    const ready = Boolean(!loading && !error && currentCatalog);
    if (data.runtime_catalog_ready !== ready) updates.runtime_catalog_ready = ready;
    if (ready) {
      if (data.runtime_catalog !== catalog) updates.runtime_catalog = catalog;
      let selectedTemplates = (data.credential_template_ids || []).filter((id) => templates.some((template) => template.id === id));
      const automaticTemplateId = data._organization_default_template_initialized === activeOrgId
        ? data._organization_default_template_id : null;
      const explicitTemplates = selectedTemplates.filter((id) => id !== automaticTemplateId)
        .map((id) => templates.find((template) => template.id === id));
      const preferredPolicy = findOrganizationDefault(policies, defaults?.default_policy_id, activeOrgId,
        (policy) => matchesTrust(policy, data.trust_profile_id)
          && selectedTemplates.every((id) => matchesTrust(templates.find((template) => template.id === id), policy.trust_profile_id)));
      let policy = selectedPolicy || (!data.default_policy_id && !defaultsLoading
        ? preferredPolicy || (!defaults?.default_policy_id && policies.length === 1 ? policies[0] : null) : null);
      const automaticPolicy = data._organization_default_policy && data._organization_default_policy.organizationId === activeOrgId
        && data._organization_default_policy.id === data.default_policy_id;
      if (automaticPolicy && policy && explicitTemplates.some((template) => !matchesTrust(template, policy.trust_profile_id))) {
        policy = null;
        updates._organization_default_policy = null;
      } else if (!data.default_policy_id && policy && policy === preferredPolicy) {
        updates._organization_default_policy = { organizationId: activeOrgId, id: policy.id };
      }
      if (data.default_policy_id !== (policy?.id || null)) updates.default_policy_id = policy?.id || null;
      if ((policy || data.default_policy_id) && data.trust_profile_id !== (policy?.trust_profile_id || null)) updates.trust_profile_id = policy?.trust_profile_id || null;
      if (automaticTemplateId) {
        const automaticTemplate = templates.find((template) => template.id === automaticTemplateId);
        if (!automaticTemplate || (policy && !matchesTrust(automaticTemplate, policy.trust_profile_id))
          || explicitTemplates.some((template) => !matchesTrust(template, automaticTemplate.trust_profile_id))) {
          selectedTemplates = selectedTemplates.filter((id) => id !== automaticTemplateId);
          updates._organization_default_template_id = null;
        }
      }
      // Remember initialization in wizard state so returning to this step does not
      // re-check a template the user deliberately unchecked.
      if (data._organization_default_template_initialized !== activeOrgId) {
        if ((data.credential_template_ids || []).length) {
          updates._organization_default_template_initialized = activeOrgId;
        } else if (policy && !defaultsLoading) {
          const preferredTemplate = findOrganizationDefault(templates, defaults?.default_template_id, activeOrgId,
            (template) => matchesTrust(template, policy.trust_profile_id));
          if (preferredTemplate) {
            selectedTemplates.push(preferredTemplate.id);
            updates._organization_default_template_id = preferredTemplate.id;
          }
          updates._organization_default_template_initialized = activeOrgId;
        }
      }
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
        
        <Typography color="text.secondary" sx={{ marginBottom: '16px', maxWidth: 600, mx: 'auto' }} component="p">
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
      <Typography color="text.secondary" component="p" sx={{ marginBottom: '16px' }}>
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
              _organization_default_policy: null,
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
              ? data.credential_template_ids.filter((id) => id !== template.id) : [...(data.credential_template_ids || []), template.id],
              _organization_default_template_id: data._organization_default_template_id === template.id ? null : data._organization_default_template_id,
              _organization_default_template_initialized: activeOrgId })} />} />)}
      </FormGroup>
      {!templates.length && <Alert severity="info">No active credential templates are available. A verification-only deployment can continue without one.</Alert>}

      {/* Enabled Flows */}
      <Typography variant="subtitle2" gutterBottom>
        {t('wizards.deploymentProfile.runtimeSettingsStep.fields.enabledFlows')}
      </Typography>
      <Typography variant="body2" color="text.secondary" component="p" sx={{ marginBottom: '16px' }}>
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
