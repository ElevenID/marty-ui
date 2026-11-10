import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  CircularProgress,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  Typography,
} from '@mui/material';

import { listApplicationTemplates } from '../../../../services/applicationTemplatesApi';
import { listDeliveryDestinations } from '../../../../services/deliveryDestinationsApi';
import { listDeploymentProfiles } from '../../../../services/deploymentProfilesApi';
import { listCredentialTemplates, listPresentationPolicies } from '../../../../services/presentationPolicyApi';
import { useConsole } from '../../../../contexts/ConsoleContext';
import { loadScopedCatalog } from '../../../../services/loadScopedCatalog';
import { useOrganizationDefaults } from '../../../../hooks/useOrganizationDefaults';
import { findOrganizationDefault, matchesTrust, policyMatchesFlow, templateMatchesFlow } from '../../organizationDefaultSelection';

const CREDENTIAL_TYPES = new Set([
  'oid4vci_authorization_code', 'oid4vci_pre_authorized', 'mdl_issuance',
  'credential_renewal', 'credential_revocation', 'physical_document_issuance', 'combined',
]);
const APPLICATION_TYPES = new Set(['application_approval_issuance', 'physical_document_issuance']);
const PRESENTATION_TYPES = new Set(['oid4vp_presentation', 'mdl_presentation', 'siopv2', 'combined']);

function items(response) {
  const value = response?.data || response || [];
  return Array.isArray(value) ? value : value.items || [];
}

function isActive(resource) {
  return String(resource?.status || '').toLowerCase() === 'active' || resource?.is_active === true;
}

const DeploymentBindingStep = ({
  applicationTemplateId,
  credentialTemplateId,
  defaultPolicyId,
  deliveryDestinationProfileId,
  flowType,
  onUpdate,
  selectedDeployment,
  trustProfileId,
  _organization_default_bindings: automaticBindings,
}) => {
  const { activeOrgId: organizationId } = useConsole();
  const { defaults, loading: defaultsLoading } = useOrganizationDefaults(organizationId);
  const [loading, setLoading] = useState(true);
  const [loadErrors, setLoadErrors] = useState([]);
  const [resourcesOrganizationId, setResourcesOrganizationId] = useState(null);
  const [resources, setResources] = useState({ applications: [], deliveries: [], deployments: [], policies: [], templates: [] });

  const required = useMemo(() => ({
    application: APPLICATION_TYPES.has(flowType),
    credential: CREDENTIAL_TYPES.has(flowType),
    delivery: flowType === 'physical_document_issuance',
    presentation: PRESENTATION_TYPES.has(flowType),
  }), [flowType]);

  const fetchData = useCallback(async (signal) => {
    if (!organizationId) return;
    setLoading(true);
    const requests = [
      ['deployments', loadScopedCatalog(listDeploymentProfiles, organizationId, { signal })],
      ['policies', loadScopedCatalog(listPresentationPolicies, organizationId, { signal })],
      ['templates', loadScopedCatalog(listCredentialTemplates, organizationId, { signal })],
      ['applications', listApplicationTemplates(organizationId)],
      ['deliveries', listDeliveryDestinations({ organizationId, activeOnly: true })],
    ];
    const settled = await Promise.allSettled(requests.map(([, request]) => request));
    if (signal.aborted) return;
    const nextResources = { applications: [], deliveries: [], deployments: [], policies: [], templates: [] };
    const errors = [];
    settled.forEach((result, index) => {
      const key = requests[index][0];
      if (result.status === 'fulfilled') {
        nextResources[key] = items(result.value).filter(isActive);
      } else {
        errors.push(key);
      }
    });
    setResources(nextResources);
    setResourcesOrganizationId(organizationId);
    setLoadErrors(errors);
    setLoading(false);
  }, [organizationId]);

  useEffect(() => {
    const controller = new AbortController();
    fetchData(controller.signal);
    return () => controller.abort();
  }, [fetchData]);

  useEffect(() => {
    if (loading || defaultsLoading || resourcesOrganizationId !== organizationId) return;
    const updates = {};
    const currentTemplate = resources.templates.find((template) => template.id === credentialTemplateId);
    const currentPolicy = resources.policies.find((policy) => policy.id === defaultPolicyId);
    const automatic = automaticBindings?.organizationId === organizationId ? automaticBindings : null;
    const isAutomatic = (field, value) => Boolean(automatic?.[field] && automatic[field] === value);
    const nextAutomatic = { ...automatic, organizationId };
    const explicitTrustIds = [!isAutomatic('selectedDeployment', selectedDeployment?.id) && selectedDeployment?.trust_profile_id,
      !isAutomatic('trustProfileId', trustProfileId) && trustProfileId,
      !isAutomatic('credentialTemplateId', credentialTemplateId) && currentTemplate?.trust_profile_id,
      !isAutomatic('defaultPolicyId', defaultPolicyId) && currentPolicy?.trust_profile_id].filter(Boolean);
    const matchesExplicitTrust = (resource) => explicitTrustIds.every((id) => matchesTrust(resource, id));

    // A later manual choice takes precedence over related automatic defaults.
    // Keep this provenance in wizard state so Back/Next preserves that distinction.
    if (isAutomatic('selectedDeployment', selectedDeployment?.id)
      && !findOrganizationDefault(resources.deployments, selectedDeployment.id, organizationId, matchesExplicitTrust)) {
      updates.selectedDeployment = null;
      delete nextAutomatic.selectedDeployment;
    }
    if (isAutomatic('credentialTemplateId', credentialTemplateId)
      && !findOrganizationDefault(resources.templates, credentialTemplateId, organizationId,
        (template) => templateMatchesFlow(template, flowType) && matchesExplicitTrust(template))) {
      updates.credentialTemplateId = null;
      delete nextAutomatic.credentialTemplateId;
    }
    const retainedTemplate = updates.credentialTemplateId === null ? null : currentTemplate;
    if (isAutomatic('defaultPolicyId', defaultPolicyId)
      && !findOrganizationDefault(resources.policies, defaultPolicyId, organizationId,
        (policy) => policyMatchesFlow(policy, flowType, retainedTemplate?.trust_profile_id) && matchesExplicitTrust(policy))) {
      updates.defaultPolicyId = null;
      delete nextAutomatic.defaultPolicyId;
    }
    if (isAutomatic('trustProfileId', trustProfileId)) {
      const retainedPolicy = updates.defaultPolicyId === null ? null : currentPolicy;
      const retainedDeployment = updates.selectedDeployment === null ? null : selectedDeployment;
      const remainingTrustIds = [retainedDeployment?.trust_profile_id, retainedTemplate?.trust_profile_id,
        retainedPolicy?.trust_profile_id].filter(Boolean);
      const nextTrust = remainingTrustIds.length && remainingTrustIds.every((id) => id === remainingTrustIds[0])
        ? remainingTrustIds[0] : null;
      if (nextTrust !== trustProfileId) {
        updates.trustProfileId = nextTrust;
        delete nextAutomatic.trustProfileId;
      }
    }
    if (Object.keys(updates).length) {
      updates._organization_default_bindings = Object.keys(nextAutomatic).length > 1 ? nextAutomatic : null;
      onUpdate(updates);
      return;
    }
    const trustIds = [selectedDeployment?.trust_profile_id, trustProfileId,
      currentTemplate?.trust_profile_id, currentPolicy?.trust_profile_id].filter(Boolean);
    const usesSelectedTrust = (resource) => trustIds.every((id) => matchesTrust(resource, id));
    const preferredTemplate = required.credential && !credentialTemplateId
      ? findOrganizationDefault(resources.templates, defaults?.default_template_id, organizationId,
        (template) => templateMatchesFlow(template, flowType) && usesSelectedTrust(template)) : null;
    const template = currentTemplate || preferredTemplate;
    const preferredPolicy = required.presentation && !defaultPolicyId
      ? findOrganizationDefault(resources.policies, defaults?.default_policy_id, organizationId,
        (policy) => policyMatchesFlow(policy, flowType, template?.trust_profile_id) && usesSelectedTrust(policy)) : null;
    if (required.credential && !credentialTemplateId) {
      if (preferredTemplate) updates.credentialTemplateId = preferredTemplate.id;
      else if (!defaults?.default_template_id && resources.templates.length === 1
        && usesSelectedTrust(resources.templates[0])
        && (!preferredPolicy || matchesTrust(resources.templates[0], preferredPolicy.trust_profile_id))) {
        updates.credentialTemplateId = resources.templates[0].id;
      }
    }
    if (required.application && !applicationTemplateId && resources.applications.length === 1) updates.applicationTemplateId = resources.applications[0].id;
    if (required.presentation && !defaultPolicyId) {
      if (preferredPolicy) updates.defaultPolicyId = preferredPolicy.id;
      else if (!defaults?.default_policy_id && resources.policies.length === 1
        && usesSelectedTrust(resources.policies[0])
        && (!preferredTemplate || matchesTrust(resources.policies[0], preferredTemplate.trust_profile_id))) {
        updates.defaultPolicyId = resources.policies[0].id;
      }
    }
    const preferredTrust = preferredTemplate?.trust_profile_id || preferredPolicy?.trust_profile_id;
    if (preferredTemplate) nextAutomatic.credentialTemplateId = preferredTemplate.id;
    if (preferredPolicy) nextAutomatic.defaultPolicyId = preferredPolicy.id;
    if (!trustProfileId && preferredTrust) {
      updates.trustProfileId = preferredTrust;
      nextAutomatic.trustProfileId = preferredTrust;
    }
    if (!selectedDeployment && !automatic?.deploymentExplicit && resources.deployments.length === 1) {
      const deployment = findOrganizationDefault(resources.deployments, resources.deployments[0].id, organizationId,
        (profile) => [...trustIds, preferredTrust].filter(Boolean).every((id) => profile.trust_profile_id === id));
      if (deployment) {
        updates.selectedDeployment = deployment;
        nextAutomatic.selectedDeployment = deployment.id;
      }
    }
    if (preferredTemplate || preferredPolicy || updates.selectedDeployment) updates._organization_default_bindings = nextAutomatic;
    if (required.delivery && !deliveryDestinationProfileId && resources.deliveries.length === 1) updates.deliveryDestinationProfileId = resources.deliveries[0].id;
    if (Object.keys(updates).length) onUpdate(updates);
  }, [applicationTemplateId, automaticBindings, credentialTemplateId, defaultPolicyId, defaults, defaultsLoading, deliveryDestinationProfileId,
    flowType, loading, onUpdate, organizationId, required, resources, resourcesOrganizationId, selectedDeployment, trustProfileId]);

  if (loading) {
    return <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}><CircularProgress /></Box>;
  }

  const select = (label, value, candidates, updateKey, requiredField = false, resolveValue = (nextValue) => nextValue || null) => {
    const inputId = `flow-binding-${updateKey}-input`;
    const labelId = `${inputId}-label`;
    return (
    <FormControl fullWidth required={requiredField}>
      <InputLabel id={labelId}>{label}</InputLabel>
      <Select
        id={inputId}
        labelId={labelId}
        label={label}
        value={value || ''}
        onChange={(event) => {
          const value = resolveValue(event.target.value);
          const candidate = candidates.find((item) => item.id === value);
          const nextAutomatic = { ...automaticBindings, organizationId };
          delete nextAutomatic[updateKey];
          if (updateKey === 'selectedDeployment') nextAutomatic.deploymentExplicit = true;
          if (['credentialTemplateId', 'defaultPolicyId'].includes(updateKey) && !selectedDeployment) delete nextAutomatic.trustProfileId;
          onUpdate({ [updateKey]: value,
            ...(['credentialTemplateId', 'defaultPolicyId'].includes(updateKey) && !selectedDeployment
              ? { trustProfileId: candidate?.trust_profile_id || null } : {}),
            _organization_default_bindings: Object.keys(nextAutomatic).length > 1 ? nextAutomatic : null,
          });
        }}
        SelectDisplayProps={{ 'data-testid': `flow-binding-${updateKey}` }}
      >
        {!requiredField && <MenuItem value=""><em>None</em></MenuItem>}
        {candidates.map((candidate) => (
          <MenuItem key={candidate.id} value={candidate.id}>{candidate.name || candidate.display_name || candidate.id}</MenuItem>
        ))}
      </Select>
    </FormControl>
    );
  };

  return (
    <Box>
      <Typography variant="h6" gutterBottom>Dependencies</Typography>
      <Stack spacing={2.5}>
        {loadErrors.length > 0 && <Alert severity="warning">Some dependency catalogs could not be loaded: {loadErrors.join(', ')}.</Alert>}
        {required.credential && select('Credential template', credentialTemplateId, resources.templates, 'credentialTemplateId', true)}
        {required.application && select('Application template', applicationTemplateId, resources.applications, 'applicationTemplateId', true)}
        {required.presentation && select('Presentation policy', defaultPolicyId, resources.policies, 'defaultPolicyId', true)}
        {required.delivery && select('Production destination', deliveryDestinationProfileId, resources.deliveries, 'deliveryDestinationProfileId', true)}
        {select(
          'Deployment profile',
          selectedDeployment?.id,
          resources.deployments,
          'selectedDeployment',
          false,
          (profileId) => resources.deployments.find((candidate) => candidate.id === profileId) || null,
        )}
      </Stack>
    </Box>
  );
};

export default DeploymentBindingStep;
