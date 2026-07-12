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
}) => {
  const { activeOrgId: organizationId } = useConsole();
  const [loading, setLoading] = useState(true);
  const [loadErrors, setLoadErrors] = useState([]);
  const [resources, setResources] = useState({ applications: [], deliveries: [], deployments: [], policies: [], templates: [] });

  const required = useMemo(() => ({
    application: APPLICATION_TYPES.has(flowType),
    credential: CREDENTIAL_TYPES.has(flowType),
    delivery: flowType === 'physical_document_issuance',
    presentation: PRESENTATION_TYPES.has(flowType),
  }), [flowType]);

  const fetchData = useCallback(async () => {
    if (!organizationId) return;
    setLoading(true);
    const requests = [
      ['deployments', listDeploymentProfiles({ organization_id: organizationId })],
      ['policies', listPresentationPolicies({ organization_id: organizationId })],
      ['templates', listCredentialTemplates({ organization_id: organizationId })],
      ['applications', listApplicationTemplates(organizationId)],
      ['deliveries', listDeliveryDestinations({ organizationId, activeOnly: true })],
    ];
    const settled = await Promise.allSettled(requests.map(([, request]) => request));
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
    setLoadErrors(errors);
    setLoading(false);
  }, [organizationId]);

  useEffect(() => { fetchData(); }, [fetchData]);

  useEffect(() => {
    const updates = {};
    if (!selectedDeployment && resources.deployments.length === 1) updates.selectedDeployment = resources.deployments[0];
    if (required.credential && !credentialTemplateId && resources.templates.length === 1) updates.credentialTemplateId = resources.templates[0].id;
    if (required.application && !applicationTemplateId && resources.applications.length === 1) updates.applicationTemplateId = resources.applications[0].id;
    if (required.presentation && !defaultPolicyId && resources.policies.length === 1) updates.defaultPolicyId = resources.policies[0].id;
    if (required.delivery && !deliveryDestinationProfileId && resources.deliveries.length === 1) updates.deliveryDestinationProfileId = resources.deliveries[0].id;
    if (Object.keys(updates).length) onUpdate(updates);
  }, [applicationTemplateId, credentialTemplateId, defaultPolicyId, deliveryDestinationProfileId, onUpdate, required, resources, selectedDeployment]);

  if (loading) {
    return <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}><CircularProgress /></Box>;
  }

  const select = (label, value, candidates, updateKey, requiredField = false, resolveValue = (nextValue) => nextValue || null) => (
    <FormControl fullWidth required={requiredField}>
      <InputLabel>{label}</InputLabel>
      <Select
        label={label}
        value={value || ''}
        onChange={(event) => onUpdate({ [updateKey]: resolveValue(event.target.value) })}
        SelectDisplayProps={{ 'data-testid': `flow-binding-${updateKey}` }}
      >
        {!requiredField && <MenuItem value=""><em>None</em></MenuItem>}
        {candidates.map((candidate) => (
          <MenuItem key={candidate.id} value={candidate.id}>{candidate.name || candidate.display_name || candidate.id}</MenuItem>
        ))}
      </Select>
    </FormControl>
  );

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
