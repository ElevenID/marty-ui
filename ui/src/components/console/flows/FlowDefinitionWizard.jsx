import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  Container,
  Paper,
  Step,
  StepLabel,
  Stepper,
  Typography,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import CheckIcon from '@mui/icons-material/Check';
import RefreshIcon from '@mui/icons-material/Refresh';

import { useWizard } from '../../../hooks/useWizard';
import { useConsole } from '../../../contexts/ConsoleContext';
import { createFlow, getFlowCapabilities } from '../../../services/flowsApi';
import { DeploymentBindingStep, FlowStepsConfigStep, FlowTypeStep, ReviewStep } from './steps';

const STEPS = ['Flow type', 'Definition', 'Dependencies', 'Review'];

const INITIAL_DATA = {
  applicationTemplateId: null,
  approvalStrategy: 'AUTO',
  credentialTemplateId: null,
  defaultPolicyId: null,
  deliveryDestinationProfileId: null,
  description: '',
  flowType: null,
  hooks: {},
  name: '',
  selectedDeployment: null,
  triggerType: 'API_CALL',
  trustProfileId: null,
};

const CREDENTIAL_TYPES = new Set([
  'oid4vci_authorization_code', 'oid4vci_pre_authorized', 'mdl_issuance',
  'credential_renewal', 'credential_revocation', 'physical_document_issuance', 'combined',
]);
const APPLICATION_TYPES = new Set(['application_approval_issuance', 'physical_document_issuance']);
const PRESENTATION_TYPES = new Set(['oid4vp_presentation', 'mdl_presentation', 'siopv2', 'combined']);

export function buildFlowPayload(data, organizationId) {
  return {
    organization_id: organizationId,
    name: data.name.trim(),
    description: data.description.trim() || null,
    flow_type: data.flowType,
    approval_strategy: data.approvalStrategy,
    hooks: data.hooks,
    trigger: { trigger_type: data.triggerType, config: {} },
    trust_profile_id: data.selectedDeployment?.trust_profile_id || data.trustProfileId || null,
    credential_template_id: CREDENTIAL_TYPES.has(data.flowType) ? data.credentialTemplateId : null,
    application_template_id: APPLICATION_TYPES.has(data.flowType) ? data.applicationTemplateId : null,
    presentation_policy_id: PRESENTATION_TYPES.has(data.flowType) ? data.defaultPolicyId : null,
    delivery_destination_profile_id: data.flowType === 'physical_document_issuance'
      ? data.deliveryDestinationProfileId
      : null,
    deployment_profile_ids: data.selectedDeployment?.id ? [data.selectedDeployment.id] : [],
  };
}

const FlowDefinitionWizard = () => {
  const navigate = useNavigate();
  const { activeOrgId: organizationId } = useConsole();
  const [capabilities, setCapabilities] = useState(null);
  const [capabilityError, setCapabilityError] = useState('');
  const [capabilitiesLoading, setCapabilitiesLoading] = useState(true);

  const loadCapabilities = useCallback(async () => {
    setCapabilitiesLoading(true);
    setCapabilityError('');
    try {
      const result = await getFlowCapabilities();
      if (!result || typeof result !== 'object' || !result.sequences || typeof result.sequences !== 'object') {
        throw new Error('Flow capability contract is malformed.');
      }
      setCapabilities(result);
    } catch (error) {
      setCapabilities(null);
      setCapabilityError(error.message || 'Flow capabilities are unavailable.');
    } finally {
      setCapabilitiesLoading(false);
    }
  }, []);

  useEffect(() => { loadCapabilities(); }, [loadCapabilities]);

  const validateStep = useCallback((stepIndex, data) => {
    if (stepIndex === 0) return Boolean(data.flowType);
    if (stepIndex === 1) return Boolean(data.name.trim() && capabilities?.sequences?.[data.flowType]?.length);
    if (stepIndex === 2) {
      if (CREDENTIAL_TYPES.has(data.flowType) && !data.credentialTemplateId) return false;
      if (APPLICATION_TYPES.has(data.flowType) && !data.applicationTemplateId) return false;
      if (PRESENTATION_TYPES.has(data.flowType) && !data.defaultPolicyId) return false;
      if (data.flowType === 'physical_document_issuance' && !data.deliveryDestinationProfileId) return false;
    }
    return true;
  }, [capabilities]);

  const wizard = useWizard({
    steps: STEPS,
    initialData: INITIAL_DATA,
    validateStep,
    onSubmit: async (data) => {
      if (!organizationId) throw new Error('Select an organization before creating a flow.');
      return createFlow(buildFlowPayload(data, organizationId));
    },
    onComplete: (flow) => navigate(`/console/org/flows/definitions/${flow.id}`),
    onCancel: () => navigate('/console/org/flows/definitions'),
  });

  const content = [
    <FlowTypeStep
      key="type"
      capabilities={capabilities}
      selectedType={wizard.data.flowType}
      onSelectType={(flowType) => wizard.updateData({ ...INITIAL_DATA, flowType })}
      onOpenCustomBuilder={() => navigate('/console/org/flows/definitions/new/custom')}
    />,
    <FlowStepsConfigStep
      key="definition"
      {...wizard.data}
      capabilities={capabilities}
      onUpdate={wizard.updateData}
    />,
    <DeploymentBindingStep
      key="dependencies"
      {...wizard.data}
      onUpdate={wizard.updateData}
    />,
    <ReviewStep key="review" capabilities={capabilities} data={wizard.data} />,
  ];

  if (capabilitiesLoading && !capabilities) {
    return <Box sx={{ display: 'flex', justifyContent: 'center', py: 10 }}><CircularProgress /></Box>;
  }

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h4">Create flow</Typography>
        <Typography color="text.secondary">MIP 0.3 standard flow</Typography>
      </Box>

      {capabilityError && (
        <Alert
          severity="error"
          sx={{ mb: 3 }}
          action={(
            <Button
              color="inherit"
              size="small"
              startIcon={<RefreshIcon />}
              onClick={loadCapabilities}
              disabled={capabilitiesLoading}
            >
              Refresh
            </Button>
          )}
        >
          {capabilityError}
        </Alert>
      )}
      {wizard.error && <Alert severity="error" sx={{ mb: 3 }}>{wizard.error}</Alert>}
      {wizard.success && <Alert severity="success" sx={{ mb: 3 }}>Draft created. Opening validation workspace...</Alert>}

      <Stepper activeStep={wizard.activeStep} sx={{ mb: 3 }}>
        {STEPS.map((label) => <Step key={label}><StepLabel>{label}</StepLabel></Step>)}
      </Stepper>

      <Paper variant="outlined" sx={{ p: { xs: 2, sm: 3 }, minHeight: 420 }}>
        {content[wizard.activeStep]}
      </Paper>

      <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 3 }}>
        <Button
          startIcon={<ArrowBackIcon />}
          onClick={wizard.activeStep === 0 ? wizard.cancel : wizard.goBack}
          disabled={wizard.loading || wizard.success}
          data-testid={wizard.activeStep === 0 ? 'wizard.flow.cancel' : 'wizard.flow.back'}
        >
          {wizard.activeStep === 0 ? 'Cancel' : 'Back'}
        </Button>
        {wizard.isLastStep ? (
          <Button
            variant="contained"
            startIcon={wizard.loading ? <CircularProgress size={18} /> : <CheckIcon />}
            onClick={wizard.submit}
            disabled={wizard.loading || wizard.success || !wizard.isStepValid()}
            data-testid="wizard.flow.submit"
          >
            Create draft
          </Button>
        ) : (
          <Button
            variant="contained"
            endIcon={<ArrowForwardIcon />}
            onClick={wizard.goNext}
            disabled={!wizard.isStepValid() || wizard.loading || capabilitiesLoading || !capabilities}
            data-testid="wizard.flow.next"
          >
            Next
          </Button>
        )}
      </Box>
    </Container>
  );
};

export default FlowDefinitionWizard;
