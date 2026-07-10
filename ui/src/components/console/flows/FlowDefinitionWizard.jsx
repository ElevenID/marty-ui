/**
 * Flow Definition Wizard
 * 
 * Multi-step wizard for creating flow definitions with:
 * - Flow type selection (Verification/Issuance/Combined)
 * - Flow steps configuration with drag-drop ordering
 * - Deployment profile binding
 * - Review and activation
 */

import { useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  Box,
  Container,
  Paper,
  Stepper,
  Step,
  StepLabel,
  Button,
  Typography,
  Alert,
  CircularProgress,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';

import { useWizard } from '../../../hooks/useWizard';
import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import { createFlow } from '../../../services/flowsApi';
import {
  FlowTypeStep,
  FlowStepsConfigStep,
  PreconditionsStep,
  DeploymentBindingStep,
  ReviewStep,
} from './steps';

const getSteps = (t) => [
  { label: t('wizards.flowDefinition.steps.flowType'), optional: false },
  { label: t('wizards.flowDefinition.steps.configureSteps'), optional: false },
  { label: t('wizards.flowDefinition.steps.preconditions'), optional: true },
  { label: t('wizards.flowDefinition.steps.bindDeployment'), optional: false },
  { label: t('wizards.flowDefinition.steps.review'), optional: false },
];

const INITIAL_DATA = {
  flowType: null, // 'verification', 'issuance', 'combined', 'issuance_oid4vci'
  name: '',
  description: '',
  flowSteps: [],
  preconditions: [],
  selectedDeployment: null,
  defaultPolicyId: null,
  credentialTemplateId: null,
  activateImmediately: true,
};

const ISSUANCE_FLOW_TYPES = new Set(['issuance', 'issuance_oid4vci', 'combined']);
const PRESENTATION_FLOW_TYPES = new Set(['verification', 'combined']);

const STEP_TYPE_ALIASES = {
  add_step: 'user_input',
  collect_data: 'data_collection',
  create_offer: 'issuance',
  custom: 'user_input',
  deliver_credential: 'issuance',
  display_qr: 'user_input',
  generate_code: 'issuance',
  grant_access: 'end',
  issue_credential: 'issuance',
  request_presentation: 'verification',
  send_invitation: 'callback',
  show_result: 'end',
  validate_age: 'validation',
  validate_credentials: 'validation',
  verify_identity: 'verification',
};

function normalizeFlowStepType(type) {
  const normalized = String(type || 'user_input').trim().toLowerCase();
  return STEP_TYPE_ALIASES[normalized] || normalized;
}

function buildFlowPayload(formData, organizationId) {
  const selectedDeployment = formData.selectedDeployment || null;
  const selectedPolicyId = formData.defaultPolicyId || selectedDeployment?.default_policy_id || selectedDeployment?.default_presentation_policy_id || null;
  const selectedTemplateId = formData.credentialTemplateId || null;

  return {
    organization_id: organizationId,
    name: formData.name,
    description: formData.description,
    flow_type: formData.flowType,
    steps: (formData.flowSteps || []).map((step) => ({
      name: step.name,
      description: step.description || null,
      step_type: normalizeFlowStepType(step.type || step.step_type),
      config: step.config || {},
      timeout_seconds: step.timeout_seconds || null,
      conditions: step.conditions || [],
    })),
    transitions: [],
    preconditions: formData.preconditions || [],
    deployment_profile_id: selectedDeployment?.id || null,
    deployment_profile_ids: selectedDeployment?.id ? [selectedDeployment.id] : [],
    credential_template_id: ISSUANCE_FLOW_TYPES.has(formData.flowType) ? selectedTemplateId : null,
    presentation_policy_id: PRESENTATION_FLOW_TYPES.has(formData.flowType) ? selectedPolicyId : null,
    trust_profile_id: selectedDeployment?.trust_profile_id || formData.trustProfileId || null,
    approval_strategy: 'AUTO',
    enabled: formData.activateImmediately !== false,
  };
}

const FlowDefinitionWizard = () => {
  const navigate = useNavigate();
  const { t } = useTranslation('console');
  const { organizationId: authOrganizationId } = useAuth();
  const { activeOrgId } = useConsole();
  const organizationId = activeOrgId || authOrganizationId;

  // Validation function for each step
  const validateStep = useCallback((stepIndex, stepData) => {
    switch (stepIndex) {
      case 0: // Flow Type
        return stepData.flowType !== null;
      case 1: // Configure Steps
        return (
          stepData.name.trim() !== '' &&
          stepData.flowSteps.length > 0
        );
      case 2: // Preconditions (optional)
        return true;
      case 3: { // Bind Deployment and required flow references
        if (!stepData.selectedDeployment?.id) {
          return false;
        }
        if (ISSUANCE_FLOW_TYPES.has(stepData.flowType) && !stepData.credentialTemplateId) {
          return false;
        }
        if (PRESENTATION_FLOW_TYPES.has(stepData.flowType) && !stepData.defaultPolicyId) {
          return false;
        }
        return true;
      }
      case 4: // Review
        return true;
      default:
        return false;
    }
  }, []);

  // Handle submission
  const handleSubmit = useCallback(async (formData) => {
    if (!organizationId) {
      throw new Error('Select an organization before creating a flow.');
    }
    return createFlow(buildFlowPayload(formData, organizationId));
  }, [organizationId]);

  const wizard = useWizard({
    steps: getSteps(t),
    initialData: INITIAL_DATA,
    validateStep,
    onSubmit: handleSubmit,
    onComplete: () => {
      // Redirect to operate page after 2 seconds
      setTimeout(() => {
        navigate('/console/org/operate');
      }, 2000);
    },
    onCancel: () => navigate('/console/org/flows'),
  });

  // Render current step content
  const renderStepContent = () => {
    switch (wizard.activeStep) {
      case 0:
        return (
          <FlowTypeStep
            selectedType={wizard.data.flowType}
            onSelectType={(type) => wizard.updateData({ flowType: type })}
          />
        );
      case 1:
        return (
          <FlowStepsConfigStep
            flowType={wizard.data.flowType}
            name={wizard.data.name}
            description={wizard.data.description}
            flowSteps={wizard.data.flowSteps}
            onUpdate={(updates) => wizard.updateData(updates)}
          />
        );
      case 2:
        return (
          <PreconditionsStep
            flowType={wizard.data.flowType}
            preconditions={wizard.data.preconditions}
            onUpdate={(updates) => wizard.updateData(updates)}
          />
        );
      case 3:
        return (
          <DeploymentBindingStep
            selectedDeployment={wizard.data.selectedDeployment}
            defaultPolicyId={wizard.data.defaultPolicyId}
            credentialTemplateId={wizard.data.credentialTemplateId}
            flowType={wizard.data.flowType}
            onUpdate={(updates) => wizard.updateData(updates)}
          />
        );
      case 4:
        return (
          <ReviewStep
            data={wizard.data}
            onEdit={(step) => wizard.goToStep(step)}
            onToggleActivation={(value) => wizard.updateData({ activateImmediately: value })}
          />
        );
      default:
        return <Typography>{t('wizards.flowDefinition.unknownStep')}</Typography>;
    }
  };

  // Show success message
  if (wizard.success) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper elevation={3} sx={{ p: 4, textAlign: 'center' }}>
          <CheckCircleIcon color="success" sx={{ fontSize: 64, mb: 2 }} />
          <Typography variant="h5" gutterBottom>
            {t('wizards.flowDefinition.success.title')}
          </Typography>
          <Typography color="text.secondary" paragraph>
            {wizard.data.activateImmediately 
              ? t('wizards.flowDefinition.success.messageActive', { name: wizard.data.name })
              : t('wizards.flowDefinition.success.messageDraft', { name: wizard.data.name })}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {t('wizards.flowDefinition.success.redirecting')}
          </Typography>
        </Paper>
      </Container>
    );
  }

  return (
    <Container maxWidth="lg" sx={{ py: 4 }}>
      <Paper elevation={3} sx={{ p: 4 }}>
        {/* Header */}
        <Box sx={{ mb: 4 }}>
          <Typography variant="h4" gutterBottom>
            {t('wizards.flowDefinition.title')}
          </Typography>
          <Typography color="text.secondary">
            {t('wizards.flowDefinition.description')}
          </Typography>
        </Box>

        {/* Stepper */}
        <Stepper activeStep={wizard.activeStep} sx={{ mb: 4 }}>
          {getSteps(t).map((step) => (
            <Step key={step.label}>
              <StepLabel optional={step.optional && <Typography variant="caption">{t('wizards.common.optional')}</Typography>}>
                {step.label}
              </StepLabel>
            </Step>
          ))}
        </Stepper>

        {/* Error Alert */}
        {wizard.error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {wizard.error}
          </Alert>
        )}

        {/* Step Content */}
        <Box sx={{ minHeight: 400, mb: 4 }}>
          {renderStepContent()}
        </Box>

        {/* Navigation Buttons */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', pt: 2 }}>
          <Button
            onClick={wizard.activeStep === 0 ? () => navigate('/console/org/flows/definitions') : wizard.goBack}
            startIcon={<ArrowBackIcon />}
            disabled={wizard.loading}
            data-testid={wizard.activeStep === 0 ? 'wizard.flow.cancel' : 'wizard.flow.back'}
          >
            {wizard.activeStep === 0 ? t('wizards.flowDefinition.buttons.cancel') : t('wizards.flowDefinition.buttons.back')}
          </Button>

          <Box sx={{ display: 'flex', gap: 2 }}>
            {/* Skip button for optional steps */}
            {getSteps(t)[wizard.activeStep].optional && (
              <Button
                onClick={wizard.goNext}
                disabled={wizard.loading}
                data-testid="wizard.flow.skip"
              >
                {t('wizards.flowDefinition.buttons.skip')}
              </Button>
            )}

            {wizard.activeStep === getSteps(t).length - 1 ? (
              <Button
                variant="contained"
                onClick={wizard.submit}
                disabled={wizard.loading || !wizard.isStepValid()}
                startIcon={wizard.loading ? <CircularProgress size={20} /> : <CheckCircleIcon />}
                data-testid="wizard.flow.submit"
              >
                {wizard.loading ? t('wizards.flowDefinition.buttons.submitting') : t('wizards.flowDefinition.buttons.submit')}
              </Button>
            ) : (
              <Button
                variant="contained"
                onClick={wizard.goNext}
                disabled={wizard.loading || !wizard.isStepValid()}
                endIcon={<ArrowForwardIcon />}
                data-testid="wizard.flow.next"
              >
                {t('wizards.flowDefinition.buttons.next')}
              </Button>
            )}
          </Box>
        </Box>
      </Paper>
    </Container>
  );
};

export default FlowDefinitionWizard;
