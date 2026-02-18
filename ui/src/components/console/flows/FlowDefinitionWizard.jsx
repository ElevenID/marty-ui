/**
 * Flow Definition Wizard
 * 
 * Multi-step wizard for creating flow definitions with:
 * - Flow type selection (Verification/Issuance/Combined)
 * - Flow steps configuration with drag-drop ordering
 * - Deployment profile binding
 * - Review and activation
 */

import { useState, useEffect, useCallback } from 'react';
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
  { label: t('wizards.flowDefinition.steps.bindDeployment'), optional: true },
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
  activateImmediately: true,
};

const FlowDefinitionWizard = () => {
  const navigate = useNavigate();
  const { t } = useTranslation('console');
  const [apiError, setApiError] = useState(null);

  // Validation function for each step
  const validateStep = useCallback((stepIndex, stepData) => {
    const valid = (() => {
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
        case 3: // Bind Deployment (optional)
          return true;
        case 4: // Review
          return true;
        default:
          return false;
      }
    })();
    console.log('[FlowWizard] validateStep called:', { stepIndex, flowType: stepData.flowType, valid });
    return valid;
  }, []);

  // Handle submission
  const handleSubmit = useCallback(async (formData) => {
    const payload = {
      name: formData.name,
      description: formData.description,
      type: formData.flowType,
      steps: formData.flowSteps,
      preconditions: formData.preconditions || [],
      deployment_profile_id: formData.selectedDeployment?.id || null,
      default_policy_id: formData.defaultPolicyId || null,
      is_active: formData.activateImmediately,
    };
    
    // Return the created flow (this would be returned by the API)
    return {
      id: 'flow_' + Date.now(),
      ...payload,
    };
  }, []);

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

  // Debug logging
  useEffect(() => {
    console.log('[FlowWizard] Data changed:', { flowType: wizard.data.flowType, activeStep: wizard.activeStep });
    console.log('[FlowWizard] validateStep called:', { stepIndex: wizard.activeStep, flowType: wizard.data.flowType, valid: validateStep(wizard.activeStep, wizard.data) });
    console.log('[FlowWizard] isStepValid():', wizard.isStepValid());
  }, [wizard.data, wizard.activeStep, wizard, validateStep]);

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
        {(wizard.error || apiError) && (
          <Alert severity="error" sx={{ mb: 3 }} onClose={() => { setApiError(null); }}>
            {wizard.error || apiError}
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
