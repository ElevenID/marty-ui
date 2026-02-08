/**
 * Flow Definition Wizard
 * 
 * Multi-step wizard for creating flow definitions with:
 * - Flow type selection (Verification/Issuance/Combined)
 * - Flow steps configuration with drag-drop ordering
 * - Deployment profile binding
 * - Review and activation
 */

import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
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
  DeploymentBindingStep,
  ReviewStep,
} from './steps';

const STEPS = [
  { label: 'Flow Type', optional: false },
  { label: 'Configure Steps', optional: false },
  { label: 'Bind Deployment', optional: true },
  { label: 'Review', optional: false },
];

const INITIAL_DATA = {
  flowType: null, // 'verification', 'issuance', 'combined'
  name: '',
  description: '',
  flowSteps: [],
  selectedDeployment: null,
  defaultPolicyId: null,
  activateImmediately: true,
};

const FlowDefinitionWizard = () => {
  const navigate = useNavigate();
  const [apiError, setApiError] = useState(null);

  const {
    activeStep,
    data,
    loading,
    error,
    success,
    goNext,
    goBack,
    goToStep,
    updateData,
    submit,
    isStepValid,
  } = useWizard({
    steps: STEPS,
    initialData: INITIAL_DATA,
    apiEndpoint: '/api/v1/identity/flows',
    onSuccess: () => {
      // Redirect to operate page after 2 seconds
      setTimeout(() => {
        navigate('/console/operate');
      }, 2000);
    },
  });

  // Validate current step
  useEffect(() => {
    let valid = false;
    
    switch (activeStep) {
      case 0: // Flow Type
        valid = data.flowType !== null;
        break;
      case 1: // Configure Steps
        valid = (
          data.name.trim() !== '' &&
          data.flowSteps.length > 0
        );
        break;
      case 2: // Bind Deployment (optional)
        valid = true;
        break;
      case 3: // Review
        valid = true;
        break;
      default:
        valid = false;
    }
    
    // Update validation state in wizard hook
    isStepValid(valid);
  }, [activeStep, data, isStepValid]);

  // Render current step content
  const renderStepContent = () => {
    switch (activeStep) {
      case 0:
        return (
          <FlowTypeStep
            selectedType={data.flowType}
            onSelectType={(type) => updateData({ flowType: type })}
          />
        );
      case 1:
        return (
          <FlowStepsConfigStep
            flowType={data.flowType}
            name={data.name}
            description={data.description}
            flowSteps={data.flowSteps}
            onUpdate={(updates) => updateData(updates)}
          />
        );
      case 2:
        return (
          <DeploymentBindingStep
            selectedDeployment={data.selectedDeployment}
            defaultPolicyId={data.defaultPolicyId}
            onUpdate={(updates) => updateData(updates)}
          />
        );
      case 3:
        return (
          <ReviewStep
            data={data}
            onEdit={(step) => goToStep(step)}
            onToggleActivation={(value) => updateData({ activateImmediately: value })}
          />
        );
      default:
        return <Typography>Unknown step</Typography>;
    }
  };

  // Handle submission with activation
  const handleSubmit = async () => {
    setApiError(null);
    
    try {
      const payload = {
        name: data.name,
        description: data.description,
        flow_type: data.flowType,
        steps: data.flowSteps,
        deployment_profile_id: data.selectedDeployment?.id || null,
        default_presentation_policy_id: data.defaultPolicyId || null,
        is_active: data.activateImmediately,
      };

      await submit(payload);
    } catch (err) {
      console.error('Failed to create flow definition:', err);
      setApiError(err.message || 'Failed to create flow definition');
    }
  };

  // Show success message
  if (success) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper elevation={3} sx={{ p: 4, textAlign: 'center' }}>
          <CheckCircleIcon color="success" sx={{ fontSize: 64, mb: 2 }} />
          <Typography variant="h5" gutterBottom>
            Flow Definition Created Successfully!
          </Typography>
          <Typography color="text.secondary" paragraph>
            Your flow &quot;{data.name}&quot; is now ready to use.
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Redirecting to operations dashboard...
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
            Create Flow Definition
          </Typography>
          <Typography color="text.secondary">
            Define an end-to-end credential verification or issuance flow
          </Typography>
        </Box>

        {/* Stepper */}
        <Stepper activeStep={activeStep} sx={{ mb: 4 }}>
          {STEPS.map((step) => (
            <Step key={step.label}>
              <StepLabel optional={step.optional && <Typography variant="caption">Optional</Typography>}>
                {step.label}
              </StepLabel>
            </Step>
          ))}
        </Stepper>

        {/* Error Alert */}
        {(error || apiError) && (
          <Alert severity="error" sx={{ mb: 3 }} onClose={() => { setApiError(null); }}>
            {error || apiError}
          </Alert>
        )}

        {/* Step Content */}
        <Box sx={{ minHeight: 400, mb: 4 }}>
          {renderStepContent()}
        </Box>

        {/* Navigation Buttons */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', pt: 2 }}>
          <Button
            onClick={activeStep === 0 ? () => navigate('/console/flows/definitions') : goBack}
            startIcon={<ArrowBackIcon />}
            disabled={loading}
          >
            {activeStep === 0 ? 'Cancel' : 'Back'}
          </Button>

          <Box sx={{ display: 'flex', gap: 2 }}>
            {/* Skip button for optional steps */}
            {STEPS[activeStep].optional && (
              <Button
                onClick={goNext}
                disabled={loading}
              >
                Skip
              </Button>
            )}

            {activeStep === STEPS.length - 1 ? (
              <Button
                variant="contained"
                onClick={handleSubmit}
                disabled={loading}
                startIcon={loading ? <CircularProgress size={20} /> : <CheckCircleIcon />}
              >
                {loading ? 'Creating...' : 'Create Flow'}
              </Button>
            ) : (
              <Button
                variant="contained"
                onClick={goNext}
                disabled={loading}
                endIcon={<ArrowForwardIcon />}
              >
                Next
              </Button>
            )}
          </Box>
        </Box>
      </Paper>
    </Container>
  );
};

export default FlowDefinitionWizard;
