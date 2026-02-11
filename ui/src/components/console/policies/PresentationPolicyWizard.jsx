/**
 * Presentation Policy Creation Wizard
 * 
 * Multi-step wizard for creating presentation policies with:
 * - Trust Profile prerequisite check
 * - Standards-based templates
 * - Claims configuration with CredentialTemplate lookup
 * - Freshness and binding settings
 * - Review and activation
 */

import { useState, useCallback } from 'react';
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
  TrustProfileStep,
  TemplateSelectionStep,
  ClaimsConfigurationStep,
  FreshnessBindingStep,
  ReviewStep,
} from './steps';

const STEPS = [
  { label: 'Trust Profile', optional: false },
  { label: 'Select Template', optional: false },
  { label: 'Configure Claims', optional: false },
  { label: 'Freshness & Binding', optional: true },
  { label: 'Review', optional: false },
];

const INITIAL_DATA = {
  selectedTrustProfile: null,
  selectedTemplate: null,
  policyConfig: {
    name: '',
    description: '',
    purpose: '',
    accepted_credential_types: [],
    required_claims: [],
    holder_binding: 'device_key',
    freshness_requirements: {
      max_credential_age_seconds: 31536000, // 1 year default
      max_proof_age_seconds: 300, // 5 minutes default
      require_revocation_check: true,
    },
    prefer_predicates: true,
    single_presentation: false,
    metadata: {},
  },
  activateImmediately: true,
};

const PresentationPolicyWizard = () => {
  const navigate = useNavigate();
  const [apiError, setApiError] = useState(null);

  // Validation function for each step
  const validateStep = useCallback((stepIndex, stepData) => {
    switch (stepIndex) {
      case 0: // Trust Profile
        return stepData.selectedTrustProfile !== null;
      case 1: // Template Selection
        return stepData.selectedTemplate !== null;
      case 2: // Claims Configuration
        return (
          stepData.policyConfig.name.trim() !== '' &&
          stepData.policyConfig.purpose.trim() !== '' &&
          stepData.policyConfig.required_claims.length > 0
        );
      case 3: // Freshness & Binding (optional)
        return true;
      case 4: // Review
        return true;
      default:
        return false;
    }
  }, []);

  const handleSubmit = useCallback(async (data) => {
    // TODO: Implement actual API call
    const payload = {
      ...data.policyConfig,
      trust_profile_id: data.selectedTrustProfile?.id,
      template_id: data.selectedTemplate?.id,
      status: data.activateImmediately ? 'active' : 'draft',
    };
    return { id: 'mock_policy_id', ...payload };
  }, []);

  const wizard = useWizard({
    steps: STEPS,
    initialData: INITIAL_DATA,
    validateStep,
    onSubmit: handleSubmit,
    onComplete: () => {
      setTimeout(() => {
        navigate('/console/deploy/profiles');
      }, 2000);
    },
    onCancel: () => {
      navigate('/console/policies');
    },
  });

  // Handle template selection - pre-populate config
  const handleTemplateSelect = (template) => {
    const updates = { selectedTemplate: template };
    
    if (template && template.config) {
      updates.policyConfig = {
        ...wizard.data.policyConfig,
        name: template.name,
        description: template.description,
        purpose: `Verify ${template.name}`,
        ...template.config,
        metadata: {
          standard_reference: template.standardReference,
          template_id: template.id,
        },
      };
    }
    
    wizard.updateData(updates);
  };

  // Render current step content
  const renderStepContent = () => {
    switch (wizard.activeStep) {
      case 0:
        return (
          <TrustProfileStep
            selectedTrustProfile={wizard.data.selectedTrustProfile}
            onSelectTrustProfile={(profile) => wizard.updateData({ selectedTrustProfile: profile })}
          />
        );
      case 1:
        return (
          <TemplateSelectionStep
            trustProfile={wizard.data.selectedTrustProfile}
            selectedTemplate={wizard.data.selectedTemplate}
            onSelectTemplate={handleTemplateSelect}
          />
        );
      case 2:
        return (
          <ClaimsConfigurationStep
            policyConfig={wizard.data.policyConfig}
            onConfigChange={(config) => wizard.updateData({ policyConfig: config })}
          />
        );
      case 3:
        return (
          <FreshnessBindingStep
            policyConfig={wizard.data.policyConfig}
            onConfigChange={(config) => wizard.updateData({ policyConfig: config })}
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
        return <Typography>Unknown step</Typography>;
    }
  };

  // Show success message
  if (wizard.success) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper elevation={3} sx={{ p: 4, textAlign: 'center' }}>
          <CheckCircleIcon color="success" sx={{ fontSize: 64, mb: 2 }} />
          <Typography variant="h5" gutterBottom>
            Presentation Policy Created Successfully!
          </Typography>
          <Typography color="text.secondary" paragraph>
            Your policy &quot;{wizard.data.policyConfig.name}&quot; is now ready to use.
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Redirecting to deployment profiles...
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
            Create Presentation Policy
          </Typography>
          <Typography color="text.secondary">
            Define what credentials and claims are required for verification
          </Typography>
        </Box>

        {/* Stepper */}
        <Stepper activeStep={wizard.activeStep} sx={{ mb: 4 }}>
          {STEPS.map((step) => (
            <Step key={step.label}>
              <StepLabel optional={step.optional && <Typography variant="caption">Optional</Typography>}>
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
            onClick={wizard.activeStep === 0 ? () => navigate('/console/policies/presentation') : wizard.goBack}
            startIcon={<ArrowBackIcon />}
            disabled={wizard.loading}
            data-testid={wizard.activeStep === 0 ? 'wizard.policy.cancel' : 'wizard.policy.back'}
          >
            {wizard.activeStep === 0 ? 'Cancel' : 'Back'}
          </Button>

          <Box sx={{ display: 'flex', gap: 2 }}>
            {/* Skip button for optional steps */}
            {STEPS[wizard.activeStep].optional && (
              <Button
                onClick={wizard.goNext}
                disabled={wizard.loading}
                data-testid="wizard.policy.skip"
              >
                Skip
              </Button>
            )}

            {wizard.activeStep === STEPS.length - 1 ? (
              <Button
                variant="contained"
                onClick={wizard.submit}
                disabled={wizard.loading || !wizard.isStepValid()}
                startIcon={wizard.loading ? <CircularProgress size={20} /> : <CheckCircleIcon />}
                data-testid="wizard.policy.submit"
              >
                {wizard.loading ? 'Creating...' : 'Create Policy'}
              </Button>
            ) : (
              <Button
                variant="contained"
                onClick={wizard.goNext}
                disabled={wizard.loading || !wizard.isStepValid()}
                endIcon={<ArrowForwardIcon />}
                data-testid="wizard.policy.next"
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

export default PresentationPolicyWizard;
