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
    apiEndpoint: '/api/v1/presentation-policies',
    onSuccess: () => {
      // Redirect to deployment profiles after 2 seconds
      setTimeout(() => {
        navigate('/console/deploy/profiles');
      }, 2000);
    },
  });

  // Handle template selection - pre-populate config
  const handleTemplateSelect = (template) => {
    const updates = { selectedTemplate: template };
    
    if (template && template.config) {
      updates.policyConfig = {
        ...data.policyConfig,
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
    
    updateData(updates);
  };

  // Validate current step
  useEffect(() => {
    let valid = false;
    
    switch (activeStep) {
      case 0: // Trust Profile
        valid = data.selectedTrustProfile !== null;
        break;
      case 1: // Template Selection
        valid = data.selectedTemplate !== null;
        break;
      case 2: // Claims Configuration
        valid = (
          data.policyConfig.name.trim() !== '' &&
          data.policyConfig.purpose.trim() !== '' &&
          data.policyConfig.required_claims.length > 0
        );
        break;
      case 3: // Freshness & Binding (optional)
        valid = true;
        break;
      case 4: // Review
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
          <TrustProfileStep
            selectedTrustProfile={data.selectedTrustProfile}
            onSelectTrustProfile={(profile) => updateData({ selectedTrustProfile: profile })}
          />
        );
      case 1:
        return (
          <TemplateSelectionStep
            trustProfile={data.selectedTrustProfile}
            selectedTemplate={data.selectedTemplate}
            onSelectTemplate={handleTemplateSelect}
          />
        );
      case 2:
        return (
          <ClaimsConfigurationStep
            policyConfig={data.policyConfig}
            onConfigChange={(config) => updateData({ policyConfig: config })}
          />
        );
      case 3:
        return (
          <FreshnessBindingStep
            policyConfig={data.policyConfig}
            onConfigChange={(config) => updateData({ policyConfig: config })}
          />
        );
      case 4:
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
        ...data.policyConfig,
        trust_profile_id: data.selectedTrustProfile?.id || null,
        is_active: data.activateImmediately,
      };

      await submit(payload);
    } catch (err) {
      console.error('Failed to create presentation policy:', err);
      setApiError(err.message || 'Failed to create presentation policy');
    }
  };

  // Show success message
  if (success) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper elevation={3} sx={{ p: 4, textAlign: 'center' }}>
          <CheckCircleIcon color="success" sx={{ fontSize: 64, mb: 2 }} />
          <Typography variant="h5" gutterBottom>
            Presentation Policy Created Successfully!
          </Typography>
          <Typography color="text.secondary" paragraph>
            Your policy &quot;{data.policyConfig.name}&quot; is now ready to use.
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
            onClick={activeStep === 0 ? () => navigate('/console/policies/presentation') : goBack}
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
                {loading ? 'Creating...' : 'Create Policy'}
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

export default PresentationPolicyWizard;
