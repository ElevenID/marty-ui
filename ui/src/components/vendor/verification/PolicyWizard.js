/**
 * Presentation Policy Creation Wizard
 * 
 * Multi-step wizard for creating presentation policies with:
 * - Trust Profile prerequisite check
 * - Standards-based templates
 * - Claims configuration with CredentialTemplate lookup
 * - Freshness and binding settings
 * - Standard version tracking
 */

import React, { useState, useEffect } from 'react';
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

import TrustProfilePrerequisiteStep from './steps/TrustProfilePrerequisiteStep';
import TemplateSelectionStep from './steps/TemplateSelectionStep';
import ClaimsConfigurationStep from './steps/ClaimsConfigurationStep';
import FreshnessBindingStep from './steps/FreshnessBindingStep';
import ReviewStep from './steps/ReviewStep';

import { createPresentationPolicy } from '../../../services/presentationPolicyApi';

const STEPS = [
  'Trust Profile',
  'Select Template',
  'Configure Claims',
  'Freshness & Binding',
  'Review',
];

/**
 * Dot-based Progress Indicator Component
 */
const DotProgress = ({ steps, activeStep }) => (
  <Box
    sx={{
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      gap: 1.5,
      py: 2,
    }}
  >
    {steps.map((_, index) => (
      <Box
        key={index}
        sx={{
          width: 10,
          height: 10,
          borderRadius: '50%',
          bgcolor: index <= activeStep ? 'primary.main' : 'grey.300',
          transition: 'background-color 0.3s ease',
        }}
      />
    ))}
  </Box>
);

const PolicyWizard = ({ onComplete, onCancel }) => {
  const [activeStep, setActiveStep] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);

  // Step data
  const [selectedTrustProfile, setSelectedTrustProfile] = useState(null);
  const [selectedTemplate, setSelectedTemplate] = useState(null);
  const [policyConfig, setPolicyConfig] = useState({
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
  });

  // Handle step navigation
  const handleNext = () => {
    setError(null);
    setActiveStep((prev) => prev + 1);
  };

  const handleBack = () => {
    setError(null);
    setActiveStep((prev) => prev - 1);
  };

  // Handle template selection - pre-populate config
  const handleTemplateSelect = (template) => {
    setSelectedTemplate(template);
    
    if (template && template.config) {
      setPolicyConfig({
        ...policyConfig,
        name: template.name,
        description: template.description,
        purpose: `Verify ${template.name}`,
        ...template.config,
        metadata: {
          standard_reference: template.standardReference,
          template_id: template.id,
        },
      });
    } else {
      // Custom template - reset to defaults
      setPolicyConfig({
        name: '',
        description: '',
        purpose: '',
        accepted_credential_types: [],
        required_claims: [],
        holder_binding: 'device_key',
        freshness_requirements: {
          max_credential_age_seconds: 31536000,
          max_proof_age_seconds: 300,
          require_revocation_check: true,
        },
        prefer_predicates: true,
        single_presentation: false,
        metadata: {},
      });
    }
  };

  // Handle final submission
  const handleSubmit = async () => {
    setLoading(true);
    setError(null);

    try {
      const payload = {
        ...policyConfig,
        trust_profile_id: selectedTrustProfile?.id || null,
      };

      const result = await createPresentationPolicy(payload);
      setSuccess(true);

      // Notify parent component
      if (onComplete) {
        setTimeout(() => {
          onComplete(result);
        }, 1500);
      }
    } catch (err) {
      console.error('Failed to create presentation policy:', err);
      setError(err.message || 'Failed to create presentation policy');
    } finally {
      setLoading(false);
    }
  };

  // Determine if current step is valid
  const isStepValid = () => {
    switch (activeStep) {
      case 0: // Trust Profile
        return selectedTrustProfile !== null;
      case 1: // Template Selection
        return selectedTemplate !== null;
      case 2: // Claims Configuration
        return (
          policyConfig.name.trim() !== '' &&
          policyConfig.purpose.trim() !== '' &&
          policyConfig.required_claims.length > 0
        );
      case 3: // Freshness & Binding
        return true; // All fields have defaults
      case 4: // Review
        return true;
      default:
        return false;
    }
  };

  // Render current step content
  const renderStepContent = () => {
    switch (activeStep) {
      case 0:
        return (
          <TrustProfilePrerequisiteStep
            selectedTrustProfile={selectedTrustProfile}
            onSelectTrustProfile={setSelectedTrustProfile}
          />
        );
      case 1:
        return (
          <TemplateSelectionStep
            trustProfile={selectedTrustProfile}
            selectedTemplate={selectedTemplate}
            onSelectTemplate={handleTemplateSelect}
          />
        );
      case 2:
        return (
          <ClaimsConfigurationStep
            policyConfig={policyConfig}
            onConfigChange={setPolicyConfig}
          />
        );
      case 3:
        return (
          <FreshnessBindingStep
            policyConfig={policyConfig}
            onConfigChange={setPolicyConfig}
          />
        );
      case 4:
        return (
          <ReviewStep
            policyConfig={policyConfig}
            trustProfile={selectedTrustProfile}
            template={selectedTemplate}
            onEdit={(step) => setActiveStep(step)}
          />
        );
      default:
        return <Typography>Unknown step</Typography>;
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
            Your policy "{policyConfig.name}" is now ready to use in verification requests.
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

        {/* Progress Indicator */}
        <DotProgress steps={STEPS} activeStep={activeStep} />

        {/* Stepper */}
        <Stepper activeStep={activeStep} sx={{ mb: 4 }}>
          {STEPS.map((label) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
            </Step>
          ))}
        </Stepper>

        {/* Error Alert */}
        {error && (
          <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
            {error}
          </Alert>
        )}

        {/* Step Content */}
        <Box sx={{ minHeight: 400, mb: 4 }}>
          {renderStepContent()}
        </Box>

        {/* Navigation Buttons */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', pt: 2 }}>
          <Button
            onClick={activeStep === 0 ? onCancel : handleBack}
            startIcon={<ArrowBackIcon />}
            disabled={loading}
          >
            {activeStep === 0 ? 'Cancel' : 'Back'}
          </Button>

          {activeStep === STEPS.length - 1 ? (
            <Button
              variant="contained"
              onClick={handleSubmit}
              disabled={!isStepValid() || loading}
              startIcon={loading ? <CircularProgress size={20} /> : <CheckCircleIcon />}
            >
              {loading ? 'Creating...' : 'Create Policy'}
            </Button>
          ) : (
            <Button
              variant="contained"
              onClick={handleNext}
              disabled={!isStepValid() || loading}
              endIcon={<ArrowForwardIcon />}
            >
              Next
            </Button>
          )}
        </Box>
      </Paper>
    </Container>
  );
};

export default PolicyWizard;
