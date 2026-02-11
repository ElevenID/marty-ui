/**
 * Trust Profile Wizard
 * 
 * Multi-step wizard for creating trust profiles.
 * Defines trusted issuers and validation rules for credential verification.
 */

import { useCallback } from 'react';
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
  CircularProgress,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';

import { useWizard } from '../../../hooks/useWizard';
import { createTrustProfile } from '../../../services/presentationPolicyApi';
import BasicsStep from './steps/BasicsStep';
import TrustSourcesStep from './steps/TrustSourcesStep';
import ValidationRulesStep from './steps/ValidationRulesStep';
import ReviewStep from './steps/ReviewStep';

const STEPS = ['Basics', 'Trust Sources', 'Validation Rules', 'Review & Activate'];

const TrustProfileWizard = () => {
  const navigate = useNavigate();

  const validateStep = useCallback((stepIndex, data) => {
    switch (stepIndex) {
      case 0: // Basics
        return data.name?.trim().length > 0;
      case 1: // Trust Sources (optional)
        return true;
      case 2: // Validation Rules (optional)
        return true;
      case 3: // Review
        return true;
      default:
        return false;
    }
  }, []);

  const handleSubmit = useCallback(async (data) => {
    // Set status based on activate_immediately flag
    const payload = {
      ...data,
      status: data.activate_immediately ? 'active' : 'draft',
    };
    delete payload.activate_immediately;
    
    return await createTrustProfile(payload);
  }, []);

  const wizard = useWizard({
    steps: STEPS,
    initialData: {
      name: '',
      description: '',
      framework_type: 'custom',
      supported_formats: ['jwt_vc', 'sd_jwt_vc', 'mdoc'],
      trusted_issuers: [],
      validation_rules: {
        allowed_algorithms: ['ES256', 'ES384', 'ES512', 'EdDSA'],
        allow_self_signed: false,
        min_key_size: 2048,
        require_key_usage: true,
      },
      status: 'active',
      activate_immediately: true,
    },
    validateStep,
    onSubmit: handleSubmit,
    onComplete: () => {
      navigate('/console/templates/credentials');
    },
    onCancel: () => {
      navigate('/console/trust/profiles');
    },
  });

  const renderStepContent = () => {
    switch (wizard.activeStep) {
      case 0:
        return (
          <BasicsStep
            data={wizard.data}
            onChange={wizard.updateData}
          />
        );
      case 1:
        return (
          <TrustSourcesStep
            data={wizard.data}
            onChange={wizard.updateData}
          />
        );
      case 2:
        return (
          <ValidationRulesStep
            data={wizard.data}
            onChange={wizard.updateData}
          />
        );
      case 3:
        return (
          <ReviewStep
            data={wizard.data}
            onChange={wizard.updateData}
            onEdit={wizard.goToStep}
          />
        );
      default:
        return <Typography>Unknown step</Typography>;
    }
  };

  // Success screen
  if (wizard.success) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper
          elevation={3}
          sx={{ p: 4, textAlign: 'center' }}
          data-testid="wizard.trustProfile.success"
        >
          <Box
            sx={{
              display: 'inline-flex',
              p: 2,
              borderRadius: '50%',
              bgcolor: 'success.lighter',
              mb: 2,
            }}
          >
            <CheckCircleIcon color="success" sx={{ fontSize: 64 }} />
          </Box>
          <Typography variant="h4" gutterBottom>
            🎉 Trust Profile Created!
          </Typography>
          <Typography variant="h6" color="text.secondary" paragraph>
            &quot;{wizard.data.name}&quot; is now {wizard.data.activate_immediately ? 'active and ready to use' : 'saved as draft'}.
          </Typography>
          <Typography color="text.secondary" variant="body2" sx={{ mb: 3 }}>
            Next, create a credential template to define what credentials this profile will verify.
          </Typography>
          <Typography variant="caption" color="text.secondary">
            Redirecting to Credential Templates...
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
            Build Trust Profile
          </Typography>
          <Typography color="text.secondary">
            Define trusted issuers and validation rules for credential verification
          </Typography>
        </Box>

        {/* Stepper */}
        <Stepper activeStep={wizard.activeStep} sx={{ mb: 4 }}>
          {STEPS.map((label) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
            </Step>
          ))}
        </Stepper>

        {/* Error Alert */}
        {wizard.error && (
          <Box
            sx={{ mb: 3, p: 2, bgcolor: 'error.light', borderRadius: 1 }}
            data-testid="wizard.trustProfile.error"
          >
            <Typography color="error.contrastText">
              {wizard.error}
            </Typography>
          </Box>
        )}

        {/* Step Content */}
        <Box sx={{ minHeight: 400, mb: 4 }}>
          {renderStepContent()}
        </Box>

        {/* Navigation Buttons */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', pt: 2 }}>
          <Button
            onClick={wizard.isFirstStep ? wizard.cancel : wizard.goBack}
            startIcon={<ArrowBackIcon />}
            disabled={wizard.loading}
            data-testid={wizard.isFirstStep ? 'wizard.trustProfile.cancel' : 'wizard.trustProfile.back'}
          >
            {wizard.isFirstStep ? 'Cancel' : 'Back'}
          </Button>

          <Box sx={{ display: 'flex', gap: 1 }}>
            {/* Show Skip button for optional steps */}
            {wizard.activeStep > 0 && wizard.activeStep < 3 && (
              <Button
                onClick={wizard.goNext}
                disabled={wizard.loading}
                data-testid="wizard.trustProfile.skip"
              >
                Skip
              </Button>
            )}

            {wizard.isLastStep ? (
              <Button
                variant="contained"
                onClick={wizard.submit}
                disabled={!wizard.isStepValid() || wizard.loading}
                startIcon={wizard.loading ? <CircularProgress size={20} /> : <CheckCircleIcon />}
                data-testid="wizard.trustProfile.submit"
              >
                {wizard.loading ? 'Creating...' : 'Create Trust Profile'}
              </Button>
            ) : (
              <Button
                variant="contained"
                onClick={wizard.goNext}
                disabled={!wizard.isStepValid() || wizard.loading}
                endIcon={<ArrowForwardIcon />}
                data-testid="wizard.trustProfile.next"
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

export default TrustProfileWizard;
