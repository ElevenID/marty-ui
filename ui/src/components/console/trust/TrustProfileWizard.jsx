/**
 * Trust Profile Wizard
 * 
 * Multi-step wizard for creating trust profiles.
 * Defines trusted issuers and validation rules for credential verification.
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

const getSteps = (t) => [
  t('wizards.trustProfile.steps.basics'),
  t('wizards.trustProfile.steps.trustSources'),
  t('wizards.trustProfile.steps.validationRules'),
  t('wizards.trustProfile.steps.review'),
];

const TrustProfileWizard = () => {
  const navigate = useNavigate();
  const { t } = useTranslation('console');

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
    steps: getSteps(t),
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
        return <Typography>{t('wizards.trustProfile.unknownStep')}</Typography>;
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
            {t('wizards.trustProfile.success.title')}
          </Typography>
          <Typography variant="h6" color="text.secondary" paragraph>
            {wizard.data.activate_immediately 
              ? t('wizards.trustProfile.success.messageActive', { name: wizard.data.name })
              : t('wizards.trustProfile.success.messageDraft', { name: wizard.data.name })}
          </Typography>
          <Typography color="text.secondary" variant="body2" sx={{ mb: 3 }}>
            {t('wizards.trustProfile.success.nextStep')}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            {t('wizards.trustProfile.success.redirecting')}
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
            {t('wizards.trustProfile.title')}
          </Typography>
          <Typography color="text.secondary">
            {t('wizards.trustProfile.description')}
          </Typography>
        </Box>

        {/* Stepper */}
        <Stepper activeStep={wizard.activeStep} sx={{ mb: 4 }}>
          {getSteps(t).map((label) => (
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
            {wizard.isFirstStep ? t('wizards.trustProfile.buttons.cancel') : t('wizards.trustProfile.buttons.back')}
          </Button>

          <Box sx={{ display: 'flex', gap: 1 }}>
            {/* Show Skip button for optional steps */}
            {wizard.activeStep > 0 && wizard.activeStep < 3 && (
              <Button
                onClick={wizard.goNext}
                disabled={wizard.loading}
                data-testid="wizard.trustProfile.skip"
              >
                {t('wizards.trustProfile.buttons.skip')}
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
                {wizard.loading ? t('wizards.trustProfile.buttons.submitting') : t('wizards.trustProfile.buttons.submit')}
              </Button>
            ) : (
              <Button
                variant="contained"
                onClick={wizard.goNext}
                disabled={!wizard.isStepValid() || wizard.loading}
                endIcon={<ArrowForwardIcon />}
                data-testid="wizard.trustProfile.next"
              >
                {t('wizards.trustProfile.buttons.next')}
              </Button>
            )}
          </Box>
        </Box>
      </Paper>
    </Container>
  );
};

export default TrustProfileWizard;
