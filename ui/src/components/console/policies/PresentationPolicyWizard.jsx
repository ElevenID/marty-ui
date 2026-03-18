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
import { createPresentationPolicy } from '../../../services/presentationPolicyApi';

import { useWizard } from '../../../hooks/useWizard';
import {
  TrustProfileStep,
  TemplateSelectionStep,
  ClaimsConfigurationStep,
  FreshnessBindingStep,
  ReviewStep,
} from './steps';

const getSteps = (t) => [
  { label: t('wizards.presentationPolicy.steps.trustProfile'), optional: false },
  { label: t('wizards.presentationPolicy.steps.selectTemplate'), optional: false },
  { label: t('wizards.presentationPolicy.steps.configureClaims'), optional: false },
  { label: t('wizards.presentationPolicy.steps.freshnessBinding'), optional: true },
  { label: t('wizards.presentationPolicy.steps.review'), optional: false },
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
  const { t } = useTranslation('console');
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
    const payload = {
      ...data.policyConfig,
      trust_profile_id: data.selectedTrustProfile?.id,
      template_id: data.selectedTemplate?.id,
      status: data.activateImmediately ? 'active' : 'draft',
    };
    return createPresentationPolicy(payload);
  }, []);

  const wizard = useWizard({
    steps: getSteps(t),
    initialData: INITIAL_DATA,
    validateStep,
    onSubmit: handleSubmit,
    onComplete: () => {
      setTimeout(() => {
        navigate('/console/org/deploy/profiles');
      }, 2000);
    },
    onCancel: () => {
      navigate('/console/org/policies');
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
        return <Typography>{t('wizards.presentationPolicy.unknownStep')}</Typography>;
    }
  };

  // Show success message
  if (wizard.success) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper elevation={3} sx={{ p: 4, textAlign: 'center' }}>
          <CheckCircleIcon color="success" sx={{ fontSize: 64, mb: 2 }} />
          <Typography variant="h5" gutterBottom>
            {t('wizards.presentationPolicy.success.title')}
          </Typography>
          <Typography color="text.secondary" paragraph>
            {wizard.data.activateImmediately 
              ? t('wizards.presentationPolicy.success.messageActive', { name: wizard.data.policyConfig.name })
              : t('wizards.presentationPolicy.success.messageDraft', { name: wizard.data.policyConfig.name })}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {t('wizards.presentationPolicy.success.redirecting')}
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
            {t('wizards.presentationPolicy.title')}
          </Typography>
          <Typography color="text.secondary">
            {t('wizards.presentationPolicy.description')}
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
            onClick={wizard.activeStep === 0 ? () => navigate('/console/org/policies/presentation') : wizard.goBack}
            startIcon={<ArrowBackIcon />}
            disabled={wizard.loading}
            data-testid={wizard.activeStep === 0 ? 'wizard.policy.cancel' : 'wizard.policy.back'}
          >
            {wizard.activeStep === 0 ? t('wizards.presentationPolicy.buttons.cancel') : t('wizards.presentationPolicy.buttons.back')}
          </Button>

          <Box sx={{ display: 'flex', gap: 2 }}>
            {/* Skip button for optional steps */}
            {getSteps(t)[wizard.activeStep].optional && (
              <Button
                onClick={wizard.goNext}
                disabled={wizard.loading}
                data-testid="wizard.policy.skip"
              >
                {t('wizards.presentationPolicy.buttons.skip')}
              </Button>
            )}

            {wizard.activeStep === getSteps(t).length - 1 ? (
              <Button
                variant="contained"
                onClick={wizard.submit}
                disabled={wizard.loading || !wizard.isStepValid()}
                startIcon={wizard.loading ? <CircularProgress size={20} /> : <CheckCircleIcon />}
                data-testid="wizard.policy.submit"
              >
                {wizard.loading ? t('wizards.presentationPolicy.buttons.submitting') : t('wizards.presentationPolicy.buttons.submit')}
              </Button>
            ) : (
              <Button
                variant="contained"
                onClick={wizard.goNext}
                disabled={wizard.loading || !wizard.isStepValid()}
                endIcon={<ArrowForwardIcon />}
                data-testid="wizard.policy.next"
              >
                {t('wizards.presentationPolicy.buttons.next')}
              </Button>
            )}
          </Box>
        </Box>
      </Paper>
    </Container>
  );
};

export default PresentationPolicyWizard;
