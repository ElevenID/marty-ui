/**
 * Deployment Profile Wizard
 * 
 * Multi-step wizard for creating deployment profiles.
 * Binds identity logic to runtime environments (API, Kiosk, Mobile).
 */

import { useNavigate } from 'react-router-dom';
import { useCallback } from 'react';
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
import { createDeploymentProfile } from '../../../services/deploymentProfilesApi';
import EnvironmentStep from './steps/EnvironmentStep';
import RuntimeSettingsStep from './steps/RuntimeSettingsStep';
import IntegrationStep from './steps/IntegrationStep';
import ReviewStep from './steps/ReviewStep';

const DeploymentProfileWizard = () => {
  const navigate = useNavigate();
  const { t } = useTranslation('console');

  const STEPS = [
    t('wizards.deploymentProfile.steps.environment'),
    t('wizards.deploymentProfile.steps.runtimeSettings'),
    t('wizards.deploymentProfile.steps.integration'),
    t('wizards.deploymentProfile.steps.review'),
  ];

  const validateStep = useCallback((stepIndex, data) => {
    switch (stepIndex) {
      case 0: // Environment
        return data.name?.trim().length > 0 && data.environment_type;
      case 1: // Runtime Settings
        return data.default_policy_id !== null;
      case 2: // Integration (optional)
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
      name: data.name,
      description: data.description,
      environment_type: data.environment_type,
      network_mode: data.network_mode,
      presentation_policy_ids: data.default_policy_id ? [data.default_policy_id] : [],
      enabled_flows: data.enabled_flows,
      webhook_url: data.webhooks.url || null,
      webhook_events: data.webhooks.events,
      feature_flags: data.feature_flags,
      environment_config: data.ux_config,
      status: data.activate_immediately ? 'active' : 'draft',
    };
    
    const result = await createDeploymentProfile(payload);
    
    // Generate API key if requested
    if (data.generate_api_key && result.id) {
      // TODO: Call API key creation endpoint
      console.log('API key generation would happen here for profile:', result.id);
    }
    
    return result;
  }, []);

  const wizard = useWizard({
    steps: STEPS,
    initialData: {
      name: '',
      description: '',
      environment_type: 'api',
      network_mode: 'ONLINE',
      default_policy_id: null,
      enabled_flows: [],
      webhooks: {
        url: '',
        events: [],
      },
      feature_flags: {
        qr_code: true,
        nfc: false,
        ble: false,
      },
      ux_config: {
        theme: 'default',
        language: 'en',
      },
      status: 'active',
      generate_api_key: true,
      activate_immediately: true,
    },
    validateStep,
    onSubmit: handleSubmit,
    onComplete: () => {
      navigate('/console/flows/definitions');
    },
    onCancel: () => {
      navigate('/console/deploy/profiles');
    },
  });

  const renderStepContent = () => {
    switch (wizard.activeStep) {
      case 0:
        return (
          <EnvironmentStep
            data={wizard.data}
            onChange={wizard.updateData}
          />
        );
      case 1:
        return (
          <RuntimeSettingsStep
            data={wizard.data}
            onChange={wizard.updateData}
          />
        );
      case 2:
        return (
          <IntegrationStep
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
        return <Typography>{t('wizards.deploymentProfile.unknownStep')}</Typography>;
    }
  };

  // Success screen
  if (wizard.success) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper elevation={3} sx={{ p: 4, textAlign: 'center' }}>
          <CheckCircleIcon color="success" sx={{ fontSize: 64, mb: 2 }} />
          <Typography variant="h5" gutterBottom>
            {t('wizards.deploymentProfile.success.title')}
          </Typography>
          <Typography color="text.secondary" paragraph>
            {wizard.data.activate_immediately
              ? t('wizards.deploymentProfile.success.messageActive', { name: wizard.data.name })
              : t('wizards.deploymentProfile.success.messageDraft', { name: wizard.data.name })}
          </Typography>
          {wizard.data.generate_api_key && (
            <Typography color="text.secondary" variant="body2">
              {t('wizards.deploymentProfile.success.apiKeyGenerated')}
            </Typography>
          )}
          <Typography color="text.secondary" variant="body2" sx={{ mt: 1 }}>
            {t('wizards.deploymentProfile.success.redirecting')}
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
            {t('wizards.deploymentProfile.title')}
          </Typography>
          <Typography color="text.secondary">
            {t('wizards.deploymentProfile.description')}
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
          <Box sx={{ mb: 3, p: 2, bgcolor: 'error.light', borderRadius: 1 }}>
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
            data-testid={wizard.isFirstStep ? 'wizard.deployment.cancel' : 'wizard.deployment.back'}
          >
            {wizard.isFirstStep
              ? t('wizards.deploymentProfile.buttons.cancel')
              : t('wizards.deploymentProfile.buttons.back')}
          </Button>

          <Box sx={{ display: 'flex', gap: 1 }}>
            {/* Show Skip button for optional Integration step */}
            {wizard.activeStep === 2 && (
              <Button
                onClick={wizard.goNext}
                disabled={wizard.loading}
                data-testid="wizard.deployment.skip"
              >
                {t('wizards.deploymentProfile.buttons.skip')}
              </Button>
            )}

            {wizard.isLastStep ? (
              <Button
                variant="contained"
                onClick={wizard.submit}
                disabled={!wizard.isStepValid() || wizard.loading}
                startIcon={wizard.loading ? <CircularProgress size={20} /> : <CheckCircleIcon />}
                data-testid="wizard.deployment.submit"
              >
                {wizard.loading
                  ? t('wizards.deploymentProfile.buttons.submitting')
                  : t('wizards.deploymentProfile.buttons.submit')}
              </Button>
            ) : (
              <Button
                variant="contained"
                onClick={wizard.goNext}
                disabled={!wizard.isStepValid() || wizard.loading}
                endIcon={<ArrowForwardIcon />}
                data-testid="wizard.deployment.next"
              >
                {t('wizards.deploymentProfile.buttons.next')}
              </Button>
            )}
          </Box>
        </Box>
      </Paper>
    </Container>
  );
};

export default DeploymentProfileWizard;
