/**
 * Credential Template Wizard
 * 
 * Multi-step wizard for creating credential templates.
 * Defines what credentials are issued and their structure.
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
import AccountTreeIcon from '@mui/icons-material/AccountTree';

import { useWizard } from '../../../hooks/useWizard';
import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import { createCredentialTemplate } from '../../../services/presentationPolicyApi';
import BasicsStep from './steps/BasicsStep';
import ClaimsStep from './steps/ClaimsStep';
import TrustComplianceStep from './steps/TrustComplianceStep';
import CryptoValidityStep from './steps/CryptoValidityStep';
import ReviewStep from './steps/ReviewStep';

const getSteps = (t) => [
  t('wizards.credentialTemplate.steps.basics'),
  t('wizards.credentialTemplate.steps.claims'),
  t('wizards.credentialTemplate.steps.trustCompliance'),
  t('wizards.credentialTemplate.steps.cryptoValidity'),
  t('wizards.credentialTemplate.steps.review'),
];

const CredentialTemplateWizard = () => {
  const navigate = useNavigate();
  const { t } = useTranslation('console');
  const { organizationId: authOrganizationId } = useAuth();
  const { activeOrgId } = useConsole();
  const effectiveOrganizationId = activeOrgId;

  const validateStep = useCallback((stepIndex, data) => {
    switch (stepIndex) {
      case 0: // Basics
        return (
          data.name?.trim().length > 0 &&
          data.credential_type?.trim().length > 0 &&
          data.vct?.trim().length > 0
        );
      case 1: // Claims
        return data.claims && data.claims.length > 0;
      case 2: // Trust & Compliance
        return Boolean(data.trust_profile_id && data.issuer_profile_id && data.compliance_profile_id);
      case 3: // Crypto & Validity (optional)
        return Boolean(data.revocation_profile_id);
      case 4: // Review
        return true;
      default:
        return false;
    }
  }, []);

  const handleSubmit = useCallback(async (data) => {
    if (!effectiveOrganizationId) {
      throw new Error(t('wizards.credentialTemplate.errors.organizationRequired', {
        defaultValue: 'An active organization is required before creating a credential template.',
      }));
    }

    const payload = {
      ...data,
      organization_id: effectiveOrganizationId,
      auto_generate_artifacts: data.generate_artifacts_automatically,
    };
    delete payload.generate_artifacts_automatically;
    
    const result = await createCredentialTemplate(payload);
    return result;
  }, [effectiveOrganizationId, t]);

  const wizard = useWizard({
    steps: getSteps(t),
    initialData: {
      name: '',
      credential_type: 'VerifiableCredential',
      vct: '',
      description: '',
      claims: [],
      trust_profile_id: null,
      compliance_profile_id: null,
      issuer_profile_id: null,
      signing_algorithm: 'ES256',
      validity_rules: {
        ttl_seconds: 31536000, // 1 year
        not_before_offset: 0,
        max_validity_seconds: 63072000, // 2 years
      },
      revocation_profile_id: null,
      generate_artifacts_automatically: true,
      activate_immediately: true,
    },
    validateStep,
    onSubmit: handleSubmit,
    onComplete: (result) => {
      // Don't auto-navigate - show success screen with CTAs
      wizard.templateId = result?.id;
    },
    onCancel: () => {
      navigate('/console/org/templates/credentials');
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
          <ClaimsStep
            data={wizard.data}
            onChange={wizard.updateData}
          />
        );
      case 2:
        return (
          <TrustComplianceStep
            data={wizard.data}
            onChange={wizard.updateData}
          />
        );
      case 3:
        return (
          <CryptoValidityStep
            data={wizard.data}
            onChange={wizard.updateData}
          />
        );
      case 4:
        return (
          <ReviewStep
            data={wizard.data}
            onChange={wizard.updateData}
            onEdit={wizard.goToStep}
          />
        );
      default:
        return <Typography>{t('wizards.credentialTemplate.unknownStep')}</Typography>;
    }
  };

  // Success screen
  if (wizard.success) {
    const templateId = wizard.result?.id || 'unknown';
    
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper elevation={3} sx={{ p: 4, textAlign: 'center' }}>
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
            {t('wizards.credentialTemplate.success.title')}
          </Typography>
          <Typography variant="h6" color="text.secondary" paragraph>
            {wizard.data.activate_immediately 
              ? t('wizards.credentialTemplate.success.messageActive', { name: wizard.data.name })
              : t('wizards.credentialTemplate.success.messageDraft', { name: wizard.data.name })}
          </Typography>
          
          {/* Updated messaging */}
          <Typography color="text.secondary" variant="body2" sx={{ mb: 1 }}>
            <strong>{t('wizards.credentialTemplate.success.nextStepTitle')}</strong>
          </Typography>
          <Typography color="text.secondary" variant="body2" sx={{ mb: 4 }}>
            {t('wizards.credentialTemplate.success.nextStepDescription')}
          </Typography>
          
          {/* Primary CTA: Create Flow */}
          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center' }}>
            <Button
              variant="contained"
              size="large"
              startIcon={<AccountTreeIcon />}
              onClick={() => navigate(`/console/org/flows/definitions/new?templateId=${templateId}`)}
            >
              {t('wizards.credentialTemplate.success.createFlowButton')}
            </Button>
            
            {/* Secondary: Return to Templates */}
            <Button
              variant="outlined"
              size="large"
              onClick={() => navigate('/console/org/templates/credentials')}
            >
              {t('wizards.credentialTemplate.success.returnToTemplatesButton')}
            </Button>
          </Box>
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
            {t('wizards.credentialTemplate.title')}
          </Typography>
          <Typography color="text.secondary">
            {t('wizards.credentialTemplate.description')}
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
            data-testid={wizard.isFirstStep ? 'wizard.template.cancel' : 'wizard.template.back'}
          >
            {wizard.isFirstStep ? t('wizards.credentialTemplate.buttons.cancel') : t('wizards.credentialTemplate.buttons.back')}
          </Button>

          <Box sx={{ display: 'flex', gap: 1 }}>
            {/* Show Skip button for optional step (Crypto & Validity) */}
            {wizard.activeStep === 3 && (
              <Button
                onClick={wizard.goNext}
                disabled={wizard.loading}
                data-testid="wizard.template.skip"
              >
                {t('wizards.credentialTemplate.buttons.skip')}
              </Button>
            )}

            {wizard.isLastStep ? (
              <Button
                variant="contained"
                onClick={wizard.submit}
                disabled={!wizard.isStepValid() || wizard.loading}
                startIcon={wizard.loading ? <CircularProgress size={20} /> : <CheckCircleIcon />}
                data-testid="wizard.template.submit"
              >
                {wizard.loading ? t('wizards.credentialTemplate.buttons.submitting') : t('wizards.credentialTemplate.buttons.submit')}
              </Button>
            ) : (
              <Button
                variant="contained"
                onClick={wizard.goNext}
                disabled={!wizard.isStepValid() || wizard.loading}
                endIcon={<ArrowForwardIcon />}
                data-testid="wizard.template.next"
              >
                {t('wizards.credentialTemplate.buttons.next')}
              </Button>
            )}
          </Box>
        </Box>
      </Paper>
    </Container>
  );
};

export default CredentialTemplateWizard;
