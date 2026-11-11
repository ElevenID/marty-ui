/**
 * Credential Template Wizard
 * 
 * Multi-step wizard for creating credential templates.
 * Defines what credentials are issued and their structure.
 */

import { useNavigate } from 'react-router';
import { useCallback, useLayoutEffect, useRef, useMemo, useState } from 'react';
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
import { useConsole } from '../../../contexts/ConsoleContext';
import { useAuth } from '../../../hooks/useAuth';
import { createTemplateCreationOperation } from '../../../services/templateCreationOperation';
import BasicsStep from './steps/BasicsStep';
import ClaimsStep from './steps/ClaimsStep';
import TrustComplianceStep from './steps/TrustComplianceStep';
import CryptoValidityStep from './steps/CryptoValidityStep';
import ReviewStep from './steps/ReviewStep';
import issuerIdentitiesApi from '../../../services/issuerIdentitiesApi';
import { templateIssuerRequest, templateIssuerRequirementsSatisfied, validTemplateIssuerSelection } from './templateIssuerSelection';
import { buildWizardValidityRules, credentialTemplateValidity, INITIAL_TEMPLATE_VALIDITY } from './credentialTemplateValidity';

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
  const { activeOrgId } = useConsole();
  const { user } = useAuth();
  const principalId = user?.user_id;
  const effectiveOrganizationId = activeOrgId;
  const organizationEpoch = useRef(0);
  const creation = useMemo(() => createTemplateCreationOperation(activeOrgId, principalId), [activeOrgId, principalId]);
  const [createdDraft, setCreatedDraft] = useState(null);
  const submissionPending = useRef(false);

  const validateStep = useCallback((stepIndex, data) => {
    switch (stepIndex) {
      case 0: // Basics
        return (
          data.name?.trim().length > 0 &&
          data.credential_type?.trim().length > 0
        );
      case 1: // Claims
        return data.claims && data.claims.length > 0;
      case 2: // Trust & Compliance
        return validTemplateIssuerSelection(data, effectiveOrganizationId);
      case 3: // Crypto & Validity (optional)
        return credentialTemplateValidity(data.validity_rules).valid
          && (data._issuer_selection?.requirements?.revocation_profile === false
            ? !data.revocation_profile_id : Boolean(data.revocation_profile_id));
      case 4: // Review
        return validTemplateIssuerSelection(data, effectiveOrganizationId)
          && credentialTemplateValidity(data.validity_rules).valid
          && (data._issuer_selection?.requirements?.revocation_profile === false ? !data.revocation_profile_id : Boolean(data.revocation_profile_id));
      default:
        return false;
    }
  }, [effectiveOrganizationId]);

  const handleSubmit = useCallback(async (data) => {
    if (!effectiveOrganizationId) {
      throw new Error(t('wizards.credentialTemplate.errors.organizationRequired', {
        defaultValue: 'An active organization is required before creating a credential template.',
      }));
    }

    if (!credentialTemplateValidity(data.validity_rules).valid) {
      throw new Error(t('wizards.credentialTemplate.cryptoValidityStep.validation.reviewSettings', {
        defaultValue: 'Review the highlighted validity settings before creating the template.',
      }));
    }
    const { _organization_default_trust: _defaultTrust, ...templateData } = data;
    const payload = {
      ...templateData,
      validity_rules: buildWizardValidityRules(data.validity_rules),
      organization_id: effectiveOrganizationId,
    };
    const epoch = organizationEpoch.current;
    const options = await issuerIdentitiesApi.getTemplateIssuerOptions(templateIssuerRequest(data, effectiveOrganizationId));
    if (epoch !== organizationEpoch.current) throw new Error('Organization changed. Review issuer compatibility before submitting.');
    if (!options.identities.some((identity) => identity.issuer_did === data.issuer_did)
      || options.issuance_protocol !== data.issuance_protocol
      || !templateIssuerRequirementsSatisfied(data, options.requirements)) {
      throw new Error('Issuer compatibility changed. Return to Trust & Compliance and refresh the available options.');
    }
    let result;
    try {
      result = await creation.submit(payload, { isCurrent: () => epoch === organizationEpoch.current });
    } catch (error) {
      if (epoch === organizationEpoch.current && error.createdResource) setCreatedDraft(error.createdResource);
      throw error;
    }
    if (epoch !== organizationEpoch.current) throw new Error('The request completed for the previous organization. Check its templates before retrying.');
    return result;
  }, [effectiveOrganizationId, t, creation]);

  const submitReviewedData = useCallback(async (data) => {
    const epoch = organizationEpoch.current;
    // Lock edits before the first await, including events before loading renders.
    submissionPending.current = true;
    try {
      return await handleSubmit(data);
    } finally {
      if (epoch === organizationEpoch.current) submissionPending.current = false;
    }
  }, [handleSubmit]);

  const wizard = useWizard({
    scopeKey: `${activeOrgId}:${principalId}`,
    steps: getSteps(t),
    initialData: {
      name: '',
      credential_type: 'VerifiableCredential',
      vct: '',
      description: '',
      claims: [],
      trust_profile_id: null,
      compliance_profile_id: null,
      issuer_did: null,
      validity_rules: { ...INITIAL_TEMPLATE_VALIDITY },
      revocation_profile_id: null,
      activate_immediately: true,
    },
    validateStep,
    onSubmit: submitReviewedData,
    onCancel: () => {
      navigate('/console/org/templates/credentials');
    },
  });

  const updateWizardData = wizard.updateData;
  const updateFormData = useCallback((updates) => {
    if (!submissionPending.current) updateWizardData(updates);
  }, [updateWizardData]);
  const goToWizardStep = wizard.goToStep;
  const editStep = useCallback((step) => {
    if (!submissionPending.current) goToWizardStep(step);
  }, [goToWizardStep]);
  useLayoutEffect(() => {
    organizationEpoch.current += 1;
    submissionPending.current = false;
    setCreatedDraft(null);
    updateWizardData({ trust_profile_id: null, compliance_profile_id: null, issuer_did: null,
      revocation_profile_id: null, credential_payload_format: undefined, supported_formats: undefined,
      issuance_protocol: undefined, _issuer_selection: null, _organization_default_trust: null });
    return () => { organizationEpoch.current += 1; };
  }, [activeOrgId, principalId, updateWizardData]);

  const renderStepContent = () => {
    switch (wizard.activeStep) {
      case 0:
        return (
          <BasicsStep
            data={wizard.data}
            onChange={updateFormData}
          />
        );
      case 1:
        return (
          <ClaimsStep
            data={wizard.data}
            onChange={updateFormData}
          />
        );
      case 2:
        return (
          <TrustComplianceStep
            data={wizard.data}
            onChange={updateFormData}
          />
        );
      case 3:
        return (
          <CryptoValidityStep
            data={wizard.data}
            onChange={updateFormData}
          />
        );
      case 4:
        return (
          <ReviewStep
            data={wizard.data}
            onChange={updateFormData}
            onEdit={editStep}
          />
        );
      default:
        return <Typography>{t('wizards.credentialTemplate.unknownStep')}</Typography>;
    }
  };

  // Success screen
  if (wizard.success) {
    const templateId = wizard.result?.id;
    
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
          <Typography variant="h6" color="text.secondary" component="p" sx={{ marginBottom: '16px' }}>
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
              disabled={!templateId}
              onClick={() => navigate(`/console/org/flows/definitions/new?templateId=${encodeURIComponent(templateId)}`)}
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
            {createdDraft && <Button onClick={() => navigate(`/console/org/templates/credentials/${encodeURIComponent(createdDraft.id)}`)}>Open created draft</Button>}
          </Box>
        )}

        {/* Step Content */}
        <Box component="fieldset" disabled={wizard.loading} aria-label={getSteps(t)[wizard.activeStep]}
          sx={{ border: 0, p: 0, m: 0, minWidth: 0, minHeight: 400, mb: 4 }}>
          {renderStepContent()}
        </Box>

        {/* Navigation Buttons */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', pt: 2 }}>
          <Button
            onClick={() => { if (!submissionPending.current) (wizard.isFirstStep ? wizard.cancel : wizard.goBack)(); }}
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
                onClick={() => { if (!submissionPending.current) wizard.goNext(); }}
                disabled={!wizard.isStepValid() || wizard.loading}
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
                {wizard.loading ? t('wizards.credentialTemplate.buttons.submitting') : createdDraft ? 'Retry activation' : t('wizards.credentialTemplate.buttons.submit')}
              </Button>
            ) : (
              <Button
                variant="contained"
                onClick={() => { if (!submissionPending.current) wizard.goNext(); }}
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
