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
import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import { activateTrustProfile, addTrustProfileIssuer, createTrustProfile } from '../../../services/presentationPolicyApi';
import signingKeysApi from '../../../services/signingKeysApi';
import BasicsStep from './steps/BasicsStep';
import TrustSourcesStep from './steps/TrustSourcesStep';
import ValidationRulesStep from './steps/ValidationRulesStep';
import ReviewStep from './steps/ReviewStep';
import {
  getAllowedAlgorithmsForFramework,
  getSupportedFormatsForFramework,
} from './trustProfileFormatCatalog';

const getSteps = (t) => [
  t('wizards.trustProfile.steps.basics'),
  t('wizards.trustProfile.steps.trustSources'),
  t('wizards.trustProfile.steps.validationRules'),
  t('wizards.trustProfile.steps.review'),
];

const MANAGED_ISSUER_SOURCES = new Set([
  'kms-derived-identity',
  'auto-created',
  'imported-did',
  'issuer-profile',
]);

const issuerMetadata = (issuer) => (issuer && typeof issuer.metadata === 'object' ? issuer.metadata : {});

const issuerProfileId = (issuer) => issuerMetadata(issuer).issuer_profile_id || issuer.issuer_profile_id || '';

const issuerSigningServiceId = (issuer) => issuerMetadata(issuer).signing_service_id || issuer.signing_service_id || '';

const issuerSigningKeyReference = (issuer) => issuerMetadata(issuer).signing_key_reference || issuer.signing_key_reference || '';

const hasTrustConfiguration = (data) => (
  (data.trusted_issuers?.length || 0) > 0
  || (data.trust_sources?.length || 0) > 0
  || data.allow_all_issuers === true
);

const needsManagedIssuerProfile = (issuer) => {
  if (!issuer?.did || issuer.certificate_pem || issuerProfileId(issuer)) {
    return false;
  }
  if (issuerMetadata(issuer).source === 'kms-derived-identity' && issuerSigningKeyReference(issuer)) {
    return false;
  }
  return MANAGED_ISSUER_SOURCES.has(issuerMetadata(issuer).source);
};

const TrustProfileWizard = () => {
  const navigate = useNavigate();
  const { t } = useTranslation('console');
  const { organizationId } = useAuth();
  const { activeOrgId } = useConsole();
  const effectiveOrganizationId = activeOrgId;

  const validateStep = useCallback((stepIndex, data) => {
    switch (stepIndex) {
      case 0: // Basics
        return data.name?.trim().length > 0;
      case 1: // Trust Sources (optional)
        return true;
      case 2: // Validation Rules (optional)
        return true;
      case 3: // Review
        return data.name?.trim().length > 0 && (!data.activate_immediately || hasTrustConfiguration(data));
      default:
        return false;
    }
  }, []);

  const handleSubmit = useCallback(async (data) => {
    if (!effectiveOrganizationId) {
      throw new Error(t('trust.failedToLoad', { defaultValue: 'Organization context is required to create a trust profile.' }));
    }
    if (data.activate_immediately && !hasTrustConfiguration(data)) {
      throw new Error(t('trust.activeProfileRequiresTrustSource', {
        defaultValue: 'Add at least one trusted issuer, trust source, or explicitly allow any issuer before activating a trust profile.',
      }));
    }

    const trustedIssuers = data.trusted_issuers || [];
    let keyManagementConfig = null;
    const trustedIssuersWithProfiles = [];

    for (const issuer of trustedIssuers) {
      if (!needsManagedIssuerProfile(issuer)) {
        trustedIssuersWithProfiles.push(issuer);
        continue;
      }

      if (!keyManagementConfig) {
        keyManagementConfig = await signingKeysApi.getKeyManagementConfig({ organization_id: effectiveOrganizationId });
      }

      const signingServiceId = issuerSigningServiceId(issuer) || keyManagementConfig?.default_service_id || '';
      if (!signingServiceId) {
        throw new Error(t('trust.issuerIdentityRequiresKms', {
          defaultValue: 'A managed DID issuer identity must be backed by a KMS signing service. Configure Key Management before creating this trust profile.',
        }));
      }

      const response = await signingKeysApi.createIssuerProfile({
        organization_id: effectiveOrganizationId,
        name: issuer.name || issuer.did,
        issuer_did: issuer.did,
        signing_service_id: signingServiceId,
        signing_key_reference: issuerSigningKeyReference(issuer) || undefined,
        key_purpose: 'vc_jwt_issuer',
        status: 'active',
      });
      const profile = response?.profile || response || {};
      trustedIssuersWithProfiles.push({
        ...issuer,
        issuer_profile_id: profile.id || issuerProfileId(issuer),
        signing_service_id: profile.signing_service_id || signingServiceId,
        signing_key_reference: profile.signing_key_reference || issuerSigningKeyReference(issuer),
        metadata: {
          ...issuerMetadata(issuer),
          source: issuerMetadata(issuer).source || 'issuer-profile',
          issuer_profile_id: profile.id || issuerProfileId(issuer),
          signing_service_id: profile.signing_service_id || signingServiceId,
          signing_key_reference: profile.signing_key_reference || issuerSigningKeyReference(issuer),
        },
      });
    }

    const didIssuers = trustedIssuersWithProfiles.filter((i) => i.did);
    const certIssuers = trustedIssuersWithProfiles.filter((i) => i.certificate_pem);
    const hasExplicitTrustConfiguration = trustedIssuersWithProfiles.length > 0 || (data.trust_sources?.length || 0) > 0;
    const effectiveAllowedIssuers = hasExplicitTrustConfiguration
      ? data.allowed_issuers
      : (data.allow_all_issuers ? null : []);
    const effectiveValidationRules = {
      ...(data.validation_rules || {}),
      allowed_algorithms: getAllowedAlgorithmsForFramework(
        data.framework_type || 'custom',
        data.validation_rules?.allowed_algorithms,
      ),
    };
    const certTrustSources = certIssuers.map((i) => ({
      name: i.name || 'X.509 Root CA',
      source_type: 'ROOT_CA',
      certificate_pem: i.certificate_pem,
      description: i.description || null,
    }));

    const profile = await createTrustProfile({
      ...data,
      trusted_issuers: trustedIssuersWithProfiles,
      organization_id: effectiveOrganizationId,
      status: data.activate_immediately ? 'active' : 'draft',
      allowed_issuers: effectiveAllowedIssuers,
      validation_rules: effectiveValidationRules,
      trust_sources: [...(data.trust_sources || []), ...certTrustSources],
    });

    await Promise.all(
      didIssuers.map((issuer) => addTrustProfileIssuer(profile.id, {
        name: issuer.name || issuer.did,
        description: issuer.description || null,
        issuer_did: issuer.did,
      }))
    );

    if (data.activate_immediately) {
      return activateTrustProfile(profile.id);
    }

    return profile;
  }, [effectiveOrganizationId, t]);

  const wizard = useWizard({
    steps: getSteps(t),
    initialData: {
      name: '',
      description: '',
      framework_type: 'custom',
      supported_formats: getSupportedFormatsForFramework('custom'),
      supported_wallet_ids: [],
      issuance_protocol: 'oid4vci',
      trusted_issuers: [],
      allow_all_issuers: false,
      registry_imports: [],
      revocation_policy: {
        check_mode: 'HARD_FAIL',
      },
      time_policy: {
        clock_skew_seconds: 300,
        require_freshness: false,
        freshness_window_seconds: 86400,
      },
      validation_rules: {
        allowed_algorithms: getAllowedAlgorithmsForFramework('custom'),
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
      navigate('/console/org/templates/credentials');
    },
    onCancel: () => {
      navigate('/console/org/trust/profiles');
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
            organizationId={effectiveOrganizationId}
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
