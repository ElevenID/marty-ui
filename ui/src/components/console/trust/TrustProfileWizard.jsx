/**
 * Trust Profile Wizard
 * 
 * Multi-step wizard for creating trust profiles.
 * Defines trusted issuers and validation rules for credential verification.
 */

import { useCallback, useRef } from 'react';
import { useNavigate, useLocation, Link as RouterLink } from 'react-router';
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
  Alert,
  Link,
  LinearProgress,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';

import { useWizard } from '../../../hooks/useWizard';
import { useAsyncActionScope } from '../../../hooks/useAsyncActionScope';
import { useAuth } from '../../../hooks/useAuth';
import { usePermissions } from '../../../hooks/usePermissions';
import { useConsole } from '../../../contexts/ConsoleContext';
import {
  activateTrustProfile,
  addTrustProfileIssuer,
  createTrustProfile,
  synchronizeTrustProfileRegistries,
} from '../../../services/presentationPolicyApi';
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

const hasTrustConfiguration = (data) => (
  (data.trusted_issuers?.length || 0) > 0
  || (data.trust_sources?.length || 0) > 0
  || (data.registry_sources?.length || 0) > 0
  || data.allow_all_issuers === true
);

const TrustProfileWizardContent = ({ organizationId, canActivate, canViewProfile, canViewIssuers, canCreateIssuers }) => {
  const navigate = useNavigate();
  const { t } = useTranslation('console');
  const effectiveOrganizationId = organizationId;
  const startAction = useAsyncActionScope();
  const submissionPending = useRef(false);
  const currentSubmission = useRef(null);
  const createdProfile = useRef(null);
  // BrowserRouter updates the history entry before its React transition commits.
  const browserEntry = useRef(typeof window === 'undefined' ? null : {
    href: window.location.href, key: window.history.state?.key,
  });
  const isCurrentBrowserEntry = useCallback(() => !browserEntry.current || (
    typeof window !== 'undefined' && window.location.href === browserEntry.current.href
      && window.history.state?.key === browserEntry.current.key
  ), []);
  const missingPermission = useCallback((data) => {
    if (data.trusted_issuers?.some((issuer) => issuer.did) && (!canViewIssuers || !canCreateIssuers)) {
      return t('trust.trustProfileWizard.issuerDenied');
    }
    if (data.registry_sources?.length && !canViewProfile) {
      return t('trust.trustProfileWizard.registryDenied');
    }
    if (data.activate_immediately && !canActivate) {
      return t('trust.trustProfileWizard.activateDenied');
    }
    return null;
  }, [canActivate, canViewProfile, canViewIssuers, canCreateIssuers, t]);

  const validateStep = useCallback((stepIndex, data) => {
    switch (stepIndex) {
      case 0: // Basics
        return data.name?.trim().length > 0;
      case 1: // Trust Sources (optional)
        return true;
      case 2: // Validation Rules (optional)
        return true;
      case 3: // Review
        return data.name?.trim().length > 0 && (!data.activate_immediately || hasTrustConfiguration(data))
          && !missingPermission(data);
      default:
        return false;
    }
  }, [missingPermission]);

  const handleSubmit = useCallback(async (data) => {
    const action = startAction();
    const ownsView = () => action.isCurrent() && isCurrentBrowserEntry();
    const isCurrent = () => submissionPending.current && ownsView();
    currentSubmission.current = ownsView;
    const assertCurrent = () => {
      if (!isCurrent()) {
        const error = new Error('The trust profile view or action changed.');
        error.name = 'AbortError';
        throw error;
      }
    };
    const run = async (operation, ...args) => {
      assertCurrent();
      try {
        return await action.run(operation, ...args);
      } finally {
        assertCurrent();
      }
    };
    assertCurrent();
    if (createdProfile.current) {
      throw new Error(t('trust.trustProfileWizard.profileCreated', { id: createdProfile.current.id }));
    }
    const permissionError = missingPermission(data);
    if (permissionError) throw new Error(permissionError);
    if (!effectiveOrganizationId) {
      throw new Error(t('trust.failedToLoad', { defaultValue: 'Organization context is required to create a trust profile.' }));
    }
    if (data.activate_immediately && !hasTrustConfiguration(data)) {
      throw new Error(t('trust.activeProfileRequiresTrustSource', {
        defaultValue: 'Add at least one trusted issuer, trust source, or explicitly allow any issuer before activating a trust profile.',
      }));
    }

    const configuredIssuers = data.trusted_issuers || [];

    const didIssuers = configuredIssuers.filter((i) => i.did);
    const certIssuers = configuredIssuers.filter((i) => i.certificate_pem);
    const hasExplicitTrustConfiguration = configuredIssuers.length > 0
      || (data.trust_sources?.length || 0) > 0
      || (data.registry_sources?.length || 0) > 0;
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
      source_type: 'ROOT_CA',
      certificate_pem: i.certificate_pem,
      description: i.description || i.name || null,
    }));
    const controlledDidSources = didIssuers
      .filter((issuer) => ['organization_id', 'verification_method_ids', 'did_resolution'].some((field) => issuer[field] !== undefined))
      .map((issuer) => ({
        source_type: 'PINNED_ISSUER', issuer_did: issuer.did,
        ...Object.fromEntries(['organization_id', 'verification_method_ids', 'did_resolution']
          .filter((field) => issuer[field] !== undefined).map((field) => [field, issuer[field]])),
      }));

    const profile = await run(createTrustProfile, {
      ...data,
      // Relationships retain issuer lifecycle/accreditation. Explicit DID source
      // controls separately govern resolution and cannot be dropped at creation.
      trusted_issuers: [],
      organization_id: effectiveOrganizationId,
      status: data.activate_immediately ? 'active' : 'draft',
      allowed_issuers: effectiveAllowedIssuers,
      validation_rules: effectiveValidationRules,
      trust_sources: [
        ...(data.trust_sources || []),
        ...(data.registry_sources || []),
        ...certTrustSources,
        ...controlledDidSources,
      ],
    }, { isCurrent });
    if (typeof profile?.id !== 'string' || !profile.id.trim()
      || profile.organization_id !== effectiveOrganizationId || profile.status !== 'draft') {
      throw new Error(t('trust.trustProfileWizard.responseMismatch'));
    }
    // Creation has persisted. A later failure must lead to this profile, never
    // silently recreate the entire chain or claim a dispatched write was undone.
    createdProfile.current = profile;

    await run(() => Promise.all(
      didIssuers.map((issuer) => addTrustProfileIssuer(profile.id, effectiveOrganizationId, {
        name: issuer.name || issuer.did,
        description: issuer.description || null,
        issuer_did: issuer.did,
        accreditation_body: issuer.accreditation_body || null,
        accreditations: Array.isArray(issuer.accreditations) ? issuer.accreditations : [],
      }, { isCurrent, singleAttemptReads: true }))
    ));

    if ((data.registry_sources?.length || 0) > 0) {
      const synchronized = await run(synchronizeTrustProfileRegistries, profile.id, { isCurrent });
      if (synchronized?.trust_profile_id !== profile.id || !Array.isArray(synchronized.sources)
        || synchronized.sources.length === 0 || typeof synchronized.synchronized_at !== 'string'
        || Number.isNaN(Date.parse(synchronized.synchronized_at))) {
        throw new Error(t('trust.trustProfileWizard.responseMismatch'));
      }
    }

    if (data.activate_immediately) {
      const activated = await run(activateTrustProfile, profile.id, {
        isCurrent, allowReadback: canViewProfile, singleAttemptReads: true,
      });
      if (activated?.id !== profile.id || activated.organization_id !== effectiveOrganizationId
        || activated.status !== 'active') {
        throw new Error(t('trust.trustProfileWizard.responseMismatch'));
      }
      return activated;
    }

    assertCurrent();
    return profile;
  }, [effectiveOrganizationId, t, startAction, isCurrentBrowserEntry, missingPermission, canViewProfile]);

  const wizard = useWizard({
    steps: getSteps(t),
    initialData: {
      name: '',
      description: '',
      framework_type: 'custom',
      supported_formats: getSupportedFormatsForFramework('custom'),
      trusted_issuers: [],
      allow_all_issuers: false,
      registry_sources: [],
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
    onSubmit: async (data) => {
      submissionPending.current = true;
      try {
        return await handleSubmit(data);
      } finally {
        submissionPending.current = false;
      }
    },
    onComplete: () => {
      if (currentSubmission.current?.()) navigate('/console/org/templates/credentials');
    },
    onCancel: () => {
      if (isCurrentBrowserEntry()) navigate('/console/org/trust/profiles');
    },
  });

  const canEditForm = () => !submissionPending.current && !createdProfile.current && isCurrentBrowserEntry();
  const updateData = (updates) => { if (canEditForm()) wizard.updateData(updates); };
  const goToStep = (index) => { if (canEditForm()) wizard.goToStep(index); };
  const renderStepContent = () => {
    switch (wizard.activeStep) {
      case 0:
        return (
          <BasicsStep
            data={wizard.data}
            onChange={updateData}
          />
        );
      case 1:
        return (
          <TrustSourcesStep
            data={wizard.data}
            onChange={updateData}
          />
        );
      case 2:
        return (
          <ValidationRulesStep
            data={wizard.data}
            onChange={updateData}
          />
        );
      case 3:
        return (
          <ReviewStep
            data={wizard.data}
            onChange={updateData}
            onEdit={goToStep}
          />
        );
      default:
        return <Typography>{t('wizards.trustProfile.unknownStep')}</Typography>;
    }
  };

  // The shared hook retains its duplicate-submit and unmount protections. A
  // still-mounted old browser entry may neither display its outcome nor redirect.
  if (!isCurrentBrowserEntry()) return <LinearProgress />;

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
          <Typography variant="h6" color="text.secondary" component="p" sx={{ marginBottom: '16px' }}>
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
        {wizard.error && createdProfile.current && (
          <Alert severity="info" sx={{ mb: 3 }}>
            {t('trust.trustProfileWizard.profileCreated', { id: createdProfile.current.id })}{' '}
            {canViewProfile && <Link component={RouterLink} to={`/console/org/trust/profiles/${encodeURIComponent(createdProfile.current.id)}`}>
              {t('trust.trustProfilesPage.viewDetails')}
            </Link>}
          </Alert>
        )}
        {wizard.isLastStep && missingPermission(wizard.data) && (
          <Alert severity="error" sx={{ mb: 3 }}>{missingPermission(wizard.data)}</Alert>
        )}

        {/* Step Content */}
        <Box component="fieldset" disabled={wizard.loading || Boolean(createdProfile.current)}
          sx={{ minHeight: 400, minWidth: 0, m: 0, mb: 4, p: 0, border: 0 }}>
          {renderStepContent()}
        </Box>

        {/* Navigation Buttons */}
        <Box sx={{ display: 'flex', justifyContent: 'space-between', pt: 2 }}>
          <Button
            onClick={() => { if (canEditForm()) (wizard.isFirstStep ? wizard.cancel : wizard.goBack)(); }}
            startIcon={<ArrowBackIcon />}
            disabled={wizard.loading || Boolean(createdProfile.current)}
            data-testid={wizard.isFirstStep ? 'wizard.trustProfile.cancel' : 'wizard.trustProfile.back'}
          >
            {wizard.isFirstStep ? t('wizards.trustProfile.buttons.cancel') : t('wizards.trustProfile.buttons.back')}
          </Button>

          <Box sx={{ display: 'flex', gap: 1 }}>
            {/* Show Skip button for optional steps */}
            {wizard.activeStep > 0 && wizard.activeStep < 3 && (
              <Button
                onClick={() => { if (canEditForm()) wizard.goNext(); }}
                disabled={wizard.loading || Boolean(createdProfile.current)}
                data-testid="wizard.trustProfile.skip"
              >
                {t('wizards.trustProfile.buttons.skip')}
              </Button>
            )}

            {wizard.isLastStep ? (
              <Button
                variant="contained"
                onClick={() => { if (canEditForm()) wizard.submit(); }}
                disabled={!wizard.isStepValid() || wizard.loading || Boolean(createdProfile.current)}
                startIcon={wizard.loading ? <CircularProgress size={20} /> : <CheckCircleIcon />}
                data-testid="wizard.trustProfile.submit"
              >
                {wizard.loading ? t('wizards.trustProfile.buttons.submitting') : t('wizards.trustProfile.buttons.submit')}
              </Button>
            ) : (
              <Button
                variant="contained"
                onClick={() => { if (canEditForm()) wizard.goNext(); }}
                disabled={!wizard.isStepValid() || wizard.loading || Boolean(createdProfile.current)}
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

function TrustProfileWizard() {
  const { t } = useTranslation('console');
  const { activeOrgId } = useConsole();
  const { user, isAuthenticated } = useAuth();
  const { can, isLoading } = usePermissions();
  const location = useLocation();
  const principalId = user?.user_id || user?.sub || user?.id || null;
  const canCreate = can('trust-profile', 'create');
  const canActivate = can('trust-profile', 'activate');
  const canViewProfile = can('trust-profile', 'view');
  const canViewIssuers = can('trusted-issuer', 'view');
  const canCreateIssuers = can('trusted-issuer', 'create');

  if (isLoading) return <LinearProgress />;
  if (typeof activeOrgId !== 'string' || !activeOrgId.trim()) {
    return <Alert severity="info">{t('trust.trustProfileWizard.selectOrganization')}</Alert>;
  }
  if (!canCreate) return <Alert severity="error">{t('trust.trustProfileWizard.createDenied')}</Alert>;
  return <TrustProfileWizardContent
    key={JSON.stringify([activeOrgId, principalId, isAuthenticated, location.key, location.pathname,
      location.search, location.hash, canCreate, canActivate, canViewProfile, canViewIssuers, canCreateIssuers])}
    organizationId={activeOrgId}
    canActivate={canActivate}
    canViewProfile={canViewProfile}
    canViewIssuers={canViewIssuers}
    canCreateIssuers={canCreateIssuers}
  />;
}

export default TrustProfileWizard;
