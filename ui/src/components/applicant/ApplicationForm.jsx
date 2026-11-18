/**
 * Application Form Component
 *
 * Dynamic multi-step wizard for applicants to apply for credentials.
 * Dynamically renders fields based on credential configuration's
 * required_fields, optional_fields, and custom_fields.
 */

import { useState, useEffect, useRef, useMemo } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router';
import { useTranslation } from 'react-i18next';
import {
  Box,
  Container,
  Paper,
  Typography,
  Button,
  Stepper,
  Step,
  StepLabel,
  Grid,
  Card,
  CardContent,
  Alert,
  CircularProgress,
  Checkbox,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  FormControlLabel,
  Chip,
  Fade,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';
import LoginIcon from '@mui/icons-material/Login';
import BadgeIcon from '@mui/icons-material/Badge';
import DirectionsCarIcon from '@mui/icons-material/DirectionsCar';
import { useAuth } from '../../hooks/useAuth';
import { useAsyncActionScope } from '../../hooks/useAsyncActionScope';
import useWalletPreferences from '../../hooks/useWalletPreferences';
import { usePreview } from '../../contexts/PreviewContext';
import { get } from '../../services/api';
import { APPLY_LOCATION_STATE_STORAGE_KEY } from '../../application/routing';
import {
  createApplication as createApplicationApi,
  enrollMyBiometric,
  getMyApplicantProfile,
  listApplications as listApplicationsApi,
  submitApplicationEvidence as submitApplicationEvidenceApi,
  submitApplication as submitApplicationApi,
  upsertMyApplicantProfile,
  withdrawApplication,
} from '../../services/applicantApi';
import { generateIssuanceOffer } from '../../services/credentialsApi';
import { listApplicationTemplates } from '../../services/applicationTemplatesApi';
import { DynamicFieldGroup } from './DynamicFieldRenderer';
import ClaimCredentialDialog from '../console/applicant/ClaimCredentialDialog';
import { pickOfficialReference } from '../../utils/officialReferences';
import {
  autoApplyForCredential,
  canAutoApplyApplicationTemplate,
  loadCredentialApplicationConfig,
  resolveApplicantIdForApplication,
  submitCredentialApplication,
  getCredentialKindFlags,
  getWalletOfferDialogError,
  getOneClickSummaryFields,
  groupFieldsIntoSteps,
  normalizeApplicationTemplateToFormConfig,
  normalizeCredentialConfigInput,
  validateApplicationStep,
} from '../../application/applications';

function readStoredApplyLocationState() {
  try {
    const serialized = sessionStorage.getItem(APPLY_LOCATION_STATE_STORAGE_KEY);

    if (!serialized) {
      return null;
    }

    sessionStorage.removeItem(APPLY_LOCATION_STATE_STORAGE_KEY);
    return JSON.parse(serialized);
  } catch {
    sessionStorage.removeItem(APPLY_LOCATION_STATE_STORAGE_KEY);
    return null;
  }
}

export default function ApplicationForm({ previewContext = null } = {}) {
  const { credentialType } = useParams();
  const location = useLocation();
  const { user, organizationId } = useAuth();
  const { isPreview } = usePreview?.() || { isPreview: false };
  // Router parameter/query changes reuse the same route component. Every
  // application entry needs its own draft, launch context and async lifetime.
  const scope = JSON.stringify([
    user?.user_id || user?.sub || user?.id || null,
    organizationId,
    credentialType,
    location.key,
    location.pathname,
    location.search,
    Boolean(isPreview),
    previewContext?.applicationTemplate?.id,
    previewContext?.credential?.id,
  ]);
  return <ApplicationFormSession key={scope} previewContext={previewContext} />;
}

function ApplicationFormSession({ previewContext }) {
  const { t } = useTranslation('applicant');
  const { credentialType: credentialConfigId } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const { user, organizationId } = useAuth();
  const { walletIds: preferredWallets } = useWalletPreferences(user?.user_id);
  const hasRegisteredWallet = preferredWallets.length > 0;
  const { isPreview } = usePreview?.() || { isPreview: false };
  const fileInputRefs = useRef({});
  const beginConfigLoad = useAsyncActionScope();
  const beginSubmission = useAsyncActionScope();
  const submissionPending = useRef(false);
  const [initialApplyState] = useState(() => (
    isPreview && previewContext ? previewContext : location.state || readStoredApplyLocationState()
  ));
  const requestedApplicationTemplateId = useMemo(
    () => isPreview ? '' : new URLSearchParams(location.search).get('application_template_id') || '',
    [isPreview, location.search]
  );

  const [activeStep, setActiveStep] = useState(0);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [submitted, setSubmitted] = useState(false);
  const [applicationId, setApplicationId] = useState(null);
  const [applicationReference, setApplicationReference] = useState(null);
  const [credentialConfig, setCredentialConfig] = useState(() => {
    const initialCredential = normalizeCredentialConfigInput(initialApplyState?.credential) || null;
    const initialTemplate = initialApplyState?.applicationTemplate
      || initialApplyState?.credential?.application_template
      || null;
    return initialTemplate
      ? normalizeApplicationTemplateToFormConfig(initialTemplate, initialCredential)
      : initialCredential;
  });
  const [configLoading, setConfigLoading] = useState(false);
  const [applicationTemplate, setApplicationTemplate] = useState(
    initialApplyState?.applicationTemplate
      || initialApplyState?.credential?.application_template
      || null
  );
  const [duplicateConflict, setDuplicateConflict] = useState(null);

  // MemberCredential / auto-approve claim dialog state
  const [claimDialogOpen, setClaimDialogOpen] = useState(false);
  const [autoOfferData, setAutoOfferData] = useState(null);
  const [autoApplying, setAutoApplying] = useState(false);

  // Dynamic form data (keys based on credential config)
  const [formData, setFormData] = useState({
    acceptTerms: false,
  });

  // Validation errors
  const [validationErrors, setValidationErrors] = useState({});

  // Compute steps dynamically from credential config
  const steps = useMemo(() => {
    if (!credentialConfig) return [{ label: t('applicationForm.steps.review'), fields: [] }];
    
    return groupFieldsIntoSteps(
      credentialConfig.required_fields || [],
      credentialConfig.optional_fields || [],
      credentialConfig.custom_fields || [],
      t
    );
  }, [credentialConfig, t]);
  
  // Flatten all fields for validation
  const allFields = useMemo(() => {
    return steps.slice(0, -1).flatMap(step => step.fields);
  }, [steps]);

  const submittedApplicationReference = useMemo(() => pickOfficialReference({
    reference: applicationReference,
    rawId: applicationId,
    kind: 'application',
  }), [applicationId, applicationReference]);
  
  const requiredFieldNames = useMemo(() => {
    return allFields.filter(f => f.required).map(f => f.name);
  }, [allFields]);

  const applicationOrganizationId = applicationTemplate?.organization_id || organizationId;

  const getCredentialTemplate = async (templateId) => get(`/v1/credential-templates/${templateId}`);
  const getApplicationTemplate = async (templateId) => get(`/v1/application-templates/${templateId}`);

  const resolveApplicantId = async (action) => resolveApplicantIdForApplication({
    user,
    getApplicant: () => action.run(getMyApplicantProfile),
    getApplicantByUser: () => action.run(getMyApplicantProfile),
  });

  const readFileAsBase64 = (file) =>
    new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const result = reader.result;
        if (typeof result !== 'string') {
          resolve(null);
          return;
        }
        const [, base64] = result.split(',');
        resolve(base64 || null);
      };
      reader.onerror = reject;
      reader.readAsDataURL(file);
    });

  useEffect(() => {
    const action = beginConfigLoad();
    const fetchCredentialConfig = async () => {
      const needsCredentialTemplate = credentialConfigId && !credentialConfig;
      const needsApplicationTemplate = requestedApplicationTemplateId && applicationTemplate?.id !== requestedApplicationTemplateId;
      if (!needsCredentialTemplate && !needsApplicationTemplate) {
        return;
      }
      setConfigLoading(true);
      try {
        const result = await action.run(loadCredentialApplicationConfig, {
          credentialConfigId,
          credentialConfig,
          organizationId: applicationOrganizationId,
          getCredentialTemplate: (id) => action.run(getCredentialTemplate, id),
          applicationTemplateId: requestedApplicationTemplateId || null,
          getApplicationTemplate: (id) => action.run(getApplicationTemplate, id),
          listApplicationTemplates: (id) => action.run(listApplicationTemplates, id),
        });
        setCredentialConfig(result.credentialConfig);
        if (result.applicationTemplate) {
          setApplicationTemplate(result.applicationTemplate);
        }
        setError(result.error);
      } catch (err) {
        if (!action.isCurrent()) return;
        setError(err.message);
      } finally {
        if (action.isCurrent()) setConfigLoading(false);
      }
    };

    fetchCredentialConfig();
  }, [
    beginConfigLoad,
    credentialConfigId,
    credentialConfig,
    applicationOrganizationId,
    requestedApplicationTemplateId,
    applicationTemplate?.id,
  ]);

  useEffect(() => {
    // Pre-fill user email if email field exists
    if (user?.email && allFields.some(f => f.name === 'email')) {
      setFormData(prev => (
        prev.email === user.email ? prev : { ...prev, email: user.email }
      ));
    }
  }, [user, allFields]);

  // ===========================================================================
  // MemberCredential / mDL: derived flags & one-click auto-apply handler
  // ===========================================================================
  const { isMdlCredential, isMdocMemberCredential, isOpenBadgeCredential, isOneClickCredential } = getCredentialKindFlags(credentialConfig);
  const canAutoApply = isOneClickCredential && canAutoApplyApplicationTemplate({ applicationTemplate, user });
  const isOneClickApplication = canAutoApply;
  const applicationDisplayName = credentialConfig?.display_name || applicationTemplate?.name || t('applicationForm.title.default');
  const applicationDescription = t('applicationForm.description');
  const shouldShowStepper = true;

  const handleAutoApply = async () => {
    if (submissionPending.current) return;
    if (isPreview) { setSubmitted(true); return; }
    const action = beginSubmission();
    submissionPending.current = true;
    setAutoApplying(true);
    setError(null);
    try {
      const result = await action.run(autoApplyForCredential, {
        organizationId: applicationOrganizationId,
        user,
        credentialConfig,
        applicationTemplate,
        credentialConfigId,
        hasRegisteredWallet,
        resolveApplicantId: () => resolveApplicantId(action),
        createApplicant: (data) => action.run(upsertMyApplicantProfile, data),
        updateApplicantProfile: (_applicantId, data) => action.run(upsertMyApplicantProfile, data),
        createApplication: (data) => action.run(createApplicationApi, data),
        submitApplication: (id) => action.run(submitApplicationApi, id),
        generateIssuanceOffer: async (id) => {
          try {
            return await action.run(generateIssuanceOffer, id);
          } catch (offerError) {
            // The application already exists. Keep its identity so an offer
            // failure cannot send the applicant through creation again.
            if (action.isCurrent()) setApplicationId(id);
            throw offerError;
          }
        },
        listApplications: (params) => action.run(listApplicationsApi, params),
      });
      setApplicationId(result.applicationId);
      setApplicationReference(result.applicationReference || null);
      setAutoOfferData(result.offerData);
      setClaimDialogOpen(true);
    } catch (err) {
      if (!action.isCurrent()) return;
      console.error('Auto-apply error:', err);
      setError(getWalletOfferDialogError(err));
    } finally {
      if (action.isCurrent()) {
        submissionPending.current = false;
        setAutoApplying(false);
      }
    }
  };

  const handleFieldChange = (fieldName, value) => {
    setFormData(prev => ({
      ...prev,
      [fieldName]: value
    }));
    // Clear validation error when field is edited
    if (validationErrors[fieldName]) {
      setValidationErrors(prev => ({ ...prev, [fieldName]: null }));
    }
  };

  const validateStep = (stepIndex) => {
    const validation = validateApplicationStep({
      stepIndex,
      steps,
      formData,
      validationRules: credentialConfig?.field_validation_rules || {},
    });
    setValidationErrors(validation.errors);
    return validation.valid;
  };

  const handleNext = () => {
    if (validateStep(activeStep)) {
      setActiveStep(prev => prev + 1);
    }
  };

  const handleBack = () => {
    setActiveStep(prev => prev - 1);
  };

  const submitApplicationForm = async (duplicateApplicationAction = null) => {
    if (submissionPending.current) return;
    if (isPreview) { setSubmitted(true); return; }
    const action = beginSubmission();
    submissionPending.current = true;
    setSubmitting(true);
    setError(null);

    try {
      const result = await action.run(submitCredentialApplication, {
        organizationId: applicationOrganizationId,
        user,
        formData,
        credentialConfig,
        credentialConfigId,
        allFields,
        resolveApplicantId: () => resolveApplicantId(action),
        createApplicant: (data) => action.run(upsertMyApplicantProfile, data),
        updateApplicantProfile: (_applicantId, data) => action.run(upsertMyApplicantProfile, data),
        getApplicantByUser: () => action.run(getMyApplicantProfile),
        createApplication: (data) => action.run(createApplicationApi, data),
        submitApplicationEvidence: (id, data) => action.run(submitApplicationEvidenceApi, id, data),
        submitApplication: (id) => action.run(submitApplicationApi, id),
        listApplicantApplications: () => action.run(listApplicationsApi, { limit: 100 }).then((page) => page.items),
        supersedeApplication: (id, data) => action.run(withdrawApplication, id, data),
        duplicateApplicationAction,
        enrollBiometric: (_applicantId, data) => action.run(enrollMyBiometric, data),
        readFileAsBase64: (file) => action.run(readFileAsBase64, file),
      });

      if (result.duplicateApplicationConflict) {
        setDuplicateConflict(result.duplicateApplicationConflict);
        return;
      }

      setApplicationId(result.applicationId);
      setApplicationReference(result.applicationReference || null);
      setSubmitted(result.submitted);
      setDuplicateConflict(null);
    } catch (err) {
      if (!action.isCurrent()) return;
      console.error('Error submitting application:', err);
      setError(err.message);
    } finally {
      if (action.isCurrent()) {
        submissionPending.current = false;
        setSubmitting(false);
      }
    }
  };

  const handleSubmit = async () => {
    if (!validateStep(activeStep)) return;
    await submitApplicationForm();
  };

  const handleUseExistingApplication = () => {
    const existingApplication = duplicateConflict?.existingApplication;
    setDuplicateConflict(null);
    if (existingApplication?.id) {
      navigate(`/console/applicant/identity?id=${existingApplication.id}`);
    }
  };

  const handleReplaceExistingApplication = async () => {
    if (!validateStep(activeStep)) return;
    setDuplicateConflict(null);
    await submitApplicationForm('replace');
  };

  // Render a dynamic step based on fields
  const renderDynamicStep = (stepIndex) => {
    const step = steps[stepIndex];
    if (!step) return null;

    return (
      <Box data-testid={`step-${stepIndex}`}>
        <Typography variant="h6" gutterBottom>
          {step.label}
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
          {credentialConfig?.submission_instructions || t('applicationForm.instructions.default')}
        </Typography>

        <DynamicFieldGroup
          fields={step.fields}
          values={formData}
          onChange={handleFieldChange}
          errors={validationErrors}
          requiredFields={requiredFieldNames}
          validationRules={credentialConfig?.field_validation_rules}
          fileInputRefs={fileInputRefs.current}
        />
      </Box>
    );
  };

  const renderReviewStep = () => (
    <Box data-testid="review-step">
      <Typography variant="h6" gutterBottom>
        {t('applicationForm.review.title')}
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        {t('applicationForm.review.description')}
      </Typography>


      <Grid container spacing={3}>
        <Grid size={{ xs: 12 }}>
          {steps.slice(0, -1).map((step, idx) => (
            <Card key={idx} variant="outlined" sx={{ mb: 2 }}>
              <CardContent>
                <Typography variant="subtitle2" color="text.secondary" gutterBottom>
                  {step.label}
                </Typography>
                <Grid container spacing={2}>
                  {step.fields.map((field) => {
                    const fieldName = field.name;
                    const value = formData[fieldName];
                    
                    // Skip empty optional fields
                    if ((value === undefined || value === null || value === '') && !field.required) return null;
                    
                    // Format value for display
                    let displayValue = value;
                    if (field.type === 'file') {
                      displayValue = value?.name || t('applicationForm.review.uploaded');
                    } else if (field.type === 'address') {
                      displayValue = value ? `${value.street}, ${value.city}, ${value.state} ${value.zip}` : '';
                    } else if (field.type === 'boolean') {
                      displayValue = value ? t('common.yes', { ns: 'common' }) : t('common.no', { ns: 'common' });
                    }
                    
                    return (
                      <Grid size={{ xs: 12, sm: 6 }} key={fieldName}>
                        <Typography variant="body2" color="text.secondary">
                          {field.label || fieldName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                        </Typography>
                        <Typography>{displayValue === '' ? '-' : (displayValue ?? '-')}</Typography>
                      </Grid>
                    );
                  })}
                </Grid>
              </CardContent>
            </Card>
          ))}
        </Grid>

        <Grid size={{ xs: 12 }}>
          <FormControlLabel
            control={
              <Checkbox
                checked={formData.acceptTerms}
                onChange={(e) => setFormData(prev => ({ ...prev, acceptTerms: e.target.checked }))}
                data-testid="accept-terms-checkbox"
              />
            }
            label={t('applicationForm.review.terms')}
          />
          {validationErrors.acceptTerms && (
            <Typography color="error" variant="caption" sx={{ display: 'block' }}>
              {validationErrors.acceptTerms}
            </Typography>
          )}
        </Grid>
      </Grid>
    </Box>
  );

  const renderSubmittedState = () => (
    <Fade in>
      <Box sx={{ textAlign: 'center', py: 6 }} data-testid="application-submitted">
        <CheckCircleIcon sx={{ fontSize: 80, color: 'success.main', mb: 2 }} />
        <Typography variant="h4" gutterBottom>
          {isPreview ? t('applicationForm.success.previewTitle') : t('applicationForm.success.title')}
        </Typography>
        {isPreview ? (
          <>
            <Alert severity="info" sx={{ maxWidth: 600, mx: 'auto', mb: 3, textAlign: 'left' }}>
              <Typography variant="body2" component="p" sx={{ marginBottom: '16px' }}>
                <strong>{t('applicationForm.success.previewMode')}:</strong> {t(isOneClickApplication
                  ? 'applicationForm.oneClick.previewMessage'
                  : 'applicationForm.success.previewMessage')}
              </Typography>
              <Typography variant="body2">
                {t('applicationForm.success.previewNote')}
              </Typography>
            </Alert>
            {!isOneClickApplication && (
              <>
                <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
                  {t('applicationForm.success.dataCollected')}
                </Typography>
                <Box component="pre" sx={{ textAlign: 'left', bgcolor: 'grey.100', p: 2, borderRadius: 1, fontSize: '0.85rem', overflow: 'auto', maxHeight: 300, maxWidth: 600, mx: 'auto' }}>
                  {JSON.stringify(formData, null, 2)}
                </Box>
              </>
            )}
          </>
        ) : (
          <>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
              {t('applicationForm.success.message')}
            </Typography>
            
            {applicationId && (
              <Chip
                label={t('applicationForm.success.applicationReference', {
                  id: submittedApplicationReference,
                  defaultValue: 'Application Reference: {{id}}',
                })}
                color="primary"
                variant="outlined"
                sx={{ mb: 3 }}
                data-testid="application-id"
                data-value={applicationId}
              />
            )}

            <Alert severity="info" sx={{ maxWidth: 400, mx: 'auto', mb: 3 }}>
              {t('applicationForm.success.nextSteps')}
            </Alert>

            <Button
              variant="contained"
              onClick={() => navigate(`/console/applicant/identity${applicationId ? `?id=${encodeURIComponent(applicationId)}` : ''}`)}
            >
              {t('applicationForm.success.viewApplications')}
            </Button>
          </>
        )}
      </Box>
    </Fade>
  );

  // Use dynamic rendering for all steps
  const getStepContent = (stepIndex) => {
    // Last step is always review
    if (stepIndex === steps.length - 1) {
      return renderReviewStep();
    }
    return renderDynamicStep(stepIndex);
  };

  const duplicateExistingApplication = duplicateConflict?.existingApplication || null;
  const duplicateExistingStatus = String(duplicateExistingApplication?.status || '').toUpperCase();
  const duplicateCanReplace = duplicateExistingApplication
    && !['CREDENTIALED', 'ISSUED'].includes(duplicateExistingStatus);
  const duplicateReference = duplicateExistingApplication?.reference_number
    || duplicateExistingApplication?.referenceNumber
    || duplicateExistingApplication?.id;
  const renderDuplicateConflictDialog = () => (
    <Dialog
      open={Boolean(duplicateConflict)}
      onClose={() => !submitting && setDuplicateConflict(null)}
      maxWidth="sm"
      fullWidth
    >
      <DialogTitle>Credential request already exists</DialogTitle>
      <DialogContent>
        <DialogContentText sx={{ mb: 2 }}>
          You already have an active request for this credential. Continue with the existing request, or retire the previous request and submit again.
        </DialogContentText>
        {duplicateExistingApplication && (
          <Box sx={{ p: 2, border: '1px solid', borderColor: 'divider', borderRadius: 1, bgcolor: 'action.hover' }}>
            <Typography variant="body2" color="text.secondary">Existing request</Typography>
            <Typography variant="subtitle2">{duplicateReference}</Typography>
            {duplicateExistingStatus && (
              <Chip size="small" label={duplicateExistingStatus.replace(/_/g, ' ').toLowerCase()} sx={{ mt: 1 }} />
            )}
          </Box>
        )}
        {!duplicateCanReplace && (
          <Alert severity="info" sx={{ mt: 2 }}>
            This request has already been issued, so it can only be continued.
          </Alert>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={() => setDuplicateConflict(null)} disabled={submitting}>
          Cancel
        </Button>
        <Button onClick={handleUseExistingApplication} disabled={submitting || !duplicateExistingApplication?.id}>
          Continue Existing
        </Button>
        <Button
          variant="contained"
          color="warning"
          onClick={handleReplaceExistingApplication}
          disabled={submitting || !duplicateCanReplace}
        >
          Retire Previous and Submit
        </Button>
      </DialogActions>
    </Dialog>
  );

  if (submitted) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper sx={{ p: 4 }}>
          {renderSubmittedState()}
          {renderDuplicateConflictDialog()}
        </Paper>
      </Container>
    );
  }

  if (configLoading) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper sx={{ p: 4, textAlign: 'center' }}>
          <CircularProgress />
          <Typography sx={{ mt: 2 }}>{t('applicationForm.loadingConfig')}</Typography>
        </Paper>
      </Container>
    );
  }

  if (!credentialConfig && !credentialConfigId) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper sx={{ p: 4 }}>
          <Alert severity="warning" sx={{ mb: 2 }}>
            {t('applicationForm.errors.noCredential')}
          </Alert>
          <Button variant="contained" onClick={() => navigate('/console/applicant/catalog')}>
            {t('applicationForm.actions.gotoCatalog')}
          </Button>
        </Paper>
      </Container>
    );
  }

  // ===========================================================================
  // One-click issuance UI (MemberCredential & mDL)
  // ===========================================================================
  if (isOneClickApplication) {
    const isMdocCredential = isMdlCredential || isMdocMemberCredential;
    const HeroIcon = isMdlCredential ? DirectionsCarIcon : (isOpenBadgeCredential ? BadgeIcon : LoginIcon);
    const fallbackTitle = isMdocCredential
      ? 'Membership ID'
      : (isOpenBadgeCredential ? 'Verified Member Badge' : 'Login Credential');
    const heroTitle = credentialConfig?.display_name || credentialConfig?.name || fallbackTitle;
    const heroDescription = credentialConfig?.description || 'Add this credential to a compatible wallet.';
    const ctaLabel = isPreview
      ? t('applicationForm.oneClick.previewAction')
      : (applicationId ? t('applicationForm.oneClick.viewSavedApplication') : (isMdocCredential ? 'Get Membership ID' : 'Add to Wallet'));
    const plannedFormat = credentialConfig?.format || credentialConfig?.credential_payload_format;
    const ctaSubtext = credentialConfig?.issuanceProtocol || credentialConfig?.issuance_protocol || '';

    const summaryFields = getOneClickSummaryFields({ credentialConfig, user, organizationId: applicationOrganizationId });

    const gradientBg = isMdlCredential
      ? 'linear-gradient(145deg, #0f4c8108, #0f4c8114)'
      : 'linear-gradient(145deg, #1a237e08, #1a237e14)';
    return (
      <Container maxWidth="sm" sx={{ py: 6 }}>
        <Fade in timeout={600}>
          <Paper
            elevation={4}
            sx={{
              p: 5,
              borderRadius: 3,
              textAlign: 'center',
              background: gradientBg,
              border: '1px solid',
              borderColor: 'primary.light',
            }}
          >
            {/* Icon + title */}
            <Box sx={{ mb: 3 }}>
              <HeroIcon sx={{ fontSize: 64, color: 'primary.main', mb: 1 }} />
              <Typography variant="h5" sx={{ fontWeight: 700 }} gutterBottom>
                {heroTitle}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {heroDescription}
              </Typography>
            </Box>

            {credentialConfig?.vendorName && (
              <Box sx={{ mb: 2 }}>
                <Typography variant="caption" color="text.secondary">
                  {t('applicationForm.oneClick.issuerLabel')}
                </Typography>
                <Typography variant="body2" sx={{ fontWeight: 600 }}>
                  {credentialConfig.vendorName}
                </Typography>
              </Box>
            )}

            {/* Credential details */}
            <Paper
              variant="outlined"
              sx={{ p: 2.5, mb: 2, textAlign: 'left', borderRadius: 2, bgcolor: 'background.default' }}
            >
              <Typography variant="overline" color="text.secondary" sx={{ mb: 1, display: 'block' }}>
                {t('applicationForm.oneClick.credentialPreview')}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
                {t('applicationForm.oneClick.previewStatus')}
              </Typography>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.75 }}>
                {summaryFields.map(({ label, value }) => (
                  <Box key={label} sx={{ display: 'flex', justifyContent: 'space-between', gap: 2 }}>
                    <Typography variant="body2" color="text.secondary">{label}</Typography>
                    <Typography variant="body2" sx={{ fontWeight: 500 }}>{value}</Typography>
                  </Box>
                ))}
              </Box>
            </Paper>

            {/* Planned properties do not establish issuance or verification. */}
            <Box sx={{ mb: 3, display: 'flex', flexDirection: 'column', gap: 0.5, alignItems: 'center' }}>
              {plannedFormat && (
                <Typography variant="caption" color="text.secondary">
                  {t('applicationForm.oneClick.plannedFormat', { format: plannedFormat })}
                </Typography>
              )}
              <Typography variant="caption" color="text.secondary">
                {t('applicationForm.oneClick.signingAfterIssue')}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {t('applicationForm.oneClick.acceptanceAfterIssue')}
              </Typography>
            </Box>

            {/* Error */}
            {error && (
              <Alert severity="error" sx={{ mb: 2, textAlign: 'left' }} onClose={() => setError(null)}>
                {error}
              </Alert>
            )}

            {/* CTA button */}
            <Button
              data-testid="credential-claim-action"
              variant="contained"
              size="large"
              fullWidth
              onClick={applicationId
                ? () => navigate(`/console/applicant/identity?id=${encodeURIComponent(applicationId)}`)
                : handleAutoApply}
              disabled={autoApplying}
              startIcon={autoApplying ? <CircularProgress size={20} color="inherit" /> : (isMdlCredential ? <DirectionsCarIcon /> : <BadgeIcon />)}
              sx={{ py: 1.5, fontSize: '1rem', borderRadius: 2 }}
            >
              {autoApplying ? t('applicationForm.oneClick.requesting') : ctaLabel}
            </Button>

            {/* Helper text */}
            <Typography variant="caption" color="text.secondary" sx={{ mt: 1.5, display: 'block' }}>
              {t(isPreview ? 'applicationForm.oneClick.previewHelper' : 'applicationForm.oneClick.requestHelper')}
            </Typography>

            <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
              {ctaSubtext}
            </Typography>
          </Paper>
        </Fade>

        {/* The wallet invite is not evidence of completed credential issuance. */}
        <ClaimCredentialDialog
          open={claimDialogOpen}
          onClose={() => {
            setClaimDialogOpen(false);
            navigate('/console/applicant/applications');
          }}
          applicationId={applicationId}
          offerData={autoOfferData}
          organizationId={applicationOrganizationId}
          autoOpenWallet={isOpenBadgeCredential}
        />
      </Container>
    );
  }

  return (
    <Container maxWidth="md" sx={{ py: 4 }} data-testid="credential-application-form">
      {/* Header */}
      <Box sx={{ mb: 4 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 1 }}>
          <CheckCircleIcon color="primary" fontSize="large" />
          <Typography variant="h4" component="h1">
            {applicationDisplayName}
          </Typography>
        </Box>
        <Typography variant="body1" color="text.secondary">
          {applicationDescription}
        </Typography>
      </Box>

      {/* Stepper */}
      {shouldShowStepper && (
        <Paper sx={{ p: 3, mb: 3 }}>
          <Stepper activeStep={activeStep} alternativeLabel>
            {steps.map((step, idx) => (
              <Step key={idx}>
                <StepLabel>{step.label}</StepLabel>
              </Step>
            ))}
          </Stepper>
        </Paper>
      )}

      {/* Error Alert */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {/* Form Content */}
      <Paper sx={{ p: 4, mb: 3 }}>
        {getStepContent(activeStep)}
      </Paper>

      {/* Navigation */}
      <Paper sx={{ p: 2 }}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
          <Button
            disabled={activeStep === 0}
            onClick={handleBack}
            startIcon={<ArrowBackIcon />}
          >
            {t('applicationForm.navigation.back')}
          </Button>

          {activeStep < steps.length - 1 ? (
            <Button
              variant="contained"
              onClick={handleNext}
              endIcon={<ArrowForwardIcon />}
              data-testid="next-step-btn"
            >
              {t('applicationForm.navigation.next')}
            </Button>
          ) : (
            <Button
              variant="contained"
              color="success"
              onClick={handleSubmit}
              disabled={submitting}
              endIcon={submitting ? <CircularProgress size={20} /> : <CheckCircleIcon />}
              data-testid="submit-application-btn"
            >
              {submitting
                ? (isPreview ? t('applicationForm.navigation.simulating') : t('applicationForm.navigation.submitting'))
                : (isPreview ? t('applicationForm.navigation.previewSubmit') : t('applicationForm.navigation.submit'))}
            </Button>
          )}
        </Box>
      </Paper>
      {renderDuplicateConflictDialog()}
    </Container>
  );
}
