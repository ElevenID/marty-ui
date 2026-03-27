/**
 * Application Form Component
 *
 * Dynamic multi-step wizard for applicants to apply for credentials.
 * Dynamically renders fields based on credential configuration's
 * required_fields, optional_fields, and custom_fields.
 */

import { useState, useEffect, useRef, useMemo } from 'react';
import { useParams, useNavigate, useLocation } from 'react-router-dom';
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
import PersonIcon from '@mui/icons-material/Person';
import { useAuth } from '../../hooks/useAuth';
import { usePreview } from '../../contexts/PreviewContext';
import { get } from '../../services/api';
import {
  autoIssueApplication as autoIssueApplicationApi,
  createApplicant as createApplicantApi,
  createApplication as createApplicationApi,
  enrollBiometric as enrollBiometricApi,
  getApplicant as getApplicantApi,
  getApplicantByUser as getApplicantByUserApi,
  listApplications as listApplicationsApi,
  submitApplication as submitApplicationApi,
  updateApplicantProfile as updateApplicantProfileApi,
} from '../../services/applicantApi';
import { DynamicFieldGroup } from './DynamicFieldRenderer';
import ClaimCredentialDialog from '../console/applicant/ClaimCredentialDialog';
import {
  autoApplyForCredential,
  buildApplicantProfileData,
  buildAutoApplyContext,
  buildStandardApplicationPayload,
  loadCredentialApplicationConfig,
  resolveApplicantIdForApplication,
  submitCredentialApplication,
  getCredentialKindFlags,
  getOneClickSummaryFields,
  groupFieldsIntoSteps,
  normalizeCredentialConfigInput,
  normalizeTemplateToFormConfig,
  validateApplicationStep,
} from '../../application/applications';

export default function ApplicationForm() {
  const { t } = useTranslation('applicant');
  const { credentialType: credentialConfigId } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const { user, organizationId } = useAuth();
  const { isPreview } = usePreview?.() || { isPreview: false };
  const fileInputRefs = useRef({});

  const [activeStep, setActiveStep] = useState(0);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [submitted, setSubmitted] = useState(false);
  const [applicationId, setApplicationId] = useState(null);
  const [credentialConfig, setCredentialConfig] = useState(
    normalizeCredentialConfigInput(location.state?.credential) || null
  );
  const [configLoading, setConfigLoading] = useState(false);

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
  
  const requiredFieldNames = useMemo(() => {
    return allFields.filter(f => f.required).map(f => f.name);
  }, [allFields]);

  const getCredentialTemplate = async (templateId) => get(`/v1/credential-templates/${templateId}`);

  const resolveApplicantId = async () => resolveApplicantIdForApplication({
    user,
    getApplicant: getApplicantApi,
    getApplicantByUser: getApplicantByUserApi,
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
    const fetchCredentialConfig = async () => {
      if (!credentialConfigId || credentialConfig) {
        return;
      }
      setConfigLoading(true);
      try {
        const result = await loadCredentialApplicationConfig({
          credentialConfigId,
          credentialConfig,
          organizationId,
          getCredentialTemplate,
        });
        setCredentialConfig(result.credentialConfig);
        setError(result.error);
      } catch (err) {
        setError(err.message);
      } finally {
        setConfigLoading(false);
      }
    };

    fetchCredentialConfig();
  }, [credentialConfigId, credentialConfig, organizationId]);

  useEffect(() => {
    // Pre-fill user email if email field exists
    if (user?.email && allFields.some(f => f.name === 'email')) {
      setFormData(prev => ({ ...prev, email: user.email }));
    }
  }, [user, allFields]);

  // ===========================================================================
  // MemberCredential / mDL: derived flags & one-click auto-apply handler
  // ===========================================================================
  const { isMemberCredential, isMdlCredential, isMdocMemberCredential, isOpenBadgeCredential, isAccessBadgeCredential, isOneClickCredential } = getCredentialKindFlags(credentialConfig);

  const handleAutoApply = async () => {
    setAutoApplying(true);
    setError(null);
    try {
      const result = await autoApplyForCredential({
        organizationId,
        user,
        credentialConfig,
        credentialConfigId,
        resolveApplicantId,
        createApplicant: createApplicantApi,
        createApplication: createApplicationApi,
        autoIssueApplication: autoIssueApplicationApi,
        listApplications: listApplicationsApi,
      });
      setApplicationId(result.applicationId);
      setAutoOfferData(result.offerData);
      setClaimDialogOpen(true);
    } catch (err) {
      console.error('Auto-apply error:', err);
      setError(err.message);
    } finally {
      setAutoApplying(false);
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

  const handleSubmit = async () => {
    if (!validateStep(activeStep)) return;

    setSubmitting(true);
    setError(null);

    try {
      const result = await submitCredentialApplication({
        organizationId,
        user,
        formData,
        credentialConfig,
        credentialConfigId,
        allFields,
        resolveApplicantId,
        createApplicant: createApplicantApi,
        updateApplicantProfile: updateApplicantProfileApi,
        getApplicantByUser: getApplicantByUserApi,
        createApplication: createApplicationApi,
        submitApplication: submitApplicationApi,
        enrollBiometric: enrollBiometricApi,
        readFileAsBase64,
      });

      setApplicationId(result.applicationId);
      setSubmitted(result.submitted);
    } catch (err) {
      console.error('Error submitting application:', err);
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
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
        <Grid item xs={12}>
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
                    if (!value && !field.required) return null;
                    
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
                      <Grid item xs={12} sm={6} key={fieldName}>
                        <Typography variant="body2" color="text.secondary">
                          {field.label || fieldName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
                        </Typography>
                        <Typography>{displayValue || '-'}</Typography>
                      </Grid>
                    );
                  })}
                </Grid>
              </CardContent>
            </Card>
          ))}
        </Grid>

        <Grid item xs={12}>
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
            <Typography color="error" variant="caption" display="block">
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
              <Typography variant="body2" paragraph>
                <strong>{t('applicationForm.success.previewMode')}:</strong> {t('applicationForm.success.previewMessage')}
              </Typography>
              <Typography variant="body2">
                {t('applicationForm.success.previewNote')}
              </Typography>
            </Alert>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
              {t('applicationForm.success.dataCollected')}
            </Typography>
            <Box component="pre" sx={{ textAlign: 'left', bgcolor: 'grey.100', p: 2, borderRadius: 1, fontSize: '0.85rem', overflow: 'auto', maxHeight: 300, maxWidth: 600, mx: 'auto' }}>
              {JSON.stringify(formData, null, 2)}
            </Box>
          </>
        ) : (
          <>
            <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
              {t('applicationForm.success.message')}
            </Typography>
            
            {applicationId && (
              <Chip
                label={t('applicationForm.success.applicationId', { id: applicationId })}
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
              onClick={() => navigate(`/console/applicant/applications${applicationId ? `?id=${applicationId}` : ''}`)}
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

  if (submitted) {
    return (
      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper sx={{ p: 4 }}>
          {renderSubmittedState()}
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
  if (isOneClickCredential) {
    const displayRole = (user?.roles || []).find(r => ['applicant', 'vendor', 'administrator'].includes(r)) || 'applicant';

    const HeroIcon = isMdlCredential ? DirectionsCarIcon : LoginIcon;
    const heroTitle = isMdlCredential
      ? (credentialConfig?.display_name || 'Membership ID (mDoc)')
      : (credentialConfig?.display_name || 'Login Credential (Open Badge)');
    const heroDescription = isMdlCredential
      ? (credentialConfig?.description || 'Mobile-first membership identity in mDoc format — compatible with Apple & Google Wallet style experiences.')
      : (credentialConfig?.description || 'Log in securely using your wallet — no password required. W3C Verifiable Credential in SD-JWT format.');
    const ctaLabel = isMdlCredential ? 'Get Membership ID' : 'Add to Wallet';
    const ctaSubtext = isMdlCredential ? 'Free · Instant · mDoc (ISO 18013-5)' : 'Free · Instant · Open Badge (W3C)';

    const summaryFields = getOneClickSummaryFields({ credentialConfig, user, organizationId });

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
              <Typography variant="h5" fontWeight={700} gutterBottom>
                {heroTitle}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {heroDescription}
              </Typography>
            </Box>

            {/* Issuer info */}
            <Box sx={{ mb: 2 }}>
              <Typography variant="caption" color="text.secondary">
                Issued by
              </Typography>
              <Typography variant="body2" fontWeight={600}>
                ElevenID LLC
              </Typography>
            </Box>

            {/* Credential details */}
            <Paper
              variant="outlined"
              sx={{ p: 2.5, mb: 2, textAlign: 'left', borderRadius: 2, bgcolor: 'background.default' }}
            >
              <Typography variant="overline" color="text.secondary" sx={{ mb: 1, display: 'block' }}>
                Credential Details
              </Typography>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.75 }}>
                {summaryFields.map(({ label, value }) => (
                  <Box key={label} sx={{ display: 'flex', justifyContent: 'space-between', gap: 2 }}>
                    <Typography variant="body2" color="text.secondary">{label}</Typography>
                    <Typography variant="body2" fontWeight={500}>{value}</Typography>
                  </Box>
                ))}
              </Box>
            </Paper>

            {/* Trust signals */}
            <Box sx={{ mb: 3, display: 'flex', flexDirection: 'column', gap: 0.5, alignItems: 'center' }}>
              <Typography variant="caption" color="text.secondary">🔒 Cryptographically signed</Typography>
              <Typography variant="caption" color="text.secondary">🪪 Verifiable credential (W3C / ISO)</Typography>
              <Typography variant="caption" color="text.secondary">🔁 Reusable across services</Typography>
            </Box>

            {/* Error */}
            {error && (
              <Alert severity="error" sx={{ mb: 2, textAlign: 'left' }} onClose={() => setError(null)}>
                {error}
              </Alert>
            )}

            {/* CTA button */}
            <Button
              variant="contained"
              size="large"
              fullWidth
              onClick={handleAutoApply}
              disabled={autoApplying}
              startIcon={autoApplying ? <CircularProgress size={20} color="inherit" /> : (isMdlCredential ? <DirectionsCarIcon /> : <BadgeIcon />)}
              sx={{ py: 1.5, fontSize: '1rem', borderRadius: 2 }}
            >
              {autoApplying ? 'Issuing credential…' : ctaLabel}
            </Button>

            {/* Helper text */}
            <Typography variant="caption" color="text.secondary" sx={{ mt: 1.5, display: 'block' }}>
              You'll be prompted to open your wallet to receive this credential.
            </Typography>

            <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
              {ctaSubtext}
            </Typography>
          </Paper>
        </Fade>

        {/* Wallet claim dialog — opens after successful issuance */}
        <ClaimCredentialDialog
          open={claimDialogOpen}
          onClose={() => {
            setClaimDialogOpen(false);
            navigate('/console/applicant/applications');
          }}
          applicationId={applicationId}
          offerData={autoOfferData}
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
            {credentialConfig?.display_name || t('applicationForm.title.default')}
          </Typography>
        </Box>
        <Typography variant="body1" color="text.secondary">
          {t('applicationForm.description')}
        </Typography>
      </Box>

      {/* Stepper */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Stepper activeStep={activeStep} alternativeLabel>
          {steps.map((step, idx) => (
            <Step key={idx}>
              <StepLabel>{step.label}</StepLabel>
            </Step>
          ))}
        </Stepper>
      </Paper>

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
    </Container>
  );
}
