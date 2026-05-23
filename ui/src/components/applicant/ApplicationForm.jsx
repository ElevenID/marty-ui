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
import PersonIcon from '@mui/icons-material/Person';
import { useAuth } from '../../hooks/useAuth';
import useWalletPreferences from '../../hooks/useWalletPreferences';
import { usePreview } from '../../contexts/PreviewContext';
import { get, post } from '../../services/api';
import { APPLY_LOCATION_STATE_STORAGE_KEY } from '../../application/routing';
import {
  createApplicant as createApplicantApi,
  createApplication as createApplicationApi,
  enrollBiometric as enrollBiometricApi,
  getApplicant as getApplicantApi,
  getApplicantByUser as getApplicantByUserApi,
  listApplicantApplicationsForProfile,
  listApplications as listApplicationsApi,
  submitApplication as submitApplicationApi,
  supersedeApplication as supersedeApplicationApi,
  updateApplicantProfile as updateApplicantProfileApi,
} from '../../services/applicantApi';
import { generateIssuanceOffer } from '../../services/credentialsApi';
import { DynamicFieldGroup } from './DynamicFieldRenderer';
import ClaimCredentialDialog from '../console/applicant/ClaimCredentialDialog';
import { pickOfficialReference } from '../../utils/officialReferences';
import {
  autoApplyForCredential,
  loadCredentialApplicationConfig,
  resolveApplicantIdForApplication,
  submitCredentialApplication,
  getCredentialKindFlags,
  getOneClickSummaryFields,
  groupFieldsIntoSteps,
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

function getLtiSessionValue(session, key) {
  return (
    session?.[key]
    || session?.mip_primitives?.context?.[key]
    || session?.verified_launch?.[key]
    || null
  );
}

function buildCanvasLtiApplicationContext(session, state, bootstrap = null) {
  if (!session || !state) {
    return null;
  }

  const verifiedLaunch = session.verified_launch || {};
  const canvasContext = verifiedLaunch.context || {};
  const learnerIdentity = verifiedLaunch.learner_identity || {};
  return {
    state,
    issuance_application_id: bootstrap?.application_id || session?.application_id || null,
    bootstrap: bootstrap ? {
      created: bootstrap.created,
      application_status: bootstrap.application_status,
    } : null,
    canvas_account_id: session.canvas_account_id,
    canvas_platform_id: getLtiSessionValue(session, 'canvas_platform_id'),
    canvas_program_binding_id: getLtiSessionValue(session, 'canvas_program_binding_id'),
    application_template_id: getLtiSessionValue(session, 'application_template_id'),
    credential_template_id: getLtiSessionValue(session, 'credential_template_id'),
    canvas_context: canvasContext,
    learner_identity: learnerIdentity,
    roles: verifiedLaunch.roles || [],
    subject: verifiedLaunch.subject || learnerIdentity.subject || null,
  };
}

function canvasLearnerProfile(session) {
  const verifiedLaunch = session?.verified_launch || {};
  const learner = verifiedLaunch.learner_identity || {};
  const rawClaims = verifiedLaunch.raw_claims || {};
  return {
    email: learner.email || rawClaims.email || null,
    given_name: learner.given_name || rawClaims.given_name || null,
    family_name: learner.family_name || rawClaims.family_name || null,
    name: learner.name || rawClaims.name || null,
  };
}

function rawLtiClaim(rawClaims, uri, fallbackKey) {
  const value = rawClaims?.[uri] || rawClaims?.[fallbackKey];
  return value && typeof value === 'object' ? value : {};
}

function canvasLtiDerivedApplicationFields(session, bootstrap = null) {
  const verifiedLaunch = session?.verified_launch || {};
  const rawClaims = verifiedLaunch.raw_claims || {};
  const learner = verifiedLaunch.learner_identity || {};
  const context = verifiedLaunch.context || {};
  const custom = rawLtiClaim(rawClaims, 'https://purl.imsglobal.org/spec/lti/claim/custom', 'custom');
  const resourceLink = rawLtiClaim(rawClaims, 'https://purl.imsglobal.org/spec/lti/claim/resource_link', 'resource_link');
  const bootstrapCanvas = bootstrap?.canvas_context || {};
  const bootstrapFormData = bootstrap?.form_data || bootstrap?.application?.form_data || {};

  return {
    ...bootstrapFormData,
    email: learner.email || rawClaims.email || bootstrapFormData.email,
    given_name: learner.given_name || rawClaims.given_name || bootstrapFormData.given_name,
    family_name: learner.family_name || rawClaims.family_name || bootstrapFormData.family_name,
    name: learner.name || rawClaims.name || bootstrapFormData.name,
    canvas_subject: verifiedLaunch.subject || learner.subject || rawClaims.sub || bootstrapFormData.canvas_subject,
    canvas_course_id: context.id || context.context_id || bootstrapCanvas.canvas_course_id || bootstrapFormData.canvas_course_id,
    canvas_course_name: context.title || context.label || bootstrapCanvas.canvas_course_name || bootstrapFormData.canvas_course_name,
    course_name: context.title || context.label || bootstrapCanvas.canvas_course_name || bootstrapFormData.course_name,
    canvas_assignment_id: custom.assignment_id || resourceLink.id || bootstrapFormData.canvas_assignment_id,
    canvas_assignment_name: custom.assignment_name || resourceLink.title || bootstrapFormData.canvas_assignment_name,
    quiz_name: custom.quiz_name || resourceLink.title || bootstrapFormData.quiz_name,
    score_percent: custom.score_percent || custom.score || bootstrapFormData.score_percent,
  };
}

function isPresent(value) {
  return value !== undefined && value !== null && String(value).trim() !== '';
}

function firstPresent(...values) {
  return values.find(isPresent) || null;
}

function humanizeCanvasLabel(value) {
  return String(value || '')
    .replace(/^canvas[._-]/i, '')
    .replace(/[._-]/g, ' ')
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatEvidenceRequirement(requirement) {
  const evidenceType = requirement?.fact_type || requirement?.evidence_type || requirement?.type;
  const passRule = requirement?.pass_rule || requirement?.rule || {};
  const scope = requirement?.scope || requirement?.canvas_scope || {};
  const details = [];

  if (passRule.completed === true || passRule.status === 'completed') {
    details.push('completion required');
  }
  if (isPresent(passRule.min_score_percent)) {
    details.push(`minimum score ${passRule.min_score_percent}%`);
  }
  if (isPresent(passRule.score_gte)) {
    details.push(`score at least ${passRule.score_gte}`);
  }
  if (isPresent(scope.course_id)) {
    details.push(`course ${scope.course_id}`);
  }
  if (isPresent(scope.assignment_id)) {
    details.push(`assignment ${scope.assignment_id}`);
  }
  if (isPresent(scope.quiz_id)) {
    details.push(`quiz ${scope.quiz_id}`);
  }
  if (isPresent(scope.module_id)) {
    details.push(`module ${scope.module_id}`);
  }

  return {
    label: humanizeCanvasLabel(evidenceType || 'Canvas completion check'),
    details: details.length > 0 ? details.join(' - ') : 'Canvas completion will be checked automatically',
  };
}

export default function ApplicationForm() {
  const { t } = useTranslation('applicant');
  const { credentialType: credentialConfigId } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const { user, organizationId } = useAuth();
  const { walletIds: preferredWallets } = useWalletPreferences(user?.user_id);
  const hasRegisteredWallet = preferredWallets.length > 0;
  const { isPreview } = usePreview?.() || { isPreview: false };
  const fileInputRefs = useRef({});
  const [initialApplyState] = useState(() => location.state || readStoredApplyLocationState());
  const canvasLtiState = useMemo(() => new URLSearchParams(location.search).get('canvas_lti_state') || '', [location.search]);
  const canvasApplicationTemplateIdFromUrl = useMemo(
    () => new URLSearchParams(location.search).get('application_template_id') || '',
    [location.search]
  );

  const [activeStep, setActiveStep] = useState(0);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [submitted, setSubmitted] = useState(false);
  const [applicationId, setApplicationId] = useState(null);
  const [applicationReference, setApplicationReference] = useState(null);
  const [credentialConfig, setCredentialConfig] = useState(
    normalizeCredentialConfigInput(initialApplyState?.credential) || null
  );
  const [configLoading, setConfigLoading] = useState(false);
  const [canvasLtiSession, setCanvasLtiSession] = useState(initialApplyState?.canvasLtiSession || null);
  const [canvasLtiBootstrap, setCanvasLtiBootstrap] = useState(initialApplyState?.canvasLtiBootstrap || null);
  const [applicationTemplate, setApplicationTemplate] = useState(initialApplyState?.applicationTemplate || null);
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

  const canvasApplicationTemplateId = useMemo(
    () => canvasApplicationTemplateIdFromUrl || getLtiSessionValue(canvasLtiSession, 'application_template_id') || '',
    [canvasApplicationTemplateIdFromUrl, canvasLtiSession]
  );

  const getCredentialTemplate = async (templateId) => get(`/v1/credential-templates/${templateId}`);
  const getApplicationTemplate = async (templateId) => get(`/v1/application-templates/${templateId}`);

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
      const needsCredentialTemplate = credentialConfigId && !credentialConfig;
      const needsApplicationTemplate = canvasApplicationTemplateId && applicationTemplate?.id !== canvasApplicationTemplateId;
      if (!needsCredentialTemplate && !needsApplicationTemplate) {
        return;
      }
      setConfigLoading(true);
      try {
        const result = await loadCredentialApplicationConfig({
          credentialConfigId,
          credentialConfig,
          organizationId,
          getCredentialTemplate,
          applicationTemplateId: canvasApplicationTemplateId || null,
          getApplicationTemplate,
        });
        setCredentialConfig(result.credentialConfig);
        if (result.applicationTemplate) {
          setApplicationTemplate(result.applicationTemplate);
        }
        setError(result.error);
      } catch (err) {
        setError(err.message);
      } finally {
        setConfigLoading(false);
      }
    };

    fetchCredentialConfig();
  }, [credentialConfigId, credentialConfig, organizationId, canvasApplicationTemplateId, applicationTemplate?.id]);

  useEffect(() => {
    let alive = true;

    async function loadCanvasLtiSession() {
      if (!canvasLtiState || canvasLtiSession) {
        return;
      }

      try {
        const session = await get(`/v1/integrations/canvas/lti/experience-sessions/${encodeURIComponent(canvasLtiState)}`);
        if (alive) {
          setCanvasLtiSession(session);
        }
      } catch (err) {
        if (alive) {
          setError(err?.message || 'Canvas launch context could not be loaded.');
        }
      }
    }

    loadCanvasLtiSession();
    return () => {
      alive = false;
    };
  }, [canvasLtiState, canvasLtiSession]);

  useEffect(() => {
    let alive = true;

    async function bootstrapCanvasApplication() {
      const applicationTemplateId = getLtiSessionValue(canvasLtiSession, 'application_template_id');
      if (!canvasLtiState || !canvasLtiSession || !applicationTemplateId || canvasLtiBootstrap) {
        return;
      }

      const learner = canvasLearnerProfile(canvasLtiSession);
      try {
        const bootstrap = await post(
          `/v1/integrations/canvas/lti/experience-sessions/${encodeURIComponent(canvasLtiState)}/bootstrap`,
          {
            applicant_identifier: user?.email || user?.user_id || learner.email || null,
            applicant_data: {
              email: user?.email || learner.email || undefined,
              given_name: user?.given_name || learner.given_name || undefined,
              family_name: user?.family_name || learner.family_name || undefined,
              name: learner.name || undefined,
            },
          }
        );
        if (alive) {
          setCanvasLtiBootstrap(bootstrap);
        }
      } catch (err) {
        if (alive) {
          setError(err?.message || 'Canvas application context could not be prepared.');
        }
      }
    }

    bootstrapCanvasApplication();
    return () => {
      alive = false;
    };
  }, [canvasLtiState, canvasLtiSession, canvasLtiBootstrap, user]);

  useEffect(() => {
    // Pre-fill user email if email field exists
    if (user?.email && allFields.some(f => f.name === 'email')) {
      setFormData(prev => ({ ...prev, email: user.email }));
    }
  }, [user, allFields]);

  useEffect(() => {
    if (!canvasLtiSession) {
      return;
    }

    const profile = canvasLearnerProfile(canvasLtiSession);
    const derivedFields = canvasLtiDerivedApplicationFields(canvasLtiSession, canvasLtiBootstrap);
    const fieldNames = new Set(allFields.map((field) => field.name));
    setFormData((prev) => {
      const updates = {};
      if (profile.email && !prev.email && allFields.some((field) => field.name === 'email')) {
        updates.email = profile.email;
      }
      if (profile.given_name && !prev.given_name && allFields.some((field) => field.name === 'given_name')) {
        updates.given_name = profile.given_name;
      }
      if (profile.family_name && !prev.family_name && allFields.some((field) => field.name === 'family_name')) {
        updates.family_name = profile.family_name;
      }
      if (profile.name && !prev.name && allFields.some((field) => field.name === 'name')) {
        updates.name = profile.name;
      }
      Object.entries(derivedFields).forEach(([fieldName, value]) => {
        if (value !== undefined && value !== null && value !== '' && !prev[fieldName] && fieldNames.has(fieldName)) {
          updates[fieldName] = value;
        }
      });
      return Object.keys(updates).length > 0 ? { ...prev, ...updates } : prev;
    });
  }, [canvasLtiSession, canvasLtiBootstrap, allFields]);

  const canvasLtiApplicationContext = useMemo(
    () => buildCanvasLtiApplicationContext(canvasLtiSession, canvasLtiState, canvasLtiBootstrap),
    [canvasLtiSession, canvasLtiState, canvasLtiBootstrap]
  );
  const isCanvasLtiApplication = Boolean(canvasLtiState || canvasLtiSession);
  const canvasDerivedFields = useMemo(
    () => canvasLtiDerivedApplicationFields(canvasLtiSession, canvasLtiBootstrap),
    [canvasLtiSession, canvasLtiBootstrap]
  );
  const canvasEvidenceRequirements = useMemo(() => {
    const fromConfig = credentialConfig?.evidence_requirements;
    const fromTemplate = applicationTemplate?.evidence_requirements;
    if (Array.isArray(fromConfig) && fromConfig.length > 0) {
      return fromConfig;
    }
    if (Array.isArray(fromTemplate) && fromTemplate.length > 0) {
      return fromTemplate;
    }
    return [];
  }, [credentialConfig, applicationTemplate]);
  const canvasSummaryItems = useMemo(() => {
    if (!isCanvasLtiApplication) {
      return [];
    }

    const learnerName = firstPresent(
      canvasDerivedFields.name,
      [canvasDerivedFields.given_name, canvasDerivedFields.family_name].filter(Boolean).join(' '),
      user?.given_name || user?.family_name ? [user?.given_name, user?.family_name].filter(Boolean).join(' ') : null
    );
    const rawClaims = canvasLtiSession?.verified_launch?.raw_claims || {};
    const resourceLink = rawLtiClaim(rawClaims, 'https://purl.imsglobal.org/spec/lti/claim/resource_link', 'resource_link');

    return [
      { label: 'Learner', value: learnerName },
      { label: 'Email', value: firstPresent(canvasDerivedFields.email, user?.email) },
      { label: 'Course', value: firstPresent(canvasDerivedFields.canvas_course_name, canvasDerivedFields.course_name) },
      { label: 'Canvas activity', value: firstPresent(canvasDerivedFields.canvas_assignment_name, canvasDerivedFields.quiz_name, resourceLink.title) },
      { label: 'Canvas account', value: canvasLtiSession?.canvas_account_id },
    ].filter((item) => isPresent(item.value));
  }, [isCanvasLtiApplication, canvasDerivedFields, user, canvasLtiSession]);

  useEffect(() => {
    const boundCredentialTemplateId = getLtiSessionValue(canvasLtiSession, 'credential_template_id');
    if (boundCredentialTemplateId && credentialConfigId && boundCredentialTemplateId !== credentialConfigId) {
      setError('Canvas launch context is bound to a different credential application.');
    }
  }, [canvasLtiSession, credentialConfigId]);

  // ===========================================================================
  // MemberCredential / mDL: derived flags & one-click auto-apply handler
  // ===========================================================================
  const { isMemberCredential, isMdlCredential, isMdocMemberCredential, isOpenBadgeCredential, isAccessBadgeCredential, isOneClickCredential } = getCredentialKindFlags(credentialConfig);
  const applicationDisplayName = credentialConfig?.display_name || applicationTemplate?.name || (
    isCanvasLtiApplication ? 'Canvas Credential Application' : t('applicationForm.title.default')
  );
  const applicationDescription = isCanvasLtiApplication
    ? 'Review your Canvas course details and request the credential. ElevenID will check the configured Canvas completion rule after you submit.'
    : t('applicationForm.description');
  const shouldShowStepper = !(isCanvasLtiApplication && steps.length === 1);

  const handleAutoApply = async () => {
    setAutoApplying(true);
    setError(null);
    try {
      const result = await autoApplyForCredential({
        organizationId,
        user,
        credentialConfig,
        credentialConfigId,
        hasRegisteredWallet,
        resolveApplicantId,
        createApplicant: createApplicantApi,
        updateApplicantProfile: updateApplicantProfileApi,
        createApplication: createApplicationApi,
        submitApplication: submitApplicationApi,
        generateIssuanceOffer,
        listApplications: listApplicationsApi,
      });
      setApplicationId(result.applicationId);
      setApplicationReference(result.applicationReference || null);
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

  const submitApplicationForm = async (duplicateApplicationAction = null) => {
    setSubmitting(true);
    setError(null);

    try {
      const result = await submitCredentialApplication({
        organizationId,
        user,
        formData,
        credentialConfig,
        credentialConfigId,
        canvasLtiContext: canvasLtiApplicationContext,
        allFields,
        resolveApplicantId,
        createApplicant: createApplicantApi,
        updateApplicantProfile: updateApplicantProfileApi,
        getApplicantByUser: getApplicantByUserApi,
        createApplication: createApplicationApi,
        submitApplication: submitApplicationApi,
        listApplicantApplications: listApplicantApplicationsForProfile,
        supersedeApplication: supersedeApplicationApi,
        duplicateApplicationAction,
        enrollBiometric: enrollBiometricApi,
        readFileAsBase64,
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
      console.error('Error submitting application:', err);
      setError(err.message);
    } finally {
      setSubmitting(false);
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

  const renderCanvasSummaryPanel = ({ compact = false } = {}) => {
    if (!isCanvasLtiApplication) {
      return null;
    }

    const evidenceItems = canvasEvidenceRequirements.map(formatEvidenceRequirement);
    const hasNoAdditionalFields = allFields.length === 0;

    return (
      <Box
        data-testid="canvas-application-context"
        sx={{
          mb: compact ? 3 : 4,
          p: compact ? 2 : 3,
          border: '1px solid',
          borderColor: 'primary.light',
          borderRadius: 1,
          bgcolor: 'action.hover',
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap', mb: 1 }}>
          <Typography variant={compact ? 'subtitle1' : 'h6'} fontWeight={700}>
            Canvas course completion
          </Typography>
          <Chip size="small" color="success" variant="outlined" label="Launch verified" />
          {canvasLtiBootstrap?.application_status && (
            <Chip size="small" color="primary" variant="outlined" label={`Application ${canvasLtiBootstrap.application_status}`} />
          )}
        </Box>

        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          This application is connected to your Canvas launch. ElevenID will use the course context and completion rule configured by the issuer to evaluate the credential request.
        </Typography>

        {hasNoAdditionalFields && (
          <Alert severity="info" sx={{ mb: 2 }}>
            No additional form fields are required. Review the Canvas details below, then submit the application so the credential can be checked and issued.
          </Alert>
        )}

        {canvasSummaryItems.length > 0 && (
          <Grid container spacing={2} sx={{ mb: evidenceItems.length > 0 ? 2 : 0 }}>
            {canvasSummaryItems.map((item) => (
              <Grid item xs={12} sm={6} key={item.label}>
                <Typography variant="caption" color="text.secondary" sx={{ display: 'block' }}>
                  {item.label}
                </Typography>
                <Typography variant="body2" fontWeight={600}>
                  {item.value}
                </Typography>
              </Grid>
            ))}
          </Grid>
        )}

        {evidenceItems.length > 0 && (
          <Box>
            <Typography variant="subtitle2" sx={{ mb: 1 }}>
              Completion checks
            </Typography>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              {evidenceItems.map((item, index) => (
                <Box
                  key={`${item.label}-${index}`}
                  sx={{
                    p: 1.5,
                    border: '1px solid',
                    borderColor: 'divider',
                    borderRadius: 1,
                    bgcolor: 'background.paper',
                  }}
                >
                  <Typography variant="body2" fontWeight={600}>{item.label}</Typography>
                  <Typography variant="caption" color="text.secondary">{item.details}</Typography>
                </Box>
              ))}
            </Box>
          </Box>
        )}
      </Box>
    );
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

      {renderCanvasSummaryPanel({ compact: true })}

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
          You already have an active request for this credential. Continue with the existing request, or retire the previous request and submit this Canvas request again.
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
