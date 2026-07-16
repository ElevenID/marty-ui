import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  FormControl,
  FormControlLabel,
  IconButton,
  InputLabel,
  LinearProgress,
  MenuItem,
  Paper,
  Select,
  Stack,
  Step,
  StepLabel,
  Stepper,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import ArchiveIcon from '@mui/icons-material/Archive';
import DeleteIcon from '@mui/icons-material/Delete';
import EditIcon from '@mui/icons-material/Edit';
import LinkIcon from '@mui/icons-material/Link';
import PlayCircleIcon from '@mui/icons-material/PlayCircle';
import RefreshIcon from '@mui/icons-material/Refresh';
import SaveIcon from '@mui/icons-material/Save';
import SyncIcon from '@mui/icons-material/Sync';
import TaskAltIcon from '@mui/icons-material/TaskAlt';
import WarningAmberIcon from '@mui/icons-material/WarningAmber';

import { useAsyncData } from '../../../hooks/useAsyncData';
import { usePermissions } from '../../../hooks/usePermissions';
import { useConsole } from '../../../contexts/ConsoleContext';
import {
  createCanvasPlatform,
  createCanvasIntegrationSecret,
  createCanvasProgramBinding,
  activateCanvasProgramBinding,
  deactivateCanvasProgramBinding,
  deleteCanvasPlatform,
  deleteCanvasProgramBinding,
  disconnectCanvasOAuthConnection,
  discoverCanvasScope,
  finalizeCanvasLtiInstallation,
  getCanvasMirrorHealth,
  getCanvasLtiRegistrationConfig,
  getCanvasPlatformReadiness,
  listCanvasAwardCandidates,
  listCanvasEvidencePolicyReviews,
  listCanvasIntegrationSecrets,
  listCanvasPlatforms,
  listCanvasProgramBindings,
  listCanvasSyncJobs,
  processCanvasMirrorStatusSyncFailures,
  processPendingCanvasMirrorDeliveries,
  resolveCanvasEvidencePolicyReview,
  resolveCanvasSyncJob,
  retryCanvasSyncJob,
  runCanvasMirrorAutomationCycle,
  startCanvasOAuthConnection,
  updateCanvasIntegrationSecret,
  updateCanvasPlatform,
  updateCanvasProgramBinding,
  validateCanvasCredentialsProvider,
  validateCanvasProgramBinding,
} from '../../../services/canvasIntegrationsApi';
import { listApplicationTemplates } from '../../../services/applicationTemplatesApi';
import { listCredentialTemplates } from '../../../services/presentationPolicyApi';
import { listDeploymentProfiles } from '../../../services/deploymentProfilesApi';
import { listDeliveryDestinations } from '../../../services/deliveryDestinationsApi';
import CanvasMirrorProvenanceLookup from '../../canvas/CanvasMirrorProvenanceLookup';
import { ResourcePage, EmptyState, StatusChip } from '../../common';

const EVIDENCE_TYPES = [
  { value: 'canvas.course_completion', label: 'Course completion' },
  { value: 'canvas.assignment_score', label: 'Assignment score' },
  { value: 'canvas.quiz_score', label: 'Quiz score' },
  { value: 'canvas.module_completion', label: 'Module completion' },
];

const OAUTH_CAPABILITIES = [
  { value: 'catalog', label: 'Course and activity catalog' },
  { value: 'native_activity_scores', label: 'Existing assignment and quiz scores' },
  { value: 'course_completion', label: 'Course completion' },
  { value: 'module_completion', label: 'Module completion' },
  { value: 'background_roster', label: 'Background roster evaluation' },
];

const DEPLOY_TABS = [
  { label: 'Flows', path: '/console/org/flows/definitions' },
  { label: 'Deployment Profiles', path: '/console/org/deploy/profiles' },
  { label: 'Canvas', path: '/console/org/deploy/canvas' },
  { label: 'Issuer Identity', path: '/console/org/deploy/issuer-identity' },
  { label: 'Key Management', path: '/console/org/deploy/key-management' },
];

const CANVAS_FEATURE_KEYS = [
  'enable_canvas_evidence',
  'enable_canvas_lti',
  'enable_canvas_mirror_publish',
  'enable_canvas_mirror_ops',
  'enable_canvas_deep_linking',
  'enable_canvas_ags',
  'enable_canvas_nrps',
];

const CANVAS_FEATURE_LABELS = {
  enable_canvas_evidence: 'Evidence',
  enable_canvas_lti: 'LTI',
  enable_canvas_mirror_publish: 'Mirror publish',
  enable_canvas_mirror_ops: 'Mirror ops',
  enable_canvas_deep_linking: 'Deep Linking',
  enable_canvas_ags: 'AGS',
  enable_canvas_nrps: 'NRPS',
};

const BREADCRUMBS = [
  { label: 'Console', path: '/console' },
  { label: 'Deploy', path: '/console/org/deploy' },
  { label: 'Canvas', path: '/console/org/deploy/canvas' },
];

const BINDING_WIZARD_STEPS = ['Program', 'Canvas activity', 'Delivery'];

const EVIDENCE_SOURCES = [
  { value: 'ags_result', label: 'Marty-bound assignment (AGS Result)' },
  { value: 'canvas_rest', label: 'Existing Canvas activity (REST)' },
];

function defaultEvidenceSource(factType = '') {
  if (factType === 'canvas.assignment_score') return 'ags_result';
  return 'canvas_rest';
}

function evidenceSourcesForFactType(factType = '') {
  if (factType === 'canvas.assignment_score') return EVIDENCE_SOURCES;
  return EVIDENCE_SOURCES.filter((source) => source.value === 'canvas_rest');
}

const CANVAS_CREDENTIALS_DESTINATION_ID = 'dd-canvas-credentials-institutional';

const CANVAS_CREDENTIALS_PROJECTION_POLICY = {
  mode: 'public_badge',
  allowed_claims: [
    'achievement',
    'issuer',
    'credentialSubject',
    'credentialStatus',
    'provenance',
  ],
};

function platformFormFrom(platform = {}) {
  const connection = platform.connection_config || {};
  return {
    display_name: platform.display_name || '',
    canvas_account_id: platform.canvas_account_id || '',
    canvas_base_url: platform.canvas_base_url || '',
    lti_client_id: platform.lti_client_id || '',
    lti_deployment_id: platform.lti_deployment_id || '',
    lti_issuer: platform.lti_issuer || '',
    lti_jwks_url: platform.lti_jwks_url || '',
    oauth_client_id: connection.oauth_client_id || '',
    oauth_client_secret_value: '',
    oauth_capabilities: Array.isArray(connection.capabilities)
      ? connection.capabilities
      : Array.isArray(platform.oauth_capabilities)
        ? platform.oauth_capabilities
        : ['catalog'],
    enabled: Boolean(platform.enabled),
  };
}

function firstRequirement(binding = {}) {
  return Array.isArray(binding.evidence_requirements) && binding.evidence_requirements.length > 0
    ? binding.evidence_requirements[0]
    : {};
}

const PORTABLE_EVIDENCE_SOURCES = new Set(['ags_result', 'canvas_rest']);
const READINESS_SUCCESS_STATUSES = new Set(['pass', 'ready', 'ok', 'not_applicable']);

function hasLegacyOrAmbiguousEvidenceRequirements(binding = {}) {
  const requirements = binding.evidence_requirements;
  return !Array.isArray(requirements)
    || requirements.length === 0
    || requirements.some((requirement) => (
      !requirement
      || !PORTABLE_EVIDENCE_SOURCES.has(requirement.source)
    ));
}

function isSuccessfulReadinessStatus(status) {
  return READINESS_SUCCESS_STATUSES.has(String(status || '').toLowerCase());
}

export function requirementFormFields(requirement = {}, fallbackScope = {}) {
  const scope = requirement.scope || requirement.canvas_scope || fallbackScope || {};
  const factType = requirement.fact_type || requirement.evidence_type || 'canvas.course_completion';
  const passRule = requirement.pass_rule || {};
  const activityId = scope.activity_id || scope.assignment_id || scope.quiz_id || '';
  return {
    evidence_type: factType,
    evidence_source: requirement.source || defaultEvidenceSource(factType),
    course_id: scope.course_id || '',
    assignment_id: factType === 'canvas.assignment_score' ? activityId : '',
    module_id: scope.module_id || '',
    quiz_id: factType === 'canvas.quiz_score' ? activityId : '',
    min_score_percent: passRule.min_score_percent ?? passRule.score_percent ?? '',
  };
}

function bindingFormFrom(binding = {}, platformId = '') {
  const requirement = firstRequirement(binding);
  const canvasCredentials = binding.canvas_credentials || {};
  return {
    platform_id: binding.platform_id || platformId,
    deployment_profile_id: binding.deployment_profile_id || '',
    feature_flags: normalizeCanvasFeatureFlags(binding.feature_flags || {}),
    application_template_id: binding.application_template_id || '',
    credential_template_id: binding.credential_template_id || '',
    display_name: binding.display_name || '',
    ...requirementFormFields(requirement, binding.canvas_scope),
    auto_approve_on_evidence: Boolean(binding.auto_approve_on_evidence),
    direct_issue_enabled: Boolean(binding.direct_issue_enabled),
    delivery_mode: binding.delivery_mode || 'wallet_only',
    issuer_mode: binding.issuer_mode || 'org_managed',
    approval_policy_set_id: binding.approval_policy_set_id || '',
    canvas_credentials_provider: canvasCredentials.provider || 'badgr_api',
    canvas_credentials_api_base_url: canvasCredentials.api_base_url || '',
    canvas_credentials_issuer_id: canvasCredentials.issuer_id || canvasCredentials.canvas_credentials_issuer_id || '',
    canvas_credentials_badgeclass_id: canvasCredentials.badgeclass_id || canvasCredentials.canvas_credentials_badgeclass_id || '',
    canvas_credentials_assertion_scope: canvasCredentials.assertion_scope || 'badgeclasses',
    canvas_credentials_api_token_secret_id: canvasCredentials.api_token_secret_id || canvasCredentials.api_token_secret_ref || '',
    legacy_read_only: Boolean(binding.id) && hasLegacyOrAmbiguousEvidenceRequirements(binding),
    evidence_requirements: Array.isArray(binding.evidence_requirements) ? binding.evidence_requirements : [],
    enabled: Boolean(binding.enabled),
  };
}

function normalizeCanvasFeatureFlags(flags = {}) {
  return Object.fromEntries(CANVAS_FEATURE_KEYS.map((key) => [key, Boolean(flags?.[key])]));
}

function canvasFeatureFlagsFromProfile(profile) {
  return normalizeCanvasFeatureFlags(profile?.canvas_feature_flags || {});
}

function enabledCanvasFeatureLabels(flags = {}) {
  return CANVAS_FEATURE_KEYS
    .filter((key) => Boolean(flags?.[key]))
    .map((key) => CANVAS_FEATURE_LABELS[key]);
}

export function buildCanvasScope(form) {
  let activityId = '';
  if (form.evidence_source === 'canvas_rest' && form.evidence_type === 'canvas.assignment_score') {
    activityId = form.assignment_id;
  } else if (form.evidence_source === 'canvas_rest' && form.evidence_type === 'canvas.quiz_score') {
    activityId = form.quiz_id;
  }
  return Object.fromEntries(
    [
      ['course_id', form.course_id],
      ['activity_id', activityId],
      ['module_id', form.evidence_type === 'canvas.module_completion' ? form.module_id : ''],
    ].filter(([, value]) => String(value || '').trim())
  );
}

export function buildCanvasBindingScope(form) {
  let assignmentId = '';
  let quizId = '';
  if (form.evidence_source === 'canvas_rest' && form.evidence_type === 'canvas.assignment_score') {
    assignmentId = form.assignment_id;
  } else if (form.evidence_source === 'canvas_rest' && form.evidence_type === 'canvas.quiz_score') {
    quizId = form.quiz_id;
  }
  return Object.fromEntries(
    [
      ['course_id', form.course_id],
      ['assignment_id', assignmentId],
      ['quiz_id', quizId],
      ['module_id', form.evidence_type === 'canvas.module_completion' ? form.module_id : ''],
    ].filter(([, value]) => String(value || '').trim())
  );
}

function buildCanvasCredentialsConfig(form) {
  if (form.delivery_mode !== 'wallet_plus_canvas_mirror') {
    return {};
  }
  return Object.fromEntries(
    [
      ['provider', form.canvas_credentials_provider || 'badgr_api'],
      ['api_base_url', form.canvas_credentials_api_base_url],
      ['issuer_id', form.canvas_credentials_issuer_id],
      ['badgeclass_id', form.canvas_credentials_badgeclass_id],
      ['assertion_scope', form.canvas_credentials_assertion_scope || 'badgeclasses'],
      ['api_token_secret_id', form.canvas_credentials_api_token_secret_id],
    ].filter(([, value]) => String(value || '').trim())
  );
}

function buildEvidenceRequirement(form, existingRequirement = form.evidence_requirements?.[0]) {
  const scope = buildCanvasScope(form);
  const passRule = {};
  if (form.evidence_type.endsWith('_completion') || form.evidence_type.endsWith('_approval')) {
    passRule.completed = true;
  }
  if (form.evidence_type.endsWith('_score') && form.min_score_percent !== '') {
    passRule.min_score_percent = Number(form.min_score_percent);
  }
  return {
    ...(existingRequirement?.requirement_id
      ? { requirement_id: existingRequirement.requirement_id }
      : {}),
    source: form.evidence_source || defaultEvidenceSource(form.evidence_type),
    fact_type: form.evidence_type,
    scope,
    pass_rule: passRule,
    required: true,
  };
}

function templateNameById(templates) {
  return Object.fromEntries((templates || []).map((template) => [template.id, template.name || template.id]));
}

function normalizeCredentialTemplates(result) {
  if (Array.isArray(result)) return result;
  if (Array.isArray(result?.items)) return result.items;
  return [];
}

function healthCount(value) {
  return Number.isFinite(Number(value)) ? Number(value) : 0;
}

function mirrorActionSummary(result) {
  if (!result) return '';
  const processed = healthCount(result.processed_count);
  const failed = healthCount(result.failed_count);
  const delivered = healthCount(result.delivered_count ?? result.publish?.delivered_count);
  const synced = healthCount(result.synced_count ?? result.status_sync?.synced_count);
  const blocked = healthCount(result.blocked_count ?? (
    healthCount(result.publish?.blocked_count) + healthCount(result.status_sync?.blocked_count)
  ));
  return [
    `${processed} processed`,
    delivered ? `${delivered} delivered` : null,
    synced ? `${synced} synced` : null,
    blocked ? `${blocked} blocked by profile` : null,
    failed ? `${failed} failed` : null,
  ].filter(Boolean).join(', ');
}

function canvasCredentialsValidationSummary(result) {
  if (!result) return '';
  if (result.ok) {
    const target = result.badgeclass_id || result.issuer_id || result.validation_url || result.provider;
    return `Provider validated${target ? `: ${target}` : ''}.`;
  }
  return result.error || 'Canvas Credentials provider validation failed.';
}

function canvasDiscoveryItemLabel(item) {
  if (!item) return '';
  const suffix = item.points_possible != null ? ` (${item.points_possible} pts)` : '';
  return `${item.name || item.id}${suffix}`;
}

function alertSeverityColor(severity) {
  if (severity === 'critical') return 'error';
  if (severity === 'warning') return 'warning';
  return 'info';
}

function CanvasIntegrationsPage() {
  const { activeOrgId } = useConsole();
  const { can, isLoading: permissionsLoading } = usePermissions();
  const organizationId = activeOrgId;
  const canViewCanvas = !permissionsLoading && can('integration-connector', 'view');
  const canCreateCanvas = !permissionsLoading && can('integration-connector', 'create');
  const canEditCanvas = !permissionsLoading && can('integration-connector', 'edit');
  const canDeleteCanvas = !permissionsLoading && can('integration-connector', 'delete');
  const [selectedPlatformId, setSelectedPlatformId] = useState('');
  const [platformDialogOpen, setPlatformDialogOpen] = useState(false);
  const [bindingDialogOpen, setBindingDialogOpen] = useState(false);
  const [editingPlatform, setEditingPlatform] = useState(null);
  const [editingBinding, setEditingBinding] = useState(null);
  const [platformForm, setPlatformForm] = useState(platformFormFrom());
  const [bindingForm, setBindingForm] = useState(bindingFormFrom());
  const [bindingRequirementIndex, setBindingRequirementIndex] = useState(0);
  const [bindingWizardStep, setBindingWizardStep] = useState(0);
  const [saveError, setSaveError] = useState(null);
  const [saving, setSaving] = useState(false);
  const [opsBusy, setOpsBusy] = useState('');
  const [opsError, setOpsError] = useState(null);
  const [opsResult, setOpsResult] = useState(null);
  const [canvasCredentialsValidation, setCanvasCredentialsValidation] = useState(null);
  const [canvasCredentialsValidationBusy, setCanvasCredentialsValidationBusy] = useState(false);
  const [canvasCredentialsSecretValue, setCanvasCredentialsSecretValue] = useState('');
  const [canvasCredentialsSecretBusy, setCanvasCredentialsSecretBusy] = useState(false);
  const [canvasCredentialsSecretError, setCanvasCredentialsSecretError] = useState(null);
  const [canvasScopeDiscovery, setCanvasScopeDiscovery] = useState(null);
  const [canvasScopeDiscoveryBusy, setCanvasScopeDiscoveryBusy] = useState(false);
  const [canvasScopeDiscoveryError, setCanvasScopeDiscoveryError] = useState(null);
  const [registrationConfig, setRegistrationConfig] = useState(null);
  const [registrationError, setRegistrationError] = useState(null);
  const [registrationBusy, setRegistrationBusy] = useState(false);
  const [oauthBusy, setOauthBusy] = useState(false);
  const [oauthAuthorizationUrl, setOauthAuthorizationUrl] = useState('');
  const [oauthError, setOauthError] = useState(null);
  const [bindingActionBusy, setBindingActionBusy] = useState('');
  const [portableOperationBusy, setPortableOperationBusy] = useState('');
  const [bindingReadiness, setBindingReadiness] = useState({});

  const {
    data: platformsData,
    loading: platformsLoading,
    error: platformsError,
    reload: reloadPlatforms,
  } = useAsyncData(async () => {
    if (!canViewCanvas) return [];
    return listCanvasPlatforms(organizationId);
  }, [organizationId, canViewCanvas]);

  const {
    data: bindingsData,
    loading: bindingsLoading,
    error: bindingsError,
    reload: reloadBindings,
  } = useAsyncData(async () => {
    if (!canViewCanvas) return [];
    return listCanvasProgramBindings({ organizationId });
  }, [organizationId, canViewCanvas]);

  const {
    data: platformReadiness = null,
    loading: readinessLoading,
    error: readinessError,
    reload: reloadReadiness,
  } = useAsyncData(async () => {
    if (!canViewCanvas || !selectedPlatformId) return null;
    return getCanvasPlatformReadiness(selectedPlatformId);
  }, [selectedPlatformId, canViewCanvas]);

  const {
    data: syncJobsData = [],
    error: syncJobsError,
    reload: reloadSyncJobs,
  } = useAsyncData(
    async () => canViewCanvas ? listCanvasSyncJobs({ organizationId }) : [],
    [organizationId, canViewCanvas]
  );

  const {
    data: awardCandidatesData = [],
    error: awardCandidatesError,
    reload: reloadAwardCandidates,
  } = useAsyncData(
    async () => canViewCanvas ? listCanvasAwardCandidates({ organizationId }) : [],
    [organizationId, canViewCanvas]
  );

  const {
    data: correctionReviewsData = [],
    error: correctionReviewsError,
    reload: reloadCorrectionReviews,
  } = useAsyncData(
    async () => canViewCanvas
      ? listCanvasEvidencePolicyReviews({ organizationId, status: 'open' })
      : [],
    [organizationId, canViewCanvas]
  );

  const { data: applicationTemplatesData } = useAsyncData(async () => {
    if (!canViewCanvas) return [];
    return listApplicationTemplates(organizationId);
  }, [organizationId, canViewCanvas]);

  const { data: credentialTemplatesData } = useAsyncData(async () => {
    if (!canViewCanvas) return [];
    return normalizeCredentialTemplates(await listCredentialTemplates({ organization_id: organizationId }));
  }, [organizationId, canViewCanvas]);

  const { data: deploymentProfilesData } = useAsyncData(async () => {
    if (!canViewCanvas) return [];
    const profiles = await listDeploymentProfiles({ organization_id: organizationId });
    return Array.isArray(profiles) ? profiles : [];
  }, [organizationId, canViewCanvas]);

  const {
    data: mirrorHealth = null,
    loading: mirrorHealthLoading,
    error: mirrorHealthError,
    reload: reloadMirrorHealth,
  } = useAsyncData(async () => {
    if (!canViewCanvas) return null;
    return getCanvasMirrorHealth(organizationId);
  }, [organizationId, canViewCanvas]);

  const {
    data: deliveryDestinationsData,
    loading: deliveryDestinationsLoading,
    error: deliveryDestinationsError,
    reload: reloadDeliveryDestinations,
  } = useAsyncData(async () => {
    if (!canViewCanvas) return [];
    return listDeliveryDestinations({
      organizationId,
      provider: 'canvas_credentials',
      activeOnly: false,
    });
  }, [organizationId, canViewCanvas]);

  const {
    data: integrationSecretsData,
    reload: reloadIntegrationSecrets,
  } = useAsyncData(async () => {
    if (!canViewCanvas) return [];
    return listCanvasIntegrationSecrets({
      organizationId,
      provider: 'canvas_credentials',
    });
  }, [organizationId, canViewCanvas]);

  const platforms = Array.isArray(platformsData) ? platformsData : [];
  const bindings = Array.isArray(bindingsData) ? bindingsData : [];
  const applicationTemplates = Array.isArray(applicationTemplatesData) ? applicationTemplatesData : [];
  const credentialTemplates = Array.isArray(credentialTemplatesData) ? credentialTemplatesData : [];
  const deploymentProfiles = Array.isArray(deploymentProfilesData) ? deploymentProfilesData : [];
  const deliveryDestinations = Array.isArray(deliveryDestinationsData) ? deliveryDestinationsData : [];
  const integrationSecrets = Array.isArray(integrationSecretsData) ? integrationSecretsData : [];
  const syncJobs = Array.isArray(syncJobsData) ? syncJobsData : [];
  const awardCandidates = Array.isArray(awardCandidatesData) ? awardCandidatesData : [];
  const correctionReviews = Array.isArray(correctionReviewsData) ? correctionReviewsData : [];
  const readinessChecks = Array.isArray(platformReadiness?.checks) ? platformReadiness.checks : [];
  const blockingReadinessChecks = readinessChecks.filter((check) => (
    check.blocking && !isSuccessfulReadinessStatus(check.status)
  ));
  const selectedIntegrationSecretMissing = Boolean(
    bindingForm.canvas_credentials_api_token_secret_id
    && !integrationSecrets.some((secret) => secret.id === bindingForm.canvas_credentials_api_token_secret_id)
  );

  useEffect(() => {
    if (!selectedPlatformId && platforms.length > 0) {
      setSelectedPlatformId(platforms[0].id);
    }
    if (selectedPlatformId && platforms.length > 0 && !platforms.find((platform) => platform.id === selectedPlatformId)) {
      setSelectedPlatformId(platforms[0].id);
    }
  }, [platforms, selectedPlatformId]);

  const platformById = useMemo(
    () => Object.fromEntries((platforms || []).map((platform) => [platform.id, platform])),
    [platforms]
  );
  const applicationTemplateName = useMemo(() => templateNameById(applicationTemplates), [applicationTemplates]);
  const credentialTemplateName = useMemo(() => templateNameById(credentialTemplates), [credentialTemplates]);
  const deploymentProfileById = useMemo(
    () => Object.fromEntries((deploymentProfiles || []).map((profile) => [profile.id, profile])),
    [deploymentProfiles]
  );
  const selectedPlatform = selectedPlatformId ? platformById[selectedPlatformId] : null;
  const visibleBindings = (bindings || []).filter((binding) => (
    selectedPlatformId ? binding.platform_id === selectedPlatformId : true
  ));
  const orgCanvasDestination = deliveryDestinations.find((destination) => (
    destination.provider === 'canvas_credentials'
    && destination.mode === 'organization_mirror'
    && !destination.is_system
  ));
  const systemCanvasDestination = deliveryDestinations.find((destination) => (
    destination.id === CANVAS_CREDENTIALS_DESTINATION_ID
    || (destination.provider === 'canvas_credentials' && destination.mode === 'organization_mirror')
  ));
  const effectiveCanvasDestination = orgCanvasDestination || systemCanvasDestination || null;
  const canvasMirrorBindingCount = bindings.filter((binding) => (
    binding.enabled !== false && binding.delivery_mode === 'wallet_plus_canvas_mirror'
  )).length;
  const canvasCredentialsReady = Boolean(
    effectiveCanvasDestination?.is_enabled !== false
    && platforms.some((platform) => platform.enabled !== false)
    && canvasMirrorBindingCount > 0
  );

  const refreshAll = async () => {
    if (!canViewCanvas) return;
    await Promise.all([
      reloadPlatforms(),
      reloadBindings(),
      reloadMirrorHealth(),
      reloadDeliveryDestinations(),
      reloadIntegrationSecrets(),
      reloadReadiness(),
      reloadSyncJobs(),
      reloadAwardCandidates(),
      reloadCorrectionReviews(),
    ]);
  };

  const openCreatePlatform = () => {
    if (!canCreateCanvas) return;
    setEditingPlatform(null);
    setPlatformForm(platformFormFrom());
    setSaveError(null);
    setPlatformDialogOpen(true);
  };

  const openEditPlatform = (platform) => {
    if (!canEditCanvas) return;
    setEditingPlatform(platform);
    setPlatformForm(platformFormFrom(platform));
    setSaveError(null);
    setOauthAuthorizationUrl('');
    setOauthError(null);
    setPlatformDialogOpen(true);
  };

  const showRegistrationConfig = async (platform) => {
    if (!canViewCanvas) return;
    setRegistrationBusy(true);
    setRegistrationError(null);
    try {
      setRegistrationConfig(await getCanvasLtiRegistrationConfig(platform.id));
    } catch (error) {
      setRegistrationError(error);
    } finally {
      setRegistrationBusy(false);
    }
  };

  const openCreateBinding = () => {
    if (!canCreateCanvas) return;
    setEditingBinding(null);
    setBindingForm(bindingFormFrom({}, selectedPlatformId));
    setBindingRequirementIndex(0);
    setBindingWizardStep(0);
    setSaveError(null);
    setCanvasCredentialsValidation(null);
    setCanvasCredentialsSecretValue('');
    setCanvasCredentialsSecretError(null);
    setCanvasScopeDiscovery(null);
    setCanvasScopeDiscoveryError(null);
    setBindingDialogOpen(true);
  };

  const openEditBinding = (binding) => {
    if (!canEditCanvas || hasLegacyOrAmbiguousEvidenceRequirements(binding)) return;
    setEditingBinding(binding);
    setBindingForm(bindingFormFrom(binding, binding.platform_id));
    setBindingRequirementIndex(0);
    setBindingWizardStep(0);
    setSaveError(null);
    setCanvasCredentialsValidation(null);
    setCanvasCredentialsSecretValue('');
    setCanvasCredentialsSecretError(null);
    setCanvasScopeDiscovery(null);
    setCanvasScopeDiscoveryError(null);
    setBindingDialogOpen(true);
  };

  const savePlatform = async () => {
    const canSave = editingPlatform ? canEditCanvas : canCreateCanvas;
    if (!organizationId || !canSave) return;
    const ltiClientId = platformForm.lti_client_id.trim();
    const ltiDeploymentId = platformForm.lti_deployment_id.trim();
    if (Boolean(ltiClientId) !== Boolean(ltiDeploymentId)) {
      setSaveError(new Error('Enter both the Canvas LTI client ID and deployment ID, or leave both blank for a draft.'));
      return;
    }
    setSaving(true);
    setSaveError(null);
    const payload = {
      display_name: platformForm.display_name,
      canvas_base_url: platformForm.canvas_base_url,
      lti_client_id: ltiClientId || null,
      lti_deployment_id: ltiDeploymentId || null,
      enabled: editingPlatform ? platformForm.enabled : false,
    };
    try {
      const saved = editingPlatform
        ? await updateCanvasPlatform(editingPlatform.id, payload)
        : await createCanvasPlatform(payload, { organizationId });
      if (ltiClientId && ltiDeploymentId) {
        await finalizeCanvasLtiInstallation(saved.id, {
          lti_client_id: ltiClientId,
          lti_deployment_id: ltiDeploymentId,
        });
      }
      setSelectedPlatformId(saved.id);
      setPlatformDialogOpen(false);
      await reloadPlatforms();
    } catch (error) {
      setSaveError(error);
    } finally {
      setSaving(false);
    }
  };

  const connectCanvasOAuth = async () => {
    if (!canEditCanvas || !editingPlatform || !platformForm.oauth_client_id.trim()) return;
    setOauthBusy(true);
    setOauthError(null);
    setOauthAuthorizationUrl('');
    try {
      let secretId = editingPlatform.connection_config?.oauth_client_secret_id;
      if (secretId && platformForm.oauth_client_secret_value.trim()) {
        await updateCanvasIntegrationSecret(secretId, { secret_value: platformForm.oauth_client_secret_value });
      } else if (!secretId) {
        if (!platformForm.oauth_client_secret_value.trim()) {
          throw new Error('Enter the Canvas API Developer Key client secret.');
        }
        const secret = await createCanvasIntegrationSecret({
          organization_id: organizationId,
          name: `Canvas API client secret - ${editingPlatform.id}`,
          provider: 'canvas',
          purpose: 'oauth_client_secret',
          secret_value: platformForm.oauth_client_secret_value,
          metadata: { canvas_platform_id: editingPlatform.id },
        });
        secretId = secret.id;
      }
      const result = await startCanvasOAuthConnection(editingPlatform.id, {
        client_id: platformForm.oauth_client_id,
        client_secret_secret_id: secretId,
        capabilities: platformForm.oauth_capabilities,
      });
      setPlatformForm({ ...platformForm, oauth_client_secret_value: '' });
      setOauthAuthorizationUrl(result.authorization_url);
    } catch (error) {
      setOauthError(error);
    } finally {
      setOauthBusy(false);
    }
  };

  const disconnectCanvasOAuth = async () => {
    if (!canEditCanvas || !editingPlatform) return;
    setOauthBusy(true);
    setOauthError(null);
    try {
      await disconnectCanvasOAuthConnection(editingPlatform.id);
      setOauthAuthorizationUrl('');
      await Promise.all([reloadPlatforms(), reloadReadiness()]);
    } catch (error) {
      setOauthError(error);
    } finally {
      setOauthBusy(false);
    }
  };

  const saveBinding = async () => {
    const platformId = bindingForm.platform_id || selectedPlatformId;
    const canSave = editingBinding ? canEditCanvas : canCreateCanvas;
    if (!platformId || !canSave || bindingForm.legacy_read_only) return;
    setSaving(true);
    setSaveError(null);
    const requirements = [...(bindingForm.evidence_requirements || [])];
    const existingRequirement = requirements[bindingRequirementIndex] || {};
    requirements[bindingRequirementIndex] = buildEvidenceRequirement(bindingForm, existingRequirement);
    const payload = {
      application_template_id: bindingForm.application_template_id,
      credential_template_id: bindingForm.credential_template_id || null,
      display_name: bindingForm.display_name || null,
      auto_approve_on_evidence: editingBinding ? bindingForm.auto_approve_on_evidence : false,
      evidence_requirements: requirements,
      canvas_scope: buildCanvasBindingScope(bindingForm),
      delivery_mode: bindingForm.delivery_mode,
      approval_policy_set_id: bindingForm.approval_policy_set_id || null,
      deployment_profile_id: bindingForm.deployment_profile_id || null,
      feature_flags: bindingForm.deployment_profile_id
        ? normalizeCanvasFeatureFlags(bindingForm.feature_flags)
        : {},
      canvas_credentials: buildCanvasCredentialsConfig(bindingForm),
    };
    try {
      const saved = editingBinding
        ? await updateCanvasProgramBinding(editingBinding.id, payload)
        : await createCanvasProgramBinding(platformId, payload, { organizationId });
      setSelectedPlatformId(saved.platform_id);
      setBindingDialogOpen(false);
      await reloadBindings();
    } catch (error) {
      setSaveError(error);
    } finally {
      setSaving(false);
    }
  };

  const persistCurrentRequirement = () => {
    const requirements = [...(bindingForm.evidence_requirements || [])];
    const existingRequirement = requirements[bindingRequirementIndex] || {};
    requirements[bindingRequirementIndex] = buildEvidenceRequirement(bindingForm, existingRequirement);
    return requirements;
  };

  const selectBindingRequirement = (index) => {
    const requirements = persistCurrentRequirement();
    setBindingRequirementIndex(index);
    setBindingForm({
      ...bindingForm,
      evidence_requirements: requirements,
      ...requirementFormFields(requirements[index], bindingForm.canvas_scope),
    });
  };

  const addBindingRequirement = () => {
    const requirements = persistCurrentRequirement();
    const nextRequirement = {
      source: 'canvas_rest',
      fact_type: 'canvas.course_completion',
      scope: bindingForm.course_id ? { course_id: bindingForm.course_id } : {},
      pass_rule: { completed: true },
      required: true,
    };
    requirements.push(nextRequirement);
    setBindingRequirementIndex(requirements.length - 1);
    setBindingForm({
      ...bindingForm,
      evidence_requirements: requirements,
      ...requirementFormFields(nextRequirement),
    });
  };

  const removeBindingRequirement = (index) => {
    const requirements = persistCurrentRequirement();
    if (requirements.length <= 1) return;
    requirements.splice(index, 1);
    const nextIndex = Math.min(bindingRequirementIndex === index ? index : bindingRequirementIndex, requirements.length - 1);
    setBindingRequirementIndex(nextIndex);
    setBindingForm({
      ...bindingForm,
      evidence_requirements: requirements,
      ...requirementFormFields(requirements[nextIndex], bindingForm.canvas_scope),
    });
  };

  const runBindingAction = async (binding, action) => {
    if (!canEditCanvas || hasLegacyOrAmbiguousEvidenceRequirements(binding)) return;
    setBindingActionBusy(`${binding.id}:${action}`);
    setOpsError(null);
    try {
      if (action === 'validate') {
        const result = await validateCanvasProgramBinding(binding.id);
        setBindingReadiness((current) => ({ ...current, [binding.id]: result }));
      } else if (action === 'activate') {
        await activateCanvasProgramBinding(binding.id);
      } else {
        await deactivateCanvasProgramBinding(binding.id);
      }
      await Promise.all([reloadBindings(), reloadReadiness()]);
    } catch (error) {
      setOpsError(error);
    } finally {
      setBindingActionBusy('');
    }
  };

  const retryPortableSyncJob = async (job) => {
    if (!canEditCanvas) return;
    setPortableOperationBusy(`job:${job.id}`);
    setOpsError(null);
    try {
      await retryCanvasSyncJob(job.id);
      await reloadSyncJobs();
    } catch (error) {
      setOpsError(error);
    } finally {
      setPortableOperationBusy('');
    }
  };

  const resolvePortableSyncJob = async (job) => {
    if (!canEditCanvas) return;
    const confirmed = window.confirm(
      'Acknowledge this dead letter and leave its synchronization target stopped? Use Retry instead if the target should resume.',
    );
    if (!confirmed) return;
    setPortableOperationBusy(`job:${job.id}`);
    setOpsError(null);
    try {
      await resolveCanvasSyncJob(job.id);
      await reloadSyncJobs();
    } catch (error) {
      setOpsError(error);
    } finally {
      setPortableOperationBusy('');
    }
  };

  const resolveCorrectionReview = async (review, action) => {
    if (!canEditCanvas) return;
    if (['suspend', 'revoke'].includes(action)) {
      const confirmed = window.confirm(
        `${action === 'revoke' ? 'Revoke' : 'Suspend'} the credential associated with this evidence correction?`,
      );
      if (!confirmed) return;
    }
    setPortableOperationBusy(`review:${review.id}`);
    setOpsError(null);
    try {
      await resolveCanvasEvidencePolicyReview(review.id, action);
      await reloadCorrectionReviews();
    } catch (error) {
      setOpsError(error);
    } finally {
      setPortableOperationBusy('');
    }
  };

  const validateCanvasCredentialsSettings = async () => {
    if (!canViewCanvas) return;
    setCanvasCredentialsValidationBusy(true);
    setCanvasCredentialsValidation(null);
    try {
      const result = await validateCanvasCredentialsProvider(
        buildCanvasCredentialsConfig(bindingForm),
        { organizationId },
      );
      setCanvasCredentialsValidation(result);
    } catch (error) {
      setCanvasCredentialsValidation({
        ok: false,
        error: error?.message || String(error),
      });
    } finally {
      setCanvasCredentialsValidationBusy(false);
    }
  };

  const saveCanvasCredentialsManagedSecret = async () => {
    const maySaveSecret = bindingForm.canvas_credentials_api_token_secret_id
      ? canEditCanvas
      : canCreateCanvas;
    if (!organizationId || !maySaveSecret || !canvasCredentialsSecretValue.trim()) return;
    setCanvasCredentialsSecretBusy(true);
    setCanvasCredentialsSecretError(null);
    try {
      const secretId = bindingForm.canvas_credentials_api_token_secret_id;
      const selectedSecret = integrationSecrets.find((secret) => secret.id === secretId);
      const name = selectedSecret?.name
        || bindingForm.display_name
        || selectedPlatform?.display_name
        || 'Canvas Credentials API token';
      const saved = selectedSecret
        ? await updateCanvasIntegrationSecret(selectedSecret.id, {
          secret_value: canvasCredentialsSecretValue,
        })
        : await createCanvasIntegrationSecret({
          organization_id: organizationId,
          name,
          provider: 'canvas_credentials',
          purpose: 'api_token',
          secret_value: canvasCredentialsSecretValue,
          metadata: {
            canvas_platform_id: bindingForm.platform_id || selectedPlatformId,
            canvas_account_id: selectedPlatform?.canvas_account_id,
          },
        });
      setBindingForm({
        ...bindingForm,
        canvas_credentials_api_token_secret_id: saved.id,
      });
      setCanvasCredentialsSecretValue('');
      await reloadIntegrationSecrets();
    } catch (error) {
      setCanvasCredentialsSecretError(error);
    } finally {
      setCanvasCredentialsSecretBusy(false);
    }
  };

  const discoverCanvasActivities = async () => {
    const platformId = bindingForm.platform_id || selectedPlatformId;
    if (!canViewCanvas || !platformId) return;
    setCanvasScopeDiscoveryBusy(true);
    setCanvasScopeDiscoveryError(null);
    try {
      const result = await discoverCanvasScope(platformId, {
        courseId: bindingForm.course_id,
      });
      setCanvasScopeDiscovery(result);
    } catch (error) {
      setCanvasScopeDiscoveryError(error);
    } finally {
      setCanvasScopeDiscoveryBusy(false);
    }
  };

  const removePlatform = async (platform) => {
    if (!canDeleteCanvas) return;
    if (!window.confirm(`Archive ${platform.display_name || platform.canvas_account_id}? Existing launches, evidence, and credentials will be retained.`)) return;
    await deleteCanvasPlatform(platform.id);
    await refreshAll();
  };

  const removeBinding = async (binding) => {
    if (!canDeleteCanvas) return;
    if (!window.confirm(`Archive ${binding.display_name || binding.application_template_id}? Existing launches, evidence, and credentials will be retained.`)) return;
    await deleteCanvasProgramBinding(binding.id);
    await reloadBindings();
  };

  const runMirrorOps = async (action) => {
    if (!organizationId || !canEditCanvas) return;
    setOpsBusy(action);
    setOpsError(null);
    setOpsResult(null);
    try {
      const params = { organizationId, limit: 25 };
      let result;
      if (action === 'publish') {
        result = await processPendingCanvasMirrorDeliveries({ ...params, retryFailed: true });
      } else if (action === 'status-sync') {
        result = await processCanvasMirrorStatusSyncFailures(params);
      } else {
        result = await runCanvasMirrorAutomationCycle({ ...params, retryFailed: true });
      }
      setOpsResult({ action, result });
      await reloadMirrorHealth();
    } catch (error) {
      setOpsError(error);
    } finally {
      setOpsBusy('');
    }
  };

  const loading = platformsLoading || bindingsLoading;
  const error = platformsError || bindingsError;
  const opsDisabled = !canEditCanvas || !organizationId || Boolean(opsBusy);
  const mirrorAlerts = Array.isArray(mirrorHealth?.alerts) ? mirrorHealth.alerts : [];
  const bindingProfileGated = Boolean(bindingForm.deployment_profile_id);
  const bindingCanvasFlags = normalizeCanvasFeatureFlags(bindingForm.feature_flags);
  const bindingCanvasEvidenceEnabled = !bindingProfileGated || bindingCanvasFlags.enable_canvas_evidence;
  const bindingCanvasMirrorPublishEnabled = !bindingProfileGated || bindingCanvasFlags.enable_canvas_mirror_publish;
  const bindingWizardLastStep = bindingWizardStep === BINDING_WIZARD_STEPS.length - 1;
  const discoveredCourses = Array.isArray(canvasScopeDiscovery?.courses) ? canvasScopeDiscovery.courses : [];
  const discoveredAssignments = Array.isArray(canvasScopeDiscovery?.assignments) ? canvasScopeDiscovery.assignments : [];
  const discoveredQuizzes = Array.isArray(canvasScopeDiscovery?.quizzes) ? canvasScopeDiscovery.quizzes : [];
  const discoveredModules = Array.isArray(canvasScopeDiscovery?.modules) ? canvasScopeDiscovery.modules : [];
  const bindingWizardNextDisabled = (
    saving
    || bindingForm.legacy_read_only
    || (editingBinding ? !canEditCanvas : !canCreateCanvas)
    || (bindingWizardStep === 0 && (
      !(bindingForm.platform_id || selectedPlatformId)
      || !bindingForm.application_template_id
      || !bindingCanvasEvidenceEnabled
    ))
    || (bindingWizardStep === 1 && !bindingForm.evidence_type)
  );
  const bindingSaveDisabled = (
    saving
    || bindingForm.legacy_read_only
    || (editingBinding ? !canEditCanvas : !canCreateCanvas)
    || !bindingForm.platform_id
    || !bindingForm.application_template_id
    || !bindingForm.credential_template_id
    || !bindingCanvasEvidenceEnabled
    || (bindingForm.delivery_mode === 'wallet_plus_canvas_mirror' && !bindingCanvasMirrorPublishEnabled)
  );

  if (!canViewCanvas) {
    return (
      <ResourcePage
        title="Canvas"
        description="Canvas platforms and program bindings."
        tabs={DEPLOY_TABS}
        breadcrumbs={BREADCRUMBS}
      >
        {permissionsLoading ? (
          <Stack spacing={1}>
            <LinearProgress />
            <Typography variant="body2" color="text.secondary">
              Checking your Canvas integration permissions...
            </Typography>
          </Stack>
        ) : (
          <Alert severity="warning">
            You do not have permission to view Canvas integration connectors for this organization.
          </Alert>
        )}
      </ResourcePage>
    );
  }

  return (
    <>
      <ResourcePage
        title="Canvas"
        description="Canvas platforms and program bindings."
        tabs={DEPLOY_TABS}
        breadcrumbs={BREADCRUMBS}
        actions={(
          <>
            <Tooltip title="Refresh">
              <span>
                <IconButton onClick={refreshAll} disabled={loading}>
                  <RefreshIcon />
                </IconButton>
              </span>
            </Tooltip>
            {canCreateCanvas && (
              <>
                <Button variant="outlined" startIcon={<AddIcon />} onClick={openCreatePlatform}>
                  Platform
                </Button>
                <Button
                  variant="contained"
                  startIcon={<LinkIcon />}
                  onClick={openCreateBinding}
                  disabled={!selectedPlatform}
                >
                  Binding
                </Button>
              </>
            )}
          </>
        )}
      >
        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error?.message || String(error)}
          </Alert>
        )}

        {loading && <LinearProgress sx={{ mb: 2 }} />}

        <Stack spacing={3}>
          <Box>
            <Typography variant="h5">Setup</Typography>
            <Typography variant="body2" color="text.secondary">
              Install the standard LTI 1.3 configuration, verify a signed Canvas launch, and authorize only the Canvas API capabilities this program needs.
            </Typography>
          </Box>

          <Paper sx={{ p: 2 }} data-testid="canvas-readiness">
            <Stack spacing={2}>
              <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} justifyContent="space-between">
                <Box>
                  <Typography variant="h6">Production readiness</Typography>
                  <Typography variant="body2" color="text.secondary">
                    {selectedPlatform ? selectedPlatform.display_name || selectedPlatform.canvas_base_url : 'Select a Canvas platform.'}
                  </Typography>
                </Box>
                <Stack direction="row" spacing={1} alignItems="center">
                  <Chip
                    label={platformReadiness?.ready ? 'Ready' : 'Action required'}
                    color={platformReadiness?.ready ? 'success' : 'warning'}
                    variant="outlined"
                  />
                  <Tooltip title="Run readiness checks">
                    <span>
                      <IconButton disabled={!selectedPlatformId || readinessLoading} onClick={reloadReadiness}>
                        <RefreshIcon />
                      </IconButton>
                    </span>
                  </Tooltip>
                </Stack>
              </Stack>
              {readinessLoading && <LinearProgress />}
              {readinessError && <Alert severity="warning">{readinessError?.message || String(readinessError)}</Alert>}
              {blockingReadinessChecks.length > 0 && (
                <Alert severity="warning">
                  Activation is blocked by {blockingReadinessChecks.length} readiness check{blockingReadinessChecks.length === 1 ? '' : 's'}.
                </Alert>
              )}
              <Stack spacing={1}>
                {readinessChecks.map((check) => {
                  const passed = isSuccessfulReadinessStatus(check.status);
                  const readinessLabel = String(check.status || '').toLowerCase() === 'not_applicable'
                    ? 'Not applicable'
                    : passed ? 'Pass' : check.blocking ? 'Blocking' : 'Advisory';
                  return (
                    <Stack
                      key={check.code || check.id || check.name}
                      direction={{ xs: 'column', md: 'row' }}
                      spacing={1}
                      alignItems={{ xs: 'flex-start', md: 'center' }}
                    >
                      <Chip size="small" label={readinessLabel} color={passed ? 'success' : check.blocking ? 'error' : 'warning'} variant="outlined" />
                      <Box>
                        <Typography variant="body2" fontWeight={600}>{check.component || check.name || check.code || check.id}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          {check.remediation || check.detail || check.message}
                        </Typography>
                      </Box>
                    </Stack>
                  );
                })}
                {!readinessLoading && readinessChecks.length === 0 && (
                  <Typography variant="body2" color="text.secondary">No readiness result has been recorded yet.</Typography>
                )}
              </Stack>
            </Stack>
          </Paper>

          <Box>
            <Typography variant="h5">Operations</Typography>
            <Typography variant="body2" color="text.secondary">
              Monitor synchronization, pending claims, evidence corrections, and the optional Canvas Credentials projection.
            </Typography>
          </Box>

          <Paper sx={{ p: 2 }} data-testid="canvas-portable-operations">
            <Stack spacing={2}>
              <Typography variant="h6">Portable award pipeline</Typography>
              {(syncJobsError || awardCandidatesError || correctionReviewsError) && (
                <Alert severity="warning">
                  {(syncJobsError || awardCandidatesError || correctionReviewsError)?.message || 'Some Canvas operations could not be loaded.'}
                </Alert>
              )}
              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                <Chip label={`Sync jobs: ${syncJobs.length}`} variant="outlined" />
                <Chip label={`Pending awards: ${awardCandidates.filter((candidate) => candidate.status === 'pending_claim').length}`} color="info" variant="outlined" />
                <Chip label={`Identity links required: ${awardCandidates.filter((candidate) => candidate.status === 'identity_link_required').length}`} color="warning" variant="outlined" />
                <Chip label={`Correction reviews: ${correctionReviews.length}`} color={correctionReviews.length ? 'warning' : 'default'} variant="outlined" />
              </Stack>
              <Typography variant="caption" color="text.secondary">
                Background evaluation can prepare a pending claim, but credential signing happens only after the learner completes the wallet claim.
              </Typography>
              {opsError && (
                <Alert severity="error">{opsError?.message || String(opsError)}</Alert>
              )}

              <Box>
                <Typography variant="subtitle2" sx={{ mb: 1 }}>Synchronization jobs</Typography>
                {syncJobs.length === 0 ? (
                  <Typography variant="body2" color="text.secondary">No synchronization jobs have been recorded.</Typography>
                ) : (
                  <TableContainer variant="outlined" component={Paper}>
                    <Table size="small" aria-label="Canvas synchronization jobs">
                      <TableHead>
                        <TableRow>
                          <TableCell>Target</TableCell>
                          <TableCell>Status</TableCell>
                          <TableCell>Attempts</TableCell>
                          <TableCell>Last result</TableCell>
                          <TableCell align="right">Action</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {syncJobs.slice(0, 10).map((job) => {
                          const retryable = ['dead_letter', 'dead-letter', 'failed'].includes(String(job.status || '').toLowerCase());
                          return (
                            <TableRow key={job.id}>
                              <TableCell>
                                <Typography variant="body2">{job.target_type || 'Canvas evidence'}</Typography>
                                <Typography variant="caption" color="text.secondary">{job.application_id || job.candidate_id || job.target_id}</Typography>
                              </TableCell>
                              <TableCell><StatusChip status={job.status} /></TableCell>
                              <TableCell>{job.attempt_count ?? 0} / {job.max_attempts ?? 8}</TableCell>
                              <TableCell>
                                <Typography variant="caption" color={job.last_error_summary ? 'error.main' : 'text.secondary'}>
                                  {job.last_error_summary || job.last_error_code || 'No error'}
                                </Typography>
                              </TableCell>
                              <TableCell align="right">
                                {retryable && (
                                  <Stack direction="row" spacing={1} justifyContent="flex-end">
                                    <Button
                                      size="small"
                                      disabled={!canEditCanvas || Boolean(portableOperationBusy)}
                                      onClick={() => retryPortableSyncJob(job)}
                                    >
                                      Retry dead letter
                                    </Button>
                                    <Button
                                      size="small"
                                      color="inherit"
                                      disabled={!canEditCanvas || Boolean(portableOperationBusy)}
                                      onClick={() => resolvePortableSyncJob(job)}
                                    >
                                      Resolve dead letter
                                    </Button>
                                  </Stack>
                                )}
                              </TableCell>
                            </TableRow>
                          );
                        })}
                      </TableBody>
                    </Table>
                  </TableContainer>
                )}
              </Box>

              <Box>
                <Typography variant="subtitle2" sx={{ mb: 1 }}>Pending awards and identity links</Typography>
                {awardCandidates.length === 0 ? (
                  <Typography variant="body2" color="text.secondary">No background award candidates have been observed.</Typography>
                ) : (
                  <TableContainer variant="outlined" component={Paper}>
                    <Table size="small" aria-label="Canvas award candidates">
                      <TableHead>
                        <TableRow>
                          <TableCell>Candidate</TableCell>
                          <TableCell>Binding</TableCell>
                          <TableCell>Status</TableCell>
                          <TableCell>Application</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {awardCandidates.slice(0, 10).map((candidate) => (
                          <TableRow key={candidate.id}>
                            <TableCell>{candidate.id}</TableCell>
                            <TableCell>{candidate.binding_id || 'Not bound'}</TableCell>
                            <TableCell><StatusChip status={candidate.status} /></TableCell>
                            <TableCell>{candidate.application_id || 'Learner launch required'}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                )}
              </Box>

              <Box>
                <Typography variant="subtitle2" sx={{ mb: 1 }}>Evidence correction reviews</Typography>
                {correctionReviews.length === 0 ? (
                  <Typography variant="body2" color="text.secondary">No open evidence corrections require administrator action.</Typography>
                ) : (
                  <Stack spacing={1}>
                    {correctionReviews.slice(0, 10).map((review) => (
                      <Paper key={review.id} variant="outlined" sx={{ p: 1.5 }}>
                        <Stack direction={{ xs: 'column', md: 'row' }} spacing={1} justifyContent="space-between" alignItems={{ xs: 'stretch', md: 'center' }}>
                          <Box>
                            <Typography variant="body2" fontWeight={600}>Credential {review.credential_id || review.id}</Typography>
                            <Typography variant="caption" color="text.secondary">
                              Authoritative Canvas evidence changed from permit to deny. The credential remains active until an administrator acts.
                            </Typography>
                          </Box>
                          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                            <Button
                              size="small"
                              disabled={!canEditCanvas || Boolean(portableOperationBusy)}
                              onClick={() => resolveCorrectionReview(review, 'dismiss')}
                            >
                              Dismiss
                            </Button>
                            <Button
                              size="small"
                              color="warning"
                              disabled={!canEditCanvas || Boolean(portableOperationBusy)}
                              onClick={() => resolveCorrectionReview(review, 'suspend')}
                            >
                              Suspend
                            </Button>
                            <Button
                              size="small"
                              color="error"
                              disabled={!canEditCanvas || Boolean(portableOperationBusy)}
                              onClick={() => resolveCorrectionReview(review, 'revoke')}
                            >
                              Revoke
                            </Button>
                          </Stack>
                        </Stack>
                      </Paper>
                    ))}
                  </Stack>
                )}
              </Box>
            </Stack>
          </Paper>

          <Paper sx={{ p: 2 }} data-testid="canvas-mirror-ops">
            <Stack spacing={2}>
              <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} justifyContent="space-between" alignItems={{ xs: 'stretch', md: 'center' }}>
                <Box>
                  <Typography variant="h6">Canvas mirror ops</Typography>
                  <Typography variant="caption" color="text.secondary">
                    {organizationId}
                  </Typography>
                </Box>
                <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                  <Tooltip title="Refresh mirror health">
                    <span>
                      <IconButton onClick={reloadMirrorHealth} disabled={mirrorHealthLoading}>
                        <RefreshIcon />
                      </IconButton>
                    </span>
                  </Tooltip>
                  <Button
                    size="small"
                    variant="contained"
                    startIcon={<PlayCircleIcon />}
                    disabled={opsDisabled}
                    onClick={() => runMirrorOps('cycle')}
                  >
                    Run cycle
                  </Button>
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<TaskAltIcon />}
                    disabled={opsDisabled}
                    onClick={() => runMirrorOps('publish')}
                  >
                    Retry publish
                  </Button>
                  <Button
                    size="small"
                    variant="outlined"
                    startIcon={<SyncIcon />}
                    disabled={opsDisabled}
                    onClick={() => runMirrorOps('status-sync')}
                  >
                    Retry status
                  </Button>
                </Stack>
              </Stack>

              {mirrorHealthLoading && <LinearProgress />}
              {mirrorHealthError && (
                <Alert severity="error">
                  {mirrorHealthError?.message || String(mirrorHealthError)}
                </Alert>
              )}
              {opsError && (
                <Alert severity="error">
                  {opsError?.message || String(opsError)}
                </Alert>
              )}
              {opsResult && (
                <Alert severity={healthCount(opsResult.result?.failed_count) > 0 ? 'warning' : 'success'}>
                  {mirrorActionSummary(opsResult.result)}
                </Alert>
              )}

              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                <Chip
                  size="small"
                  label={`Pending publish: ${healthCount(mirrorHealth?.pending_publish_count)}`}
                  color={healthCount(mirrorHealth?.pending_publish_count) > 0 ? 'warning' : 'default'}
                  variant="outlined"
                />
                <Chip
                  size="small"
                  label={`Failed publish: ${healthCount(mirrorHealth?.failed_publish_count)}`}
                  color={healthCount(mirrorHealth?.failed_publish_count) > 0 ? 'error' : 'default'}
                  variant="outlined"
                />
                <Chip
                  size="small"
                  label={`Delivered: ${healthCount(mirrorHealth?.delivered_count)}`}
                  color={healthCount(mirrorHealth?.delivered_count) > 0 ? 'success' : 'default'}
                  variant="outlined"
                />
                <Chip
                  size="small"
                  label={`Sync failures: ${healthCount(mirrorHealth?.lifecycle_sync_failed_count)}`}
                  color={healthCount(mirrorHealth?.lifecycle_sync_failed_count) > 0 ? 'error' : 'default'}
                  variant="outlined"
                />
                <Chip
                  size="small"
                  label={`Sync OK: ${healthCount(mirrorHealth?.lifecycle_sync_ok_count)}`}
                  variant="outlined"
                />
                <Chip
                  size="small"
                  icon={<WarningAmberIcon />}
                  label={`Alerts: ${healthCount(mirrorHealth?.alert_count)}`}
                  color={healthCount(mirrorHealth?.critical_alert_count) > 0 ? 'error' : healthCount(mirrorHealth?.warning_alert_count) > 0 ? 'warning' : 'default'}
                  variant="outlined"
                />
              </Stack>

              {mirrorAlerts.length > 0 && (
                <Stack spacing={1} data-testid="canvas-mirror-alerts">
                  {mirrorAlerts.slice(0, 5).map((alert) => (
                    <Alert
                      key={`${alert.alert_type}-${alert.delivery_record_id}`}
                      severity={alertSeverityColor(alert.severity)}
                      icon={<WarningAmberIcon fontSize="inherit" />}
                    >
                      <Stack spacing={0.5}>
                        <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
                          <Typography variant="body2" fontWeight={600}>
                            {alert.message}
                          </Typography>
                          <Chip size="small" label={alert.severity} color={alertSeverityColor(alert.severity)} />
                          <Chip size="small" label={`${healthCount(alert.attempt_count)} attempts`} variant="outlined" />
                        </Stack>
                        <Typography variant="caption" color="text.secondary">
                          {alert.delivery_record_id} - {alert.last_error || 'No error detail'}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {alert.recommended_action}
                        </Typography>
                      </Stack>
                    </Alert>
                  ))}
                  {mirrorAlerts.length > 5 && (
                    <Typography variant="caption" color="text.secondary">
                      {mirrorAlerts.length - 5} more alerts hidden.
                    </Typography>
                  )}
                </Stack>
              )}
            </Stack>
          </Paper>

          <Paper sx={{ p: 2 }} data-testid="canvas-credentials-destination">
            <Stack spacing={2}>
              <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} justifyContent="space-between" alignItems={{ xs: 'stretch', md: 'center' }}>
                <Box>
                  <Typography variant="h6">Canvas Credentials destination</Typography>
                  <Typography variant="body2" color="text.secondary">
                    Organization-managed public badge publishing for Canvas Credentials.
                  </Typography>
                </Box>
                <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                  <Chip
                    size="small"
                    label={canvasCredentialsReady ? 'Ready' : 'Needs setup'}
                    color={canvasCredentialsReady ? 'success' : 'warning'}
                    variant="outlined"
                  />
                  <Chip
                    size="small"
                    label={orgCanvasDestination ? 'Org override' : 'System default'}
                    variant="outlined"
                  />
                  <Chip
                    size="small"
                    label={`Projection: ${effectiveCanvasDestination?.claim_projection_policy?.mode || 'public_badge'}`}
                    variant="outlined"
                  />
                </Stack>
              </Stack>

              {deliveryDestinationsLoading && <LinearProgress />}
              {deliveryDestinationsError && (
                <Alert severity="error">
                  {deliveryDestinationsError?.message || String(deliveryDestinationsError)}
                </Alert>
              )}

              <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
                <Box sx={{ flex: 1 }}>
                  <Typography variant="subtitle2">Setup state</Typography>
                  <Typography variant="body2" color="text.secondary">
                    {platforms.length} platform{platforms.length === 1 ? '' : 's'}, {canvasMirrorBindingCount} Canvas mirror binding{canvasMirrorBindingCount === 1 ? '' : 's'}.
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    Students can consent to Canvas display during claim, but only an org admin can configure this destination.
                  </Typography>
                </Box>
                <Box sx={{ flex: 1 }}>
                  <Typography variant="subtitle2">Public badge projection</Typography>
                  <Typography variant="body2" color="text.secondary">
                    {(effectiveCanvasDestination?.claim_projection_policy?.allowed_claims || CANVAS_CREDENTIALS_PROJECTION_POLICY.allowed_claims).join(', ')}
                  </Typography>
                </Box>
              </Stack>

              <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                <Button
                  size="small"
                  variant="outlined"
                  href="/console/org/templates/credentials"
                  startIcon={<LinkIcon />}
                >
                  Manage per badge template
                </Button>
              </Stack>
            </Stack>
          </Paper>

          <CanvasMirrorProvenanceLookup
            organizationId={organizationId}
            showOrganizationField={false}
            title="Canvas credential verification"
            description="Look up a mirrored Canvas Credentials badge and confirm the canonical ElevenID issuance, issuer DID, and revocation status."
          />

          <Typography variant="h6">Installed platforms</Typography>
          <TableContainer component={Paper}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Platform</TableCell>
                  <TableCell>Canvas account</TableCell>
                  <TableCell>LTI</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {platforms.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5}>
                      <EmptyState title="No Canvas platforms" description="Add a platform to manage Canvas program bindings." />
                    </TableCell>
                  </TableRow>
                ) : platforms.map((platform) => (
                  <TableRow
                    key={platform.id}
                    hover
                    selected={platform.id === selectedPlatformId}
                    onClick={() => setSelectedPlatformId(platform.id)}
                    sx={{ cursor: 'pointer' }}
                  >
                    <TableCell>
                      <Typography variant="body2" fontWeight={600}>
                        {platform.display_name || platform.canvas_base_url || platform.canvas_account_id}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {platform.canvas_base_url || 'No base URL'}
                      </Typography>
                    </TableCell>
                    <TableCell>{platform.canvas_account_id}</TableCell>
                    <TableCell>
                      <Stack direction="row" spacing={1} flexWrap="wrap">
                        <Chip size="small" label={platform.lti_client_id ? 'Client' : 'No client'} variant="outlined" />
                        <Chip size="small" label={platform.lti_jwks_url || platform.lti_jwks_json ? 'JWKS' : 'No JWKS'} variant="outlined" />
                      </Stack>
                    </TableCell>
                    <TableCell>
                      <Stack spacing={0.5} alignItems="flex-start">
                        <StatusChip status={platform.enabled ? 'active' : 'disabled'} />
                        <Chip
                          size="small"
                          label={platform.registration_status === 'verified' ? 'Launch verified' : 'Installation incomplete'}
                          color={platform.registration_status === 'verified' ? 'success' : 'warning'}
                          variant="outlined"
                        />
                        {platform.last_connection_error && (
                          <Typography variant="caption" color="error">{platform.last_connection_error}</Typography>
                        )}
                      </Stack>
                    </TableCell>
                    <TableCell align="right" onClick={(event) => event.stopPropagation()}>
                      <Tooltip title="LTI registration configuration">
                        <IconButton size="small" onClick={() => showRegistrationConfig(platform)}>
                          <LinkIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      {canEditCanvas && (
                        <Tooltip title="Edit">
                          <IconButton size="small" onClick={() => openEditPlatform(platform)}>
                            <EditIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      )}
                      {canDeleteCanvas && (
                        <Tooltip title="Archive">
                          <IconButton
                            size="small"
                            aria-label={`Archive ${platform.display_name || platform.canvas_account_id || platform.id}`}
                            onClick={() => removePlatform(platform)}
                          >
                            <ArchiveIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

          <Box>
            <Typography variant="h5">Program bindings</Typography>
            <Typography variant="body2" color="text.secondary">
              Bind typed Canvas evidence rules to one active Open Badge credential template. New bindings remain inactive until every blocking readiness check passes.
            </Typography>
          </Box>
          <TableContainer component={Paper}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Program binding</TableCell>
                  <TableCell>Application template</TableCell>
                  <TableCell>Credential template</TableCell>
                  <TableCell>Evidence</TableCell>
                  <TableCell>Delivery</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {visibleBindings.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7}>
                      <EmptyState title="No Canvas bindings" description="Create a binding for this platform." />
                    </TableCell>
                  </TableRow>
                ) : visibleBindings.map((binding) => {
                  const requirement = firstRequirement(binding);
                  const legacyBinding = hasLegacyOrAmbiguousEvidenceRequirements(binding);
                  const readiness = bindingReadiness[binding.id];
                  const actionBusy = bindingActionBusy.startsWith(`${binding.id}:`);
                  return (
                    <TableRow key={binding.id} hover>
                      <TableCell>
                        <Typography variant="body2" fontWeight={600}>
                          {binding.display_name || binding.canvas_scope?.course_id || binding.id}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          {platformById[binding.platform_id]?.canvas_account_id || binding.canvas_account_id}
                        </Typography>
                        {binding.deployment_profile_id && (
                          <Typography variant="caption" color="text.secondary" display="block">
                            {deploymentProfileById[binding.deployment_profile_id]?.name || binding.deployment_profile_id}
                          </Typography>
                        )}
                      </TableCell>
                      <TableCell>{applicationTemplateName[binding.application_template_id] || binding.application_template_id}</TableCell>
                      <TableCell>{credentialTemplateName[binding.credential_template_id] || binding.credential_template_id}</TableCell>
                      <TableCell>
                        <Stack spacing={0.5}>
                          <Typography variant="body2">{requirement.fact_type || requirement.evidence_type || 'canvas.course_completion'}</Typography>
                          {(binding.evidence_requirements || []).length > 1 && (
                            <Typography variant="caption" color="text.secondary">
                              + {(binding.evidence_requirements || []).length - 1} more requirement{(binding.evidence_requirements || []).length === 2 ? '' : 's'}
                            </Typography>
                          )}
                          <Chip
                            size="small"
                            label={requirement.source || 'Legacy custom source'}
                            color={requirement.source === 'custom_webhook' || !requirement.source ? 'warning' : 'default'}
                            variant="outlined"
                            sx={{ alignSelf: 'flex-start' }}
                          />
                          <Typography variant="caption" color="text.secondary">
                            {Object.entries(binding.canvas_scope || {}).map(([key, value]) => `${key}: ${value}`).join(', ') || 'Any scope'}
                          </Typography>
                          {legacyBinding && (
                            <Typography variant="caption" color="warning.main">Legacy binding: migration review required</Typography>
                          )}
                        </Stack>
                      </TableCell>
                      <TableCell>
                        <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                          <Chip size="small" label={binding.delivery_mode} variant="outlined" />
                          {binding.auto_approve_on_evidence && <Chip size="small" label="Auto approve" color="success" variant="outlined" />}
                          {enabledCanvasFeatureLabels(binding.feature_flags).map((label) => (
                            <Chip key={label} size="small" label={label} variant="outlined" />
                          ))}
                        </Stack>
                      </TableCell>
                      <TableCell>
                        <Stack spacing={0.5} alignItems="flex-start">
                          <StatusChip status={binding.enabled ? 'active' : 'disabled'} />
                          {readiness && (
                            <Chip size="small" label={readiness.ready ? 'Ready' : 'Blocked'} color={readiness.ready ? 'success' : 'warning'} variant="outlined" />
                          )}
                        </Stack>
                      </TableCell>
                      <TableCell align="right">
                        {canEditCanvas && (
                          <>
                            <Tooltip title="Validate readiness">
                              <span>
                                <IconButton
                                  size="small"
                                  aria-label={`Validate ${binding.display_name || binding.id}`}
                                  disabled={actionBusy || legacyBinding}
                                  onClick={() => runBindingAction(binding, 'validate')}
                                >
                                  <TaskAltIcon fontSize="small" />
                                </IconButton>
                              </span>
                            </Tooltip>
                            <Tooltip title={binding.enabled ? 'Deactivate' : 'Activate'}>
                              <span>
                                <IconButton
                                  size="small"
                                  aria-label={`${binding.enabled ? 'Deactivate' : 'Activate'} ${binding.display_name || binding.id}`}
                                  disabled={actionBusy || legacyBinding || (!binding.enabled && readiness?.ready !== true)}
                                  onClick={() => runBindingAction(binding, binding.enabled ? 'deactivate' : 'activate')}
                                >
                                  <PlayCircleIcon fontSize="small" />
                                </IconButton>
                              </span>
                            </Tooltip>
                            <Tooltip title="Edit">
                              <span>
                                <IconButton
                                  size="small"
                                  aria-label={`Edit ${binding.display_name || binding.canvas_scope?.course_id || binding.id}`}
                                  disabled={legacyBinding}
                                  onClick={() => openEditBinding(binding)}
                                >
                                  <EditIcon fontSize="small" />
                                </IconButton>
                              </span>
                            </Tooltip>
                          </>
                        )}
                        {canDeleteCanvas && (
                          <Tooltip title="Archive">
                            <IconButton
                              size="small"
                              aria-label={`Archive ${binding.display_name || binding.canvas_scope?.course_id || binding.id}`}
                              onClick={() => removeBinding(binding)}
                            >
                              <ArchiveIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
        </Stack>
      </ResourcePage>

      <Dialog open={platformDialogOpen} onClose={() => setPlatformDialogOpen(false)} fullWidth maxWidth="md">
        <DialogTitle>{editingPlatform ? 'Edit Canvas platform' : 'Add Canvas platform'}</DialogTitle>
        <DialogContent>
          {saveError && <Alert severity="error" sx={{ mb: 2 }}>{saveError?.message || String(saveError)}</Alert>}
          <Stack spacing={2} sx={{ mt: 1 }}>
            {!editingPlatform && (
              <Alert severity="info">New Canvas platforms are saved as disabled drafts until installation and readiness checks succeed.</Alert>
            )}
            <TextField label="Display name" value={platformForm.display_name} onChange={(event) => setPlatformForm({ ...platformForm, display_name: event.target.value })} />
            <TextField label="Canvas HTTPS base URL" required value={platformForm.canvas_base_url} onChange={(event) => setPlatformForm({ ...platformForm, canvas_base_url: event.target.value })} helperText="Use the institution's canonical hosted Canvas origin. Redirects and private origins are rejected unless explicitly allowlisted by an operator." />
            <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
              <TextField fullWidth label="LTI client ID" value={platformForm.lti_client_id} onChange={(event) => setPlatformForm({ ...platformForm, lti_client_id: event.target.value })} />
              <TextField fullWidth label="LTI deployment ID" value={platformForm.lti_deployment_id} onChange={(event) => setPlatformForm({ ...platformForm, lti_deployment_id: event.target.value })} />
            </Stack>
            {editingPlatform && (
              <Paper variant="outlined" sx={{ p: 2 }}>
                <Stack spacing={2}>
                  <Box>
                    <Typography variant="subtitle2">Scoped Canvas API connection</Typography>
                    <Typography variant="caption" color="text.secondary">
                      Optional for modules, submissions, quizzes, and course completion not exposed through LTI services. Tokens are encrypted per organization.
                    </Typography>
                  </Box>
                  <TextField
                    label="Canvas API Developer Key client ID"
                    value={platformForm.oauth_client_id}
                    onChange={(event) => setPlatformForm({ ...platformForm, oauth_client_id: event.target.value })}
                  />
                  <TextField
                    label={editingPlatform.connection_config?.oauth_client_secret_id ? 'Rotate client secret (optional)' : 'Client secret'}
                    type="password"
                    value={platformForm.oauth_client_secret_value}
                    onChange={(event) => setPlatformForm({ ...platformForm, oauth_client_secret_value: event.target.value })}
                  />
                  <Box>
                    <Typography variant="subtitle2">Authorized capabilities</Typography>
                    <Typography variant="caption" color="text.secondary">
                      Marty maps these capabilities to a fixed least-privilege Canvas scope allowlist. Raw scopes cannot be entered.
                    </Typography>
                  </Box>
                  <Stack spacing={0.5}>
                    {OAUTH_CAPABILITIES.map((capability) => (
                      <FormControlLabel
                        key={capability.value}
                        control={(
                          <Switch
                            checked={platformForm.oauth_capabilities.includes(capability.value)}
                            onChange={(event) => setPlatformForm({
                              ...platformForm,
                              oauth_capabilities: event.target.checked
                                ? [...platformForm.oauth_capabilities, capability.value]
                                : platformForm.oauth_capabilities.filter((value) => value !== capability.value),
                            })}
                          />
                        )}
                        label={capability.label}
                      />
                    ))}
                  </Stack>
                  {oauthError && <Alert severity="error">{oauthError?.message || String(oauthError)}</Alert>}
                  {oauthAuthorizationUrl && (
                    <Alert severity="success" action={<Button color="inherit" href={oauthAuthorizationUrl}>Authorize in Canvas</Button>}>
                      OAuth request is ready. Continue to Canvas to approve the requested scopes.
                    </Alert>
                  )}
                  <Stack direction="row" spacing={1}>
                    <Button variant="outlined" onClick={connectCanvasOAuth} disabled={!canEditCanvas || oauthBusy || !platformForm.oauth_client_id || platformForm.oauth_capabilities.length === 0}>
                      Prepare Canvas authorization
                    </Button>
                    <Button color="warning" variant="text" onClick={disconnectCanvasOAuth} disabled={!canEditCanvas || oauthBusy}>
                      Disconnect OAuth
                    </Button>
                  </Stack>
                </Stack>
              </Paper>
            )}
            <FormControlLabel
              control={<Switch checked={platformForm.enabled} onChange={(event) => setPlatformForm({ ...platformForm, enabled: event.target.checked })} />}
              label="Enabled intent (readiness still required)"
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setPlatformDialogOpen(false)}>Cancel</Button>
          <Button
            startIcon={<SaveIcon />}
            variant="contained"
            disabled={
              saving
              || (editingPlatform ? !canEditCanvas : !canCreateCanvas)
              || !platformForm.display_name
              || !platformForm.canvas_base_url
            }
            onClick={savePlatform}
          >
            Save
          </Button>
        </DialogActions>
      </Dialog>

      <Dialog open={Boolean(registrationConfig) || Boolean(registrationError) || registrationBusy} onClose={() => { setRegistrationConfig(null); setRegistrationError(null); }} fullWidth maxWidth="md">
        <DialogTitle>Canvas LTI 1.3 registration</DialogTitle>
        <DialogContent>
          {registrationBusy && <LinearProgress />}
          {registrationError && <Alert severity="error">{registrationError?.message || String(registrationError)}</Alert>}
          {registrationConfig && (
            <Stack spacing={2} sx={{ mt: 1 }}>
              <Alert severity="info">
                A Canvas root-account administrator can use this Developer Key configuration without installing a Canvas plugin or modifying Canvas source.
              </Alert>
              <TextField
                label="Developer Key configuration"
                value={JSON.stringify(registrationConfig.developer_key_configuration, null, 2)}
                multiline
                minRows={14}
                InputProps={{ readOnly: true }}
              />
              {registrationConfig.registration_config_url && (
                <TextField
                  label="Revocable registration configuration URL"
                  value={registrationConfig.registration_config_url}
                  InputProps={{ readOnly: true }}
                />
              )}
              <Typography variant="caption" color="text.secondary">
                After installation, enter the Canvas client ID and deployment ID on the platform and complete a signed test launch.
              </Typography>
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => { setRegistrationConfig(null); setRegistrationError(null); }}>Close</Button>
        </DialogActions>
      </Dialog>

      <Dialog open={bindingDialogOpen} onClose={() => setBindingDialogOpen(false)} fullWidth maxWidth="md">
        <DialogTitle>{editingBinding ? 'Edit Canvas binding' : 'Add Canvas binding'}</DialogTitle>
        <DialogContent>
          {saveError && <Alert severity="error" sx={{ mb: 2 }}>{saveError?.message || String(saveError)}</Alert>}
          <Stack spacing={2} sx={{ mt: 1 }}>
            <Stepper activeStep={bindingWizardStep} alternativeLabel>
              {BINDING_WIZARD_STEPS.map((label) => (
                <Step key={label}>
                  <StepLabel>{label}</StepLabel>
                </Step>
              ))}
            </Stepper>
            {bindingWizardStep === 0 && (
              <Stack spacing={2}>
                <FormControl fullWidth>
                  <InputLabel>Platform</InputLabel>
                  <Select
                    label="Platform"
                    value={bindingForm.platform_id || selectedPlatformId || ''}
                    onChange={(event) => setBindingForm({ ...bindingForm, platform_id: event.target.value })}
                    disabled={Boolean(editingBinding)}
                  >
                    {platforms.map((platform) => (
                      <MenuItem key={platform.id} value={platform.id}>
                        {platform.display_name || platform.canvas_account_id}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
                <FormControl fullWidth>
                  <InputLabel>Deployment profile</InputLabel>
                  <Select
                    label="Deployment profile"
                    value={bindingForm.deployment_profile_id || ''}
                    onChange={(event) => {
                      const deploymentProfile = deploymentProfiles.find((profile) => profile.id === event.target.value);
                      const featureFlags = event.target.value ? canvasFeatureFlagsFromProfile(deploymentProfile) : {};
                      setBindingForm({
                        ...bindingForm,
                        deployment_profile_id: event.target.value,
                        feature_flags: featureFlags,
                        delivery_mode: featureFlags.enable_canvas_mirror_publish === false
                          ? 'wallet_only'
                          : bindingForm.delivery_mode,
                      });
                    }}
                  >
                    <MenuItem value="">No deployment profile gate</MenuItem>
                    {deploymentProfiles.map((profile) => (
                      <MenuItem key={profile.id} value={profile.id}>
                        {profile.name || profile.id}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
                {bindingForm.deployment_profile_id && (
                  <Alert severity={bindingForm.feature_flags?.enable_canvas_evidence ? 'info' : 'warning'}>
                    Canvas gates from this deployment profile: {enabledCanvasFeatureLabels(bindingForm.feature_flags).join(', ') || 'none enabled'}
                  </Alert>
                )}
                <TextField label="Display name" value={bindingForm.display_name} onChange={(event) => setBindingForm({ ...bindingForm, display_name: event.target.value })} />
                <FormControl fullWidth>
                  <InputLabel>Application template</InputLabel>
                  <Select
                    label="Application template"
                    value={bindingForm.application_template_id}
                    onChange={(event) => {
                      const applicationTemplate = applicationTemplates.find((template) => template.id === event.target.value);
                      setBindingForm({
                        ...bindingForm,
                        application_template_id: event.target.value,
                        credential_template_id: applicationTemplate?.credential_template_id || bindingForm.credential_template_id,
                      });
                    }}
                  >
                    {applicationTemplates.map((template) => (
                      <MenuItem key={template.id} value={template.id}>
                        {template.name || template.id}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
                <FormControl fullWidth>
                  <InputLabel>Credential template</InputLabel>
                  <Select
                    label="Credential template"
                    value={bindingForm.credential_template_id}
                    disabled
                  >
                    {credentialTemplates.map((template) => (
                      <MenuItem key={template.id} value={template.id}>
                        {template.name || template.id}
                      </MenuItem>
                    ))}
                  </Select>
                  <Typography variant="caption" color="text.secondary" sx={{ mt: 0.5 }}>
                    Inherited from the application template; this template controls the Open Badge format, issuer profile, external KMS key, and credential status.
                  </Typography>
                </FormControl>
              </Stack>
            )}
            {bindingWizardStep === 1 && (
              <Stack spacing={2}>
                <Alert severity="info">
                  Marty reads standard Canvas APIs. AGS is only valid for a line item created by this tool; existing assignments, Classic Quizzes, New Quizzes, course progress, and modules use the scoped Canvas REST connection.
                </Alert>
                <Paper variant="outlined" sx={{ p: 2 }}>
                  <Stack spacing={1.5}>
                    <Stack direction={{ xs: 'column', md: 'row' }} justifyContent="space-between" spacing={1} alignItems={{ xs: 'stretch', md: 'center' }}>
                      <Box>
                        <Typography variant="subtitle2">Required evidence rules</Typography>
                        <Typography variant="caption" color="text.secondary">
                          Each rule is evaluated independently. Add every Canvas fact the learner must satisfy for this badge.
                        </Typography>
                      </Box>
                      <Button size="small" startIcon={<AddIcon />} onClick={addBindingRequirement}>
                        Add requirement
                      </Button>
                    </Stack>
                    <Stack spacing={1}>
                      {Array.from({ length: Math.max(1, bindingForm.evidence_requirements?.length || 0) }).map((_, index) => {
                        const storedRequirement = bindingForm.evidence_requirements?.[index] || {};
                        const requirement = index === bindingRequirementIndex
                          ? buildEvidenceRequirement(bindingForm, storedRequirement)
                          : storedRequirement;
                        const typeLabel = EVIDENCE_TYPES.find((type) => type.value === requirement.fact_type)?.label || requirement.fact_type || 'Canvas evidence';
                        return (
                          <Stack key={requirement.requirement_id || `requirement-${index}`} direction="row" spacing={1} alignItems="center">
                            <Button
                              fullWidth
                              size="small"
                              variant={index === bindingRequirementIndex ? 'contained' : 'outlined'}
                              onClick={() => selectBindingRequirement(index)}
                              sx={{ justifyContent: 'flex-start' }}
                            >
                              Rule {index + 1}: {typeLabel} ({requirement.source || 'canvas_rest'})
                            </Button>
                            <Tooltip title="Remove evidence requirement">
                              <span>
                                <IconButton
                                  size="small"
                                  aria-label={`Remove evidence requirement ${index + 1}`}
                                  disabled={Math.max(1, bindingForm.evidence_requirements?.length || 0) <= 1}
                                  onClick={() => removeBindingRequirement(index)}
                                >
                                  <DeleteIcon fontSize="small" />
                                </IconButton>
                              </span>
                            </Tooltip>
                          </Stack>
                        );
                      })}
                    </Stack>
                  </Stack>
                </Paper>
                <Paper variant="outlined" sx={{ p: 2 }}>
                  <Stack spacing={2}>
                    <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} justifyContent="space-between" alignItems={{ xs: 'stretch', md: 'center' }}>
                      <Box>
                        <Typography variant="subtitle2">Import Canvas activity</Typography>
                        <Typography variant="caption" color="text.secondary">
                          Use the organization-scoped Canvas OAuth connection to discover real courses, assignments, quizzes, and modules.
                        </Typography>
                      </Box>
                      <Button
                        size="small"
                        variant="outlined"
                        startIcon={<RefreshIcon />}
                        disabled={canvasScopeDiscoveryBusy || !(bindingForm.platform_id || selectedPlatformId)}
                        onClick={discoverCanvasActivities}
                      >
                        Discover
                      </Button>
                    </Stack>
                    <Alert severity="info">
                      Discovery uses the organization-scoped Canvas OAuth connection configured on the selected platform.
                    </Alert>
                    {canvasScopeDiscoveryBusy && <LinearProgress />}
                    {canvasScopeDiscoveryError && (
                      <Alert severity="warning">
                        {canvasScopeDiscoveryError?.message || String(canvasScopeDiscoveryError)}
                      </Alert>
                    )}
                    {Array.isArray(canvasScopeDiscovery?.warnings) && canvasScopeDiscovery.warnings.map((warning) => (
                      <Alert key={warning} severity="info">{warning}</Alert>
                    ))}
                    {(discoveredCourses.length > 0 || discoveredAssignments.length > 0 || discoveredQuizzes.length > 0 || discoveredModules.length > 0) && (
                      <Stack spacing={2}>
                        {discoveredCourses.length > 0 && (
                          <FormControl fullWidth>
                            <InputLabel>Imported course</InputLabel>
                            <Select
                              label="Imported course"
                              value={discoveredCourses.some((item) => item.id === bindingForm.course_id) ? bindingForm.course_id : ''}
                              onChange={(event) => setBindingForm({
                                ...bindingForm,
                                course_id: event.target.value,
                                assignment_id: '',
                                module_id: '',
                                quiz_id: '',
                              })}
                            >
                              {discoveredCourses.map((item) => (
                                <MenuItem key={item.id} value={item.id}>{canvasDiscoveryItemLabel(item)}</MenuItem>
                              ))}
                            </Select>
                          </FormControl>
                        )}
                        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
                          {discoveredAssignments.length > 0 && (
                            <FormControl fullWidth>
                              <InputLabel>Imported assignment</InputLabel>
                              <Select
                                label="Imported assignment"
                                value={discoveredAssignments.some((item) => item.id === bindingForm.assignment_id) ? bindingForm.assignment_id : ''}
                                onChange={(event) => setBindingForm({ ...bindingForm, assignment_id: event.target.value })}
                              >
                                {discoveredAssignments.map((item) => (
                                  <MenuItem key={item.id} value={item.id}>{canvasDiscoveryItemLabel(item)}</MenuItem>
                                ))}
                              </Select>
                            </FormControl>
                          )}
                          {discoveredQuizzes.length > 0 && (
                            <FormControl fullWidth>
                              <InputLabel>Imported quiz assignment</InputLabel>
                              <Select
                                label="Imported quiz assignment"
                                value={discoveredQuizzes.some((item) => item.id === bindingForm.quiz_id) ? bindingForm.quiz_id : ''}
                                onChange={(event) => setBindingForm({ ...bindingForm, quiz_id: event.target.value })}
                              >
                                {discoveredQuizzes.map((item) => (
                                  <MenuItem key={item.id} value={item.id}>{canvasDiscoveryItemLabel(item)}</MenuItem>
                                ))}
                              </Select>
                            </FormControl>
                          )}
                          {discoveredModules.length > 0 && (
                            <FormControl fullWidth>
                              <InputLabel>Imported module</InputLabel>
                              <Select
                                label="Imported module"
                                value={discoveredModules.some((item) => item.id === bindingForm.module_id) ? bindingForm.module_id : ''}
                                onChange={(event) => setBindingForm({ ...bindingForm, module_id: event.target.value })}
                              >
                                {discoveredModules.map((item) => (
                                  <MenuItem key={item.id} value={item.id}>{canvasDiscoveryItemLabel(item)}</MenuItem>
                                ))}
                              </Select>
                            </FormControl>
                          )}
                        </Stack>
                      </Stack>
                    )}
                  </Stack>
                </Paper>
                <FormControl fullWidth>
                  <InputLabel>Evidence source</InputLabel>
                  <Select
                    label="Evidence source"
                    value={bindingForm.evidence_source}
                    onChange={(event) => setBindingForm({ ...bindingForm, evidence_source: event.target.value })}
                  >
                    {evidenceSourcesForFactType(bindingForm.evidence_type).map((source) => (
                      <MenuItem key={source.value} value={source.value}>{source.label}</MenuItem>
                    ))}
                  </Select>
                </FormControl>
                {bindingForm.evidence_source === 'ags_result' && (
                  <Alert severity="info">
                    AGS reads only the exact line item associated with Marty through Deep Linking. Existing Canvas assignments and quizzes must use the Canvas REST source.
                  </Alert>
                )}
                <FormControl fullWidth>
                  <InputLabel>Canvas activity</InputLabel>
                  <Select
                    label="Canvas activity"
                    value={bindingForm.evidence_type}
                    onChange={(event) => {
                      const evidenceType = event.target.value;
                      const allowed = evidenceSourcesForFactType(evidenceType).map((source) => source.value);
                      setBindingForm({
                        ...bindingForm,
                        evidence_type: evidenceType,
                        evidence_source: allowed.includes(bindingForm.evidence_source)
                          ? bindingForm.evidence_source
                          : defaultEvidenceSource(evidenceType),
                      });
                    }}
                  >
                    {EVIDENCE_TYPES.map((type) => (
                      <MenuItem key={type.value} value={type.value}>{type.label}</MenuItem>
                    ))}
                  </Select>
                </FormControl>
                <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
                  <TextField fullWidth label="Course ID" value={bindingForm.course_id} onChange={(event) => setBindingForm({ ...bindingForm, course_id: event.target.value })} />
                  <TextField fullWidth label="Assignment ID" disabled={bindingForm.evidence_source === 'ags_result' || bindingForm.evidence_type !== 'canvas.assignment_score'} value={bindingForm.assignment_id} onChange={(event) => setBindingForm({ ...bindingForm, assignment_id: event.target.value })} />
                </Stack>
                <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
                  <TextField fullWidth label="Module ID" disabled={bindingForm.evidence_type !== 'canvas.module_completion'} value={bindingForm.module_id} onChange={(event) => setBindingForm({ ...bindingForm, module_id: event.target.value })} />
                  <TextField
                    fullWidth
                    label="Quiz assignment ID"
                    helperText="Canvas quiz scores are read from the quiz's assignment-backed submission ID."
                    disabled={bindingForm.evidence_type !== 'canvas.quiz_score'}
                    value={bindingForm.quiz_id}
                    onChange={(event) => setBindingForm({ ...bindingForm, quiz_id: event.target.value })}
                  />
                </Stack>
                {bindingForm.evidence_type.endsWith('_score') && (
                  <TextField
                    label="Minimum score percent"
                    type="number"
                    inputProps={{ min: 0, max: 100 }}
                    value={bindingForm.min_score_percent}
                    onChange={(event) => setBindingForm({ ...bindingForm, min_score_percent: event.target.value })}
                  />
                )}
              </Stack>
            )}
            {bindingWizardStep === 2 && (
              <Stack spacing={2}>
                <Alert severity="info">
                  The linked credential template is the only issuer configuration. It must resolve to an active Open Badge format, external KMS key, published DID verification method, and credential-status profile before this binding can activate.
                </Alert>
                <FormControl fullWidth>
                  <InputLabel>Delivery</InputLabel>
                  <Select
                    label="Delivery"
                    value={bindingForm.delivery_mode}
                    onChange={(event) => setBindingForm({ ...bindingForm, delivery_mode: event.target.value })}
                  >
                    <MenuItem value="wallet_only">Wallet claim</MenuItem>
                    <MenuItem value="wallet_plus_canvas_mirror" disabled={!bindingCanvasMirrorPublishEnabled}>Wallet claim + optional Canvas Credentials projection</MenuItem>
                  </Select>
                </FormControl>
                {bindingForm.delivery_mode === 'wallet_plus_canvas_mirror' && (
                  <Paper variant="outlined" sx={{ p: 2 }}>
                    <Stack spacing={2}>
                      <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} justifyContent="space-between" alignItems={{ xs: 'stretch', md: 'center' }}>
                        <Box>
                          <Typography variant="subtitle2">Canvas Credentials provider</Typography>
                          <Typography variant="caption" color="text.secondary">
                            Configure this organization binding with Canvas Credentials IDs and a secret locator. Do not store token values in the binding.
                          </Typography>
                        </Box>
                        <Button
                          size="small"
                          variant="outlined"
                          startIcon={<TaskAltIcon />}
                          disabled={!canViewCanvas || canvasCredentialsValidationBusy}
                          onClick={validateCanvasCredentialsSettings}
                        >
                          Validate provider
                        </Button>
                      </Stack>
                      {canvasCredentialsValidationBusy && <LinearProgress />}
                      {canvasCredentialsValidation && (
                        <Alert severity={canvasCredentialsValidation.ok ? 'success' : 'warning'}>
                          <Stack spacing={0.5}>
                            <Typography variant="body2">
                              {canvasCredentialsValidationSummary(canvasCredentialsValidation)}
                            </Typography>
                            {canvasCredentialsValidation.validation_url && (
                              <Typography variant="caption" color="text.secondary">
                                {canvasCredentialsValidation.validation_url}
                              </Typography>
                            )}
                          </Stack>
                        </Alert>
                      )}
                      <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
                        <FormControl fullWidth>
                          <InputLabel>Provider</InputLabel>
                          <Select
                            label="Provider"
                            value={bindingForm.canvas_credentials_provider}
                            onChange={(event) => setBindingForm({ ...bindingForm, canvas_credentials_provider: event.target.value })}
                          >
                            <MenuItem value="badgr_api">Canvas Credentials API</MenuItem>
                          </Select>
                        </FormControl>
                        <FormControl fullWidth>
                          <InputLabel>Assertion scope</InputLabel>
                          <Select
                            label="Assertion scope"
                            value={bindingForm.canvas_credentials_assertion_scope}
                            onChange={(event) => setBindingForm({ ...bindingForm, canvas_credentials_assertion_scope: event.target.value })}
                          >
                            <MenuItem value="badgeclasses">Badge class</MenuItem>
                            <MenuItem value="issuers">Issuer</MenuItem>
                          </Select>
                        </FormControl>
                      </Stack>
                      <TextField
                        label="API base URL"
                        value={bindingForm.canvas_credentials_api_base_url}
                        onChange={(event) => setBindingForm({ ...bindingForm, canvas_credentials_api_base_url: event.target.value })}
                        helperText="Canvas Credentials API base URL for this organization binding."
                      />
                      <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
                        <TextField
                          fullWidth
                          label="Issuer/entity ID"
                          value={bindingForm.canvas_credentials_issuer_id}
                          onChange={(event) => setBindingForm({ ...bindingForm, canvas_credentials_issuer_id: event.target.value })}
                        />
                        <TextField
                          fullWidth
                          label="Badge class/entity ID"
                          value={bindingForm.canvas_credentials_badgeclass_id}
                          onChange={(event) => setBindingForm({ ...bindingForm, canvas_credentials_badgeclass_id: event.target.value })}
                        />
                      </Stack>
                      <Paper variant="outlined" sx={{ p: 2 }}>
                        <Stack spacing={2}>
                          <Box>
                            <Typography variant="subtitle2">Managed API token secret</Typography>
                            <Typography variant="caption" color="text.secondary">
                              Save or rotate the Canvas Credentials token as an encrypted organization secret, then reference it from this binding.
                            </Typography>
                          </Box>
                          {canvasCredentialsSecretError && (
                            <Alert severity="error">
                              {canvasCredentialsSecretError.message || 'Failed to save managed secret.'}
                            </Alert>
                          )}
                          <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
                            <FormControl fullWidth>
                              <InputLabel>Managed secret</InputLabel>
                              <Select
                                label="Managed secret"
                                value={bindingForm.canvas_credentials_api_token_secret_id}
                                onChange={(event) => setBindingForm({
                                  ...bindingForm,
                                  canvas_credentials_api_token_secret_id: event.target.value,
                                })}
                              >
                                <MenuItem value="">None selected</MenuItem>
                                {integrationSecrets.map((secret) => (
                                  <MenuItem key={secret.id} value={secret.id}>
                                    {secret.name}{secret.secret_hint ? ` (${secret.secret_hint})` : ''}
                                  </MenuItem>
                                ))}
                                {selectedIntegrationSecretMissing && (
                                  <MenuItem value={bindingForm.canvas_credentials_api_token_secret_id}>
                                    Saved managed secret
                                  </MenuItem>
                                )}
                              </Select>
                            </FormControl>
                            <TextField
                              fullWidth
                              type="password"
                              label={bindingForm.canvas_credentials_api_token_secret_id ? 'Rotate token value' : 'New token value'}
                              value={canvasCredentialsSecretValue}
                              onChange={(event) => setCanvasCredentialsSecretValue(event.target.value)}
                              helperText="Token value is encrypted server-side and never stored in the binding."
                            />
                            <Button
                              variant="outlined"
                              startIcon={<SaveIcon />}
                              disabled={
                                canvasCredentialsSecretBusy
                                || !canvasCredentialsSecretValue.trim()
                                || (bindingForm.canvas_credentials_api_token_secret_id
                                  ? !canEditCanvas
                                  : !canCreateCanvas)
                              }
                              onClick={saveCanvasCredentialsManagedSecret}
                              sx={{ minWidth: 150 }}
                            >
                              Save secret
                            </Button>
                          </Stack>
                        </Stack>
                      </Paper>
                    </Stack>
                  </Paper>
                )}
                <TextField label="Approval PolicySet ID" value={bindingForm.approval_policy_set_id} onChange={(event) => setBindingForm({ ...bindingForm, approval_policy_set_id: event.target.value })} />
                <FormControlLabel
                  control={(
                    <Switch
                      checked={bindingForm.auto_approve_on_evidence}
                      disabled={!canEditCanvas || !editingBinding || !bindingCanvasEvidenceEnabled || bindingReadiness[editingBinding?.id]?.ready !== true}
                      onChange={(event) => setBindingForm({ ...bindingForm, auto_approve_on_evidence: event.target.checked })}
                    />
                  )}
                  label="Learner auto-approval (pilot gate)"
                />
                <Typography variant="caption" color="text.secondary">
                  New bindings are inactive and auto-approval remains off. Validate and activate the binding from the bindings table after shadow results and all blocking checks pass.
                </Typography>
              </Stack>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setBindingDialogOpen(false)}>Cancel</Button>
          <Button
            disabled={saving || bindingWizardStep === 0}
            onClick={() => setBindingWizardStep((step) => Math.max(0, step - 1))}
          >
            Back
          </Button>
          {bindingWizardLastStep ? (
            <Button
              startIcon={<SaveIcon />}
              variant="contained"
              disabled={bindingSaveDisabled}
              onClick={saveBinding}
            >
              Save
            </Button>
          ) : (
            <Button
              variant="contained"
              disabled={bindingWizardNextDisabled}
              onClick={() => setBindingWizardStep((step) => Math.min(BINDING_WIZARD_STEPS.length - 1, step + 1))}
            >
              Next
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </>
  );
}

export default CanvasIntegrationsPage;
