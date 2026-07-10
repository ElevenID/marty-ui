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
import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import {
  createCanvasPlatform,
  createCanvasIntegrationSecret,
  createCanvasProgramBinding,
  deleteCanvasPlatform,
  deleteCanvasProgramBinding,
  discoverCanvasScope,
  getCanvasMirrorHealth,
  listCanvasIntegrationSecrets,
  listCanvasPlatforms,
  listCanvasProgramBindings,
  processCanvasMirrorStatusSyncFailures,
  processPendingCanvasMirrorDeliveries,
  runCanvasMirrorAutomationCycle,
  updateCanvasIntegrationSecret,
  updateCanvasPlatform,
  updateCanvasProgramBinding,
  validateCanvasCredentialsProvider,
} from '../../../services/canvasIntegrationsApi';
import { listApplicationTemplates } from '../../../services/applicationTemplatesApi';
import { listCredentialTemplates } from '../../../services/presentationPolicyApi';
import { listDeploymentProfiles } from '../../../services/deploymentProfilesApi';
import { listDeliveryDestinations } from '../../../services/deliveryDestinationsApi';
import CanvasMirrorProvenanceLookup from '../../canvas/CanvasMirrorProvenanceLookup';
import { ResourcePage, EmptyState, StatusChip } from '../../common';

const EVIDENCE_TYPES = [
  { value: 'canvas.course_completion', label: 'Course completion' },
  { value: 'canvas.assignment_completion', label: 'Assignment completion' },
  { value: 'canvas.assignment_score', label: 'Assignment score' },
  { value: 'canvas.quiz_completion', label: 'Quiz completion' },
  { value: 'canvas.quiz_score', label: 'Quiz score' },
  { value: 'canvas.module_completion', label: 'Module completion' },
  { value: 'canvas.manual_instructor_approval', label: 'Instructor approval' },
];

const DEPLOY_TABS = [
  { label: 'Issuance Flows', path: '/console/org/flows/definitions' },
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
  return {
    display_name: platform.display_name || '',
    canvas_account_id: platform.canvas_account_id || '',
    canvas_base_url: platform.canvas_base_url || '',
    lti_client_id: platform.lti_client_id || '',
    lti_deployment_id: platform.lti_deployment_id || '',
    lti_issuer: platform.lti_issuer || '',
    lti_jwks_url: platform.lti_jwks_url || '',
    enabled: platform.enabled !== false,
  };
}

function firstRequirement(binding = {}) {
  return Array.isArray(binding.evidence_requirements) && binding.evidence_requirements.length > 0
    ? binding.evidence_requirements[0]
    : {};
}

function bindingFormFrom(binding = {}, platformId = '') {
  const requirement = firstRequirement(binding);
  const scope = binding.canvas_scope || requirement.scope || requirement.canvas_scope || {};
  const passRule = requirement.pass_rule || {};
  const canvasCredentials = binding.canvas_credentials || {};
  return {
    platform_id: binding.platform_id || platformId,
    deployment_profile_id: binding.deployment_profile_id || '',
    feature_flags: normalizeCanvasFeatureFlags(binding.feature_flags || {}),
    application_template_id: binding.application_template_id || '',
    credential_template_id: binding.credential_template_id || '',
    display_name: binding.display_name || '',
    evidence_type: requirement.fact_type || requirement.evidence_type || 'canvas.course_completion',
    course_id: scope.course_id || '',
    assignment_id: scope.assignment_id || '',
    module_id: scope.module_id || '',
    quiz_id: scope.quiz_id || '',
    min_score_percent: passRule.min_score_percent || passRule.score_percent || '',
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
    canvas_credentials_api_token_env: canvasCredentials.api_token_env || '',
    canvas_credentials_api_token_file: canvasCredentials.api_token_file || '',
    canvas_admin_api_token_env: '',
    canvas_admin_api_token_file: '',
    enabled: binding.enabled !== false,
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

function buildCanvasScope(form) {
  return Object.fromEntries(
    [
      ['course_id', form.course_id],
      ['assignment_id', form.assignment_id],
      ['module_id', form.module_id],
      ['quiz_id', form.quiz_id],
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
      ['api_token_env', form.canvas_credentials_api_token_env],
      ['api_token_file', form.canvas_credentials_api_token_file],
    ].filter(([, value]) => String(value || '').trim())
  );
}

function buildEvidenceRequirement(form) {
  const scope = buildCanvasScope(form);
  const passRule = {};
  if (form.evidence_type.endsWith('_completion') || form.evidence_type.endsWith('_approval')) {
    passRule.completed = true;
  }
  if (form.evidence_type.endsWith('_score') && form.min_score_percent !== '') {
    passRule.min_score_percent = Number(form.min_score_percent);
  }
  return {
    provider: 'canvas',
    fact_type: form.evidence_type,
    scope,
    pass_rule: passRule,
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
  const { organizationId: authOrganizationId } = useAuth();
  const { activeOrgId } = useConsole();
  const organizationId = activeOrgId || authOrganizationId;
  const [selectedPlatformId, setSelectedPlatformId] = useState('');
  const [platformDialogOpen, setPlatformDialogOpen] = useState(false);
  const [bindingDialogOpen, setBindingDialogOpen] = useState(false);
  const [editingPlatform, setEditingPlatform] = useState(null);
  const [editingBinding, setEditingBinding] = useState(null);
  const [platformForm, setPlatformForm] = useState(platformFormFrom());
  const [bindingForm, setBindingForm] = useState(bindingFormFrom());
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

  const {
    data: platformsData,
    loading: platformsLoading,
    error: platformsError,
    reload: reloadPlatforms,
  } = useAsyncData(async () => {
    return listCanvasPlatforms(organizationId);
  }, [organizationId]);

  const {
    data: bindingsData,
    loading: bindingsLoading,
    error: bindingsError,
    reload: reloadBindings,
  } = useAsyncData(async () => {
    return listCanvasProgramBindings({ organizationId });
  }, [organizationId]);

  const { data: applicationTemplatesData } = useAsyncData(async () => {
    return listApplicationTemplates(organizationId);
  }, [organizationId]);

  const { data: credentialTemplatesData } = useAsyncData(async () => {
    return normalizeCredentialTemplates(await listCredentialTemplates({ organization_id: organizationId }));
  }, [organizationId]);

  const { data: deploymentProfilesData } = useAsyncData(async () => {
    const profiles = await listDeploymentProfiles({ organization_id: organizationId });
    return Array.isArray(profiles) ? profiles : [];
  }, [organizationId]);

  const {
    data: mirrorHealth = null,
    loading: mirrorHealthLoading,
    error: mirrorHealthError,
    reload: reloadMirrorHealth,
  } = useAsyncData(async () => {
    return getCanvasMirrorHealth(organizationId);
  }, [organizationId]);

  const {
    data: deliveryDestinationsData,
    loading: deliveryDestinationsLoading,
    error: deliveryDestinationsError,
    reload: reloadDeliveryDestinations,
  } = useAsyncData(async () => {
    return listDeliveryDestinations({
      organizationId,
      provider: 'canvas_credentials',
      activeOnly: false,
    });
  }, [organizationId]);

  const {
    data: integrationSecretsData,
    reload: reloadIntegrationSecrets,
  } = useAsyncData(async () => {
    return listCanvasIntegrationSecrets({
      organizationId,
      provider: 'canvas_credentials',
    });
  }, [organizationId]);

  const platforms = Array.isArray(platformsData) ? platformsData : [];
  const bindings = Array.isArray(bindingsData) ? bindingsData : [];
  const applicationTemplates = Array.isArray(applicationTemplatesData) ? applicationTemplatesData : [];
  const credentialTemplates = Array.isArray(credentialTemplatesData) ? credentialTemplatesData : [];
  const deploymentProfiles = Array.isArray(deploymentProfilesData) ? deploymentProfilesData : [];
  const deliveryDestinations = Array.isArray(deliveryDestinationsData) ? deliveryDestinationsData : [];
  const integrationSecrets = Array.isArray(integrationSecretsData) ? integrationSecretsData : [];
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
    await Promise.all([
      reloadPlatforms(),
      reloadBindings(),
      reloadMirrorHealth(),
      reloadDeliveryDestinations(),
      reloadIntegrationSecrets(),
    ]);
  };

  const openCreatePlatform = () => {
    setEditingPlatform(null);
    setPlatformForm(platformFormFrom());
    setSaveError(null);
    setPlatformDialogOpen(true);
  };

  const openEditPlatform = (platform) => {
    setEditingPlatform(platform);
    setPlatformForm(platformFormFrom(platform));
    setSaveError(null);
    setPlatformDialogOpen(true);
  };

  const openCreateBinding = () => {
    setEditingBinding(null);
    setBindingForm(bindingFormFrom({}, selectedPlatformId));
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
    setEditingBinding(binding);
    setBindingForm(bindingFormFrom(binding, binding.platform_id));
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
    if (!organizationId) return;
    setSaving(true);
    setSaveError(null);
    const payload = {
      organization_id: organizationId,
      ...platformForm,
    };
    try {
      const saved = editingPlatform
        ? await updateCanvasPlatform(editingPlatform.id, payload)
        : await createCanvasPlatform(payload);
      setSelectedPlatformId(saved.id);
      setPlatformDialogOpen(false);
      await reloadPlatforms();
    } catch (error) {
      setSaveError(error);
    } finally {
      setSaving(false);
    }
  };

  const saveBinding = async () => {
    const platformId = bindingForm.platform_id || selectedPlatformId;
    if (!platformId) return;
    setSaving(true);
    setSaveError(null);
    const payload = {
      application_template_id: bindingForm.application_template_id,
      credential_template_id: bindingForm.credential_template_id || null,
      display_name: bindingForm.display_name || null,
      flow_mode: 'elevenid_orchestrated_canvas_evidence',
      direct_issue_enabled: bindingForm.direct_issue_enabled,
      auto_approve_on_evidence: bindingForm.auto_approve_on_evidence,
      evidence_requirements: [buildEvidenceRequirement(bindingForm)],
      canvas_scope: buildCanvasScope(bindingForm),
      delivery_mode: bindingForm.delivery_mode,
      issuer_mode: bindingForm.issuer_mode,
      approval_policy_set_id: bindingForm.approval_policy_set_id || null,
      deployment_profile_id: bindingForm.deployment_profile_id || null,
      feature_flags: bindingForm.deployment_profile_id
        ? normalizeCanvasFeatureFlags(bindingForm.feature_flags)
        : {},
      canvas_credentials: buildCanvasCredentialsConfig(bindingForm),
      enabled: bindingForm.enabled,
    };
    try {
      const saved = editingBinding
        ? await updateCanvasProgramBinding(editingBinding.id, payload)
        : await createCanvasProgramBinding(platformId, payload);
      setSelectedPlatformId(saved.platform_id);
      setBindingDialogOpen(false);
      await reloadBindings();
    } catch (error) {
      setSaveError(error);
    } finally {
      setSaving(false);
    }
  };

  const validateCanvasCredentialsSettings = async () => {
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
    if (!organizationId || !canvasCredentialsSecretValue.trim()) return;
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
        canvas_credentials_api_token_env: '',
        canvas_credentials_api_token_file: '',
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
    if (!platformId) return;
    setCanvasScopeDiscoveryBusy(true);
    setCanvasScopeDiscoveryError(null);
    try {
      const result = await discoverCanvasScope(platformId, {
        courseId: bindingForm.course_id,
        apiTokenEnv: bindingForm.canvas_admin_api_token_env,
        apiTokenFile: bindingForm.canvas_admin_api_token_file,
      });
      setCanvasScopeDiscovery(result);
    } catch (error) {
      setCanvasScopeDiscoveryError(error);
    } finally {
      setCanvasScopeDiscoveryBusy(false);
    }
  };

  const removePlatform = async (platform) => {
    if (!window.confirm(`Delete ${platform.display_name || platform.canvas_account_id}?`)) return;
    await deleteCanvasPlatform(platform.id);
    await refreshAll();
  };

  const removeBinding = async (binding) => {
    if (!window.confirm(`Delete ${binding.display_name || binding.application_template_id}?`)) return;
    await deleteCanvasProgramBinding(binding.id);
    await reloadBindings();
  };

  const runMirrorOps = async (action) => {
    if (!organizationId) return;
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
  const opsDisabled = !organizationId || Boolean(opsBusy);
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
    || (bindingWizardStep === 0 && (
      !(bindingForm.platform_id || selectedPlatformId)
      || !bindingForm.application_template_id
      || !bindingCanvasEvidenceEnabled
    ))
    || (bindingWizardStep === 1 && !bindingForm.evidence_type)
  );
  const bindingSaveDisabled = (
    saving
    || !bindingForm.platform_id
    || !bindingForm.application_template_id
    || !bindingCanvasEvidenceEnabled
    || (bindingForm.delivery_mode === 'wallet_plus_canvas_mirror' && !bindingCanvasMirrorPublishEnabled)
  );

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
      >
        {error && (
          <Alert severity="error" sx={{ mb: 3 }}>
            {error?.message || String(error)}
          </Alert>
        )}

        {loading && <LinearProgress sx={{ mb: 2 }} />}

        <Stack spacing={3}>
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
                      <StatusChip status={platform.enabled ? 'active' : 'disabled'} />
                    </TableCell>
                    <TableCell align="right" onClick={(event) => event.stopPropagation()}>
                      <Tooltip title="Edit">
                        <IconButton size="small" onClick={() => openEditPlatform(platform)}>
                          <EditIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Delete">
                        <IconButton size="small" onClick={() => removePlatform(platform)}>
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>

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
                          <Typography variant="caption" color="text.secondary">
                            {Object.entries(binding.canvas_scope || {}).map(([key, value]) => `${key}: ${value}`).join(', ') || 'Any scope'}
                          </Typography>
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
                        <StatusChip status={binding.enabled ? 'active' : 'disabled'} />
                      </TableCell>
                      <TableCell align="right">
                        <Tooltip title="Edit">
                          <IconButton
                            size="small"
                            aria-label={`Edit ${binding.display_name || binding.canvas_scope?.course_id || binding.id}`}
                            onClick={() => openEditBinding(binding)}
                          >
                            <EditIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Delete">
                          <IconButton
                            size="small"
                            aria-label={`Delete ${binding.display_name || binding.canvas_scope?.course_id || binding.id}`}
                            onClick={() => removeBinding(binding)}
                          >
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
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
            <TextField label="Display name" value={platformForm.display_name} onChange={(event) => setPlatformForm({ ...platformForm, display_name: event.target.value })} />
            <TextField label="Canvas account ID" required value={platformForm.canvas_account_id} onChange={(event) => setPlatformForm({ ...platformForm, canvas_account_id: event.target.value })} />
            <TextField label="Canvas base URL" value={platformForm.canvas_base_url} onChange={(event) => setPlatformForm({ ...platformForm, canvas_base_url: event.target.value })} />
            <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
              <TextField fullWidth label="LTI client ID" value={platformForm.lti_client_id} onChange={(event) => setPlatformForm({ ...platformForm, lti_client_id: event.target.value })} />
              <TextField fullWidth label="LTI deployment ID" value={platformForm.lti_deployment_id} onChange={(event) => setPlatformForm({ ...platformForm, lti_deployment_id: event.target.value })} />
            </Stack>
            <TextField label="LTI issuer" value={platformForm.lti_issuer} onChange={(event) => setPlatformForm({ ...platformForm, lti_issuer: event.target.value })} />
            <TextField label="JWKS URL" value={platformForm.lti_jwks_url} onChange={(event) => setPlatformForm({ ...platformForm, lti_jwks_url: event.target.value })} />
            <FormControlLabel
              control={<Switch checked={platformForm.enabled} onChange={(event) => setPlatformForm({ ...platformForm, enabled: event.target.checked })} />}
              label="Enabled"
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setPlatformDialogOpen(false)}>Cancel</Button>
          <Button startIcon={<SaveIcon />} variant="contained" disabled={saving || !platformForm.canvas_account_id} onClick={savePlatform}>
            Save
          </Button>
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
                    onChange={(event) => setBindingForm({ ...bindingForm, credential_template_id: event.target.value })}
                  >
                    {credentialTemplates.map((template) => (
                      <MenuItem key={template.id} value={template.id}>
                        {template.name || template.id}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Stack>
            )}
            {bindingWizardStep === 1 && (
              <Stack spacing={2}>
                <Alert severity="info">
                  Use Canvas IDs from the institution admin/API setup for the course, assignment, module, or quiz this credential should follow. Leave activity IDs blank only when the binding should match any Canvas launch for this platform.
                </Alert>
                <Paper variant="outlined" sx={{ p: 2 }}>
                  <Stack spacing={2}>
                    <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} justifyContent="space-between" alignItems={{ xs: 'stretch', md: 'center' }}>
                      <Box>
                        <Typography variant="subtitle2">Import Canvas activity</Typography>
                        <Typography variant="caption" color="text.secondary">
                          Use an admin API token reference to discover real Canvas courses, assignments, quizzes, and modules.
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
                    <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
                      <TextField
                        fullWidth
                        label="Canvas API token env var"
                        value={bindingForm.canvas_admin_api_token_env}
                        onChange={(event) => setBindingForm({ ...bindingForm, canvas_admin_api_token_env: event.target.value })}
                        helperText="Example: CANVAS_ADMIN_API_TOKEN"
                      />
                      <TextField
                        fullWidth
                        label="Canvas API token file"
                        value={bindingForm.canvas_admin_api_token_file}
                        onChange={(event) => setBindingForm({ ...bindingForm, canvas_admin_api_token_file: event.target.value })}
                        helperText="Example: /run/secrets/canvas_admin_api_token"
                      />
                    </Stack>
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
                              <InputLabel>Imported quiz</InputLabel>
                              <Select
                                label="Imported quiz"
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
                  <InputLabel>Canvas activity</InputLabel>
                  <Select
                    label="Canvas activity"
                    value={bindingForm.evidence_type}
                    onChange={(event) => setBindingForm({ ...bindingForm, evidence_type: event.target.value })}
                  >
                    {EVIDENCE_TYPES.map((type) => (
                      <MenuItem key={type.value} value={type.value}>{type.label}</MenuItem>
                    ))}
                  </Select>
                </FormControl>
                <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
                  <TextField fullWidth label="Course ID" value={bindingForm.course_id} onChange={(event) => setBindingForm({ ...bindingForm, course_id: event.target.value })} />
                  <TextField fullWidth label="Assignment ID" value={bindingForm.assignment_id} onChange={(event) => setBindingForm({ ...bindingForm, assignment_id: event.target.value })} />
                </Stack>
                <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
                  <TextField fullWidth label="Module ID" value={bindingForm.module_id} onChange={(event) => setBindingForm({ ...bindingForm, module_id: event.target.value })} />
                  <TextField fullWidth label="Quiz ID" value={bindingForm.quiz_id} onChange={(event) => setBindingForm({ ...bindingForm, quiz_id: event.target.value })} />
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
                <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
                  <FormControl fullWidth>
                    <InputLabel>Delivery</InputLabel>
                    <Select
                      label="Delivery"
                      value={bindingForm.delivery_mode}
                      onChange={(event) => setBindingForm({ ...bindingForm, delivery_mode: event.target.value })}
                    >
                      <MenuItem value="wallet_only">Wallet only</MenuItem>
                      <MenuItem value="wallet_plus_canvas_mirror" disabled={!bindingCanvasMirrorPublishEnabled}>Wallet + Canvas mirror</MenuItem>
                    </Select>
                  </FormControl>
                  <FormControl fullWidth>
                    <InputLabel>Issuer mode</InputLabel>
                    <Select
                      label="Issuer mode"
                      value={bindingForm.issuer_mode}
                      onChange={(event) => setBindingForm({ ...bindingForm, issuer_mode: event.target.value })}
                    >
                      <MenuItem value="org_managed">Org managed</MenuItem>
                      <MenuItem value="canvas_alias">Canvas alias</MenuItem>
                    </Select>
                  </FormControl>
                </Stack>
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
                          disabled={canvasCredentialsValidationBusy}
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
                            <MenuItem value="bridge">Bridge endpoint</MenuItem>
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
                                  canvas_credentials_api_token_env: event.target.value ? '' : bindingForm.canvas_credentials_api_token_env,
                                  canvas_credentials_api_token_file: event.target.value ? '' : bindingForm.canvas_credentials_api_token_file,
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
                              disabled={canvasCredentialsSecretBusy || !canvasCredentialsSecretValue.trim()}
                              onClick={saveCanvasCredentialsManagedSecret}
                              sx={{ minWidth: 150 }}
                            >
                              Save secret
                            </Button>
                          </Stack>
                        </Stack>
                      </Paper>
                      <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
                        <TextField
                          fullWidth
                          label="API token secret env"
                          value={bindingForm.canvas_credentials_api_token_env}
                          disabled={Boolean(bindingForm.canvas_credentials_api_token_secret_id)}
                          onChange={(event) => setBindingForm({ ...bindingForm, canvas_credentials_api_token_env: event.target.value })}
                          helperText="Deployment-managed secret name, not the token value."
                        />
                        <TextField
                          fullWidth
                          label="API token secret file"
                          value={bindingForm.canvas_credentials_api_token_file}
                          disabled={Boolean(bindingForm.canvas_credentials_api_token_secret_id)}
                          onChange={(event) => setBindingForm({ ...bindingForm, canvas_credentials_api_token_file: event.target.value })}
                          helperText="Mounted secret file path available to issuance."
                        />
                      </Stack>
                    </Stack>
                  </Paper>
                )}
                <TextField label="Approval PolicySet ID" value={bindingForm.approval_policy_set_id} onChange={(event) => setBindingForm({ ...bindingForm, approval_policy_set_id: event.target.value })} />
                <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
                  <FormControlLabel
                    control={<Switch checked={bindingForm.auto_approve_on_evidence} disabled={!bindingCanvasEvidenceEnabled} onChange={(event) => setBindingForm({ ...bindingForm, auto_approve_on_evidence: event.target.checked })} />}
                    label="Auto approve"
                  />
                  <FormControlLabel
                    control={<Switch checked={bindingForm.direct_issue_enabled} onChange={(event) => setBindingForm({ ...bindingForm, direct_issue_enabled: event.target.checked })} />}
                    label="Direct issue"
                  />
                  <FormControlLabel
                    control={<Switch checked={bindingForm.enabled} onChange={(event) => setBindingForm({ ...bindingForm, enabled: event.target.checked })} />}
                    label="Enabled"
                  />
                </Stack>
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
