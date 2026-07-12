/**
 * Dashboard Readiness & Blocking Rules
 * 
 * Defines the exact rules for:
 * - Setup readiness (Trust → Template → Policy → Deployment → Flow)
 * - Blocking issues detection
 * - Quick action visibility
 */

/**
 * Setup order: Trust → Template → Policy → Deployment → Flow
 */
export const SETUP_ORDER = [
  'compliance',
  'trust',
  'template',
  'policy',
  'deployment',
  'flow',
];

export const SETUP_INTENTS = {
  VERIFY: 'verify',
  ISSUE: 'issue',
  APPLICATION: 'application',
  PHYSICAL: 'physical',
  LIFECYCLE: 'lifecycle',
};

export const SETUP_INTENT_LABELS = {
  [SETUP_INTENTS.VERIFY]: 'Verify credentials',
  [SETUP_INTENTS.ISSUE]: 'Issue credentials',
  [SETUP_INTENTS.APPLICATION]: 'Application approval then issue',
  [SETUP_INTENTS.PHYSICAL]: 'Issue a physical document',
  [SETUP_INTENTS.LIFECYCLE]: 'Revoke or renew credentials',
};

export const INTENT_SETUP_ORDER = {
  [SETUP_INTENTS.VERIFY]: ['compliance', 'trust', 'policy', 'flow'],
  [SETUP_INTENTS.ISSUE]: ['compliance', 'issuer', 'trust', 'template', 'flow'],
  [SETUP_INTENTS.APPLICATION]: ['compliance', 'applicationTemplate', 'policySet', 'flow'],
  [SETUP_INTENTS.PHYSICAL]: ['compliance', 'physicalCapability', 'issuer', 'trust', 'template', 'applicationTemplate', 'deliveryDestination', 'flow'],
  [SETUP_INTENTS.LIFECYCLE]: ['template', 'revocation', 'flow'],
};

/**
 * Readiness states
 */
export const ReadinessState = {
  READY: 'ready',       // ✔ Complete and valid
  BLOCKED: 'blocked',   // ⚠ Exists but has issues
  MISSING: 'missing',   // ○ Does not exist
};

const TRUST_KEY_MANAGEMENT_PATH = '/console/org/deploy/key-management';
const TRUST_ISSUER_IDENTITY_PATH = '/console/org/deploy/issuer-identity';
const COMPLIANCE_PROFILES_PATH = '/console/org/policies/compliance';
const APPLICATION_TEMPLATES_PATH = '/console/org/templates/applications';
const REVOCATION_PROFILES_PATH = '/console/org/trust/revocation';
const POLICY_SETS_PATH = '/console/org/policies/sets';
const DELIVERY_DESTINATIONS_PATH = '/console/org/connect/delivery-destinations';

const ISSUANCE_FLOW_TYPES = new Set([
  'oid4vci_pre_authorized',
  'oid4vci_authorization_code',
  'mdl_issuance',
  'credential_renewal',
  'credential_revocation',
]);
const VERIFICATION_FLOW_TYPES = new Set(['oid4vp_presentation', 'mdl_presentation', 'siopv2']);
const APPLICATION_FLOW_TYPES = new Set(['application_approval_issuance']);
const PHYSICAL_FLOW_TYPES = new Set(['physical_document_issuance']);
const LIFECYCLE_FLOW_TYPES = new Set(['credential_renewal', 'credential_revocation']);

function getMessageId(error) {
  return error?.message_id || error?.messageId || error?.data?.message_id || error?.response?.data?.message_id || null;
}

function buildLoadErrorReadiness(label, error) {
  const messageId = getMessageId(error);
  const suffix = messageId ? ` Message ID: ${messageId}` : '';
  return {
    state: ReadinessState.BLOCKED,
    message: `${label} could not be loaded.${suffix}`,
    action: null,
    path: null,
    blockReason: `${label} is unavailable, so setup readiness cannot be trusted.${suffix}`,
    serviceError: true,
  };
}

function firstResourceError(resourceErrors, keys) {
  if (!resourceErrors) {
    return null;
  }
  for (const key of keys) {
    if (resourceErrors[key]) {
      return { key, error: resourceErrors[key] };
    }
  }
  return null;
}

function getDefaultKeyManagementService(config) {
  const services = Array.isArray(config?.services)
    ? config.services.filter((service) => service && typeof service === 'object')
    : [];

  if (services.length === 0) {
    return null;
  }

  if (typeof config?.default_service_id === 'string') {
    return services.find((service) => service.id === config.default_service_id) || null;
  }

  return services[0] || null;
}

function hasManagedIssuerInput(signingKeys, issuerProfiles) {
  const safeSigningKeys = Array.isArray(signingKeys) ? signingKeys : [];
  const safeIssuerProfiles = Array.isArray(issuerProfiles) ? issuerProfiles : [];
  return safeSigningKeys.length > 0 || safeIssuerProfiles.length > 0;
}

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function isActiveStatus(resource) {
  return String(resource?.status || resource?.state || '').trim().toLowerCase() === 'active'
    || resource?.is_active === true
    || resource?.enabled === true;
}

function isVerificationFlow(flow) {
  return VERIFICATION_FLOW_TYPES.has(String(flow?.flow_type || '').trim())
    || Boolean(flow?.presentation_policy_id);
}

function isIssuanceFlow(flow) {
  return ISSUANCE_FLOW_TYPES.has(String(flow?.flow_type || '').trim())
    || Boolean(flow?.credential_template_id);
}

function isApplicationFlow(flow) {
  return APPLICATION_FLOW_TYPES.has(String(flow?.flow_type || '').trim());
}

function isPhysicalFlow(flow) {
  return PHYSICAL_FLOW_TYPES.has(String(flow?.flow_type || '').trim());
}

function isLifecycleFlow(flow) {
  return LIFECYCLE_FLOW_TYPES.has(String(flow?.flow_type || '').trim());
}

function inferSetupIntent(data) {
  if (Object.values(SETUP_INTENTS).includes(data?.setupIntent)) {
    return data.setupIntent;
  }

  const flows = safeArray(data?.flows);
  if (flows.some(isPhysicalFlow)) {
    return SETUP_INTENTS.PHYSICAL;
  }
  if (flows.some(isVerificationFlow) || safeArray(data?.policies).length > 0) {
    return SETUP_INTENTS.VERIFY;
  }
  if (flows.some(isApplicationFlow) || safeArray(data?.applicationTemplates).length > 0) {
    return SETUP_INTENTS.APPLICATION;
  }
  if (flows.some(isLifecycleFlow) || safeArray(data?.revocationProfiles).length > 0) {
    return SETUP_INTENTS.LIFECYCLE;
  }
  if (flows.some(isIssuanceFlow) || safeArray(data?.templates).length > 0) {
    return SETUP_INTENTS.ISSUE;
  }

  return SETUP_INTENTS.VERIFY;
}

function hasActiveKmsBackedIssuerProfile(template, issuerProfiles) {
  const issuerProfileId = String(template?.issuer_profile_id || '').trim();
  if (!issuerProfileId) {
    return false;
  }

  const keyAccessMode = String(template?.key_access_mode || '').trim().toUpperCase();
  if (keyAccessMode && keyAccessMode !== 'REMOTE_SIGNING') {
    return false;
  }

  if (!Array.isArray(issuerProfiles)) {
    return false;
  }

  return issuerProfiles.some((profile) => (
    String(profile?.id || '').trim() === issuerProfileId
    && String(profile?.status || '').trim().toLowerCase() === 'active'
    && String(profile?.issuer_did || profile?.did || '').trim().startsWith('did:')
    && String(profile?.signing_service_id || profile?.service_id || profile?.metadata?.signing_service_id || '').trim()
  ));
}

function isActiveComplianceProfile(profile) {
  if (typeof profile === 'string') {
    return profile.trim().length > 0;
  }

  if (!profile || typeof profile !== 'object') {
    return false;
  }

  const status = String(profile.status || profile.lifecycle_status || '').trim().toLowerCase();
  return !status || status === 'active';
}

/**
 * Compute Compliance Profile readiness
 */
function evaluateComplianceReadiness(lifecycle, dashboardErrors = {}) {
  if (dashboardErrors?.lifecycle) {
    return buildLoadErrorReadiness('Compliance profiles', dashboardErrors.lifecycle);
  }

  if (!lifecycle || !Object.prototype.hasOwnProperty.call(lifecycle, 'complianceProfiles')) {
    return {
      state: ReadinessState.READY,
      message: 'Compliance profile status not reported',
      action: null,
      path: null,
      blockReason: null,
    };
  }

  const safeProfiles = Array.isArray(lifecycle.complianceProfiles) ? lifecycle.complianceProfiles : [];
  const activeProfiles = safeProfiles.filter(isActiveComplianceProfile);

  if (activeProfiles.length === 0) {
    return {
      state: ReadinessState.BLOCKED,
      message: 'No active Compliance Profiles',
      action: 'Review',
      path: COMPLIANCE_PROFILES_PATH,
      blockReason: 'Activate a Compliance Profile before creating production credential templates or flows',
    };
  }

  return {
    state: ReadinessState.READY,
    message: `${activeProfiles.length} active Compliance Profile(s)`,
    action: null,
    path: null,
    blockReason: null,
  };
}

function evaluateIssuerReadiness(dependencies = {}) {
  const { signingKeys = [], issuerProfiles = [], keyManagementConfig = null, resourceErrors = {} } = dependencies || {};
  const loadError = firstResourceError(resourceErrors, [
    'keyManagementConfig',
    'signingKeys',
    'issuerProfiles',
  ]);

  if (loadError) {
    const labels = {
      keyManagementConfig: 'Key management configuration',
      signingKeys: 'Signing keys',
      issuerProfiles: 'Issuer profiles',
    };
    return buildLoadErrorReadiness(labels[loadError.key] || 'Issuer identity', loadError.error);
  }

  if (!getDefaultKeyManagementService(keyManagementConfig)) {
    return {
      state: ReadinessState.BLOCKED,
      message: 'Blocked: configure key management before production issuance',
      action: 'Configure KMS',
      path: TRUST_KEY_MANAGEMENT_PATH,
      blockReason: 'Production issuance requires a configured key management service',
    };
  }

  if (!hasManagedIssuerInput(signingKeys, issuerProfiles)) {
    return {
      state: ReadinessState.BLOCKED,
      message: 'Blocked: add an issuer identity or signing key before production issuance',
      action: 'Set Up Issuer Identity',
      path: TRUST_ISSUER_IDENTITY_PATH,
      blockReason: 'Production issuance requires an issuer identity or available signing key',
    };
  }

  return {
    state: ReadinessState.READY,
    message: 'Issuer identity and signing input ready',
    action: null,
    path: null,
    blockReason: null,
  };
}

/**
 * Compute Trust Profile readiness
 */
function evaluateTrustReadiness(trustProfiles, dependencies = {}) {
  const safeTrustProfiles = Array.isArray(trustProfiles) ? trustProfiles : [];
  const {
    signingKeys = [],
    issuerProfiles = [],
    keyManagementConfig = null,
    resourceErrors = {},
    requiresIssuerIdentity = true,
  } = dependencies || {};
  const loadError = firstResourceError(resourceErrors, [
    'trustProfiles',
    'keyManagementConfig',
    'signingKeys',
    'issuerProfiles',
  ]);

  if (loadError) {
    const labels = {
      trustProfiles: 'Trust profiles',
      keyManagementConfig: 'Key management configuration',
      signingKeys: 'Signing keys',
      issuerProfiles: 'Issuer profiles',
    };
    return buildLoadErrorReadiness(labels[loadError.key] || 'Setup data', loadError.error);
  }

  if (safeTrustProfiles.length === 0) {
    if (requiresIssuerIdentity && !getDefaultKeyManagementService(keyManagementConfig)) {
      return {
        state: ReadinessState.BLOCKED,
        message: 'Blocked: configure key management before creating Trust Profiles',
        action: 'Configure KMS',
        path: TRUST_KEY_MANAGEMENT_PATH,
        blockReason: 'Trust Profile setup requires a configured key management service',
      };
    }

    if (requiresIssuerIdentity && !hasManagedIssuerInput(signingKeys, issuerProfiles)) {
      return {
        state: ReadinessState.BLOCKED,
        message: 'Blocked: add an issuer identity or signing key before creating Trust Profiles',
        action: 'Set Up Issuer Identity',
        path: TRUST_ISSUER_IDENTITY_PATH,
        blockReason: 'Trust Profile setup requires an issuer identity or available signing key',
      };
    }

    return {
      state: ReadinessState.MISSING,
      message: 'No Trust Profiles configured',
      action: 'Create',
      path: '/console/org/trust/profiles/new',
      blockReason: null,
    };
  }

  const activeTrusts = safeTrustProfiles.filter((t) => t.status === 'active');
  if (activeTrusts.length === 0) {
    return {
      state: ReadinessState.BLOCKED,
      message: `${safeTrustProfiles.length} Trust Profile(s) configured but none active`,
      action: 'Activate',
      path: '/console/org/trust/profiles',
      blockReason: 'Trust Profile exists but status is not active',
    };
  }

  return {
    state: ReadinessState.READY,
    message: `${activeTrusts.length} active Trust Profile(s)`,
    action: null,
    path: null,
    blockReason: null,
  };
}

/**
 * Compute Credential Template readiness
 */
function evaluateTemplateReadiness(templates, trustProfiles, trustDependencies = {}) {
  const trustReady = evaluateTrustReadiness(trustProfiles, trustDependencies);
  if (trustReady.state !== ReadinessState.READY) {
    // Template depends on Trust
    return {
      state: ReadinessState.MISSING,
      message: 'Blocked: no active Trust Profile',
      action: null,
      path: null,
      blockReason: null,
      dependencyBlocked: true,
    };
  }

  const loadError = firstResourceError(trustDependencies.resourceErrors, ['templates']);
  if (loadError) {
    return buildLoadErrorReadiness('Credential templates', loadError.error);
  }

  if (templates.length === 0) {
    return {
      state: ReadinessState.MISSING,
      message: 'No Credential Templates configured',
      action: 'Create',
      path: '/console/org/templates/credentials/new',
      blockReason: null,
    };
  }

  // Check for artifacts issues
  const issuerProfiles = trustDependencies.issuerProfiles;
  const blocked = templates.filter((t) => 
    t.status !== 'active' || 
    t.artifacts_status === 'missing' || 
    t.artifacts_status === 'invalid' ||
    !t.trust_profile_id ||
    !hasActiveKmsBackedIssuerProfile(t, issuerProfiles)
  );

  if (blocked.length > 0) {
    const reasons = [];
    if (blocked.some((t) => t.artifacts_status === 'missing' || t.artifacts_status === 'invalid')) {
      reasons.push('missing signing artifacts');
    }
    if (blocked.some((t) => !t.trust_profile_id)) {
      reasons.push('missing trust profile');
    }
    if (blocked.some((t) => !hasActiveKmsBackedIssuerProfile(t, issuerProfiles))) {
      reasons.push('missing active KMS-backed issuer profile');
    }
    if (blocked.some((t) => t.status !== 'active')) {
      reasons.push('inactive status');
    }

    return {
      state: ReadinessState.BLOCKED,
      message: `${blocked.length} of ${templates.length} template(s) with issues: ${reasons.join(', ')}`,
      action: 'Fix',
      path: '/console/org/templates/credentials',
      blockReason: `Credential Template(s) have issues: ${reasons.join(', ')}`,
    };
  }

  const activeTemplates = templates.filter((t) => t.status === 'active');
  return {
    state: ReadinessState.READY,
    message: `${activeTemplates.length} active template(s)`,
    action: null,
    path: null,
    blockReason: null,
  };
}

/**
 * Compute Presentation Policy readiness
 */
function evaluatePolicyReadiness(policies, templates, trustProfiles, trustDependencies = {}) {
  const templateReady = evaluateTemplateReadiness(templates, trustProfiles, trustDependencies);
  if (templateReady.state !== ReadinessState.READY) {
    return {
      state: ReadinessState.MISSING,
      message: 'Blocked: no active Credential Template',
      action: null,
      path: null,
      blockReason: null,
      dependencyBlocked: true,
    };
  }

  const loadError = firstResourceError(trustDependencies.resourceErrors, ['policies']);
  if (loadError) {
    return buildLoadErrorReadiness('Presentation policies', loadError.error);
  }

  if (policies.length === 0) {
    return {
      state: ReadinessState.MISSING,
      message: 'No Presentation Policies configured',
      action: 'Create',
      path: '/console/org/policies/presentation/new',
      blockReason: null,
    };
  }

  const blocked = policies.filter((p) =>
    !p.required_claims ||
    p.required_claims.length === 0
  );

  if (blocked.length > 0) {
    return {
      state: ReadinessState.BLOCKED,
      message: `${blocked.length} of ${policies.length} policy(ies) missing required claims`,
      action: 'Fix',
      path: '/console/org/policies/presentation',
      blockReason: 'Presentation Policy exists but has no required claims',
    };
  }

  return {
    state: ReadinessState.READY,
    message: `${policies.length} policy(ies) configured`,
    action: null,
    path: null,
    blockReason: null,
  };
}

function evaluateVerificationPolicyReadiness(policies, trustProfiles, trustDependencies = {}) {
  const trustReady = evaluateTrustReadiness(trustProfiles, {
    ...trustDependencies,
    requiresIssuerIdentity: false,
  });
  if (trustReady.state !== ReadinessState.READY) {
    return {
      state: ReadinessState.MISSING,
      message: 'Blocked: no active verifier Trust Profile',
      action: null,
      path: null,
      blockReason: null,
      dependencyBlocked: true,
    };
  }

  const loadError = firstResourceError(trustDependencies.resourceErrors, ['policies']);
  if (loadError) {
    return buildLoadErrorReadiness('Presentation policies', loadError.error);
  }

  if (policies.length === 0) {
    return {
      state: ReadinessState.MISSING,
      message: 'No Presentation Policies configured',
      action: 'Create',
      path: '/console/org/policies/presentation/new',
      blockReason: null,
    };
  }

  const blocked = policies.filter((p) =>
    !p.required_claims ||
    p.required_claims.length === 0
  );

  if (blocked.length > 0) {
    return {
      state: ReadinessState.BLOCKED,
      message: `${blocked.length} of ${policies.length} policy(ies) missing required claims`,
      action: 'Fix',
      path: '/console/org/policies/presentation',
      blockReason: 'Presentation Policy exists but has no required claims',
    };
  }

  return {
    state: ReadinessState.READY,
    message: `${policies.length} policy(ies) configured`,
    action: null,
    path: null,
    blockReason: null,
  };
}

/**
 * Compute Deployment Profile readiness
 */
function evaluateDeploymentReadiness(deployments, apiKeys, policies, templates, trustProfiles, trustDependencies = {}) {
  const policyReady = evaluatePolicyReadiness(policies, templates, trustProfiles, trustDependencies);
  if (policyReady.state !== ReadinessState.READY) {
    return {
      state: ReadinessState.MISSING,
      message: 'Blocked: no active Presentation Policy',
      action: null,
      path: null,
      blockReason: null,
      dependencyBlocked: true,
    };
  }

  const loadError = firstResourceError(trustDependencies.resourceErrors, ['deployments', 'apiKeys']);
  if (loadError) {
    const label = loadError.key === 'apiKeys' ? 'API keys' : 'Deployment profiles';
    return buildLoadErrorReadiness(label, loadError.error);
  }

  if (deployments.length === 0) {
    return {
      state: ReadinessState.MISSING,
      message: 'No Deployment Profiles configured',
      action: 'Create',
      path: '/console/org/deploy/profiles/new',
      blockReason: null,
    };
  }

  const activeDeployments = deployments.filter((d) => d.status === 'active');
  if (activeDeployments.length === 0) {
    return {
      state: ReadinessState.BLOCKED,
      message: `${deployments.length} Deployment Profile(s) configured but none active`,
      action: 'Activate',
      path: '/console/org/deploy/profiles',
      blockReason: 'Deployment Profile exists but is not active',
    };
  }

  // Check if we have API keys
  if (apiKeys.length === 0) {
    return {
      state: ReadinessState.BLOCKED,
      message: `${activeDeployments.length} active Deployment Profile(s) but no API keys`,
      action: 'Generate Key',
      path: '/console/org/api-keys',
      blockReason: 'Deployment exists but no API key generated',
    };
  }

  return {
    state: ReadinessState.READY,
    message: `${activeDeployments.length} active Deployment Profile(s), ${apiKeys.length} API key(s)`,
    action: null,
    path: null,
    blockReason: null,
  };
}

function evaluateDeliveryReadiness(deployments, apiKeys, dependencyReadiness, trustDependencies = {}, dependencyLabel = 'setup dependency') {
  if (dependencyReadiness.state !== ReadinessState.READY) {
    return {
      state: ReadinessState.MISSING,
      message: `Blocked: no active ${dependencyLabel}`,
      action: null,
      path: null,
      blockReason: null,
      dependencyBlocked: true,
    };
  }

  const loadError = firstResourceError(trustDependencies.resourceErrors, ['deployments', 'apiKeys']);
  if (loadError) {
    const label = loadError.key === 'apiKeys' ? 'API keys' : 'Deployment profiles';
    return buildLoadErrorReadiness(label, loadError.error);
  }

  if (deployments.length === 0) {
    return {
      state: ReadinessState.MISSING,
      message: 'No Deployment Profiles configured',
      action: 'Create',
      path: '/console/org/deploy/profiles/new',
      blockReason: null,
    };
  }

  const activeDeployments = deployments.filter(isActiveStatus);
  if (activeDeployments.length === 0) {
    return {
      state: ReadinessState.BLOCKED,
      message: `${deployments.length} Deployment Profile(s) configured but none active`,
      action: 'Activate',
      path: '/console/org/deploy/profiles',
      blockReason: 'Deployment Profile exists but is not active',
    };
  }

  if (apiKeys.length === 0) {
    return {
      state: ReadinessState.BLOCKED,
      message: `${activeDeployments.length} active Deployment Profile(s) but no API keys`,
      action: 'Generate Key',
      path: '/console/org/api-keys',
      blockReason: 'Deployment exists but no API key generated',
    };
  }

  return {
    state: ReadinessState.READY,
    message: `${activeDeployments.length} active Deployment Profile(s), ${apiKeys.length} API key(s)`,
    action: null,
    path: null,
    blockReason: null,
  };
}

/**
 * Compute Flow readiness
 */
function evaluateFlowReadiness(flows, deployments, apiKeys, policies, templates, trustProfiles, trustDependencies = {}) {
  const deploymentReady = evaluateDeploymentReadiness(deployments, apiKeys, policies, templates, trustProfiles, trustDependencies);
  if (deploymentReady.state !== ReadinessState.READY) {
    return {
      state: ReadinessState.MISSING,
      message: 'Blocked: no active Deployment Profile',
      action: null,
      path: null,
      blockReason: null,
      dependencyBlocked: true,
    };
  }

  const loadError = firstResourceError(trustDependencies.resourceErrors, ['flows']);
  if (loadError) {
    return buildLoadErrorReadiness('Flows', loadError.error);
  }

  if (flows.length === 0) {
    return {
      state: ReadinessState.MISSING,
      message: 'No Flows configured',
      action: 'Create',
      path: '/console/org/flows/definitions/new',
      blockReason: null,
    };
  }

  const blocked = flows.filter((f) =>
    f.status !== 'active' ||
    !f.trust_profile_id ||
    (!f.presentation_policy_id && !f.credential_template_id)
  );

  if (blocked.length > 0) {
    return {
      state: ReadinessState.BLOCKED,
      message: `${blocked.length} of ${flows.length} flow(s) inactive or missing references`,
      action: 'Fix',
      path: '/console/org/flows/definitions',
      blockReason: 'Flow exists but missing references or inactive',
    };
  }

  const activeFlows = flows.filter((f) => f.status === 'active');
  return {
    state: ReadinessState.READY,
    message: `${activeFlows.length} active flow(s)`,
    action: null,
    path: null,
    blockReason: null,
  };
}

function evaluateIntentFlowReadiness(flows, dependencyReadiness, trustDependencies = {}, options = {}) {
  const {
    label = 'Flows',
    emptyMessage = 'No Flows configured',
    missingReferenceMessage = 'flow(s) inactive or missing references',
    filter = () => true,
    referenceCheck = () => true,
  } = options;

  if (dependencyReadiness.state !== ReadinessState.READY) {
    return {
      state: ReadinessState.MISSING,
      message: `Blocked: ${dependencyReadiness.message}`,
      action: null,
      path: null,
      blockReason: null,
      dependencyBlocked: true,
    };
  }

  const loadError = firstResourceError(trustDependencies.resourceErrors, ['flows']);
  if (loadError) {
    return buildLoadErrorReadiness(label, loadError.error);
  }

  const matchingFlows = flows.filter(filter);
  if (matchingFlows.length === 0) {
    return {
      state: ReadinessState.MISSING,
      message: emptyMessage,
      action: 'Create',
      path: '/console/org/flows/definitions/new',
      blockReason: null,
    };
  }

  const blocked = matchingFlows.filter((flow) => !isActiveStatus(flow) || !referenceCheck(flow));
  if (blocked.length > 0) {
    return {
      state: ReadinessState.BLOCKED,
      message: `${blocked.length} of ${matchingFlows.length} ${missingReferenceMessage}`,
      action: 'Fix',
      path: '/console/org/flows/definitions',
      blockReason: `${label} exist but are inactive or missing required references`,
    };
  }

  const activeFlows = matchingFlows.filter(isActiveStatus);
  return {
    state: ReadinessState.READY,
    message: `${activeFlows.length} active flow(s)`,
    action: null,
    path: null,
    blockReason: null,
  };
}

function combineDependencyReadiness(...readinessValues) {
  const unresolved = readinessValues.find((readiness) => readiness?.state !== ReadinessState.READY);
  if (unresolved) {
    return unresolved;
  }
  return {
    state: ReadinessState.READY,
    message: 'Required resources ready',
    action: null,
    path: null,
    blockReason: null,
  };
}

function evaluateApplicationTemplateReadiness(applicationTemplates, trustDependencies = {}) {
  const loadError = firstResourceError(trustDependencies.resourceErrors, ['applicationTemplates']);
  if (loadError) {
    return buildLoadErrorReadiness('Application templates', loadError.error);
  }

  const safeTemplates = safeArray(applicationTemplates);
  if (safeTemplates.length === 0) {
    return {
      state: ReadinessState.MISSING,
      message: 'No Application Templates configured',
      action: 'Create',
      path: APPLICATION_TEMPLATES_PATH,
      blockReason: null,
    };
  }

  const activeTemplates = safeTemplates.filter(isActiveStatus);
  if (activeTemplates.length === 0) {
    return {
      state: ReadinessState.BLOCKED,
      message: `${safeTemplates.length} Application Template(s) configured but none active`,
      action: 'Activate',
      path: APPLICATION_TEMPLATES_PATH,
      blockReason: 'Application Template exists but status is not active',
    };
  }

  return {
    state: ReadinessState.READY,
    message: `${activeTemplates.length} active Application Template(s)`,
    action: null,
    path: null,
    blockReason: null,
  };
}

function evaluatePolicySetReadiness(policySets, applicationTemplateReadiness, trustDependencies = {}) {
  if (applicationTemplateReadiness.state !== ReadinessState.READY) {
    return {
      state: ReadinessState.MISSING,
      message: 'Blocked: no active Application Template',
      action: null,
      path: null,
      blockReason: null,
      dependencyBlocked: true,
    };
  }

  const loadError = firstResourceError(trustDependencies.resourceErrors, ['policySets']);
  if (loadError) {
    return buildLoadErrorReadiness('Policy Sets', loadError.error);
  }

  const approvalSets = safeArray(policySets).filter((policySet) => (
    String(policySet?.policy_type || '').trim().toUpperCase() === 'APPROVAL_RULES'
  ));
  if (approvalSets.length === 0) {
    return {
      state: ReadinessState.MISSING,
      message: 'No approval Policy Sets configured',
      action: 'Create',
      path: `${POLICY_SETS_PATH}/new`,
      blockReason: null,
    };
  }

  const activeSets = approvalSets.filter(isActiveStatus);
  if (activeSets.length === 0) {
    return {
      state: ReadinessState.BLOCKED,
      message: `${approvalSets.length} approval Policy Set(s) configured but none active`,
      action: 'Activate',
      path: POLICY_SETS_PATH,
      blockReason: 'Application approval requires an active APPROVAL_RULES Policy Set',
    };
  }

  return {
    state: ReadinessState.READY,
    message: `${activeSets.length} active approval Policy Set(s)`,
    action: null,
    path: null,
    blockReason: null,
  };
}

function evaluatePhysicalCapabilityReadiness(capabilities, trustDependencies = {}) {
  const loadError = firstResourceError(trustDependencies.resourceErrors, ['physicalDocumentCapabilities']);
  if (loadError) {
    return buildLoadErrorReadiness('Physical document capability', loadError.error);
  }

  if (!capabilities) {
    return {
      state: ReadinessState.BLOCKED,
      message: 'Physical document capability is not reported',
      action: 'Configure',
      path: TRUST_KEY_MANAGEMENT_PATH,
      blockReason: 'Physical issuance must report signer, encrypted artifact store, and bureau readiness',
    };
  }

  const blockers = safeArray(capabilities.blockers).filter(Boolean);
  if (capabilities.supported !== true || blockers.length > 0) {
    return {
      state: ReadinessState.BLOCKED,
      message: blockers.length > 0 ? blockers.join(' ') : 'Physical document issuance is not supported',
      action: 'Configure',
      path: TRUST_KEY_MANAGEMENT_PATH,
      blockReason: blockers.length > 0
        ? `Physical issuance capability blockers: ${blockers.join(' ')}`
        : 'Physical document issuance capability is disabled',
    };
  }

  return {
    state: ReadinessState.READY,
    message: 'Signer, encrypted artifact storage, and personalization bureau ready',
    action: null,
    path: null,
    blockReason: null,
  };
}

function isPhysicalDeliveryDestination(destination) {
  const provider = String(destination?.provider || '').trim().toLowerCase();
  const mode = String(destination?.mode || '').trim().toLowerCase();
  const target = String(destination?.delivery_target || '').trim().toLowerCase();
  const capabilities = destination?.capabilities || {};
  return destination?.is_enabled !== false && (
    capabilities.physical_document === true
    || capabilities.personalization_bureau === true
    || provider.includes('bureau')
    || provider.includes('personalization')
    || mode === 'physical_document'
    || target === 'physical_document'
  );
}

function evaluateDeliveryDestinationReadiness(destinations, capabilityReadiness, trustDependencies = {}) {
  if (capabilityReadiness.state !== ReadinessState.READY) {
    return {
      state: ReadinessState.MISSING,
      message: 'Blocked: physical issuance capability is not ready',
      action: null,
      path: null,
      blockReason: null,
      dependencyBlocked: true,
    };
  }

  const loadError = firstResourceError(trustDependencies.resourceErrors, ['deliveryDestinations']);
  if (loadError) {
    return buildLoadErrorReadiness('Delivery destinations', loadError.error);
  }

  const physicalDestinations = safeArray(destinations).filter(isPhysicalDeliveryDestination);
  if (physicalDestinations.length === 0) {
    return {
      state: ReadinessState.MISSING,
      message: 'No physical personalization destination configured',
      action: 'Create',
      path: DELIVERY_DESTINATIONS_PATH,
      blockReason: null,
    };
  }

  return {
    state: ReadinessState.READY,
    message: `${physicalDestinations.length} physical production destination(s) ready`,
    action: null,
    path: null,
    blockReason: null,
  };
}

function evaluateRevocationReadiness(revocationProfiles, templates, trustDependencies = {}) {
  const loadError = firstResourceError(trustDependencies.resourceErrors, ['revocationProfiles']);
  if (loadError) {
    return buildLoadErrorReadiness('Revocation profiles', loadError.error);
  }

  const profiles = safeArray(revocationProfiles);
  const templateUsesRevocationProfile = safeArray(templates).some((template) => template.revocation_profile_id);
  if (profiles.length === 0 && !templateUsesRevocationProfile) {
    return {
      state: ReadinessState.MISSING,
      message: 'No Revocation Profiles configured',
      action: 'Create',
      path: REVOCATION_PROFILES_PATH,
      blockReason: null,
    };
  }

  const activeProfiles = profiles.filter(isActiveStatus);
  if (profiles.length > 0 && activeProfiles.length === 0) {
    return {
      state: ReadinessState.BLOCKED,
      message: `${profiles.length} Revocation Profile(s) configured but none active`,
      action: 'Activate',
      path: REVOCATION_PROFILES_PATH,
      blockReason: 'Revocation Profile exists but status is not active',
    };
  }

  return {
    state: ReadinessState.READY,
    message: activeProfiles.length > 0
      ? `${activeProfiles.length} active Revocation Profile(s)`
      : 'Credential Template has a revocation profile binding',
    action: null,
    path: null,
    blockReason: null,
  };
}

/**
 * Compute overall setup readiness
 * @param {Object} data - Dashboard data from useDashboardData hook
 * @returns {Object} Readiness for each resource type
 */
export function computeSetupReadiness(data) {
  const {
    trustProfiles,
    signingKeys,
    issuerProfiles,
    keyManagementConfig,
    templates,
    policies,
    deployments,
    flows,
    apiKeys,
    applicationTemplates,
    deliveryDestinations,
    policySets,
    physicalDocumentCapabilities,
    revocationProfiles,
    lifecycle,
    resourceErrors,
    dashboardErrors,
  } = data;

  const trustDependencies = {
    signingKeys,
    issuerProfiles,
    keyManagementConfig,
    resourceErrors,
  };

  const compliance = evaluateComplianceReadiness(lifecycle, dashboardErrors);
  const activeIntent = inferSetupIntent(data);
  const issuer = evaluateIssuerReadiness(trustDependencies);
  const trust = evaluateTrustReadiness(trustProfiles, trustDependencies);
  const template = evaluateTemplateReadiness(templates, trustProfiles, trustDependencies);
  const policy = evaluatePolicyReadiness(policies, templates, trustProfiles, trustDependencies);
  const deployment = evaluateDeploymentReadiness(deployments, apiKeys, policies, templates, trustProfiles, trustDependencies);
  const flow = evaluateFlowReadiness(flows, deployments, apiKeys, policies, templates, trustProfiles, trustDependencies);

  const verifierTrust = evaluateTrustReadiness(trustProfiles, {
    ...trustDependencies,
    requiresIssuerIdentity: false,
  });
  const verifierPolicy = evaluateVerificationPolicyReadiness(policies, trustProfiles, trustDependencies);
  const verifierFlow = evaluateIntentFlowReadiness(safeArray(flows), verifierPolicy, trustDependencies, {
    label: 'Verification flows',
    emptyMessage: 'No Verification Flows configured',
    missingReferenceMessage: 'verification flow(s) inactive or missing references',
    filter: isVerificationFlow,
    referenceCheck: (candidate) => Boolean(candidate.presentation_policy_id),
  });

  const issuanceFlow = evaluateIntentFlowReadiness(safeArray(flows), template, trustDependencies, {
    label: 'Issuance flows',
    emptyMessage: 'No flows configured',
    missingReferenceMessage: 'issuance flow(s) inactive or missing references',
    filter: isIssuanceFlow,
    referenceCheck: (candidate) => Boolean(candidate.credential_template_id),
  });

  const applicationTemplate = evaluateApplicationTemplateReadiness(applicationTemplates, trustDependencies);
  const policySet = evaluatePolicySetReadiness(policySets, applicationTemplate, trustDependencies);
  const applicationFlow = evaluateIntentFlowReadiness(
    safeArray(flows),
    combineDependencyReadiness(applicationTemplate, policySet),
    trustDependencies,
    {
    label: 'Application approval flows',
    emptyMessage: 'No Application Approval Flows configured',
    missingReferenceMessage: 'application approval flow(s) inactive or missing references',
    filter: isApplicationFlow,
    referenceCheck: (candidate) => Boolean(candidate.application_template_id),
    },
  );

  const physicalCapability = evaluatePhysicalCapabilityReadiness(physicalDocumentCapabilities, trustDependencies);
  const deliveryDestination = evaluateDeliveryDestinationReadiness(
    deliveryDestinations,
    physicalCapability,
    trustDependencies,
  );
  const physicalFlow = evaluateIntentFlowReadiness(
    safeArray(flows),
    combineDependencyReadiness(
      physicalCapability,
      issuer,
      trust,
      template,
      applicationTemplate,
      deliveryDestination,
    ),
    trustDependencies,
    {
      label: 'Physical document flows',
      emptyMessage: 'No Physical Document Issuance Flows configured',
      missingReferenceMessage: 'physical document flow(s) inactive or missing references',
      filter: isPhysicalFlow,
      referenceCheck: (candidate) => Boolean(
        candidate.credential_template_id
        && candidate.application_template_id
        && candidate.delivery_destination_profile_id
      ),
    },
  );

  const revocation = evaluateRevocationReadiness(revocationProfiles, templates, trustDependencies);
  const lifecycleFlow = evaluateIntentFlowReadiness(safeArray(flows), revocation, trustDependencies, {
    label: 'Lifecycle flows',
    emptyMessage: 'No Renewal or Revocation Flows configured',
    missingReferenceMessage: 'lifecycle flow(s) inactive or missing references',
    filter: isLifecycleFlow,
    referenceCheck: (candidate) => Boolean(candidate.credential_template_id),
  });

  const intents = {
    [SETUP_INTENTS.VERIFY]: {
      id: SETUP_INTENTS.VERIFY,
      label: SETUP_INTENT_LABELS[SETUP_INTENTS.VERIFY],
      description: 'Configure verifier trust, a presentation policy, and an OID4VP flow. Deployment is an optional runtime binding.',
      order: INTENT_SETUP_ORDER[SETUP_INTENTS.VERIFY],
      steps: {
        compliance,
        trust: verifierTrust,
        policy: verifierPolicy,
        flow: verifierFlow,
      },
    },
    [SETUP_INTENTS.ISSUE]: {
      id: SETUP_INTENTS.ISSUE,
      label: SETUP_INTENT_LABELS[SETUP_INTENTS.ISSUE],
      description: 'Configure issuer identity, trust, a credential template, and an issuance flow. Deployment is optional.',
      order: INTENT_SETUP_ORDER[SETUP_INTENTS.ISSUE],
      steps: {
        compliance,
        issuer,
        trust,
        template,
        flow: issuanceFlow,
      },
    },
    [SETUP_INTENTS.APPLICATION]: {
      id: SETUP_INTENTS.APPLICATION,
      label: SETUP_INTENT_LABELS[SETUP_INTENTS.APPLICATION],
      description: 'Configure application intake, approval policy, and a standard application approval flow.',
      order: INTENT_SETUP_ORDER[SETUP_INTENTS.APPLICATION],
      steps: {
        compliance,
        applicationTemplate,
        policySet,
        flow: applicationFlow,
      },
    },
    [SETUP_INTENTS.PHYSICAL]: {
      id: SETUP_INTENTS.PHYSICAL,
      label: SETUP_INTENT_LABELS[SETUP_INTENTS.PHYSICAL],
      description: 'Configure fail-closed physical issuance, production dependencies, and the standard ICAO document flow.',
      order: INTENT_SETUP_ORDER[SETUP_INTENTS.PHYSICAL],
      steps: {
        compliance,
        physicalCapability,
        issuer,
        trust,
        template,
        applicationTemplate,
        deliveryDestination,
        flow: physicalFlow,
      },
    },
    [SETUP_INTENTS.LIFECYCLE]: {
      id: SETUP_INTENTS.LIFECYCLE,
      label: SETUP_INTENT_LABELS[SETUP_INTENTS.LIFECYCLE],
      description: 'Configure revocation or renewal controls and lifecycle flows.',
      order: INTENT_SETUP_ORDER[SETUP_INTENTS.LIFECYCLE],
      steps: {
        template,
        revocation,
        flow: lifecycleFlow,
      },
    },
  };

  return {
    activeIntent,
    intents,
    compliance,
    issuer,
    trust,
    template,
    policy,
    deployment,
    flow,
  };
}

/**
 * Extract blocking issues from setup readiness
 * @param {Object} readiness - Output from computeSetupReadiness
 * @returns {Array} List of blocking issues with fix actions
 */
export function computeBlockers(readiness) {
  const blockers = [];
  const readinessEntries = readiness?.intents?.[readiness.activeIntent]?.steps
    ? Object.entries(readiness.intents[readiness.activeIntent].steps)
    : Object.entries(readiness || {});

  readinessEntries.forEach(([key, value]) => {
    if (value.state === ReadinessState.BLOCKED && value.blockReason) {
      blockers.push({
        id: key,
        reason: value.blockReason,
        action: value.action,
        path: value.path,
      });
    }
  });

  return blockers;
}

/**
 * Compute visibility and disabled state for Quick Actions
 * @param {Object} readiness - Output from computeSetupReadiness
 * @returns {Object} Map of action ID to {visible, disabled, tooltip}
 */
/**
 * Compute Quick Action visibility - shows only the NEXT valid action
 * to avoid duplication with Setup Readiness panel.
 * 
 * Logic: Show one action at a time based on setup progression:
 * 1. Trust blocked on KMS → Register Signing Service
 * 2. Trust blocked on issuer input → Set Up Issuer Identity
 * 3. Trust Missing/Blocked → Create Trust Profile
 * 4. Trust Ready, Template Missing/Blocked → Create Template
 * 5. Template Ready, Policy Missing/Blocked → Create Policy
 * 6. Policy Ready, Deployment Missing/Blocked → Generate API Key
 * 7. Deployment Ready, Flow Missing/Blocked → Create Flow
 * 6. All Ready → Hide Quick Actions (user should go to Operate)
 */
export function computeQuickActionVisibility(readiness) {
  if (readiness?.intents?.[readiness.activeIntent]?.steps) {
    return computeIntentQuickActionVisibility(readiness.intents[readiness.activeIntent].steps);
  }

  const { trust, template, policy, deployment, flow } = readiness;

  const trustActionable = !trust.serviceError;
  const templateActionable = !template.serviceError;
  const policyActionable = !policy.serviceError;
  const deploymentActionable = !deployment.serviceError;
  const flowActionable = !flow.serviceError;

  const showRegisterSigningService = trustActionable && trust.state === ReadinessState.BLOCKED && trust.path === TRUST_KEY_MANAGEMENT_PATH;
  const showCreateIssuerIdentity = trustActionable && trust.state === ReadinessState.BLOCKED && trust.path === TRUST_ISSUER_IDENTITY_PATH;
  // Determine which single action to show based on progression
  const showCreateTrust = trustActionable && !showRegisterSigningService && !showCreateIssuerIdentity && trust.state !== ReadinessState.READY;
  const showCreateTemplate = templateActionable && trust.state === ReadinessState.READY && template.state !== ReadinessState.READY;
  const showCreatePolicy = policyActionable && template.state === ReadinessState.READY && policy.state !== ReadinessState.READY;
  const showGenerateApiKey = deploymentActionable && policy.state === ReadinessState.READY && deployment.state !== ReadinessState.READY;
  const showCreateFlow = flowActionable && deployment.state === ReadinessState.READY && flow.state !== ReadinessState.READY;

  return {
    'register-signing-service': {
      visible: showRegisterSigningService,
      disabled: false,
      tooltip: null,
    },
    'create-issuer-identity': {
      visible: showCreateIssuerIdentity,
      disabled: false,
      tooltip: null,
    },
    'create-trust-profile': {
      visible: showCreateTrust,
      disabled: false,
      tooltip: null,
    },
    'create-template': {
      visible: showCreateTemplate,
      disabled: false,
      tooltip: null,
    },
    'create-policy': {
      visible: showCreatePolicy,
      disabled: false,
      tooltip: null,
    },
    'generate-api-key': {
      visible: showGenerateApiKey,
      disabled: false,
      tooltip: null,
    },
    'create-flow': {
      visible: showCreateFlow,
      disabled: false,
      tooltip: null,
    },
  };
}

function computeIntentQuickActionVisibility(steps) {
  const { issuer, trust, template, policy, deployment, flow, applicationTemplate, revocation } = steps;

  const issuerActionable = !issuer?.serviceError;
  const trustActionable = !trust?.serviceError;
  const templateActionable = !template?.serviceError;
  const policyActionable = !policy?.serviceError;
  const deploymentActionable = !deployment?.serviceError;
  const flowActionable = !flow?.serviceError;
  const applicationTemplateActionable = !applicationTemplate?.serviceError;
  const revocationActionable = !revocation?.serviceError;

  const showRegisterSigningService = Boolean(issuerActionable && issuer?.state === ReadinessState.BLOCKED && issuer.path === TRUST_KEY_MANAGEMENT_PATH);
  const showCreateIssuerIdentity = Boolean(issuerActionable && issuer?.state === ReadinessState.BLOCKED && issuer.path === TRUST_ISSUER_IDENTITY_PATH);
  const issuerReadyOrNotRequired = !issuer || issuer.state === ReadinessState.READY;

  const showCreateApplicationTemplate = Boolean(applicationTemplateActionable
    && applicationTemplate
    && applicationTemplate.state !== ReadinessState.READY);
  const showCreateTrust = Boolean(trustActionable
    && issuerReadyOrNotRequired
    && trust
    && trust.state !== ReadinessState.READY);
  const showCreateTemplate = Boolean(templateActionable
    && issuerReadyOrNotRequired
    && (!trust || trust.state === ReadinessState.READY)
    && (!applicationTemplate || applicationTemplate.state === ReadinessState.READY)
    && template
    && template.state !== ReadinessState.READY);
  const showCreatePolicy = Boolean(policyActionable
    && (!trust || trust.state === ReadinessState.READY)
    && policy
    && policy.state !== ReadinessState.READY);
  const showCreateRevocation = Boolean(revocationActionable
    && (!template || template.state === ReadinessState.READY)
    && revocation
    && revocation.state !== ReadinessState.READY);
  const dependencyReadyForDeployment = (policy && policy.state === ReadinessState.READY)
    || (template && template.state === ReadinessState.READY)
    || (applicationTemplate && applicationTemplate.state === ReadinessState.READY);
  const showGenerateApiKey = Boolean(deploymentActionable
    && deployment
    && dependencyReadyForDeployment
    && deployment.state !== ReadinessState.READY);
  const flowDependencyReady = Object.entries(steps)
    .filter(([key]) => key !== 'flow')
    .every(([, readiness]) => readiness?.state === ReadinessState.READY);
  const showCreateFlow = Boolean(flowActionable
    && flow
    && flowDependencyReady
    && flow.state !== ReadinessState.READY);

  return {
    'register-signing-service': {
      visible: showRegisterSigningService,
      disabled: false,
      tooltip: null,
    },
    'create-issuer-identity': {
      visible: showCreateIssuerIdentity,
      disabled: false,
      tooltip: null,
    },
    'create-trust-profile': {
      visible: showCreateTrust,
      disabled: false,
      tooltip: null,
    },
    'create-template': {
      visible: showCreateTemplate,
      disabled: false,
      tooltip: null,
    },
    'create-policy': {
      visible: showCreatePolicy,
      disabled: false,
      tooltip: null,
    },
    'generate-api-key': {
      visible: showGenerateApiKey,
      disabled: false,
      tooltip: null,
    },
    'create-flow': {
      visible: showCreateFlow,
      disabled: false,
      tooltip: null,
    },
    'create-application-template': {
      visible: showCreateApplicationTemplate,
      disabled: false,
      tooltip: null,
    },
    'create-revocation-profile': {
      visible: showCreateRevocation,
      disabled: false,
      tooltip: null,
    },
  };
}
