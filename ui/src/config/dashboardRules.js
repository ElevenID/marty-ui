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
  'trust',
  'template',
  'policy',
  'deployment',
  'flow',
];

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

/**
 * Compute Trust Profile readiness
 */
function evaluateTrustReadiness(trustProfiles, dependencies = {}) {
  const safeTrustProfiles = Array.isArray(trustProfiles) ? trustProfiles : [];
  const { signingKeys = [], issuerProfiles = [], keyManagementConfig = null } = dependencies || {};

  if (safeTrustProfiles.length === 0) {
    if (!getDefaultKeyManagementService(keyManagementConfig)) {
      return {
        state: ReadinessState.BLOCKED,
        message: 'Blocked: configure key management before creating Trust Profiles',
        action: 'Configure KMS',
        path: TRUST_KEY_MANAGEMENT_PATH,
        blockReason: 'Trust Profile setup requires a configured key management service',
      };
    }

    if (!hasManagedIssuerInput(signingKeys, issuerProfiles)) {
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
      path: '/console/trust/profiles/new',
      blockReason: null,
    };
  }

  const activeTrusts = safeTrustProfiles.filter((t) => t.status === 'active');
  if (activeTrusts.length === 0) {
    return {
      state: ReadinessState.BLOCKED,
      message: `${safeTrustProfiles.length} Trust Profile(s) configured but none active`,
      action: 'Activate',
      path: '/console/trust/profiles',
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

  if (templates.length === 0) {
    return {
      state: ReadinessState.MISSING,
      message: 'No Credential Templates configured',
      action: 'Create',
      path: '/console/templates/credentials/new',
      blockReason: null,
    };
  }

  // Check for artifacts issues
  const blocked = templates.filter((t) => 
    t.status !== 'active' || 
    t.artifacts_status === 'missing' || 
    t.artifacts_status === 'invalid' ||
    !t.trust_profile_id
  );

  if (blocked.length > 0) {
    const reasons = [];
    if (blocked.some((t) => t.artifacts_status === 'missing' || t.artifacts_status === 'invalid')) {
      reasons.push('missing signing artifacts');
    }
    if (blocked.some((t) => !t.trust_profile_id)) {
      reasons.push('missing trust profile');
    }
    if (blocked.some((t) => t.status !== 'active')) {
      reasons.push('inactive status');
    }

    return {
      state: ReadinessState.BLOCKED,
      message: `${blocked.length} of ${templates.length} template(s) with issues: ${reasons.join(', ')}`,
      action: 'Fix',
      path: '/console/templates/credentials',
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

  if (policies.length === 0) {
    return {
      state: ReadinessState.MISSING,
      message: 'No Presentation Policies configured',
      action: 'Create',
      path: '/console/policies/presentation/new',
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
      path: '/console/policies/presentation',
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

  if (deployments.length === 0) {
    return {
      state: ReadinessState.MISSING,
      message: 'No Deployment Profiles configured',
      action: 'Create',
      path: '/console/deploy/profiles/new',
      blockReason: null,
    };
  }

  const activeDeployments = deployments.filter((d) => d.status === 'active');
  if (activeDeployments.length === 0) {
    return {
      state: ReadinessState.BLOCKED,
      message: `${deployments.length} Deployment Profile(s) configured but none active`,
      action: 'Activate',
      path: '/console/deploy/profiles',
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

  if (flows.length === 0) {
    return {
      state: ReadinessState.MISSING,
      message: 'No Flows configured',
      action: 'Create',
      path: '/console/flows/definitions/new',
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
      path: '/console/flows/definitions',
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
  } = data;

  const trustDependencies = {
    signingKeys,
    issuerProfiles,
    keyManagementConfig,
  };

  const trust = evaluateTrustReadiness(trustProfiles, trustDependencies);
  const template = evaluateTemplateReadiness(templates, trustProfiles, trustDependencies);
  const policy = evaluatePolicyReadiness(policies, templates, trustProfiles, trustDependencies);
  const deployment = evaluateDeploymentReadiness(deployments, apiKeys, policies, templates, trustProfiles, trustDependencies);
  const flow = evaluateFlowReadiness(flows, deployments, apiKeys, policies, templates, trustProfiles, trustDependencies);

  return {
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

  Object.entries(readiness).forEach(([key, value]) => {
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
 * 7. Deployment Ready, Flow Missing/Blocked → Create Issuance Flow
 * 6. All Ready → Hide Quick Actions (user should go to Operate)
 */
export function computeQuickActionVisibility(readiness) {
  const { trust, template, policy, deployment, flow } = readiness;

  const showRegisterSigningService = trust.state === ReadinessState.BLOCKED && trust.path === TRUST_KEY_MANAGEMENT_PATH;
  const showCreateIssuerIdentity = trust.state === ReadinessState.BLOCKED && trust.path === TRUST_ISSUER_IDENTITY_PATH;
  // Determine which single action to show based on progression
  const showCreateTrust = !showRegisterSigningService && !showCreateIssuerIdentity && trust.state !== ReadinessState.READY;
  const showCreateTemplate = trust.state === ReadinessState.READY && template.state !== ReadinessState.READY;
  const showCreatePolicy = template.state === ReadinessState.READY && policy.state !== ReadinessState.READY;
  const showGenerateApiKey = policy.state === ReadinessState.READY && deployment.state !== ReadinessState.READY;
  const showCreateFlow = deployment.state === ReadinessState.READY && flow.state !== ReadinessState.READY;

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
