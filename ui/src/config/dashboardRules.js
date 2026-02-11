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

/**
 * Compute Trust Profile readiness
 */
function evaluateTrustReadiness(trustProfiles) {
  if (trustProfiles.length === 0) {
    return {
      state: ReadinessState.MISSING,
      message: 'No Trust Profiles configured',
      action: 'Create',
      path: '/console/trust/profiles/new',
      blockReason: null,
    };
  }

  const activeTrusts = trustProfiles.filter((t) => t.status === 'active');
  if (activeTrusts.length === 0) {
    return {
      state: ReadinessState.BLOCKED,
      message: `${trustProfiles.length} Trust Profile(s) configured but none active`,
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
function evaluateTemplateReadiness(templates, trustProfiles) {
  const trustReady = evaluateTrustReadiness(trustProfiles);
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
function evaluatePolicyReadiness(policies, templates, trustProfiles) {
  const templateReady = evaluateTemplateReadiness(templates, trustProfiles);
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
    p.status !== 'active' ||
    !p.credential_requirements ||
    p.credential_requirements.length === 0
  );

  if (blocked.length > 0) {
    return {
      state: ReadinessState.BLOCKED,
      message: `${blocked.length} of ${policies.length} policy(ies) inactive or missing requirements`,
      action: 'Fix',
      path: '/console/policies/presentation',
      blockReason: 'Presentation Policy exists but is inactive or has no credential requirements',
    };
  }

  const activePolicies = policies.filter((p) => p.status === 'active');
  return {
    state: ReadinessState.READY,
    message: `${activePolicies.length} active policy(ies)`,
    action: null,
    path: null,
    blockReason: null,
  };
}

/**
 * Compute Deployment Profile readiness
 */
function evaluateDeploymentReadiness(deployments, apiKeys, policies, templates, trustProfiles) {
  const policyReady = evaluatePolicyReadiness(policies, templates, trustProfiles);
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
      path: '/console/deploy/api-keys/new',
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
function evaluateFlowReadiness(flows, deployments, apiKeys, policies, templates, trustProfiles) {
  const deploymentReady = evaluateDeploymentReadiness(deployments, apiKeys, policies, templates, trustProfiles);
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
  const { trustProfiles, templates, policies, deployments, flows, apiKeys } = data;

  const trust = evaluateTrustReadiness(trustProfiles);
  const template = evaluateTemplateReadiness(templates, trustProfiles);
  const policy = evaluatePolicyReadiness(policies, templates, trustProfiles);
  const deployment = evaluateDeploymentReadiness(deployments, apiKeys, policies, templates, trustProfiles);
  const flow = evaluateFlowReadiness(flows, deployments, apiKeys, policies, templates, trustProfiles);

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
 * 1. Trust Missing/Blocked → Create Trust Profile
 * 2. Trust Ready, Template Missing/Blocked → Create Template
 * 3. Template Ready, Policy Missing/Blocked → Create Policy
 * 4. Policy Ready, Deployment Missing/Blocked → Generate API Key
 * 5. Deployment Ready, Flow Missing/Blocked → Start Verification Flow
 * 6. All Ready → Hide Quick Actions (user should go to Operate)
 */
export function computeQuickActionVisibility(readiness) {
  const { trust, template, policy, deployment, flow } = readiness;

  // Determine which single action to show based on progression
  const showCreateTrust = trust.state !== ReadinessState.READY;
  const showCreateTemplate = trust.state === ReadinessState.READY && template.state !== ReadinessState.READY;
  const showCreatePolicy = template.state === ReadinessState.READY && policy.state !== ReadinessState.READY;
  const showGenerateApiKey = policy.state === ReadinessState.READY && deployment.state !== ReadinessState.READY;
  const showStartVerification = deployment.state === ReadinessState.READY && flow.state !== ReadinessState.READY;

  return {
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
    'start-verification': {
      visible: showStartVerification,
      disabled: false,
      tooltip: null,
    },
  };
}
