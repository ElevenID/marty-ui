/**
 * Guard policy for authenticated routes.
 *
 * This module is intentionally framework-agnostic: no React, router, or DOM imports.
 * Route components should adapt these decisions into rendering/navigation behavior.
 */

/**
 * @typedef {'loading' | 'allow' | 'redirect'} GuardDecisionKind
 */

/**
 * @typedef {'unauthenticated' | 'unauthorized' | 'missing-org-selection'} GuardDecisionReason
 */

/**
 * @typedef {Object} GuardDecision
 * @property {GuardDecisionKind} kind
 * @property {string} [destination]
 * @property {GuardDecisionReason} [reason]
 */

/**
 * Resolve a capability checker from either a callback or user capability map.
 *
 * @param {Object} [params]
 * @param {Function | undefined} [params.hasCapability]
 * @param {Object | null | undefined} [params.user]
 * @returns {(capability: string) => boolean}
 */
export function resolveCapabilityChecker({ hasCapability = undefined, user = null } = {}) {
  if (typeof hasCapability === 'function') {
    return (capability) => Boolean(hasCapability(capability));
  }

  return (capability) => Boolean(user?.capabilities?.[capability]);
}

/**
 * Evaluate whether a protected route should render, redirect, or show a loading state.
 *
 * @param {Object} params
 * @param {boolean} params.isLoading
 * @param {boolean} params.isAuthenticated
 * @param {Object | null | undefined} [params.user]
 * @param {Function | undefined} [params.hasCapability]
 * @param {string[] | null | undefined} [params.requiredCapabilities]
 * @param {boolean} [params.requireAllCapabilities=false]
 * @param {string} [params.redirectTo='/login']
 * @param {string} [params.unauthorizedRedirect='/']
 * @returns {GuardDecision}
 */
export function evaluateProtectedRoutePolicy({
  isLoading,
  isAuthenticated,
  user = null,
  hasCapability = undefined,
  requiredCapabilities = null,
  requireAllCapabilities = false,
  redirectTo = '/login',
  unauthorizedRedirect = '/',
}) {
  if (isLoading) {
    return { kind: 'loading' };
  }

  if (!isAuthenticated) {
    return {
      kind: 'redirect',
      destination: redirectTo,
      reason: 'unauthenticated',
    };
  }

  if (requiredCapabilities && requiredCapabilities.length > 0) {
    const can = resolveCapabilityChecker({ hasCapability, user });
    const isAllowed = requireAllCapabilities
      ? requiredCapabilities.every((capability) => can(capability))
      : requiredCapabilities.some((capability) => can(capability));

    if (!isAllowed) {
      return {
        kind: 'redirect',
        destination: unauthorizedRedirect,
        reason: 'unauthorized',
      };
    }
  }

  return { kind: 'allow' };
}

/**
 * Evaluate applicant console availability.
 *
 * @param {Object} params
 * @param {boolean} params.consoleLoading
 * @returns {GuardDecision}
 */
export function evaluateApplicantConsolePolicy({ consoleLoading }) {
  return consoleLoading ? { kind: 'loading' } : { kind: 'allow' };
}

/**
 * Evaluate org console access prior to capability checks.
 *
 * @param {Object} params
 * @param {boolean} params.consoleLoading
 * @param {'applicant' | 'org'} [params.mode]
 * @param {string | null | undefined} [params.activeOrgId]
 * @param {string} [params.setupRedirect='/console/org/setup']
 * @returns {GuardDecision}
 */
export function evaluateOrgConsolePolicy({
  consoleLoading,
  mode,
  activeOrgId,
  setupRedirect = '/console/org/setup',
}) {
  if (consoleLoading) {
    return { kind: 'loading' };
  }

  if (mode === 'org' && !activeOrgId) {
    return {
      kind: 'redirect',
      destination: setupRedirect,
      reason: 'missing-org-selection',
    };
  }

  return { kind: 'allow' };
}
