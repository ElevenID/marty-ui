/**
 * Pure onboarding flow helpers.
 *
 * These functions isolate onboarding step selection and validation from React.
 */

export const STEPS_APPLICANT = ['Choose Your Role', 'What brings you here?', 'Join Organization', 'Connect Wallet', 'Complete'];
export const STEPS_VENDOR = ['Choose Your Role', 'Create Organization', 'Trust Profile', 'Business Context', 'Technical Identity', 'Review', 'Complete'];
export const STEPS_VENDOR_SKIP_TRUST = ['Choose Your Role', 'Create Organization', 'Trust Profile', 'Complete'];
export const STEPS_VENDOR_EXISTING_ORG = ['Choose Your Role', 'Organization Settings', 'Business Context', 'Technical Identity', 'Review', 'Complete'];

/**
 * Check whether the user already has org-management capabilities.
 *
 * @param {Record<string, boolean> | null | undefined} capabilities
 * @returns {boolean}
 */
export function hasOrganizationCapability(capabilities) {
  return Boolean(
    capabilities?.['org:view'] ||
    capabilities?.['org:manage'] ||
    capabilities?.['org:issue']
  );
}

/**
 * Resolve onboarding bootstrap state from API status and capabilities.
 *
 * @param {Object} params
 * @param {Record<string, boolean> | null | undefined} params.capabilities
 * @param {Object | null | undefined} params.status
 * @returns {{userType: 'vendor' | null, roleLocked: boolean, existingOrganization: {id: string, name: string} | null, presetOrganizationName: string}}
 */
export function resolveOnboardingBootstrap({ capabilities, status }) {
  if (!hasOrganizationCapability(capabilities)) {
    return {
      userType: null,
      roleLocked: false,
      existingOrganization: null,
      presetOrganizationName: '',
    };
  }

  const existingOrganization = status?.organization_id
    ? {
        id: status.organization_id,
        name: status.organization_name || '',
      }
    : null;

  return {
    userType: 'vendor',
    roleLocked: true,
    existingOrganization,
    presetOrganizationName: existingOrganization?.name || '',
  };
}

/**
 * Whether a locked vendor role should auto-advance from step 0 to step 1.
 *
 * @param {Object} params
 * @param {boolean} params.roleLocked
 * @param {'vendor' | 'applicant' | null} params.userType
 * @param {number} params.activeStep
 * @returns {boolean}
 */
export function shouldAutoAdvanceLockedRole({ roleLocked, userType, activeStep }) {
  return Boolean(roleLocked && userType && activeStep === 0);
}

/**
 * Get the visible step labels for the current onboarding mode.
 *
 * @param {Object} params
 * @param {'vendor' | 'applicant' | null} params.userType
 * @param {boolean} params.hasExistingOrganization
 * @param {boolean} params.skipTrustSetup
 * @returns {string[]}
 */
export function getOnboardingSteps({ userType, hasExistingOrganization, skipTrustSetup }) {
  if (userType !== 'vendor') {
    return STEPS_APPLICANT;
  }

  if (hasExistingOrganization) {
    return STEPS_VENDOR_EXISTING_ORG;
  }

  return skipTrustSetup ? STEPS_VENDOR_SKIP_TRUST : STEPS_VENDOR;
}

/**
 * Validate the initial role-selection step.
 *
 * @param {'vendor' | 'applicant' | null} userType
 * @returns {{valid: boolean, error: string | null}}
 */
export function validateRoleSelection(userType) {
  if (!userType) {
    return { valid: false, error: 'Please select a role to continue' };
  }

  return { valid: true, error: null };
}

/**
 * Validate org selection from the applicant browse flow.
 *
 * @param {Object|null|undefined} organization
 * @returns {{valid: boolean, error: string | null, requiresConfirmation: boolean}}
 */
export function validateOrganizationSelection(organization) {
  if (organization?.membership_mode === 'invite_only') {
    return {
      valid: false,
      requiresConfirmation: false,
      error: 'This organization only accepts members via invitation. Please use an invite code.',
    };
  }

  return {
    valid: true,
    requiresConfirmation: true,
    error: null,
  };
}

/**
 * Validate the vendor organization-details step.
 *
 * @param {Object} params
 * @param {boolean} params.hasExistingOrganization
 * @param {string} params.newOrgName
 * @param {boolean} params.orgNameChecking
 * @param {boolean | null} params.orgNameAvailable
 * @param {string | null} params.orgNameError
 * @returns {{valid: boolean, error: string | null, nextStep: number | null}}
 */
export function validateVendorOrganizationStep({
  hasExistingOrganization,
  newOrgName,
  orgNameChecking,
  orgNameAvailable,
  orgNameError,
}) {
  if (!hasExistingOrganization && !newOrgName.trim()) {
    return { valid: false, error: 'Please enter an organization name', nextStep: null };
  }

  if (!hasExistingOrganization && newOrgName.trim().length < 3) {
    return { valid: false, error: 'Organization name must be at least 3 characters', nextStep: null };
  }

  if (orgNameChecking) {
    return { valid: false, error: 'Checking organization name availability...', nextStep: null };
  }

  if (orgNameAvailable === false) {
    return { valid: false, error: orgNameError || 'Organization name is already taken', nextStep: null };
  }

  return { valid: true, error: null, nextStep: 2 };
}

/**
 * Validate the vendor trust-profile step.
 *
 * @param {string[]} trustProfile
 * @returns {{valid: boolean, error: string | null}}
 */
export function validateTrustProfileSelection(trustProfile) {
  if (!trustProfile || trustProfile.length === 0) {
    return { valid: false, error: 'Please select at least one trust profile to continue' };
  }

  return { valid: true, error: null };
}

/**
 * Validate the business-context step.
 *
 * @param {Object} params
 * @param {string[]} params.selectedUseCases
 * @param {string[]} params.selectedAcceptance
 * @param {string} params.jurisdiction
 * @returns {{valid: boolean, error: string | null, nextStep: number | null}}
 */
export function validateBusinessContextStep({ selectedUseCases, selectedAcceptance, jurisdiction }) {
  if (selectedUseCases.length === 0) {
    return { valid: false, error: 'Please select at least one credential type', nextStep: null };
  }

  if (selectedAcceptance.length === 0) {
    return { valid: false, error: 'Please select at least one acceptance type', nextStep: null };
  }

  if (!jurisdiction) {
    return { valid: false, error: 'Please select your jurisdiction', nextStep: null };
  }

  return { valid: true, error: null, nextStep: 4 };
}

/**
 * Resolve the technical-identity step transition.
 *
 * @returns {{nextStep: number}}
 */
export function resolveTechnicalIdentityAdvance() {
  return { nextStep: 5 };
}

/**
 * Resolve the domain-match join result into UI state changes.
 *
 * @param {Object} result
 * @returns {{resultOrgName: string | null, membershipStatus: string | null, nextStep: number | null, closeModal: boolean}}
 */
export function resolveDomainJoinResult(result) {
  if (result?.action === 'joined') {
    return {
      resultOrgName: result.organization_name || null,
      membershipStatus: 'joined',
      nextStep: 3,
      closeModal: true,
    };
  }

  if (result?.action === 'requested') {
    return {
      resultOrgName: result.organization_name || null,
      membershipStatus: 'pending',
      nextStep: null,
      closeModal: true,
    };
  }

  return {
    resultOrgName: result?.organization_name || null,
    membershipStatus: null,
    nextStep: null,
    closeModal: false,
  };
}
