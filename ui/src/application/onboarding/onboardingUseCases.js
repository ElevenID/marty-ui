import { get, post, getErrorMessage, isAuthError } from '../../services/api';
import { resolveOnboardingBootstrap } from './onboardingFlow';

const ONBOARDING_API_BASE = '/api/onboarding';

async function defaultGetOnboardingStatus() {
  return get(`${ONBOARDING_API_BASE}/status`);
}

async function defaultGetOrganizations() {
  const data = await get(`${ONBOARDING_API_BASE}/organizations`);
  return data?.organizations || [];
}

async function defaultGetOrganizationSettings() {
  return get(`${ONBOARDING_API_BASE}/org-settings`);
}

async function defaultSubmitJoinWithCode(inviteCode) {
  return post(`${ONBOARDING_API_BASE}/join-with-code`, {
    invite_code: inviteCode,
  });
}

async function defaultCompleteOnboarding(payload) {
  return post(`${ONBOARDING_API_BASE}/complete`, payload);
}

async function defaultCheckOrganizationName(name) {
  return get(`${ONBOARDING_API_BASE}/check-organization-name?name=${encodeURIComponent(name)}`);
}

function toReadableError(error, fallbackMessage) {
  const message = getErrorMessage(error);
  return new Error(message || fallbackMessage);
}

export async function loadOnboardingOrganizations({ targetOrgId = null, getOrganizations = defaultGetOrganizations } = {}) {
  try {
    const organizations = await getOrganizations();
    const suggestedOrganization = targetOrgId
      ? (organizations || []).find((organization) => organization.id === targetOrgId) || null
      : null;

    return {
      organizations: organizations || [],
      suggestedOrganization,
    };
  } catch {
    return {
      organizations: [],
      suggestedOrganization: null,
    };
  }
}

export async function loadOnboardingOrganizationSettings({ getOrganizationSettings = defaultGetOrganizationSettings } = {}) {
  try {
    const data = await getOrganizationSettings();
    return {
      isDiscoverable: typeof data?.is_discoverable === 'boolean' ? data.is_discoverable : null,
      membershipMode: data?.membership_mode || null,
      organizationName: data?.organization_name || '',
    };
  } catch {
    return {
      isDiscoverable: null,
      membershipMode: null,
      organizationName: '',
    };
  }
}

export async function loadOnboardingBootstrap({
  capabilities,
  targetOrgId = null,
  getOnboardingStatus = defaultGetOnboardingStatus,
  getOrganizations = defaultGetOrganizations,
  getOrganizationSettings = defaultGetOrganizationSettings,
} = {}) {
  try {
    const status = await getOnboardingStatus();
    const bootstrap = resolveOnboardingBootstrap({ capabilities, status });

    if (bootstrap.existingOrganization) {
      const orgSettings = await loadOnboardingOrganizationSettings({ getOrganizationSettings });
      return {
        shouldRedirectTo: null,
        error: null,
        bootstrap,
        organizations: [],
        suggestedOrganization: null,
        orgSettings,
      };
    }

    if (!bootstrap.userType) {
      const organizationData = await loadOnboardingOrganizations({
        targetOrgId,
        getOrganizations,
      });

      return {
        shouldRedirectTo: null,
        error: null,
        bootstrap,
        organizations: organizationData.organizations,
        suggestedOrganization: organizationData.suggestedOrganization,
        orgSettings: {
          isDiscoverable: null,
          membershipMode: null,
          organizationName: '',
        },
      };
    }

    return {
      shouldRedirectTo: null,
      error: null,
      bootstrap,
      organizations: [],
      suggestedOrganization: null,
      orgSettings: {
        isDiscoverable: null,
        membershipMode: null,
        organizationName: '',
      },
    };
  } catch (error) {
    return {
      shouldRedirectTo: isAuthError(error) ? '/' : null,
      error: isAuthError(error) ? null : 'Failed to load onboarding status',
      bootstrap: resolveOnboardingBootstrap({ capabilities, status: null }),
      organizations: [],
      suggestedOrganization: null,
      orgSettings: {
        isDiscoverable: null,
        membershipMode: null,
        organizationName: '',
      },
    };
  }
}

export async function saveOnboardingRoleIntent({ roleIntent, saveRoleIntent }) {
  if (!roleIntent) {
    throw new Error('Please select an option to continue');
  }

  try {
    await saveRoleIntent(roleIntent);
    return { nextStep: 2 };
  } catch (error) {
    throw toReadableError(error, 'Failed to save your preference');
  }
}

export async function submitApplicantJoinWithCode({
  inviteCode,
  joinWithCode = defaultSubmitJoinWithCode,
} = {}) {
  if (!inviteCode || !inviteCode.trim()) {
    throw new Error('Please enter an invite code');
  }

  try {
    const data = await joinWithCode(inviteCode.trim());
    return {
      resultOrgName: data?.organization_name || null,
      membershipStatus: 'joined',
      nextStep: 3,
    };
  } catch (error) {
    throw toReadableError(error, 'Invalid invite code');
  }
}

export async function submitApplicantOrganizationSelection({
  organization,
  completeOnboarding = defaultCompleteOnboarding,
} = {}) {
  try {
    const data = await completeOnboarding({
      organization_id: organization.id,
      confirm_organization: true,
    });

    return {
      resultOrgName: data?.organization_name || organization?.name || null,
      membershipStatus: data?.membership_status || null,
      nextStep: 3,
    };
  } catch (error) {
    throw toReadableError(error, 'Failed to join organization');
  }
}

export async function finalizeApplicantOnboarding({
  organizationId = null,
  walletPaired = false,
  deviceId = null,
  completeOnboarding = defaultCompleteOnboarding,
  refreshUser = async () => {},
} = {}) {
  try {
    await completeOnboarding({
      organization_id: organizationId,
      wallet_paired: walletPaired,
      device_id: deviceId,
    });

    await refreshUser();

    return {
      nextStep: 4,
    };
  } catch (error) {
    throw toReadableError(error, 'Failed to complete setup');
  }
}

export async function checkOnboardingOrganizationName({
  name,
  checkOrganizationName = defaultCheckOrganizationName,
} = {}) {
  if (!name || name.trim().length < 3) {
    return {
      available: null,
      error: null,
    };
  }

  const trimmedName = name.trim();

  try {
    const data = await checkOrganizationName(trimmedName);
    return {
      available: Boolean(data?.available),
      error: data?.available
        ? null
        : `Organization name "${trimmedName}" is already taken. Please choose a different name.`,
    };
  } catch (error) {
    const message = getErrorMessage(error);
    return {
      available: false,
      error: message || 'Failed to check name availability',
    };
  }
}

export async function submitVendorOnboardingCompletion({
  existingOrganizationId = null,
  newOrgName,
  newOrgDescription,
  newOrgType,
  jurisdiction,
  isDiscoverable,
  membershipMode,
  trustProfile,
  completeOnboarding = defaultCompleteOnboarding,
} = {}) {
  const payload = {
    is_discoverable: isDiscoverable,
    membership_mode: membershipMode,
    trust_framework_codes: trustProfile,
  };

  if (existingOrganizationId) {
    payload.organization_id = existingOrganizationId;
  } else {
    payload.organization_name = newOrgName.trim();
    payload.organization_description = newOrgDescription.trim() || null;
    payload.organization_type = newOrgType || null;
    payload.jurisdiction = jurisdiction?.trim() || null;
  }

  try {
    const data = await completeOnboarding(payload);
    return {
      resultOrgName: data?.organization_name || newOrgName?.trim() || null,
      resultInviteCode: data?.invite_code || null,
      membershipStatus: 'owner',
      nextStep: 3,
    };
  } catch (error) {
    const fallbackMessage = existingOrganizationId
      ? 'Failed to save organization settings'
      : 'Failed to create organization';
    throw toReadableError(error, fallbackMessage);
  }
}