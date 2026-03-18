import { describe, expect, it, vi } from 'vitest';

import {
  checkOnboardingOrganizationName,
  finalizeApplicantOnboarding,
  loadOnboardingBootstrap,
  saveOnboardingRoleIntent,
  submitApplicantJoinWithCode,
  submitApplicantOrganizationSelection,
  submitVendorOnboardingCompletion,
} from './onboardingUseCases';

describe('onboarding use cases', () => {
  it('loads applicant bootstrap data with discoverable organizations and a suggested organization', async () => {
    await expect(loadOnboardingBootstrap({
      capabilities: { apply: true },
      targetOrgId: 'org-2',
      getOnboardingStatus: vi.fn().mockResolvedValue({}),
      getOrganizations: vi.fn().mockResolvedValue([
        { id: 'org-1', name: 'Acme' },
        { id: 'org-2', name: 'Beta' },
      ]),
    })).resolves.toEqual({
      shouldRedirectTo: null,
      error: null,
      bootstrap: {
        userType: null,
        roleLocked: false,
        existingOrganization: null,
        presetOrganizationName: '',
      },
      organizations: [
        { id: 'org-1', name: 'Acme' },
        { id: 'org-2', name: 'Beta' },
      ],
      suggestedOrganization: { id: 'org-2', name: 'Beta' },
      orgSettings: {
        isDiscoverable: null,
        membershipMode: null,
        organizationName: '',
      },
    });
  });

  it('loads locked vendor bootstrap data with organization settings', async () => {
    await expect(loadOnboardingBootstrap({
      capabilities: { 'org:manage': true },
      getOnboardingStatus: vi.fn().mockResolvedValue({
        organization_id: 'org-9',
        organization_name: 'Gamma',
      }),
      getOrganizationSettings: vi.fn().mockResolvedValue({
        is_discoverable: true,
        membership_mode: 'approval',
        organization_name: 'Gamma',
      }),
    })).resolves.toEqual({
      shouldRedirectTo: null,
      error: null,
      bootstrap: {
        userType: 'vendor',
        roleLocked: true,
        existingOrganization: { id: 'org-9', name: 'Gamma' },
        presetOrganizationName: 'Gamma',
      },
      organizations: [],
      suggestedOrganization: null,
      orgSettings: {
        isDiscoverable: true,
        membershipMode: 'approval',
        organizationName: 'Gamma',
      },
    });
  });

  it('redirects to the landing page on auth errors during bootstrap', async () => {
    await expect(loadOnboardingBootstrap({
      capabilities: { apply: true },
      getOnboardingStatus: vi.fn().mockRejectedValue({
        status: 401,
        response: { error: { code: 'AUTH.REQUIRED' } },
      }),
    })).resolves.toMatchObject({
      shouldRedirectTo: '/',
      error: null,
      organizations: [],
    });
  });

  it('saves role intent and advances applicant onboarding', async () => {
    const saveRoleIntent = vi.fn().mockResolvedValue(undefined);

    await expect(saveOnboardingRoleIntent({
      roleIntent: 'apply_for_credentials',
      saveRoleIntent,
    })).resolves.toEqual({ nextStep: 2 });

    expect(saveRoleIntent).toHaveBeenCalledWith('apply_for_credentials');
  });

  it('joins applicants by code and confirms organization selection', async () => {
    await expect(submitApplicantJoinWithCode({
      inviteCode: ' ABC123XY ',
      joinWithCode: vi.fn().mockResolvedValue({ organization_name: 'Acme Travel' }),
    })).resolves.toEqual({
      resultOrgName: 'Acme Travel',
      membershipStatus: 'joined',
      nextStep: 3,
    });

    await expect(submitApplicantOrganizationSelection({
      organization: { id: 'org-1', name: 'Acme Travel' },
      completeOnboarding: vi.fn().mockResolvedValue({
        organization_name: 'Acme Travel',
        membership_status: 'pending_approval',
      }),
    })).resolves.toEqual({
      resultOrgName: 'Acme Travel',
      membershipStatus: 'pending_approval',
      nextStep: 3,
    });
  });

  it('finalizes applicant onboarding and refreshes the user session', async () => {
    const refreshUser = vi.fn().mockResolvedValue(undefined);

    await expect(finalizeApplicantOnboarding({
      organizationId: 'org-3',
      walletPaired: true,
      deviceId: 'device-1',
      completeOnboarding: vi.fn().mockResolvedValue({ success: true }),
      refreshUser,
    })).resolves.toEqual({ nextStep: 4 });

    expect(refreshUser).toHaveBeenCalledTimes(1);
  });

  it('checks organization name availability and submits vendor completion', async () => {
    await expect(checkOnboardingOrganizationName({
      name: 'Acme Travel',
      checkOrganizationName: vi.fn().mockResolvedValue({ available: false }),
    })).resolves.toEqual({
      available: false,
      error: 'Organization name "Acme Travel" is already taken. Please choose a different name.',
    });

    await expect(submitVendorOnboardingCompletion({
      newOrgName: 'Acme Travel',
      newOrgDescription: 'Trusted issuer',
      newOrgType: 'enterprise',
      jurisdiction: 'US',
      isDiscoverable: true,
      membershipMode: 'approval',
      trustProfile: ['eu'],
      completeOnboarding: vi.fn().mockResolvedValue({
        organization_name: 'Acme Travel',
        invite_code: 'ABC123XY',
      }),
    })).resolves.toEqual({
      resultOrgName: 'Acme Travel',
      resultInviteCode: 'ABC123XY',
      membershipStatus: 'owner',
      nextStep: 3,
    });
  });
});