/**
 * Interaction tests: Onboarding Journey
 *
 * Exercises the multi-step onboarding flow for both applicant and vendor
 * personas through the headless UI layer:
 *
 *   Applicant path: bootstrap → role intent → join org → finalize
 *   Vendor path:    bootstrap → org creation → trust profile → complete
 */

import { describe, expect, it, vi } from 'vitest';

import {
  loadOnboardingBootstrap,
  saveOnboardingRoleIntent,
  submitApplicantJoinWithCode,
  submitApplicantOrganizationSelection,
  finalizeApplicantOnboarding,
  checkOnboardingOrganizationName,
  submitVendorOnboardingCompletion,
} from '../onboarding/onboardingUseCases';

describe('Onboarding — applicant journey', () => {
  it('discovers organizations, picks one, and completes onboarding', async () => {
    // ── Step 1: Bootstrap ───────────────────────────────────
    const bootstrap = await loadOnboardingBootstrap({
      capabilities: { apply: true },
      targetOrgId: 'org-acme',
      getOnboardingStatus: vi.fn().mockResolvedValue({}),
      getOrganizations: vi.fn().mockResolvedValue([
        { id: 'org-acme', name: 'Acme Corp' },
        { id: 'org-beta', name: 'Beta Inc' },
      ]),
    });

    expect(bootstrap.error).toBeNull();
    expect(bootstrap.bootstrap.userType).toBeNull(); // not a vendor
    expect(bootstrap.organizations).toHaveLength(2);
    expect(bootstrap.suggestedOrganization).toMatchObject({ id: 'org-acme' });

    // ── Step 2: Save role intent ────────────────────────────
    const roleResult = await saveOnboardingRoleIntent({
      roleIntent: 'apply_for_credentials',
      saveRoleIntent: vi.fn().mockResolvedValue(undefined),
    });
    expect(roleResult.nextStep).toBe(2);

    // ── Step 3: Select suggested organization ───────────────
    const joinResult = await submitApplicantOrganizationSelection({
      organization: bootstrap.suggestedOrganization,
      completeOnboarding: vi.fn().mockResolvedValue({
        organization_name: 'Acme Corp',
        membership_status: 'member',
      }),
    });
    expect(joinResult.resultOrgName).toBe('Acme Corp');
    expect(joinResult.membershipStatus).toBe('member');
    expect(joinResult.nextStep).toBe(3);

    // ── Step 4: Finalize ────────────────────────────────────
    const refreshUser = vi.fn().mockResolvedValue(undefined);
    const finalResult = await finalizeApplicantOnboarding({
      organizationId: 'org-acme',
      walletPaired: false,
      completeOnboarding: vi.fn().mockResolvedValue(undefined),
      refreshUser,
    });
    expect(finalResult.nextStep).toBe(4);
    expect(refreshUser).toHaveBeenCalled();
  });

  it('joins via invite code when org is not discoverable', async () => {
    const joinResult = await submitApplicantJoinWithCode({
      inviteCode: 'ACME-1234',
      joinWithCode: vi.fn().mockResolvedValue({
        organization_name: 'Acme Corp',
      }),
    });

    expect(joinResult.resultOrgName).toBe('Acme Corp');
    expect(joinResult.membershipStatus).toBe('joined');
    expect(joinResult.nextStep).toBe(3);
  });

  it('rejects empty invite code', async () => {
    await expect(submitApplicantJoinWithCode({
      inviteCode: '',
      joinWithCode: vi.fn(),
    })).rejects.toThrow('Please enter an invite code');
  });
});

describe('Onboarding — vendor journey', () => {
  it('creates a new organization and configures trust profile', async () => {
    // ── Step 1: Bootstrap detects vendor capabilities ───────
    const bootstrap = await loadOnboardingBootstrap({
      capabilities: { 'org:manage': true },
      getOnboardingStatus: vi.fn().mockResolvedValue({}),
      getOrganizations: vi.fn().mockResolvedValue([]),
    });

    expect(bootstrap.error).toBeNull();
    expect(bootstrap.bootstrap.userType).toBe('vendor');

    // ── Step 2: Check org name availability ─────────────────
    const nameCheck = await checkOnboardingOrganizationName({
      name: 'NewVendor',
      checkOrganizationName: vi.fn().mockResolvedValue({ available: true }),
    });
    expect(nameCheck.available).toBe(true);
    expect(nameCheck.error).toBeNull();

    // ── Step 3: Submit vendor completion ────────────────────
    const vendorResult = await submitVendorOnboardingCompletion({
      newOrgName: 'NewVendor',
      newOrgDescription: 'A great vendor',
      newOrgType: 'enterprise',
      jurisdiction: 'US',
      isDiscoverable: true,
      membershipMode: 'invite_only',
      trustProfile: ['eidas', 'nist_800_63'],
      completeOnboarding: vi.fn().mockResolvedValue({
        organization_name: 'NewVendor',
        invite_code: 'INV-9999',
      }),
    });

    expect(vendorResult.resultOrgName).toBe('NewVendor');
    expect(vendorResult.resultInviteCode).toBe('INV-9999');
    expect(vendorResult.membershipStatus).toBe('owner');
    expect(vendorResult.nextStep).toBe(3);
  });

  it('detects taken org name and returns error', async () => {
    const nameCheck = await checkOnboardingOrganizationName({
      name: 'ExistingOrg',
      checkOrganizationName: vi.fn().mockResolvedValue({ available: false }),
    });

    expect(nameCheck.available).toBe(false);
    expect(nameCheck.error).toContain('already taken');
  });

  it('resumes vendor onboarding with existing organization', async () => {
    const bootstrap = await loadOnboardingBootstrap({
      capabilities: { 'org:manage': true },
      getOnboardingStatus: vi.fn().mockResolvedValue({
        organization_id: 'org-existing',
        organization_name: 'ExistingOrg',
      }),
      getOrganizationSettings: vi.fn().mockResolvedValue({
        is_discoverable: true,
        membership_mode: 'approval',
        organization_name: 'ExistingOrg',
      }),
    });

    expect(bootstrap.bootstrap.existingOrganization).toMatchObject({
      id: 'org-existing',
      name: 'ExistingOrg',
    });
    expect(bootstrap.bootstrap.roleLocked).toBe(true);
    expect(bootstrap.orgSettings.isDiscoverable).toBe(true);
  });
});
