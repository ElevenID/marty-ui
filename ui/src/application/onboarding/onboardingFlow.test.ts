import { describe, expect, it } from 'vitest'
import {
  getOnboardingSteps,
  hasOrganizationCapability,
  resolveDomainJoinResult,
  resolveOnboardingBootstrap,
  resolveTechnicalIdentityAdvance,
  shouldAutoAdvanceLockedRole,
  validateBusinessContextStep,
  validateOrganizationSelection,
  validateRoleSelection,
  validateTrustProfileSelection,
  validateVendorOrganizationStep,
} from './onboardingFlow'

describe('onboardingFlow helpers', () => {
  it('detects organization capability from capability flags', () => {
    expect(hasOrganizationCapability({ 'org:view': true })).toBe(true)
    expect(hasOrganizationCapability({ apply: true })).toBe(false)
  })

  it('resolves vendor bootstrap state from onboarding status', () => {
    expect(
      resolveOnboardingBootstrap({
        capabilities: { 'org:manage': true },
        status: { organization_id: 'org-1', organization_name: 'Acme' },
      })
    ).toEqual({
      userType: 'vendor',
      roleLocked: true,
      existingOrganization: { id: 'org-1', name: 'Acme' },
      presetOrganizationName: 'Acme',
    })
  })

  it('does not bootstrap applicant users into vendor mode', () => {
    expect(
      resolveOnboardingBootstrap({
        capabilities: { apply: true },
        status: { organization_id: 'org-1', organization_name: 'Acme' },
      })
    ).toEqual({
      userType: null,
      roleLocked: false,
      existingOrganization: null,
      presetOrganizationName: '',
    })
  })

  it('auto-advances locked roles only on the first step', () => {
    expect(shouldAutoAdvanceLockedRole({ roleLocked: true, userType: 'vendor', activeStep: 0 })).toBe(true)
    expect(shouldAutoAdvanceLockedRole({ roleLocked: true, userType: 'vendor', activeStep: 1 })).toBe(false)
  })

  it('returns the correct step sets', () => {
    expect(getOnboardingSteps({ userType: 'applicant', hasExistingOrganization: false, skipTrustSetup: false })).toHaveLength(5)
    expect(getOnboardingSteps({ userType: 'vendor', hasExistingOrganization: true, skipTrustSetup: false })).toEqual([
      'Choose Your Role',
      'Organization Settings',
      'Business Context',
      'Technical Identity',
      'Review',
      'Complete',
    ])
    expect(getOnboardingSteps({ userType: 'vendor', hasExistingOrganization: false, skipTrustSetup: true })).toEqual([
      'Choose Your Role',
      'Create Organization',
      'Trust Profile',
      'Complete',
    ])
  })

  it('validates required role selection', () => {
    expect(validateRoleSelection(null)).toEqual({ valid: false, error: 'Please select a role to continue' })
    expect(validateRoleSelection('vendor')).toEqual({ valid: true, error: null })
  })

  it('rejects invite-only org browse selections', () => {
    expect(validateOrganizationSelection({ membership_mode: 'invite_only' })).toEqual({
      valid: false,
      requiresConfirmation: false,
      error: 'This organization only accepts members via invitation. Please use an invite code.',
    })
  })

  it('validates vendor org step constraints', () => {
    expect(
      validateVendorOrganizationStep({
        hasExistingOrganization: false,
        newOrgName: '',
        orgNameChecking: false,
        orgNameAvailable: null,
        orgNameError: null,
      })
    ).toEqual({ valid: false, error: 'Please enter an organization name', nextStep: null })

    expect(
      validateVendorOrganizationStep({
        hasExistingOrganization: false,
        newOrgName: 'Acme',
        orgNameChecking: false,
        orgNameAvailable: true,
        orgNameError: null,
      })
    ).toEqual({ valid: true, error: null, nextStep: 2 })
  })

  it('requires a trust profile before continuing', () => {
    expect(validateTrustProfileSelection([])).toEqual({
      valid: false,
      error: 'Please select at least one trust profile to continue',
    })
    expect(validateTrustProfileSelection(['eu'])).toEqual({ valid: true, error: null })
  })

  it('validates business context requirements', () => {
    expect(
      validateBusinessContextStep({
        selectedUseCases: [],
        selectedAcceptance: [],
        jurisdiction: '',
      })
    ).toEqual({ valid: false, error: 'Please select at least one credential type', nextStep: null })

    expect(
      validateBusinessContextStep({
        selectedUseCases: ['employee-id'],
        selectedAcceptance: ['wallet'],
        jurisdiction: 'US',
      })
    ).toEqual({ valid: true, error: null, nextStep: 4 })
  })

  it('advances technical identity to review', () => {
    expect(resolveTechnicalIdentityAdvance()).toEqual({ nextStep: 5 })
  })

  it('maps domain-join results to UI state changes', () => {
    expect(resolveDomainJoinResult({ action: 'joined', organization_name: 'Acme' })).toEqual({
      resultOrgName: 'Acme',
      membershipStatus: 'joined',
      nextStep: 3,
      closeModal: true,
    })
  })
})
