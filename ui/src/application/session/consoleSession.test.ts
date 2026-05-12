import { describe, expect, it } from 'vitest'
import {
  getDefaultLandingPath,
  isOrgConsoleBlocked,
  normalizeConsolePreferences,
  resolveApplicantOrganizationId,
  resolveActiveOrgSelection,
  resolveConsoleBootstrap,
  resolveModeChange,
} from './consoleSession'

describe('consoleSession helpers', () => {
  it('normalizes missing preferences', () => {
    expect(normalizeConsolePreferences(undefined)).toEqual({
      last_view_mode: 'applicant',
      last_active_org_id: null,
    })
  })

  it('resolves bootstrap state from memberships and preferences', () => {
    expect(
      resolveConsoleBootstrap({
        preferences: { last_view_mode: 'org', last_active_org_id: 'org-2' },
        memberships: [
          { id: 'org-1' },
          { id: 'org-2' },
        ],
        localStoredOrgId: 'org-1',
      })
    ).toEqual({
      mode: 'org',
      activeOrgId: 'org-2',
    })
  })

  it('forces applicant mode when there are no memberships', () => {
    expect(
      resolveConsoleBootstrap({
        preferences: { last_view_mode: 'org', last_active_org_id: 'org-2' },
        memberships: [],
        localStoredOrgId: 'org-2',
      })
    ).toEqual({
      mode: 'applicant',
      activeOrgId: null,
    })
  })

  it('resolves the applicant organization from fetched organizations when no explicit default is present', () => {
    expect(
      resolveApplicantOrganizationId({
        defaultOrganizationId: null,
        currentOrganizationId: null,
        organizations: [{ id: 'org-1' }, { id: 'org-2' }],
      })
    ).toBe('org-1')
  })

  it('keeps the current applicant organization when it still exists in fetched organizations', () => {
    expect(
      resolveApplicantOrganizationId({
        defaultOrganizationId: null,
        currentOrganizationId: 'org-2',
        organizations: [{ id: 'org-1' }, { id: 'org-2' }],
      })
    ).toBe('org-2')
  })

  it('resolves mode changes to applicant mode', () => {
    expect(
      resolveModeChange({
        newMode: 'applicant',
        activeOrgId: 'org-1',
        memberships: [{ id: 'org-1' }],
      })
    ).toEqual({
      mode: 'applicant',
      activeOrgId: null,
      destination: '/console/applicant/catalog',
      persistence: {
        last_view_mode: 'applicant',
        last_active_org_id: null,
      },
    })
  })

  it('auto-selects the only org when switching to org mode', () => {
    expect(
      resolveModeChange({
        newMode: 'org',
        activeOrgId: null,
        memberships: [{ id: 'org-1' }],
      })
    ).toEqual({
      mode: 'org',
      activeOrgId: 'org-1',
      destination: '/console/org',
      authOrgId: 'org-1',
      persistence: {
        last_view_mode: 'org',
        last_active_org_id: 'org-1',
      },
    })
  })

  it('requires setup when entering org mode without a selection', () => {
    expect(
      resolveModeChange({
        newMode: 'org',
        activeOrgId: null,
        memberships: [{ id: 'org-1' }, { id: 'org-2' }],
      })
    ).toEqual({
      mode: 'org',
      activeOrgId: null,
      destination: '/console/org/setup',
      persistence: {
        last_view_mode: 'org',
        last_active_org_id: null,
      },
    })
  })

  it('validates org selections against memberships', () => {
    expect(
      resolveActiveOrgSelection({
        orgId: 'org-2',
        currentMode: 'applicant',
        memberships: [{ id: 'org-1' }],
      })
    ).toEqual({
      valid: false,
      mode: 'applicant',
      activeOrgId: 'org-2',
      destination: null,
      persistence: null,
    })
  })

  it('resolves valid org selections into org mode', () => {
    expect(
      resolveActiveOrgSelection({
        orgId: 'org-1',
        currentMode: 'applicant',
        memberships: [{ id: 'org-1' }],
      })
    ).toEqual({
      valid: true,
      mode: 'org',
      activeOrgId: 'org-1',
      destination: '/console/org',
      persistence: {
        last_view_mode: 'org',
        last_active_org_id: 'org-1',
      },
    })
  })

  it('detects blocked org console state', () => {
    expect(isOrgConsoleBlocked('org', null)).toBe(true)
    expect(isOrgConsoleBlocked('org', 'org-1')).toBe(false)
  })

  it('resolves the default landing path', () => {
    expect(
      getDefaultLandingPath({
        mode: 'org',
        activeOrgId: 'org-1',
        memberships: [{ id: 'org-1' }],
      })
    ).toBe('/console/org')

    expect(
      getDefaultLandingPath({
        mode: 'applicant',
        activeOrgId: null,
        memberships: [],
      })
    ).toBe('/console/applicant/catalog')
  })
})
