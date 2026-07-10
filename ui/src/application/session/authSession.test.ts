import { describe, expect, it } from 'vitest'
import {
  DEFAULT_LOGIN_REDIRECT,
  createEnrichedUser,
  deriveCapabilities,
  getFallbackOrganizations,
  getAuthFlags,
  getConsoleEligibleOrganizations,
  membershipHasOrgConsoleAccess,
  normalizeCapabilities,
  parseOrganizationClaim,
  resolveActiveOrganization,
  resolveInteractiveLoginRedirect,
  resolveUserOrganizations,
  updateUserActiveOrganization,
} from './authSession'

describe('authSession helpers', () => {
  it('sends plain login button clicks to the console by default', () => {
    expect(resolveInteractiveLoginRedirect(undefined)).toBe(DEFAULT_LOGIN_REDIRECT)
    expect(resolveInteractiveLoginRedirect({ type: 'click' })).toBe(DEFAULT_LOGIN_REDIRECT)
  })

  it('preserves explicit login redirects for protected and deep-link flows', () => {
    expect(resolveInteractiveLoginRedirect('/developers')).toBe('/developers')
    expect(resolveInteractiveLoginRedirect('/organizations/join?inviteToken=token-1')).toBe('/organizations/join?inviteToken=token-1')
  })

  it('parses organization claims into memberships', () => {
    expect(parseOrganizationClaim({
      'org-1': { name: 'Acme' },
      'org-2': { name: 'Beta' },
    })).toEqual({
      id: 'org-1',
      name: 'Acme',
      organizations: [
        { id: 'org-1', name: 'Acme' },
        { id: 'org-2', name: 'Beta' },
      ],
    })
  })

  it('normalizes capabilities from arrays and maps', () => {
    expect(normalizeCapabilities(['apply', 'org:view'])).toEqual({ apply: true, 'org:view': true })
    expect(normalizeCapabilities({ apply: true, 'org:view': false })).toEqual({ apply: true, 'org:view': false })
  })

  it('derives capabilities from roles and memberships', () => {
    expect(
      deriveCapabilities({ roles: ['vendor'] }, [{ id: 'org-1', name: 'Acme' }])
    ).toMatchObject({
      apply: true,
      'org:view': true,
      'org:manage': true,
      'org:issue': true,
      'admin:platform': false,
    })
  })

  it('does not downgrade role-derived admin capability when API flags are false', () => {
    expect(
      deriveCapabilities({
        roles: ['administrator'],
        capabilities: {
          'admin:platform': false,
          'org:view': false,
        },
      }, [])
    ).toMatchObject({
      'admin:platform': true,
      'org:view': true,
    })
  })

  it('treats Keycloak admin as org-capable even when the role claim uses admin', () => {
    expect(deriveCapabilities({ roles: ['admin'] }, [])).toMatchObject({
      'admin:platform': true,
      'org:view': true,
      'org:manage': true,
    })
    expect(getAuthFlags({ roles: ['admin'], capabilities: { 'admin:platform': true } })).toMatchObject({
      isAdministrator: true,
    })
  })

  it('falls back to claim memberships when the organizations API returns nothing', () => {
    const rawUser = {
      organization: {
        'org-1': { name: 'Acme' },
      },
    }

    expect(getFallbackOrganizations(rawUser)).toEqual([
      { id: 'org-1', name: 'Acme', display_name: 'Acme' },
    ])
    expect(resolveUserOrganizations(rawUser, [])).toEqual([
      { id: 'org-1', name: 'Acme', display_name: 'Acme' },
    ])
  })

  it('falls back to the current organization when memberships are unavailable', () => {
    const rawUser = {
      organization_id: 'org-1',
      organization_name: 'Marty Identity Platform',
    }

    expect(resolveUserOrganizations(rawUser, null)).toEqual([
      { id: 'org-1', name: 'Marty Identity Platform', display_name: 'Marty Identity Platform' },
    ])
  })

  it('prefers the stored org id when resolving the active org', () => {
    expect(
      resolveActiveOrganization({
        storedOrgId: 'org-2',
        organizations: [
          { id: 'org-1', name: 'Acme' },
          { id: 'org-2', name: 'Beta' },
        ],
        rawUser: null,
      })
    ).toEqual({ id: 'org-2', name: 'Beta' })
  })

  it('creates an enriched auth user with organizations and derived capabilities', () => {
    const rawUser = {
      user_id: 'user-1',
      roles: ['administrator'],
      organization_id: 'org-1',
      organization_name: 'Acme',
    }

    expect(createEnrichedUser(rawUser, [{ id: 'org-1', name: 'Acme' }], 'org-1')).toMatchObject({
      user_id: 'user-1',
      organization_id: 'org-1',
      organization_name: 'Acme',
      organizations: [{ id: 'org-1', name: 'Acme' }],
      capabilities: {
        apply: true,
        'org:view': true,
        'org:manage': true,
        'org:issue': true,
        'admin:platform': true,
      },
    })
  })

  it('derives a default applicant organization from memberships when no explicit default is present', () => {
    const rawUser = {
      user_id: 'user-1',
      roles: ['applicant'],
      organization_id: null,
      organization_name: null,
    }

    expect(createEnrichedUser(rawUser, [{ id: 'org-1', name: 'Acme' }], null)).toMatchObject({
      organization_id: 'org-1',
      organization_name: 'Acme',
      default_organization_id: 'org-1',
      default_organization_name: 'Acme',
    })
  })

  it('preserves an explicit default applicant organization from the auth payload', () => {
    const rawUser = {
      user_id: 'user-1',
      roles: ['applicant'],
      organization_id: 'org-2',
      organization_name: 'Beta',
      default_organization_id: 'org-1',
      default_organization_name: 'Acme',
    }

    expect(createEnrichedUser(
      rawUser,
      [{ id: 'org-1', name: 'Acme' }, { id: 'org-2', name: 'Beta' }],
      'org-2'
    )).toMatchObject({
      organization_id: 'org-2',
      organization_name: 'Beta',
      default_organization_id: 'org-1',
      default_organization_name: 'Acme',
    })
  })

  it('restores the active organization from raw user claims when memberships are unavailable', () => {
    const rawUser = {
      user_id: 'user-1',
      roles: ['applicant'],
      organization_id: 'org-1',
      organization_name: 'Acme',
    }

    expect(createEnrichedUser(rawUser, [], null)).toMatchObject({
      user_id: 'user-1',
      organization_id: 'org-1',
      organization_name: 'Acme',
      organizations: [{ id: 'org-1', name: 'Acme', display_name: 'Acme' }],
    })
  })

  it('restores the active Marty organization from the raw Keycloak organization claim when the memberships API is empty', () => {
    const rawUser = {
      user_id: 'user-1',
      roles: ['administrator'],
      organization: {
        'marty-org': { name: 'Marty Identity Platform' },
        'org-2': { name: 'Beta Org' },
      },
    }

    expect(createEnrichedUser(rawUser, [], 'marty-org')).toMatchObject({
      user_id: 'user-1',
      organization_id: 'marty-org',
      organization_name: 'Marty Identity Platform',
      organizations: [
        { id: 'marty-org', name: 'Marty Identity Platform', display_name: 'Marty Identity Platform' },
        { id: 'org-2', name: 'Beta Org', display_name: 'Beta Org' },
      ],
      capabilities: {
        apply: true,
        'org:view': true,
        'org:manage': true,
        'org:issue': true,
        'admin:platform': true,
      },
    })
  })

  it('keeps a Keycloak org eligible when backend membership is applicant-only', () => {
    const rawUser = {
      user_id: 'user-1',
      roles: ['administrator'],
      organization: {
        'marty-org': { name: 'Marty Identity Platform' },
      },
    }
    const fetchedOrganizations = [{
      id: 'marty-org',
      name: 'marty',
      display_name: 'Marty Identity Platform',
      membership: {
        roles: [{ id: 'role-applicant', name: 'applicant' }],
        permissions: ['organization:view', 'application:view'],
        has_org_console_access: false,
      },
    }]

    const enriched = createEnrichedUser(rawUser, fetchedOrganizations, 'marty-org')

    expect(enriched.organizations[0].membership.has_org_console_access).toBe(true)
    expect(getConsoleEligibleOrganizations(enriched.organizations)).toHaveLength(1)
    expect(enriched.organization_id).toBe('marty-org')
  })

  it('derives org console access from membership roles and permissions', () => {
    expect(membershipHasOrgConsoleAccess({
      membership: {
        roles: [{ name: 'viewer' }],
        permissions: ['organization:view'],
        has_org_console_access: false,
      },
    })).toBe(true)

    expect(membershipHasOrgConsoleAccess({
      membership: {
        roles: [{ name: 'applicant' }],
        permissions: ['organization:view', 'application:view'],
        has_org_console_access: false,
      },
    })).toBe(false)
  })

  it('keeps Canvas LTI learners in applicant-only access even when they have an issuer org for catalog scope', () => {
    const rawUser = {
      user_id: 'canvas-learner-1',
      roles: ['applicant', 'canvas_lti_learner'],
      organization_id: 'marty-org',
      organization_name: 'Marty',
    }

    const enriched = createEnrichedUser(rawUser, [{ id: 'marty-org', name: 'Marty' }], 'marty-org')

    expect(enriched.capabilities).toMatchObject({
      apply: true,
      'org:view': false,
      'org:manage': false,
      'org:issue': false,
    })
    expect(getConsoleEligibleOrganizations(enriched.organizations)).toEqual([])
    expect(enriched.default_organization_id).toBe('marty-org')
  })

  it('updates active organization in auth state', () => {
    const previousUser = {
      organization_id: null,
      organization_name: 'Acme',
      organizations: [{ id: 'org-1', name: 'Acme' }],
      capabilities: { apply: true },
    }

    expect(updateUserActiveOrganization(previousUser, 'org-1')).toMatchObject({
      organization_id: 'org-1',
      organization_name: 'Acme',
      capabilities: { apply: true, 'org:view': true },
    })
  })

  it('adds supplied selected organization details when auth memberships are stale', () => {
    const previousUser = {
      organization_id: null,
      organizations: [{ id: 'marty-org', name: 'Marty' }],
      capabilities: { apply: true, 'org:view': true },
    }

    const updated = updateUserActiveOrganization(previousUser, 'org-new', {
      id: 'org-new',
      name: 'acme',
      display_name: 'Acme',
      membership: {
        roles: [{ name: 'owner' }],
        has_org_console_access: true,
      },
    })

    expect(updated).toMatchObject({
      organization_id: 'org-new',
      organization_name: 'Acme',
      capabilities: { apply: true, 'org:view': true },
      organizations: [
        { id: 'marty-org', name: 'Marty' },
        {
          id: 'org-new',
          name: 'acme',
          display_name: 'Acme',
          membership: {
            roles: [{ name: 'owner' }],
            has_org_console_access: true,
          },
        },
      ],
    })
  })

  it('returns the previous auth user when the same active organization is written again', () => {
    const previousUser = {
      organization_id: 'org-1',
      organization_name: 'Acme',
      organizations: [{ id: 'org-1', name: 'Acme' }],
      capabilities: { apply: true, 'org:view': true },
    }

    expect(updateUserActiveOrganization(previousUser, 'org-1')).toBe(previousUser)
  })

  it('preserves impersonation context when updating active organization', () => {
    const impersonationContext = {
      active: true,
      admin_email: 'admin@example.com',
      target_email: 'vendor@example.com',
    }

    const previousUser = {
      organization_id: null,
      organizations: [{ id: 'org-1', name: 'Acme' }],
      capabilities: { apply: true },
      impersonation: impersonationContext,
    }

    const updated = updateUserActiveOrganization(previousUser, 'org-1')

    expect(updated?.impersonation).toEqual(impersonationContext)
  })

  it('derives auth flags for the context shell', () => {
    expect(getAuthFlags({ roles: ['vendor'], capabilities: { 'org:view': true } })).toEqual({
      isAdministrator: false,
      isVendor: true,
      isApplicant: true,
      capabilities: { 'org:view': true },
    })
  })

  it('preserves impersonation context from raw user through enrichment', () => {
    const impersonationContext = {
      active: true,
      admin_user_id: 'admin-1',
      admin_username: 'admin',
      admin_email: 'admin@example.com',
      admin_display_name: 'Admin User',
      target_user_id: 'user-1',
      target_email: 'vendor@example.com',
      organization_id: 'org-1',
      organization_name: 'Vendor Org',
      started_at: '2026-04-16T02:00:00.000Z',
      launch_mode: 'new-tab',
    }

    const rawUser = {
      user_id: 'user-1',
      email: 'vendor@example.com',
      roles: ['vendor'],
      organization_id: 'org-1',
      organization_name: 'Vendor Org',
      impersonation: impersonationContext,
    }

    const enriched = createEnrichedUser(rawUser, [{ id: 'org-1', name: 'Vendor Org' }], 'org-1')

    expect(enriched).toMatchObject({
      user_id: 'user-1',
      email: 'vendor@example.com',
      impersonation: impersonationContext,
    })
  })

  it('returns null impersonation when not active', () => {
    const rawUser = {
      user_id: 'user-1',
      email: 'user@example.com',
      roles: ['applicant'],
      impersonation: null,
    }

    const enriched = createEnrichedUser(rawUser, [], null)

    expect(enriched?.impersonation).toBeNull()
  })
})
