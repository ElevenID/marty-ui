import { describe, expect, it } from 'vitest'
import {
  createEnrichedUser,
  deriveCapabilities,
  getAuthFlags,
  getFallbackOrganizations,
  normalizeCapabilities,
  parseOrganizationClaim,
  resolveActiveOrganization,
  resolveUserOrganizations,
  updateUserActiveOrganization,
} from './authSession'

describe('authSession helpers', () => {
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

  it('falls back to claim memberships when the API returns nothing', () => {
    const rawUser = {
      organization: {
        'org-1': { name: 'Acme' },
      },
    }

    expect(getFallbackOrganizations(rawUser)).toEqual([{ id: 'org-1', name: 'Acme' }])
    expect(resolveUserOrganizations(rawUser, [])).toEqual([{ id: 'org-1', name: 'Acme' }])
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

  it('updates active organization in auth state', () => {
    const previousUser = {
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

  it('derives auth flags for the context shell', () => {
    expect(getAuthFlags({ roles: ['vendor'], capabilities: { 'org:view': true } })).toEqual({
      isAdministrator: false,
      isVendor: true,
      isApplicant: true,
      capabilities: { 'org:view': true },
    })
  })
})
