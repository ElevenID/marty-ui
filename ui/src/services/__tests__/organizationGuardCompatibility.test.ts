import { describe, expect, it, vi } from 'vitest'
import { requireOrganizationId } from '../queryUtils'
import { listApiKeys } from '../apiKeysApi'
import { listApplicationTemplates } from '../applicationTemplatesApi'
import { listAuditEvents } from '../auditApi'
import { listComplianceProfiles, requireOrganizationId as complianceOrganizationId } from '../complianceProfilesApi'
import { listDeploymentProfiles } from '../deploymentProfilesApi'
import { listFlows } from '../flowsApi'
import { requireOrganizationId as presentationOrganizationId } from '../presentationPolicyApi'
import { listSigningKeys } from '../signingKeysApi'

describe('organization guard compatibility', () => {
  const guards = [
    ['API keys', 'An active organization is required before managing API keys.', (id: never) => listApiKeys(id)],
    ['application templates', 'organization_id is required', (id: never) => listApplicationTemplates(id)],
    ['audit', 'Organization ID is required for audit operations', (id: never) => listAuditEvents(id)],
    ['compliance', 'An active organization is required before loading compliance profiles.', (id: never) => listComplianceProfiles({ organization_id: id })],
    ['deployment', 'An active organization is required before loading deployment profiles.', (id: never) => listDeploymentProfiles({ organization_id: id })],
    ['flows', 'An active organization is required before loading flows.', (id: never) => listFlows({ organization_id: id })],
    ['presentation', 'An active organization is required before loading org-scoped credential setup artifacts.', (id: never) => presentationOrganizationId({ organization_id: id })],
    ['signing keys', 'An active organization is required before loading signing keys.', (id: never) => listSigningKeys({ organizationId: id })],
  ] as const

  it.each(guards)('keeps the %s message and rejects missing IDs before any request', async (_, message, guard) => {
    const fetch = vi.spyOn(globalThis, 'fetch')
    try {
      for (const missing of [undefined, null, '', ' ', 'null', ' UNDEFINED ']) {
        await expect(Promise.resolve().then(() => guard(missing as never))).rejects.toMatchObject({ message })
      }
      expect(fetch).not.toHaveBeenCalled()
    } finally {
      fetch.mockRestore()
    }
  })

  it('retains exported string/object inputs, trimming, and per-adapter falsy conventions', async () => {
    expect(requireOrganizationId(' org-1 ')).toBe('org-1')
    expect(requireOrganizationId(0 as never)).toBe('0')
    expect(complianceOrganizationId(' org-1 ')).toBe('org-1')
    expect(complianceOrganizationId({ organization_id: 0 })).toBe('0')
    expect(presentationOrganizationId(' org-1 ')).toBe('org-1')
    expect(presentationOrganizationId({ organization_id: ' org-1 ' })).toBe('org-1')
    expect(() => presentationOrganizationId({ organization_id: 0 })).toThrow(/active organization/)
    await expect(listApplicationTemplates(0 as never)).rejects.toMatchObject({ code: 'ORG_REQUIRED' })
    await expect(listFlows({ organization_id: false })).rejects.toThrow(/active organization/)
  })

  it('keeps the shared default action message, code and status', () => {
    expect(() => requireOrganizationId(null as never, 'loading team members')).toThrow(
      expect.objectContaining({ message: 'Organization is required for loading team members.', code: 'ORG_REQUIRED', status: 400 }),
    )
  })
})
