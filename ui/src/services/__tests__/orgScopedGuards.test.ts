import { describe, expect, it } from 'vitest'

import { listOrganizationApplications } from '../applicantApi'
import {
  createCanvasIntegrationSecret,
  createCanvasPlatform,
  createCanvasProgramBinding,
  getCanvasMirrorHealth,
  listCanvasPlatforms,
} from '../canvasIntegrationsApi'
import { createComplianceProfile, requireOrganizationId as requireComplianceOrganizationId } from '../complianceProfilesApi'
import { getOrganizationIntegrationInfo, getRuntimeStatus } from '../dashboardApi'
import { createDeliveryDestination, listDeliveryDestinations } from '../deliveryDestinationsApi'
import { listOrganizationDevices } from '../devicesApi'
import { getOrganizationMembers } from '../organizationsApi'
import { requireOrganizationId as requireCredentialSetupOrganizationId } from '../presentationPolicyApi'
import { listRoles } from '../rbacApi'
import { listMembers } from '../teamApi'
import { createWebhook, listWebhooks } from '../webhooksApi'

async function expectOrgRequired(operation: Promise<unknown>) {
  await expect(operation).rejects.toMatchObject({
    code: 'ORG_REQUIRED',
    status: 400,
  })
}

describe('org-scoped service guards', () => {
  it('fails locally before org-scoped dashboard requests can be constructed', async () => {
    await expectOrgRequired(getRuntimeStatus(null as unknown as string))
    await expectOrgRequired(getOrganizationIntegrationInfo('undefined'))
  })

  it('fails locally before org membership and RBAC requests can be constructed', async () => {
    await expectOrgRequired(listMembers('null'))
    await expectOrgRequired(getOrganizationMembers(undefined as unknown as string))
    await expectOrgRequired(listRoles(''))
  })

  it('fails locally before credential tooling integration requests can be constructed', async () => {
    await expectOrgRequired(listWebhooks('undefined'))
    await expectOrgRequired(listCanvasPlatforms(null as unknown as string))
    await expectOrgRequired(createCanvasPlatform({ name: 'Canvas' }))
    await expectOrgRequired(createCanvasProgramBinding('platform-1', { display_name: 'Course' }))
    await expectOrgRequired(createCanvasIntegrationSecret({ provider: 'canvas_credentials' }))
    await expectOrgRequired(getCanvasMirrorHealth('null'))
    await expectOrgRequired(listOrganizationDevices('undefined'))
    await expectOrgRequired(createComplianceProfile({ name: 'Enterprise VC' }))
    await expectOrgRequired(listDeliveryDestinations({ activeOnly: true }))
    await expectOrgRequired(createDeliveryDestination({ name: 'Canvas Credentials' }))
    await expectOrgRequired(createWebhook('', { url: 'https://example.com/hook', eventTypes: ['credential.issued'] }))
  })

  it('fails locally before org application requests can drop their org filter', async () => {
    await expectOrgRequired(listOrganizationApplications(null as unknown as string))
  })

  it('normalizes exported org guards used by credential setup services', () => {
    expect(requireComplianceOrganizationId({ organization_id: ' org-123 ' })).toBe('org-123')
    expect(requireCredentialSetupOrganizationId({ organization_id: ' org-123 ' })).toBe('org-123')
    expect(() => requireCredentialSetupOrganizationId({ organization_id: 'null' })).toThrow(/active organization/i)
  })
})
