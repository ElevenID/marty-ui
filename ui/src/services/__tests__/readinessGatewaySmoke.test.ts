import { describe, it, expect, vi, beforeEach } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '@test/mocks/server'
import {
  getOrganizationEnvironment,
  getRuntimeStatus,
  getTeamSnapshot,
} from '../dashboardApi'
import {
  listSigningKeys,
  rotateSigningKey,
  updateKeyManagementConfig,
} from '../signingKeysApi'

describe('readiness gateway smoke', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('normalizes dashboard gateway responses from org-scoped endpoints', async () => {
    const requestedOrgIds: string[] = []

    server.use(
      http.get('*/v1/organizations/:orgId/team/snapshot', ({ params }) => {
        requestedOrgIds.push(params.orgId as string)
        return HttpResponse.json({
          members: [{ id: 'member_1', role: 'admin' }],
          pending_invites: [{ id: 'invite_1' }],
          role_distribution: { admin: 1, developer: 2, operator: 1 },
        })
      }),
      http.get('*/v1/organizations/:orgId/runtime/status', ({ params }) => {
        requestedOrgIds.push(params.orgId as string)
        return HttpResponse.json({
          can_issue: true,
          can_verify: true,
          issuer_keys_valid: true,
          issuer_active: true,
          deployment_active: false,
          policy_reachable: true,
          last_issuance_timestamp: '2026-04-10T00:00:00Z',
          last_verification_timestamp: '2026-04-10T01:00:00Z',
        })
      }),
      http.get('*/v1/organizations/:orgId/environment', ({ params }) => {
        requestedOrgIds.push(params.orgId as string)
        return HttpResponse.json({ environment: 'staging' })
      })
    )

    const [teamSnapshot, runtimeStatus, environment] = await Promise.all([
      getTeamSnapshot('org_live'),
      getRuntimeStatus('org_live'),
      getOrganizationEnvironment('org_live'),
    ])

    expect(requestedOrgIds).toEqual(['org_live', 'org_live', 'org_live'])
    expect(teamSnapshot).toEqual({
      members: [{ id: 'member_1', role: 'admin' }],
      pendingInvites: [{ id: 'invite_1' }],
      roleDistribution: { admin: 1, developer: 2, operator: 1 },
    })
    expect(runtimeStatus).toEqual({
      canIssue: true,
      canVerify: true,
      issuerKeysValid: true,
      issuerActive: true,
      deploymentActive: false,
      policyReachable: true,
      lastIssuance: '2026-04-10T00:00:00Z',
      lastVerification: '2026-04-10T01:00:00Z',
    })
    expect(environment).toBe('staging')
  })

  it('exercises signing-key gateway list, rotate, and config endpoints', async () => {
    let queryParams: URLSearchParams | undefined
    let rotatedKeyId: string | undefined
    let rotationBody: unknown
    let configBody: unknown

    server.use(
      http.get('*/v1/signing-keys', ({ request }) => {
        queryParams = new URL(request.url).searchParams
        return HttpResponse.json({
          keys: [{ id: 'key_1', name: 'Issuer Key', status: 'active' }],
        })
      }),
      http.post('*/v1/signing-keys/:keyId/rotate', async ({ params, request }) => {
        rotatedKeyId = params.keyId as string
        rotationBody = await request.json()
        return HttpResponse.json({ id: 'key_2', rotated_from: rotatedKeyId, immediate: true })
      }),
      http.patch('*/v1/signing-keys/config', async ({ request }) => {
        configBody = await request.json()
        return HttpResponse.json(configBody)
      })
    )

    const listedKeys = await listSigningKeys({ status: 'active', limit: 25, offset: 50 })
    const rotatedKey = await rotateSigningKey('key_1', { immediate: true })
    const config = await updateKeyManagementConfig({
      hsm_enabled: true,
      hsm_settings: { slot: 'issuer-primary' },
      vault_enabled: false,
      vault_settings: {},
    })

    expect(queryParams?.get('status')).toBe('active')
    expect(queryParams?.get('limit')).toBe('25')
    expect(queryParams?.get('offset')).toBe('50')
    expect(listedKeys).toEqual({
      keys: [{ id: 'key_1', name: 'Issuer Key', status: 'active' }],
    })
    expect(rotatedKeyId).toBe('key_1')
    expect(rotationBody).toEqual({ immediate: true })
    expect(rotatedKey).toEqual({ id: 'key_2', rotated_from: 'key_1', immediate: true })
    expect(configBody).toEqual({
      hsm_enabled: true,
      hsm_settings: { slot: 'issuer-primary' },
      vault_enabled: false,
      vault_settings: {},
    })
    expect(config).toEqual({
      hsm_enabled: true,
      hsm_settings: { slot: 'issuer-primary' },
      vault_enabled: false,
      vault_settings: {},
    })
  })
})