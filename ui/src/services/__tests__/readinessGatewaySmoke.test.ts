import { describe, it, expect, vi, beforeEach } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '@test/mocks/server'
import {
  getApplicantStats,
  getOrganizationIntegrationInfo,
  getOrganizationEnvironment,
  getRuntimeStatus,
  getTeamSnapshot,
  updateOrganizationEnvironment,
} from '../dashboardApi'
import {
  getCertificateExpiryAlerts,
  getKeyManagementConfig,
  listIssuerProfiles,
  listSigningKeys,
  rotateSigningKey,
  setServiceCertificate,
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

  it('updates organization environment through the gateway v1 route', async () => {
    const requestedPaths: string[] = []

    server.use(
      http.patch('*/v1/organizations/:orgId/environment', async ({ request, params }) => {
        requestedPaths.push(new URL(request.url).pathname)
        const body = await request.json() as { environment?: string }
        return HttpResponse.json({ organization_id: params.orgId, environment: body.environment })
      }),
      http.patch('*/api/v1/organizations/:orgId/environment', () => {
        throw new Error('updateOrganizationEnvironment should not call /api/v1')
      })
    )

    await expect(updateOrganizationEnvironment('org_live', 'production')).resolves.toEqual({
      organization_id: 'org_live',
      environment: 'production',
    })
    expect(requestedPaths).toEqual(['/v1/organizations/org_live/environment'])
  })

  it('rejects incomplete dashboard gateway responses instead of inventing successful zero states', async () => {
    server.use(
      http.get('*/v1/organizations/:orgId/team/snapshot', () => HttpResponse.json({})),
      http.get('*/v1/organizations/:orgId/runtime/status', () => HttpResponse.json({})),
      http.get('*/v1/organizations/:orgId/environment', () => HttpResponse.json({})),
      http.get('*/v1/organizations/:orgId/dashboard/applicant-stats', () => HttpResponse.json({}))
    )

    await expect(getTeamSnapshot('org_live')).rejects.toMatchObject({
      code: 'DASHBOARD_PAYLOAD_INCOMPLETE',
    })
    await expect(getRuntimeStatus('org_live')).rejects.toMatchObject({
      code: 'DASHBOARD_PAYLOAD_INCOMPLETE',
    })
    await expect(getOrganizationEnvironment('org_live')).rejects.toMatchObject({
      code: 'DASHBOARD_PAYLOAD_INCOMPLETE',
    })
    await expect(getApplicantStats('org_live')).rejects.toMatchObject({
      code: 'DASHBOARD_PAYLOAD_INCOMPLETE',
    })
  })

  it('normalizes real integration metadata for developer quick start', async () => {
    server.use(
      http.get('*/v1/organizations/:orgId/integration-info', ({ params }) => {
        return HttpResponse.json({
          org_id: params.orgId,
          base_url: 'https://beta.elevenidllc.com/v1',
          example_request: 'curl -sS -X POST "https://beta.elevenidllc.com/v1/flows/instances"',
        })
      })
    )

    await expect(getOrganizationIntegrationInfo('org_live')).resolves.toEqual({
      orgId: 'org_live',
      baseUrl: 'https://beta.elevenidllc.com/v1',
      exampleRequest: 'curl -sS -X POST "https://beta.elevenidllc.com/v1/flows/instances"',
    })
  })

  it('exercises signing-key, key-management, and issuer-profile gateway endpoints', async () => {
    let queryParams: URLSearchParams | undefined
    let rotatedKeyId: string | undefined
    let rotationBody: unknown
    let configBody: unknown
    let certificateMethod: string | undefined
    let certificateQueryParams: URLSearchParams | undefined
    let certificateBody: unknown
    let expiryAlertQueryParams: URLSearchParams | undefined

    server.use(
      http.get('*/v1/signing-keys', ({ request }) => {
        queryParams = new URL(request.url).searchParams
        return HttpResponse.json({
          keys: [{ id: 'key_1', name: 'Issuer Key', status: 'active' }],
        })
      }),
      http.get('*/v1/signing-keys/config', () => HttpResponse.json({
        default_service_id: 'managed-openbao-transit',
        services: [{ id: 'managed-openbao-transit', name: 'Managed OpenBao', status: 'configured' }],
      })),
      http.get('*/v1/signing-keys/issuer-profiles', () => HttpResponse.json({
        profiles: [{
          id: 'issuer_1',
          issuer_did: 'did:web:issuer.example.com',
          signing_service_id: 'managed-openbao-transit',
          status: 'active',
        }],
      })),
      http.post('*/v1/signing-keys/:keyId/rotate', async ({ params, request }) => {
        rotatedKeyId = params.keyId as string
        rotationBody = await request.json()
        return HttpResponse.json({ id: 'key_2', rotated_from: rotatedKeyId, immediate: true })
      }),
      http.patch('*/v1/signing-keys/config', async ({ request }) => {
        configBody = await request.json()
        return HttpResponse.json(configBody)
      }),
      http.put('*/v1/signing-keys/services/:serviceId/certificate', async ({ params, request }) => {
        certificateMethod = request.method
        certificateQueryParams = new URL(request.url).searchParams
        certificateBody = await request.json()
        return HttpResponse.json({
          ok: true,
          service_id: params.serviceId,
          cert_expires_at: '2026-10-01T00:00:00Z',
        })
      }),
      http.get('*/v1/signing-keys/config/certificate-expiry-alerts', ({ request }) => {
        expiryAlertQueryParams = new URL(request.url).searchParams
        return HttpResponse.json({
          alerts: [{ service_id: 'managed-openbao-transit', status: 'warning' }],
        })
      })
    )

    const listedKeys = await listSigningKeys({ organization_id: 'org_live', status: 'active', limit: 25, offset: 50 })
    const keyManagementConfig = await getKeyManagementConfig({ organization_id: 'org_live' })
    const issuerProfiles = await listIssuerProfiles({ organization_id: 'org_live' })
    const rotatedKey = await rotateSigningKey('key_1', { organization_id: 'org_live', immediate: true })
    const config = await updateKeyManagementConfig({
      organization_id: 'org_live',
      hsm_enabled: true,
      hsm_settings: { slot: 'issuer-primary' },
      vault_enabled: false,
      vault_settings: {},
    })
    const certificate = await setServiceCertificate('managed-openbao-transit', {
      organization_id: 'org_live',
      cert_pem: '-----BEGIN CERTIFICATE-----\nmock\n-----END CERTIFICATE-----',
      cert_chain_pem: 'chain',
    })
    const expiryAlerts = await getCertificateExpiryAlerts(45, { organization_id: 'org_live' })

    expect(queryParams?.get('status')).toBe('active')
    expect(queryParams?.get('limit')).toBe('25')
    expect(queryParams?.get('offset')).toBe('50')
    expect(queryParams?.get('organization_id')).toBe('org_live')
    expect(listedKeys).toEqual({
      keys: [{ id: 'key_1', name: 'Issuer Key', status: 'active' }],
    })
    expect(keyManagementConfig).toEqual({
      default_service_id: 'managed-openbao-transit',
      services: [{ id: 'managed-openbao-transit', name: 'Managed OpenBao', status: 'configured' }],
    })
    expect(issuerProfiles).toEqual({
      profiles: [{
        id: 'issuer_1',
        issuer_did: 'did:web:issuer.example.com',
        signing_service_id: 'managed-openbao-transit',
        status: 'active',
      }],
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
    expect(certificateMethod).toBe('PUT')
    expect(certificateQueryParams?.get('organization_id')).toBe('org_live')
    expect(certificateBody).toEqual({
      cert_pem: '-----BEGIN CERTIFICATE-----\nmock\n-----END CERTIFICATE-----',
      cert_chain_pem: 'chain',
    })
    expect(certificate).toEqual({
      ok: true,
      service_id: 'managed-openbao-transit',
      cert_expires_at: '2026-10-01T00:00:00Z',
    })
    expect(expiryAlertQueryParams?.get('organization_id')).toBe('org_live')
    expect(expiryAlertQueryParams?.get('days_until_expiry')).toBe('45')
    expect(expiryAlerts).toEqual({
      alerts: [{ service_id: 'managed-openbao-transit', status: 'warning' }],
    })
  })
})
