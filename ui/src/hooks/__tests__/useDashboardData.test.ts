import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { useDashboardData } from '../useDashboardData'

const {
  mockListComplianceProfiles,
  mockListTrustProfiles,
  mockListCredentialTemplates,
  mockListApplicationTemplates,
  mockListDeliveryDestinations,
  mockListPolicySets,
  mockGetPhysicalDocumentCapabilities,
  mockListPresentationPolicies,
  mockListRevocationProfiles,
  mockListDeploymentProfiles,
  mockListFlows,
  mockListSigningKeys,
  mockListPublicIssuerIdentities,
  mockGetKeyManagementConfig,
  mockListApiKeys,
  mockGetTeamSnapshot,
  mockGetRuntimeStatus,
  mockGetCriticalEvents,
  mockGetOrganizationEnvironment,
  mockGetOrganizationLifecycle,
  mockUseAuth,
  mockUseConsole,
} = vi.hoisted(() => ({
  mockListComplianceProfiles: vi.fn(),
  mockListTrustProfiles: vi.fn(),
  mockListCredentialTemplates: vi.fn(),
  mockListApplicationTemplates: vi.fn(),
  mockListDeliveryDestinations: vi.fn(),
  mockListPolicySets: vi.fn(),
  mockGetPhysicalDocumentCapabilities: vi.fn(),
  mockListPresentationPolicies: vi.fn(),
  mockListRevocationProfiles: vi.fn(),
  mockListDeploymentProfiles: vi.fn(),
  mockListFlows: vi.fn(),
  mockListSigningKeys: vi.fn(),
  mockListPublicIssuerIdentities: vi.fn(),
  mockGetKeyManagementConfig: vi.fn(),
  mockListApiKeys: vi.fn(),
  mockGetTeamSnapshot: vi.fn(),
  mockGetRuntimeStatus: vi.fn(),
  mockGetCriticalEvents: vi.fn(),
  mockGetOrganizationEnvironment: vi.fn(),
  mockGetOrganizationLifecycle: vi.fn(),
  mockUseAuth: vi.fn(),
  mockUseConsole: vi.fn(),
}))

vi.mock('../../services/presentationPolicyApi', () => ({
  listTrustProfiles: (...args: unknown[]) => mockListTrustProfiles(...args),
  listCredentialTemplates: (...args: unknown[]) => mockListCredentialTemplates(...args),
  listPresentationPolicies: (...args: unknown[]) => mockListPresentationPolicies(...args),
  listRevocationProfiles: (...args: unknown[]) => mockListRevocationProfiles(...args),
}))

vi.mock('../../services/complianceProfilesApi', () => ({
  listComplianceProfiles: (...args: unknown[]) => mockListComplianceProfiles(...args),
}))

vi.mock('../../services/applicationTemplatesApi', () => ({
  listApplicationTemplates: (...args: unknown[]) => mockListApplicationTemplates(...args),
}))

vi.mock('../../services/deliveryDestinationsApi', () => ({
  listDeliveryDestinations: (...args: unknown[]) => mockListDeliveryDestinations(...args),
}))

vi.mock('../../services/policySetsApi', () => ({
  listPolicySets: (...args: unknown[]) => mockListPolicySets(...args),
}))

vi.mock('../../services/physicalDocumentsApi', () => ({
  getPhysicalDocumentCapabilities: (...args: unknown[]) => mockGetPhysicalDocumentCapabilities(...args),
}))

vi.mock('../../services/deploymentProfilesApi', () => ({
  listDeploymentProfiles: (...args: unknown[]) => mockListDeploymentProfiles(...args),
}))

vi.mock('../../services/flowsApi', () => ({
  listFlows: (...args: unknown[]) => mockListFlows(...args),
}))

vi.mock('../../services/apiKeysApi', () => ({
  listApiKeys: (...args: unknown[]) => mockListApiKeys(...args),
}))

vi.mock('../../services/issuerIdentitiesApi', () => ({
  listPublicIssuerIdentities: (...args: unknown[]) => mockListPublicIssuerIdentities(...args),
}))

vi.mock('../../services/signingKeysApi', () => ({
  listSigningKeys: (...args: unknown[]) => mockListSigningKeys(...args),
  getKeyManagementConfig: (...args: unknown[]) => mockGetKeyManagementConfig(...args),
}));

vi.mock('../../services/dashboardApi', () => ({
  getTeamSnapshot: (...args: unknown[]) => mockGetTeamSnapshot(...args),
  getRuntimeStatus: (...args: unknown[]) => mockGetRuntimeStatus(...args),
  getCriticalEvents: (...args: unknown[]) => mockGetCriticalEvents(...args),
  getOrganizationEnvironment: (...args: unknown[]) => mockGetOrganizationEnvironment(...args),
  getOrganizationLifecycle: (...args: unknown[]) => mockGetOrganizationLifecycle(...args),
}))

vi.mock('../useAuth', () => ({
  useAuth: () => mockUseAuth(),
}))

vi.mock('../../contexts/ConsoleContext', () => ({
  useConsole: () => mockUseConsole(),
}))

describe('useDashboardData', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.useFakeTimers()

    mockUseAuth.mockReturnValue({ organizationId: 'auth_org' })
    mockUseConsole.mockReturnValue({ activeOrgId: 'org_live' })
    mockListComplianceProfiles.mockResolvedValue([])
    mockListTrustProfiles.mockResolvedValue([])
    mockListCredentialTemplates.mockResolvedValue([])
    mockListApplicationTemplates.mockResolvedValue([])
    mockListDeliveryDestinations.mockResolvedValue([])
    mockListPolicySets.mockResolvedValue([])
    mockGetPhysicalDocumentCapabilities.mockResolvedValue({ supported: false, blockers: ['not configured'] })
    mockListPresentationPolicies.mockResolvedValue([])
    mockListRevocationProfiles.mockResolvedValue([])
    mockListDeploymentProfiles.mockResolvedValue([])
    mockListFlows.mockResolvedValue([])
    mockListSigningKeys.mockResolvedValue({ keys: [{ id: 'key_1', name: 'Issuer Key' }] })
    mockListPublicIssuerIdentities.mockResolvedValue({
      identities: [{
        issuer_did: 'did:web:issuer.example.com',
        key_purpose: 'vc_jwt_issuer',
        algorithm: 'ES256',
        status: 'active',
      }],
    })
    mockGetKeyManagementConfig.mockResolvedValue({
      default_service_id: 'managed-openbao-transit',
      services: [{ id: 'managed-openbao-transit', name: 'Managed OpenBao', status: 'configured' }],
    })
    mockListApiKeys.mockResolvedValue([])
    mockGetTeamSnapshot.mockResolvedValue({ members: [], pendingInvites: [], roleDistribution: { admin: 0, developer: 0, operator: 0 } })
    mockGetRuntimeStatus.mockResolvedValue({
      canIssue: true,
      canVerify: true,
      issuerKeysValid: true,
      issuerActive: true,
      deploymentActive: true,
      policyReachable: true,
      lastIssuance: null,
      lastVerification: null,
    })
    mockGetCriticalEvents.mockResolvedValue([])
    mockGetOrganizationEnvironment.mockResolvedValue('staging')
    mockGetOrganizationLifecycle.mockResolvedValue({ createdAt: null, complianceProfiles: [], planTier: 'free', planExpiresAt: null, commercialOffer: 'Developer Sandbox', dataRetentionMode: 'standard', auditRetentionDays: 90, pilotRetention: null })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('preserves the last healthy status across polling failures and refreshes on recovery', async () => {
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const mockFetch = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: vi.fn().mockResolvedValue({ status: 'healthy' }),
      })
      .mockRejectedValueOnce(new Error('health check failed'))
      .mockResolvedValueOnce({
        ok: true,
        json: vi.fn().mockResolvedValue({ status: 'degraded' }),
      })

    vi.stubGlobal('fetch', mockFetch)

    const { result } = renderHook(() => useDashboardData())

    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(result.current.loading).toBe(false)
    expect(result.current.data.systemHealth).toEqual({ status: 'healthy' })

    await act(async () => {
      await vi.advanceTimersByTimeAsync(60000)
      await Promise.resolve()
    })

    expect(mockFetch).toHaveBeenCalledTimes(2)
    expect(result.current.data.systemHealth).toEqual({ status: 'healthy' })
    expect(consoleErrorSpy).not.toHaveBeenCalled()

    await act(async () => {
      await vi.advanceTimersByTimeAsync(60000)
      await Promise.resolve()
    })

    expect(mockFetch).toHaveBeenCalledTimes(3)
    expect(result.current.data.systemHealth).toEqual({ status: 'degraded' })
  })

  it('loads trust setup dependencies alongside the rest of the dashboard data', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: vi.fn().mockResolvedValue({ status: 'healthy' }),
    })

    vi.stubGlobal('fetch', mockFetch)

    const { result } = renderHook(() => useDashboardData())

    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(result.current.loading).toBe(false)
    expect(mockListSigningKeys).not.toHaveBeenCalled()
    expect(mockListApplicationTemplates).toHaveBeenCalledWith('org_live')
    expect(mockListRevocationProfiles).toHaveBeenCalledWith({ organization_id: 'org_live' })
    expect(mockListComplianceProfiles).toHaveBeenCalledWith({ organization_id: 'org_live', limit: 100, offset: 0 })
    expect(mockListPublicIssuerIdentities).toHaveBeenCalledWith({ organization_id: 'org_live' })
    expect(mockGetKeyManagementConfig).not.toHaveBeenCalled()
    expect(result.current.data).not.toHaveProperty('signingKeys')
    expect(result.current.data.issuerIdentities).toEqual([{
      issuer_did: 'did:web:issuer.example.com',
      key_purpose: 'vc_jwt_issuer',
      algorithm: 'ES256',
      status: 'active',
    }])
    expect(result.current.data).not.toHaveProperty('issuerProfiles')
    expect(result.current.data).not.toHaveProperty('keyManagementConfig')
  })

  it('clears dashboard data and does not fetch org-scoped resources without organization context', async () => {
    mockUseAuth.mockReturnValue({ organizationId: null })
    mockUseConsole.mockReturnValue({ activeOrgId: null })

    const { result } = renderHook(() => useDashboardData())

    await act(async () => {
      await Promise.resolve()
    })

    expect(result.current.loading).toBe(false)
    expect(result.current.error).toBe('organization_id is required')
    expect(result.current.data.trustProfiles).toEqual([])
    expect(result.current.data).not.toHaveProperty('signingKeys')
    expect(result.current.data.teamData).toBeNull()
    expect(mockListTrustProfiles).not.toHaveBeenCalled()
    expect(mockListComplianceProfiles).not.toHaveBeenCalled()
    expect(mockListApiKeys).not.toHaveBeenCalled()
    expect(mockGetTeamSnapshot).not.toHaveBeenCalled()
  })

  it('loads native profiles beyond the first page independently of lifecycle metadata', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({ status: 'healthy' }) }))
    const first = Array.from({ length: 100 }, (_, index) => ({ id: `draft-${index}`, status: 'DRAFT' }))
    const active = { id: 'active-profile', organization_id: 'org_live', status: 'ACTIVE' }
    mockListComplianceProfiles.mockResolvedValueOnce(first).mockResolvedValueOnce([active])
    const { result } = renderHook(() => useDashboardData())
    await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve() })
    expect(mockListComplianceProfiles).toHaveBeenLastCalledWith({ organization_id: 'org_live', limit: 100, offset: 100 })
    expect(result.current.data.complianceProfiles).toEqual([...first, active])
    expect(result.current.data.lifecycle.complianceProfiles).toEqual([])
    expect(result.current.data.resourceErrors.complianceProfiles).toBeNull()
  })

  it('reports a failed profile page without exposing an incomplete catalog as ready', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({ status: 'healthy' }) }))
    mockListComplianceProfiles.mockResolvedValueOnce(Array.from({ length: 100 }, (_, index) => ({ id: `profile-${index}`, status: 'ACTIVE' })))
      .mockRejectedValueOnce(new Error('profile page unavailable'))
    const { result } = renderHook(() => useDashboardData())
    await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve() })
    expect(result.current.data.complianceProfiles).toEqual([])
    expect(result.current.data.resourceErrors.complianceProfiles?.message).toBe('profile page unavailable')
  })
})
