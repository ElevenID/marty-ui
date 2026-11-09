import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { act, renderHook, waitFor } from '@testing-library/react'
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

  it('replaces stale healthy indicators when polling fails and refreshes them on recovery', async () => {
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const mockFetch = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: vi.fn().mockResolvedValue({
          status: 'ready',
          services: { 'issuance-native': { status: 'healthy' }, verification: { status: 'healthy' } },
        }),
      })
      .mockRejectedValueOnce(new Error('health check failed'))
      .mockResolvedValueOnce({
        ok: true,
        json: vi.fn().mockResolvedValue({
          status: 'ready',
          services: { 'issuance-native': { status: 'healthy' }, verification: { status: 'healthy' } },
        }),
      })

    vi.stubGlobal('fetch', mockFetch)

    const { result } = renderHook(() => useDashboardData())

    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(result.current.loading).toBe(false)
    expect(result.current.data.systemHealth).toEqual({ gateway: 'healthy', issuer: 'healthy', verifier: 'healthy' })
    expect(mockFetch).toHaveBeenCalledWith('/health/ready', expect.objectContaining({ cache: 'no-store' }))

    await act(async () => {
      await vi.advanceTimersByTimeAsync(60000)
      await Promise.resolve()
    })

    expect(mockFetch).toHaveBeenCalledTimes(2)
    expect(result.current.data.systemHealth).toEqual({ gateway: 'error', issuer: 'unknown', verifier: 'unknown' })
    expect(consoleErrorSpy).not.toHaveBeenCalled()

    await act(async () => {
      await vi.advanceTimersByTimeAsync(60000)
      await Promise.resolve()
    })

    expect(mockFetch).toHaveBeenCalledTimes(3)
    expect(result.current.data.systemHealth).toEqual({ gateway: 'healthy', issuer: 'healthy', verifier: 'healthy' })
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
    expect(mockListRevocationProfiles).toHaveBeenCalledWith({ organization_id: 'org_live', limit: 100, offset: 0 })
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

  it('keeps malformed native readiness unavailable through the real API normalizer and recovers on retry', async () => {
    vi.useRealTimers()
    const { getRuntimeStatus } = await vi.importActual<typeof import('../../services/dashboardApi')>('../../services/dashboardApi')
    mockGetRuntimeStatus.mockImplementation(getRuntimeStatus)
    let canIssue: unknown = 'false'
    vi.stubGlobal('fetch', vi.fn(async (input: string | URL | Request) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
      if (url.endsWith('/v1/organizations/org_live/runtime/status')) {
        return Response.json({
          can_issue: canIssue,
          can_verify: false,
          issuer_keys_valid: false,
          issuer_active: false,
          deployment_active: false,
          policy_reachable: false,
        })
      }
      if (url === '/health/ready') return Response.json({ status: 'ready' })
      throw new Error(`Unexpected request: ${url}`)
    }))

    const { result } = renderHook(() => useDashboardData())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.data.runtimeStatus).toBeNull()
    expect(result.current.data.dashboardErrors.runtimeStatus).toMatchObject({
      code: 'DASHBOARD_PAYLOAD_INVALID', status: 502,
      message: 'Runtime status returned invalid boolean fields: can_issue.',
    })

    canIssue = false
    act(() => result.current.refetch())
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.data.runtimeStatus).toMatchObject({ canIssue: false, canVerify: false })
    expect(result.current.data.dashboardErrors.runtimeStatus).toBeNull()
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

  it('clears the previous organization immediately while loading an explicitly unset environment', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({ status: 'healthy' }) }))
    let resolveEnvironment!: (environment: null) => void
    const nextEnvironment = new Promise<null>((resolve) => { resolveEnvironment = resolve })
    mockGetOrganizationEnvironment.mockResolvedValueOnce('production').mockImplementationOnce(() => nextEnvironment)
    const renders: Array<{ organizationId: string; environment: unknown; loading: boolean }> = []
    const { result, rerender } = renderHook(() => {
      const dashboard = useDashboardData()
      renders.push({ organizationId: mockUseConsole().activeOrgId, environment: dashboard.data.environment, loading: dashboard.loading })
      return dashboard
    })
    await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve() })
    expect(result.current.data.environment).toBe('production')

    mockUseConsole.mockReturnValue({ activeOrgId: 'org_new' })
    rerender()
    expect(result.current.loading).toBe(true)
    expect(result.current.data.environment).toBeNull()
    expect(renders.filter((render) => render.organizationId === 'org_new')).toEqual(expect.arrayContaining([
      { organizationId: 'org_new', environment: null, loading: true },
    ]))
    expect(renders.filter((render) => render.organizationId === 'org_new').every((render) => render.environment === null && render.loading)).toBe(true)

    await act(async () => { resolveEnvironment(null); await nextEnvironment })
    expect(mockGetOrganizationEnvironment).toHaveBeenNthCalledWith(1, 'org_live')
    expect(mockGetOrganizationEnvironment).toHaveBeenNthCalledWith(2, 'org_new')
    expect(result.current.loading).toBe(false)
    expect(result.current.data.environment).toBeNull()
    expect(result.current.data.dashboardErrors.environment).toBeNull()
  })

  it('ignores an old environment response even after returning to the same organization', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({ status: 'healthy' }) }))
    let resolveOriginal!: (environment: string) => void
    const originalEnvironment = new Promise<string>((resolve) => { resolveOriginal = resolve })
    mockGetOrganizationEnvironment
      .mockImplementationOnce(() => originalEnvironment)
      .mockResolvedValueOnce('staging')
      .mockResolvedValueOnce(null)
    const { result, rerender } = renderHook(() => useDashboardData())
    expect(result.current.loading).toBe(true)

    mockUseConsole.mockReturnValue({ activeOrgId: 'org_other' })
    rerender()
    await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve() })
    expect(result.current.data.environment).toBe('staging')

    mockUseConsole.mockReturnValue({ activeOrgId: 'org_live' })
    rerender()
    await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve() })
    expect(result.current.data.environment).toBeNull()
    await act(async () => { resolveOriginal('production'); await originalEnvironment })
    expect(result.current.data.environment).toBeNull()
    expect(result.current.data.dashboardErrors.environment).toBeNull()
    expect(result.current.loading).toBe(false)
  })

  it('keeps environment request failures distinct from unset and clears them on a successful retry', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({ status: 'healthy' }) }))
    const failure = new Error('Environment service unavailable')
    mockGetOrganizationEnvironment.mockRejectedValueOnce(failure).mockResolvedValueOnce(null)
    const { result } = renderHook(() => useDashboardData())
    await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve() })
    expect(result.current.data.environment).toBeNull()
    expect(result.current.data.dashboardErrors.environment).toBe(failure)

    act(() => result.current.refetch())
    await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve() })
    expect(result.current.data.environment).toBeNull()
    expect(result.current.data.dashboardErrors.environment).toBeNull()
    expect(result.current.loading).toBe(false)
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

  it('loads later template pages for readiness instead of treating the first page as complete', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, json: async () => ({ status: 'healthy' }) }))
    const first = Array.from({ length: 100 }, (_, index) => ({ id: `draft-${index}`, status: 'DRAFT' }))
    const active = { id: 'active-template', organization_id: 'org_live', status: 'ACTIVE' }
    mockListCredentialTemplates.mockResolvedValueOnce(first).mockResolvedValueOnce([active])
    const { result } = renderHook(() => useDashboardData())
    await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve() })
    expect(mockListCredentialTemplates).toHaveBeenLastCalledWith({ organization_id: 'org_live', limit: 100, offset: 100 })
    expect(result.current.data.templates).toEqual([...first, active])
    expect(result.current.data.resourceErrors.templates).toBeNull()
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
