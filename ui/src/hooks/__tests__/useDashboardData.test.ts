import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { useDashboardData } from '../useDashboardData'

const {
  mockListTrustProfiles,
  mockListCredentialTemplates,
  mockListPresentationPolicies,
  mockListDeploymentProfiles,
  mockListFlows,
  mockListApiKeys,
  mockGetTeamSnapshot,
  mockGetRuntimeStatus,
  mockGetCriticalEvents,
  mockGetOrganizationEnvironment,
  mockUseAuth,
} = vi.hoisted(() => ({
  mockListTrustProfiles: vi.fn(),
  mockListCredentialTemplates: vi.fn(),
  mockListPresentationPolicies: vi.fn(),
  mockListDeploymentProfiles: vi.fn(),
  mockListFlows: vi.fn(),
  mockListApiKeys: vi.fn(),
  mockGetTeamSnapshot: vi.fn(),
  mockGetRuntimeStatus: vi.fn(),
  mockGetCriticalEvents: vi.fn(),
  mockGetOrganizationEnvironment: vi.fn(),
  mockUseAuth: vi.fn(),
}))

vi.mock('../../services/presentationPolicyApi', () => ({
  listTrustProfiles: (...args: unknown[]) => mockListTrustProfiles(...args),
  listCredentialTemplates: (...args: unknown[]) => mockListCredentialTemplates(...args),
  listPresentationPolicies: (...args: unknown[]) => mockListPresentationPolicies(...args),
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

vi.mock('../../services/dashboardApi', () => ({
  getTeamSnapshot: (...args: unknown[]) => mockGetTeamSnapshot(...args),
  getRuntimeStatus: (...args: unknown[]) => mockGetRuntimeStatus(...args),
  getCriticalEvents: (...args: unknown[]) => mockGetCriticalEvents(...args),
  getOrganizationEnvironment: (...args: unknown[]) => mockGetOrganizationEnvironment(...args),
}))

vi.mock('../useAuth', () => ({
  useAuth: () => mockUseAuth(),
}))

describe('useDashboardData', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.useFakeTimers()

    mockUseAuth.mockReturnValue({ organizationId: 'org_live' })
    mockListTrustProfiles.mockResolvedValue([])
    mockListCredentialTemplates.mockResolvedValue([])
    mockListPresentationPolicies.mockResolvedValue([])
    mockListDeploymentProfiles.mockResolvedValue([])
    mockListFlows.mockResolvedValue([])
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
    expect(consoleErrorSpy).toHaveBeenCalledWith('Health check failed:', expect.any(Error))

    await act(async () => {
      await vi.advanceTimersByTimeAsync(60000)
      await Promise.resolve()
    })

    expect(mockFetch).toHaveBeenCalledTimes(3)
    expect(result.current.data.systemHealth).toEqual({ status: 'degraded' })
  })
})