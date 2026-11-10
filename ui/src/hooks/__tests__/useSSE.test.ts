import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { renderHook } from '@testing-library/react'
import { useSSE } from '../useSSE'
import sseService from '../../services/sseService'

vi.mock('../../services/sseService', () => ({
  default: { connect: vi.fn(), disconnect: vi.fn(), isActive: vi.fn(() => false) },
}))

describe('useSSE', () => {
  beforeEach(() => vi.clearAllMocks())
  afterEach(() => vi.restoreAllMocks())

  it('does not connect when access leaves the organization subscription disabled', () => {
    renderHook(() => useSSE(null, 'account-a', ['credential.issued']))
    expect(sseService.connect).not.toHaveBeenCalled()
  })

  it('disconnects even a pending connection on permission loss and unmount', () => {
    const { rerender, unmount } = renderHook(({ organizationId }) => useSSE(organizationId, 'account-a'), {
      initialProps: { organizationId: 'org-a' as string | null },
    })
    expect(sseService.connect).toHaveBeenCalledTimes(1)
    rerender({ organizationId: null })
    expect(sseService.disconnect).toHaveBeenCalledTimes(1)
    rerender({ organizationId: 'org-a' })
    unmount()
    expect(sseService.disconnect).toHaveBeenCalledTimes(2)
  })

  it('replaces account, organization, and event scopes while retaining equal subscription lists', () => {
    const { rerender } = renderHook(({ organizationId, userId, subscriptions }) => useSSE(organizationId, userId, subscriptions), {
      initialProps: { organizationId: 'org-a', userId: 'account-a', subscriptions: ['credential.issued'] },
    })
    rerender({ organizationId: 'org-a', userId: 'account-a', subscriptions: ['credential.issued'] })
    expect(sseService.connect).toHaveBeenCalledTimes(1)

    rerender({ organizationId: 'org-a', userId: 'account-b', subscriptions: ['credential.issued'] })
    expect(sseService.disconnect).toHaveBeenCalledTimes(1)
    expect(sseService.connect).toHaveBeenLastCalledWith({ organizationId: 'org-a', userId: 'account-b', subscriptions: ['credential.issued'] })

    rerender({ organizationId: 'org-a', userId: 'account-b', subscriptions: ['credential.revoked'] })
    expect(sseService.disconnect).toHaveBeenCalledTimes(2)
    expect(sseService.connect).toHaveBeenLastCalledWith({ organizationId: 'org-a', userId: 'account-b', subscriptions: ['credential.revoked'] })

    rerender({ organizationId: 'org-b', userId: 'account-b', subscriptions: ['credential.revoked'] })
    expect(sseService.disconnect).toHaveBeenCalledTimes(3)
    expect(sseService.connect).toHaveBeenLastCalledWith({ organizationId: 'org-b', userId: 'account-b', subscriptions: ['credential.revoked'] })
  })
})
