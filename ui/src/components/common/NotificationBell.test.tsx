import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { act, render } from '@test/utils'
import NotificationBell from './NotificationBell'

const { mockGetUnreadCount, mockMarkAllAsRead, context, permission, can } = vi.hoisted(() => ({
  mockGetUnreadCount: vi.fn(),
  mockMarkAllAsRead: vi.fn(),
  context: { activeOrgId: 'org-a' }, permission: { isLoading: false }, can: vi.fn(),
}))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string) => key,
  }),
}))

vi.mock('../../contexts/ConsoleContext', () => ({ useConsole: () => context }))
vi.mock('../../hooks/useAuth', () => ({ useAuth: () => ({ user: { sub: 'user-a' } }) }))
vi.mock('../../hooks/usePermissions', () => ({ usePermissions: () => ({ ...permission, can }) }))

vi.mock('../../services/notificationsApi', () => ({
  default: {
    getUnreadCount: (...args: unknown[]) => mockGetUnreadCount(...args),
    markAllAsRead: (...args: unknown[]) => mockMarkAllAsRead(...args),
  },
}))

vi.mock('./NotificationDropdown', () => ({
  default: () => null,
}))

describe('NotificationBell', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.useFakeTimers()
    context.activeOrgId = 'org-a'; permission.isLoading = false; can.mockReturnValue(true)
    mockGetUnreadCount.mockReset().mockResolvedValue({ count: 0 })
    mockMarkAllAsRead.mockResolvedValue({ ok: true })
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it.each(['loading', 'denied', 'no organization'])('does not poll while %s', (condition) => {
    if (condition === 'loading') permission.isLoading = true
    if (condition === 'denied') can.mockReturnValue(false)
    if (condition === 'no organization') context.activeOrgId = ''
    render(<NotificationBell />)
    expect(mockGetUnreadCount).not.toHaveBeenCalled()
  })

  it('ignores the old organization count after a scope switch', async () => {
    let release: (value: { count: number }) => void = () => {}
    mockGetUnreadCount.mockImplementation((org) => org === 'org-a' ? new Promise((resolve) => { release = resolve }) : Promise.resolve({ count: 2 }))
    const { container, rerender } = render(<NotificationBell />)
    context.activeOrgId = 'org-b'; rerender(<NotificationBell />)
    await act(async () => { await Promise.resolve(); await Promise.resolve() })
    expect(container.querySelector('.MuiBadge-badge')?.textContent).toBe('2')
    await act(async () => { release({ count: 99 }); await Promise.resolve() })
    expect(container.querySelector('.MuiBadge-badge')?.textContent).toBe('2')
    expect(mockGetUnreadCount.mock.calls).toEqual([['org-a', 'user-a'], ['org-b', 'user-a']])
  })

  it('keeps the last unread count through a polling failure and recovers on the next poll', async () => {
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    mockGetUnreadCount
      .mockResolvedValueOnce({ count: 4 })
      .mockRejectedValueOnce(new Error('network down'))
      .mockResolvedValueOnce({ count: 1 })

    const { container } = render(<NotificationBell />)

    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(mockGetUnreadCount).toHaveBeenCalledTimes(1)
    expect(mockGetUnreadCount).toHaveBeenCalledWith('org-a', 'user-a')
    expect(container.querySelector('.MuiBadge-badge')?.textContent).toBe('4')

    await act(async () => {
      await vi.advanceTimersByTimeAsync(30000)
      await Promise.resolve()
    })

    expect(mockGetUnreadCount).toHaveBeenCalledTimes(2)
    expect(consoleErrorSpy).toHaveBeenCalledWith('Failed to load unread count:', expect.any(Error))
    expect(container.querySelector('.MuiBadge-badge')?.textContent).toBe('4')

    await act(async () => {
      await vi.advanceTimersByTimeAsync(30000)
      await Promise.resolve()
    })

    expect(mockGetUnreadCount).toHaveBeenCalledTimes(3)
    expect(container.querySelector('.MuiBadge-badge')?.textContent).toBe('1')
  })
})
