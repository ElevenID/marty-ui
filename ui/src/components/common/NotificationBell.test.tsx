import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { act, render } from '@test/utils'
import NotificationBell from './NotificationBell'

const { mockGetUnreadCount, mockMarkAllAsRead } = vi.hoisted(() => ({
  mockGetUnreadCount: vi.fn(),
  mockMarkAllAsRead: vi.fn(),
}))

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string) => key,
  }),
}))

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
    mockMarkAllAsRead.mockResolvedValue({ ok: true })
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('keeps the last unread count through a polling failure and recovers on the next poll', async () => {
    const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})

    mockGetUnreadCount
      .mockResolvedValueOnce({ unread_count: 4 })
      .mockRejectedValueOnce(new Error('network down'))
      .mockResolvedValueOnce({ unread_count: 1 })

    const { container } = render(<NotificationBell />)

    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(mockGetUnreadCount).toHaveBeenCalledTimes(1)
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