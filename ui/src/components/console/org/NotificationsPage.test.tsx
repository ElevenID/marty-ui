import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderWithRouter, screen, waitFor } from '@test/utils'
import NotificationsPage from './NotificationsPage'

const {
  mockShowNotification,
  mockListNotifications,
  mockMarkAsRead,
  mockMarkAllAsRead,
  mockDeleteNotification,
  mockListAlertRules,
  mockCreateAlertRule,
  mockUpdateAlertRule,
  mockDeleteAlertRule,
  mockGetNotificationPreferences,
  mockUpdateNotificationPreferences,
} = vi.hoisted(() => ({
  mockShowNotification: vi.fn(),
  mockListNotifications: vi.fn(),
  mockMarkAsRead: vi.fn(),
  mockMarkAllAsRead: vi.fn(),
  mockDeleteNotification: vi.fn(),
  mockListAlertRules: vi.fn(),
  mockCreateAlertRule: vi.fn(),
  mockUpdateAlertRule: vi.fn(),
  mockDeleteAlertRule: vi.fn(),
  mockGetNotificationPreferences: vi.fn(),
  mockUpdateNotificationPreferences: vi.fn(),
}))

vi.mock('react-i18next', () => ({
  initReactI18next: {
    type: '3rdParty',
    init: () => {},
  },
  useTranslation: () => ({
    t: (key: string) => key,
  }),
  Trans: ({ children }: { children: unknown }) => children,
}))

vi.mock('../../../hooks/useAuth', () => {
  const useAuth = () => ({
    organizationName: 'Test Organization',
    isAdministrator: false,
    isVendor: true,
    isApplicant: false,
  })

  return {
    useAuth,
    default: useAuth,
  }
})

vi.mock('../../../services/notificationsApi', () => ({
  default: {
    listNotifications: (...args: unknown[]) => mockListNotifications(...args),
    markAsRead: (...args: unknown[]) => mockMarkAsRead(...args),
    markAllAsRead: (...args: unknown[]) => mockMarkAllAsRead(...args),
    deleteNotification: (...args: unknown[]) => mockDeleteNotification(...args),
    listAlertRules: (...args: unknown[]) => mockListAlertRules(...args),
    createAlertRule: (...args: unknown[]) => mockCreateAlertRule(...args),
    updateAlertRule: (...args: unknown[]) => mockUpdateAlertRule(...args),
    deleteAlertRule: (...args: unknown[]) => mockDeleteAlertRule(...args),
    getNotificationPreferences: (...args: unknown[]) => mockGetNotificationPreferences(...args),
    updateNotificationPreferences: (...args: unknown[]) => mockUpdateNotificationPreferences(...args),
  },
}))

vi.mock('../../../hooks/useNotifications', () => ({
  useNotifications: () => ({
    showNotification: mockShowNotification,
  }),
}))

describe('NotificationsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.stubGlobal('confirm', vi.fn(() => true))

    mockListNotifications.mockResolvedValue({
      notifications: [
        {
          id: 'notif_1',
          title: 'Credential issued',
          message: 'A new credential was issued.',
          severity: 'info',
          read: false,
          created_at: '2026-04-10T08:00:00Z',
        },
        {
          id: 'notif_2',
          title: 'Team invite accepted',
          message: 'A teammate joined the organization.',
          severity: 'success',
          read: true,
          created_at: '2026-04-10T07:00:00Z',
        },
      ],
      total: 2,
    })
    mockMarkAsRead.mockResolvedValue({ ok: true })
    mockMarkAllAsRead.mockResolvedValue({ updated_count: 1 })
    mockDeleteNotification.mockResolvedValue({ ok: true })
    mockListAlertRules.mockResolvedValue({
      rules: [
        {
          id: 'rule_1',
          name: 'Failed sign-ins',
          event_type: 'authentication.failed',
          severity: 'error',
          enabled: true,
        },
      ],
    })
    mockCreateAlertRule.mockResolvedValue({ id: 'rule_new' })
    mockUpdateAlertRule.mockResolvedValue({ id: 'rule_1' })
    mockDeleteAlertRule.mockResolvedValue({ ok: true })
    mockGetNotificationPreferences.mockResolvedValue({
      email_notifications: true,
      push_notifications: false,
      digest_enabled: false,
      digest_frequency: 'daily',
    })
    mockUpdateNotificationPreferences.mockResolvedValue({ ok: true })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('uses unread_only when switching to the unread filter', async () => {
    const { user } = renderWithRouter(<NotificationsPage />, {
      initialEntries: ['/console/org/notifications'],
    })

    await waitFor(() => {
      expect(mockListNotifications).toHaveBeenCalledWith({
        limit: 25,
        offset: 0,
      })
    })

    await user.click(screen.getAllByRole('combobox')[0])
    await user.click(screen.getByText('org.notifications.notificationsTab.filterUnread'))

    await waitFor(() => {
      expect(mockListNotifications).toHaveBeenLastCalledWith({
        limit: 25,
        offset: 0,
        unread_only: true,
      })
    })
  })

  it('marks all notifications as read and reloads the list', async () => {
    const { user } = renderWithRouter(<NotificationsPage />, {
      initialEntries: ['/console/org/notifications'],
    })

    await waitFor(() => {
      expect(screen.getByText('Credential issued')).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: 'org.notifications.notificationsTab.markAllAsRead' }))

    await waitFor(() => {
      expect(mockMarkAllAsRead).toHaveBeenCalledTimes(1)
      expect(mockShowNotification).toHaveBeenCalledWith(
        'org.notifications.notificationsTab.success.markAllAsRead',
        'success'
      )
    })

    expect(mockListNotifications).toHaveBeenCalledTimes(2)
  })

  it('creates an alert rule from the alert-rules tab', async () => {
    const { user } = renderWithRouter(<NotificationsPage />, {
      initialEntries: ['/console/org/notifications'],
    })

    await user.click(screen.getByRole('tab', { name: 'org.notifications.tabs.alertRules' }))

    await waitFor(() => {
      expect(mockListAlertRules).toHaveBeenCalledTimes(1)
    })

    await user.click(screen.getByRole('button', { name: 'org.notifications.alertRulesTab.create' }))
    await user.type(
      screen.getByLabelText('org.notifications.alertRulesTab.dialog.nameLabel'),
      'Credential alerts'
    )

    await user.click(screen.getAllByRole('combobox')[0])
    await user.click(screen.getByText('org.notifications.alertRulesTab.eventTypes.credentialIssued'))

    await user.click(screen.getByRole('button', { name: 'org.notifications.alertRulesTab.dialog.buttonCreate' }))

    await waitFor(() => {
      expect(mockCreateAlertRule).toHaveBeenCalledWith({
        name: 'Credential alerts',
        event_type: 'credential.issued',
        severity: 'info',
        enabled: true,
      })
    })
  })

  it('loads and saves notification preferences', async () => {
    const { user } = renderWithRouter(<NotificationsPage />, {
      initialEntries: ['/console/org/notifications'],
    })

    await user.click(screen.getByRole('tab', { name: 'org.notifications.tabs.preferences' }))

    await waitFor(() => {
      expect(mockGetNotificationPreferences).toHaveBeenCalledTimes(1)
    })

    await user.click(screen.getByLabelText('org.notifications.preferencesTab.pushNotifications.label'))
    await user.click(screen.getByRole('button', { name: 'org.notifications.preferencesTab.saveButton' }))

    await waitFor(() => {
      expect(mockUpdateNotificationPreferences).toHaveBeenCalledWith({
        email_notifications: true,
        push_notifications: true,
        digest_enabled: false,
        digest_frequency: 'daily',
      })
    })
  })
})