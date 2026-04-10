import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderWithRouter, screen, waitFor } from '@test/utils'
import AuditPage from './AuditPage'

const {
  mockShowNotification,
  mockListAuditEvents,
  mockListFilterViews,
  mockExportAuditEvents,
  mockSaveFilterView,
} = vi.hoisted(() => ({
  mockShowNotification: vi.fn(),
  mockListAuditEvents: vi.fn(),
  mockListFilterViews: vi.fn(),
  mockExportAuditEvents: vi.fn(),
  mockSaveFilterView: vi.fn(),
}))

vi.mock('react-i18next', () => ({
  initReactI18next: {
    type: '3rdParty',
    init: () => {},
  },
  useTranslation: () => ({
    t: (key: string, options?: { name?: string }) => {
      if (options?.name) {
        return `${key}:${options.name}`
      }

      return key
    },
  }),
  Trans: ({ children }: { children: unknown }) => children,
}))

vi.mock('../../../hooks/useAuth', () => {
  const useAuth = () => ({
    organizationId: 'org-auth',
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

vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({
    activeOrgId: 'org-active',
  }),
}))

vi.mock('../../../services/auditApi', () => ({
  default: {
    listAuditEvents: (...args: unknown[]) => mockListAuditEvents(...args),
    listFilterViews: (...args: unknown[]) => mockListFilterViews(...args),
    exportAuditEvents: (...args: unknown[]) => mockExportAuditEvents(...args),
    saveFilterView: (...args: unknown[]) => mockSaveFilterView(...args),
  },
}))

vi.mock('../../../hooks/useNotifications', () => ({
  useNotifications: () => ({
    showNotification: mockShowNotification,
  }),
}))

describe('AuditPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()

    mockListAuditEvents.mockResolvedValue({
      events: [
        {
          id: 'evt_1',
          timestamp: '2026-04-10T08:00:00Z',
          category: 'team',
          action: 'member.invited',
          actor: 'alex@example.com',
          resource: 'Team workspace',
          severity: 'warning',
          details: { inviteId: 'invite_1' },
          ipAddress: '127.0.0.1',
        },
      ],
      total: 1,
    })
    mockListFilterViews.mockResolvedValue([
      {
        id: 'view_1',
        name: 'Critical Team',
        filters: {
          category: 'team',
          severity: 'warning',
          actor: 'alex@example.com',
          resourceType: '',
          ipAddress: '',
          startDate: null,
          endDate: null,
        },
      },
    ])
    mockExportAuditEvents.mockResolvedValue({
      download_url: '/exports/audit.csv',
    })
    mockSaveFilterView.mockResolvedValue({ id: 'view_2' })
    vi.stubGlobal('open', vi.fn())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('renders audit events and expands row details', async () => {
    const { user } = renderWithRouter(<AuditPage />, {
      initialEntries: ['/console/audit'],
    })

    await waitFor(() => {
      expect(mockListAuditEvents).toHaveBeenCalledWith('org-active', {
        limit: 25,
        offset: 0,
      })
    })

    expect(screen.getByText('alex@example.com')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Team workspace' })).toHaveAttribute('href', '/console/org/team')

    await user.click(screen.getByText('member.invited'))

    await waitFor(() => {
      expect(screen.getByText('audit.details.title')).toBeInTheDocument()
      expect(screen.getByText('127.0.0.1')).toBeInTheDocument()
    })
  })

  it('exports audit events and opens the download URL', async () => {
    const { user } = renderWithRouter(<AuditPage />, {
      initialEntries: ['/console/audit'],
    })

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'audit.export' })).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: 'audit.export' }))

    await waitFor(() => {
      expect(mockExportAuditEvents).toHaveBeenCalledWith(
        'org-active',
        {
          resource_type: undefined,
          severity: undefined,
          actor: '',
          search: undefined,
          ip_address: '',
          start_date: undefined,
          end_date: undefined,
        },
        'csv'
      )
      expect(window.open).toHaveBeenCalledWith('/exports/audit.csv', '_blank')
      expect(mockShowNotification).toHaveBeenCalledWith('audit.exportSuccess', 'success')
    })
  })

  it('applies a saved view and reloads audit events with its filters', async () => {
    const { user } = renderWithRouter(<AuditPage />, {
      initialEntries: ['/console/audit'],
    })

    await waitFor(() => {
      expect(mockListFilterViews).toHaveBeenCalledWith('org-active')
    })

    await user.click(screen.getAllByRole('combobox')[0])
    await user.click(screen.getByText('Critical Team'))

    await waitFor(() => {
      expect(mockListAuditEvents).toHaveBeenLastCalledWith('org-active', {
        limit: 25,
        offset: 0,
        resource_type: 'team',
        severity: 'warning',
        actor: 'alex@example.com',
      })
      expect(mockShowNotification).toHaveBeenCalledWith('audit.messages.appliedView:Critical Team', 'info')
    })
  })
})