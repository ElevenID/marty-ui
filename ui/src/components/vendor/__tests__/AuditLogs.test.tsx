/**
 * Integration Tests for Audit Logs Component
 * 
 * Tests event log display, filtering, search, pagination, and export.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { render } from '@test/utils'
import { server } from '@test/mocks/server'
import { http, HttpResponse } from 'msw'
import AuditLogs from '../AuditLogs'

// Mock auth hook
vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({
    organizationId: 'org_123',
    user: { id: 1, name: 'Admin' },
  }),
}))

const mockAuditEvents = [
  {
    id: 'evt_1',
    event_type: 'credential.issued',
    severity: 'info',
    timestamp: '2024-01-15T10:00:00Z',
    actor: { id: 'user_1', name: 'Alice Admin' },
    resource: { id: 'cred_123', type: 'credential' },
    details: { template_id: 'template_456' },
  },
  {
    id: 'evt_2',
    event_type: 'verification.completed',
    severity: 'info',
    timestamp: '2024-01-15T11:30:00Z',
    actor: { id: 'user_2', name: 'Bob Verifier' },
    resource: { id: 'pres_789', type: 'presentation' },
    details: { policy_id: 'policy_123', result: 'valid' },
  },
  {
    id: 'evt_3',
    event_type: 'security.api_key_revoked',
    severity: 'warning',
    timestamp: '2024-01-15T12:00:00Z',
    actor: { id: 'user_1', name: 'Alice Admin' },
    resource: { id: 'key_456', type: 'api_key' },
    details: { reason: 'Suspected leak' },
  },
  {
    id: 'evt_4',
    event_type: 'application.rejected',
    severity: 'warning',
    timestamp: '2024-01-15T13:00:00Z',
    actor: { id: 'user_3', name: 'Carol Reviewer' },
    resource: { id: 'app_999', type: 'application' },
    details: { rejection_reason: 'Incomplete documentation' },
  },
  {
    id: 'evt_5',
    event_type: 'trust.profile_updated',
    severity: 'info',
    timestamp: '2024-01-15T14:00:00Z',
    actor: { id: 'user_1', name: 'Alice Admin' },
    resource: { id: 'trust_111', type: 'trust_profile' },
    details: { changes: ['trust_list_url'] },
  },
]

describe('AuditLogs', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    
    // Default handler
    server.use(
      http.get('http://localhost:8000/v1/audit/events', ({ request }) => {
        const url = new URL(request.url)
        const category = url.searchParams.get('category')
        const severity = url.searchParams.get('severity')
        const search = url.searchParams.get('search')
        
        let events = [...mockAuditEvents]
        
        // Filter by category
        if (category && category !== 'all') {
          events = events.filter((e) => e.event_type.startsWith(category + '.'))
        }
        
        // Filter by severity
        if (severity && severity !== 'all') {
          events = events.filter((e) => e.severity === severity)
        }
        
        // Filter by search
        if (search) {
          events = events.filter((e) =>
            e.id.toLowerCase().includes(search.toLowerCase()) ||
            e.actor.name.toLowerCase().includes(search.toLowerCase()) ||
            e.event_type.toLowerCase().includes(search.toLowerCase())
          )
        }
        
        return HttpResponse.json({
          events,
          total: events.length,
          page: 1,
          per_page: 50,
        })
      })
    )
  })

  describe('Table Display', () => {
    it('should render audit logs table', async () => {
      render(<AuditLogs />)

      await waitFor(() => {
        expect(screen.getByText(/audit logs/i)).toBeInTheDocument()
      })

      // Table headers
      expect(screen.getByText(/event/i)).toBeInTheDocument()
      expect(screen.getByText(/actor/i)).toBeInTheDocument()
      expect(screen.getByText(/timestamp/i)).toBeInTheDocument()
    })

    it('should display event rows', async () => {
      render(<AuditLogs />)

      await waitFor(() => {
        expect(screen.getByText('credential.issued')).toBeInTheDocument()
        expect(screen.getByText('verification.completed')).toBeInTheDocument()
        expect(screen.getByText('security.api_key_revoked')).toBeInTheDocument()
      })
    })

    it('should show actor names', async () => {
      render(<AuditLogs />)

      await waitFor(() => {
        expect(screen.getByText('Alice Admin')).toBeInTheDocument()
        expect(screen.getByText('Bob Verifier')).toBeInTheDocument()
        expect(screen.getByText('Carol Reviewer')).toBeInTheDocument()
      })
    })

    it('should format timestamps', async () => {
      render(<AuditLogs />)

      await waitFor(() => {
        expect(screen.getByText(/Jan 15, 2024/)).toBeInTheDocument()
      })
    })

    it('should display severity icons', async () => {
      render(<AuditLogs />)

      await waitFor(() => {
        // Info icons for normal events
        const infoIcons = screen.getAllByTestId('InfoIcon')
        expect(infoIcons.length).toBeGreaterThan(0)

        // Warning icons for warnings
        const warningIcons = screen.getAllByTestId('WarningIcon')
        expect(warningIcons.length).toBeGreaterThan(0)
      })
    })

    it('should show event type chips', async () => {
      render(<AuditLogs />)

      await waitFor(() => {
        const credentialChip = screen.getByText('credential.issued')
        expect(credentialChip).toBeInTheDocument()
        expect(credentialChip.closest('.MuiChip-root')).toHaveClass('MuiChip-colorPrimary')
      })
    })
  })

  describe('Category Filtering', () => {
    it('should filter by category', async () => {
      const user = userEvent.setup()
      render(<AuditLogs />)

      await waitFor(() => screen.getByText('credential.issued'))

      // Select credential category
      const categorySelect = screen.getByLabelText(/category/i)
      await user.click(categorySelect)
      await user.click(screen.getByText('Credentials'))

      // Only credential events should show
      await waitFor(() => {
        expect(screen.getByText('credential.issued')).toBeInTheDocument()
        expect(screen.queryByText('verification.completed')).not.toBeInTheDocument()
        expect(screen.queryByText('security.api_key_revoked')).not.toBeInTheDocument()
      })
    })

    it('should filter by verification category', async () => {
      const user = userEvent.setup()
      render(<AuditLogs />)

      await waitFor(() => screen.getByText('verification.completed'))

      const categorySelect = screen.getByLabelText(/category/i)
      await user.click(categorySelect)
      await user.click(screen.getByText('Verifications'))

      await waitFor(() => {
        expect(screen.getByText('verification.completed')).toBeInTheDocument()
        expect(screen.queryByText('credential.issued')).not.toBeInTheDocument()
      })
    })

    it('should filter by security category', async () => {
      const user = userEvent.setup()
      render(<AuditLogs />)

      await waitFor(() => screen.getByText('security.api_key_revoked'))

      const categorySelect = screen.getByLabelText(/category/i)
      await user.click(categorySelect)
      await user.click(screen.getByText('Security'))

      await waitFor(() => {
        expect(screen.getByText('security.api_key_revoked')).toBeInTheDocument()
        expect(screen.queryByText('credential.issued')).not.toBeInTheDocument()
      })
    })

    it('should show all events when "all" is selected', async () => {
      const user = userEvent.setup()
      render(<AuditLogs />)

      await waitFor(() => screen.getByText('credential.issued'))

      // Filter to one category first
      const categorySelect = screen.getByLabelText(/category/i)
      await user.click(categorySelect)
      await user.click(screen.getByText('Credentials'))

      await waitFor(() => {
        expect(screen.queryByText('verification.completed')).not.toBeInTheDocument()
      })

      // Switch back to all
      await user.click(categorySelect)
      await user.click(screen.getByText('All Events'))

      await waitFor(() => {
        expect(screen.getByText('credential.issued')).toBeInTheDocument()
        expect(screen.getByText('verification.completed')).toBeInTheDocument()
      })
    })
  })

  describe('Severity Filtering', () => {
    it('should filter by severity level', async () => {
      const user = userEvent.setup()
      render(<AuditLogs />)

      await waitFor(() => screen.getByText('security.api_key_revoked'))

      const severitySelect = screen.getByLabelText(/severity/i)
      await user.click(severitySelect)
      await user.click(screen.getByText('warning'))

      await waitFor(() => {
        expect(screen.getByText('security.api_key_revoked')).toBeInTheDocument()
        expect(screen.getByText('application.rejected')).toBeInTheDocument()
        expect(screen.queryByText('credential.issued')).not.toBeInTheDocument()
      })
    })
  })

  describe('Search', () => {
    it('should search by event ID', async () => {
      const user = userEvent.setup()
      render(<AuditLogs />)

      await waitFor(() => screen.getByText('credential.issued'))

      const searchInput = screen.getByPlaceholderText(/search/i)
      await user.type(searchInput, 'evt_3')

      await waitFor(() => {
        expect(screen.getByText('security.api_key_revoked')).toBeInTheDocument()
        expect(screen.queryByText('credential.issued')).not.toBeInTheDocument()
      })
    })

    it('should search by actor name', async () => {
      const user = userEvent.setup()
      render(<AuditLogs />)

      await waitFor(() => screen.getByText('Alice Admin'))

      const searchInput = screen.getByPlaceholderText(/search/i)
      await user.type(searchInput, 'Bob')

      await waitFor(() => {
        expect(screen.getByText('Bob Verifier')).toBeInTheDocument()
        expect(screen.queryByText('Alice Admin')).not.toBeInTheDocument()
      })
    })

    it('should search by event type', async () => {
      const user = userEvent.setup()
      render(<AuditLogs />)

      await waitFor(() => screen.getByText('credential.issued'))

      const searchInput = screen.getByPlaceholderText(/search/i)
      await user.type(searchInput, 'revoked')

      await waitFor(() => {
        expect(screen.getByText('security.api_key_revoked')).toBeInTheDocument()
        expect(screen.queryByText('credential.issued')).not.toBeInTheDocument()
      })
    })
  })

  describe('Event Details', () => {
    it('should open event detail dialog', async () => {
      const user = userEvent.setup()
      render(<AuditLogs />)

      await waitFor(() => screen.getByText('credential.issued'))

      // Click view button
      const viewButtons = screen.getAllByRole('button', { name: /view/i })
      await user.click(viewButtons[0])

      // Dialog should open
      expect(screen.getByRole('dialog')).toBeInTheDocument()
      expect(screen.getByText(/event details/i)).toBeInTheDocument()
    })

    it('should display full event data', async () => {
      const user = userEvent.setup()
      render(<AuditLogs />)

      await waitFor(() => screen.getByText('credential.issued'))

      const viewButtons = screen.getAllByRole('button', { name: /view/i })
      await user.click(viewButtons[0])

      await waitFor(() => {
        const dialog = screen.getByRole('dialog')
        expect(within(dialog).getByText('evt_1')).toBeInTheDocument()
        expect(within(dialog).getByText('credential.issued')).toBeInTheDocument()
        expect(within(dialog).getByText(/template_id/i)).toBeInTheDocument()
      })
    })
  })

  describe('Pagination', () => {
    it('should show pagination controls', async () => {
      render(<AuditLogs />)

      await waitFor(() => {
        const pagination = screen.getByRole('navigation')
        expect(pagination).toBeInTheDocument()
      })
    })

    it('should change pages', async () => {
      const user = userEvent.setup()
      
      // Mock paginated response
      server.use(
        http.get('http://localhost:8000/v1/audit/events', ({ request }) => {
          const url = new URL(request.url)
          const page = parseInt(url.searchParams.get('page') || '1')
          
          return HttpResponse.json({
            events: page === 1 ? mockAuditEvents.slice(0, 3) : mockAuditEvents.slice(3),
            total: mockAuditEvents.length,
            page,
            per_page: 3,
          })
        })
      )

      render(<AuditLogs />)

      await waitFor(() => screen.getByText('credential.issued'))

      // Go to next page
      const nextButton = screen.getByRole('button', { name: /next page/i })
      await user.click(nextButton)

      await waitFor(() => {
        expect(screen.getByText('application.rejected')).toBeInTheDocument()
        expect(screen.queryByText('credential.issued')).not.toBeInTheDocument()
      })
    })
  })

  describe('Export', () => {
    it('should have export button', async () => {
      render(<AuditLogs />)

      await waitFor(() => {
        expect(screen.getByRole('button', { name: /export/i })).toBeInTheDocument()
      })
    })

    it('should export to CSV', async () => {
      const user = userEvent.setup()
      render(<AuditLogs />)

      await waitFor(() => screen.getByRole('button', { name: /export/i }))

      const exportButton = screen.getByRole('button', { name: /export/i })
      await user.click(exportButton)

      // Export menu should open
      expect(screen.getByText(/csv/i)).toBeInTheDocument()
      expect(screen.getByText(/json/i)).toBeInTheDocument()
    })
  })

  describe('Refresh', () => {
    it('should refresh audit logs', async () => {
      const user = userEvent.setup()
      let fetchCount = 0

      server.use(
        http.get('http://localhost:8000/v1/audit/events', () => {
          fetchCount++
          return HttpResponse.json({
            events: mockAuditEvents,
            total: mockAuditEvents.length,
          })
        })
      )

      render(<AuditLogs />)

      await waitFor(() => screen.getByText('credential.issued'))
      expect(fetchCount).toBe(1)

      const refreshButton = screen.getByRole('button', { name: /refresh/i })
      await user.click(refreshButton)

      await waitFor(() => {
        expect(fetchCount).toBe(2)
      })
    })
  })

  describe('Loading and Error States', () => {
    it('should show loading state', () => {
      server.use(
        http.get('http://localhost:8000/v1/audit/events', () => {
          return new Promise(() => {}) // Never resolves
        })
      )

      render(<AuditLogs />)

      expect(screen.getByRole('progressbar')).toBeInTheDocument()
    })

    it('should handle API errors', async () => {
      server.use(
        http.get('http://localhost:8000/v1/audit/events', () => {
          return HttpResponse.json(
            { error: { message: 'Unauthorized' } },
            { status: 401 }
          )
        })
      )

      render(<AuditLogs />)

      await waitFor(() => {
        expect(screen.getByText(/error/i)).toBeInTheDocument()
      })
    })
  })

  describe('Empty State', () => {
    it('should show empty state when no events', async () => {
      server.use(
        http.get('http://localhost:8000/v1/audit/events', () => {
          return HttpResponse.json({ events: [], total: 0 })
        })
      )

      render(<AuditLogs />)

      await waitFor(() => {
        expect(screen.getByText(/no events/i)).toBeInTheDocument()
      })
    })
  })
})
