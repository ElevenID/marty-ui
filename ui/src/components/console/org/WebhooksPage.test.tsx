import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { screen, waitFor, within } from '@testing-library/react'
import { renderWithoutRouter } from '../../../test/utils'
import WebhooksPage from './WebhooksPage'

const {
  mockListWebhooks,
  mockGetAvailableEventTypes,
  mockCreateWebhook,
  mockDeleteWebhook,
  mockTestWebhook,
  mockUpdateWebhook,
} = vi.hoisted(() => ({
  mockListWebhooks: vi.fn(),
  mockGetAvailableEventTypes: vi.fn(),
  mockCreateWebhook: vi.fn(),
  mockDeleteWebhook: vi.fn(),
  mockTestWebhook: vi.fn(),
  mockUpdateWebhook: vi.fn(),
}))

vi.mock('../../../hooks/useAuth', () => ({
  useAuth: () => ({
    organizationId: 'org-123',
  }),
}))

vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-123' }),
}))

vi.mock('../../../services/webhooksApi', () => ({
  listWebhooks: (...args: unknown[]) => mockListWebhooks(...args),
  getAvailableEventTypes: (...args: unknown[]) => mockGetAvailableEventTypes(...args),
  createWebhook: (...args: unknown[]) => mockCreateWebhook(...args),
  deleteWebhook: (...args: unknown[]) => mockDeleteWebhook(...args),
  testWebhook: (...args: unknown[]) => mockTestWebhook(...args),
  updateWebhook: (...args: unknown[]) => mockUpdateWebhook(...args),
}))

describe('WebhooksPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockCreateWebhook.mockResolvedValue({})
    mockDeleteWebhook.mockResolvedValue({})
    mockTestWebhook.mockResolvedValue({})
    mockUpdateWebhook.mockResolvedValue({})
    mockGetAvailableEventTypes.mockResolvedValue({
      categories: [
        {
          name: 'Audit',
          events: [
            {
              type: 'audit.security_event',
              description: 'Security relevant change',
            },
          ],
        },
      ],
    })
  })

  it('renders webhook rows from backend event_types data', async () => {
    mockListWebhooks.mockResolvedValueOnce([
      {
        id: 'wh-1',
        url: 'https://audit.example.com/events',
        description: 'Audit sink',
        event_types: ['audit.security_event'],
        enabled: true,
        last_triggered_at: '2026-04-20T12:00:00Z',
      },
    ])

    renderWithoutRouter(
      <MemoryRouter>
        <WebhooksPage />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByText('Audit sink')).toBeInTheDocument()
    })

    expect(screen.getByText('https://audit.example.com/events')).toBeInTheDocument()
    expect(screen.getByText('audit.security_event')).toBeInTheDocument()
    expect(screen.getByText('Active')).toBeInTheDocument()
  })

  it('opens and confirms webhook delete confirmation dialog', async () => {
    mockListWebhooks.mockResolvedValueOnce([
      {
        id: 'wh-1',
        url: 'https://audit.example.com/events',
        description: 'Audit sink',
        event_types: ['audit.security_event'],
        enabled: true,
        last_triggered_at: null,
      },
    ])

    const { user } = renderWithoutRouter(
      <MemoryRouter>
        <WebhooksPage />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByText('Audit sink')).toBeInTheDocument()
    })

    const deleteButton = screen.getByRole('button', { name: /delete webhook/i })
    await user.click(deleteButton)

    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument()
    })

    const confirmDialog = screen.getByRole('dialog')
    const confirmButton = within(confirmDialog).getByRole('button', { name: /delete/i })
    await user.click(confirmButton)

    await waitFor(() => {
      expect(mockDeleteWebhook).toHaveBeenCalledWith('wh-1')
    })
  })
})
