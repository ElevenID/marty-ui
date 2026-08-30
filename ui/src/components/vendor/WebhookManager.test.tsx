import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { renderWithoutRouter } from '../../test/utils'
import WebhookManager from './WebhookManager'

const {
  mockCreateWebhook,
  mockGetAvailableEventTypes,
  mockListWebhooks,
  mockShowSuccess,
} = vi.hoisted(() => ({
  mockCreateWebhook: vi.fn(),
  mockGetAvailableEventTypes: vi.fn(),
  mockListWebhooks: vi.fn(),
  mockShowSuccess: vi.fn(),
}))

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({ organizationId: 'org-123' }),
}))

vi.mock('../../hooks/useNotifications', () => ({
  useNotifications: () => ({ showSuccess: mockShowSuccess }),
}))

vi.mock('../../services/webhooksApi', () => ({
  listWebhooks: (...args: unknown[]) => mockListWebhooks(...args),
  createWebhookConfiguration: (...args: unknown[]) => mockCreateWebhook(...args),
  updateWebhookConfiguration: vi.fn(),
  deleteWebhookConfiguration: vi.fn(),
  testWebhook: vi.fn(),
  getAvailableEventTypes: (...args: unknown[]) => mockGetAvailableEventTypes(...args),
  getErrorMessage: (error: Error) => error.message,
}))

describe('WebhookManager', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockListWebhooks.mockResolvedValue([])
    mockCreateWebhook.mockResolvedValue({ secret: 'whsec-created' })
    mockGetAvailableEventTypes.mockResolvedValue({
      categories: [
        {
          name: 'Credential',
          events: [{ type: 'credential.offered', description: 'credential offered' }],
        },
        {
          name: 'Applicant',
          events: [{ type: 'applicant.approved', description: 'applicant approved' }],
        },
        {
          name: 'Device',
          events: [{ type: 'device.key_expiring', description: 'device key expiring' }],
        },
      ],
    })
  })

  it('renders safely and submits only Rust-advertised event types', async () => {
    const { user } = renderWithoutRouter(<WebhookManager />)

    await user.click(await screen.findByRole('button', { name: /add your first webhook/i }))

    expect(screen.getAllByText('credential offered').length).toBeGreaterThan(0)
    expect(screen.getAllByText('applicant approved').length).toBeGreaterThan(0)
    expect(screen.getAllByText('device key expiring').length).toBeGreaterThan(0)
    expect(screen.getByText('All Events')).toBeInTheDocument()
    expect(screen.queryByText(/credential suspended/i)).not.toBeInTheDocument()

    await user.type(screen.getByLabelText(/webhook url/i), 'https://partner.example.com/events')
    await user.click(screen.getByRole('checkbox', { name: /credential offered/i }))
    await user.click(screen.getByRole('button', { name: /^create$/i }))

    await waitFor(() => {
      expect(mockCreateWebhook).toHaveBeenCalledWith('org-123', expect.objectContaining({
        eventTypes: ['credential.offered'],
      }))
    })
  })

  it('preserves the all-current-and-future-events subscription', async () => {
    const { user } = renderWithoutRouter(<WebhookManager />)

    await user.click(await screen.findByRole('button', { name: /add your first webhook/i }))
    await user.type(screen.getByLabelText(/webhook url/i), 'https://partner.example.com/events')
    await user.click(screen.getByRole('checkbox', { name: /all events/i }))
    await user.click(screen.getByRole('button', { name: /^create$/i }))

    await waitFor(() => {
      expect(mockCreateWebhook).toHaveBeenCalledWith('org-123', expect.objectContaining({
        eventTypes: ['*'],
      }))
    })
  })
})
