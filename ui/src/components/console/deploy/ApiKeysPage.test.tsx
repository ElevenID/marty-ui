import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router'
import { screen, waitFor, within } from '@testing-library/react'
import { renderWithoutRouter } from '../../../test/utils'
import ApiKeysPage from './ApiKeysPage'

const {
  mockListApiKeys,
  mockCreateApiKey,
  mockRevokeApiKey,
  mockListWebhooks,
  mockCreateWebhook,
  mockGetAvailableEventTypes,
  mockUseConsole,
} = vi.hoisted(() => ({
  mockListApiKeys: vi.fn(),
  mockCreateApiKey: vi.fn(),
  mockRevokeApiKey: vi.fn(),
  mockListWebhooks: vi.fn(),
  mockCreateWebhook: vi.fn(),
  mockGetAvailableEventTypes: vi.fn(),
  mockUseConsole: vi.fn(),
}))

vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => mockUseConsole(),
}))

vi.mock('../../../services/apiKeysApi', () => ({
  listApiKeys: (...args: unknown[]) => mockListApiKeys(...args),
  createApiKey: (...args: unknown[]) => mockCreateApiKey(...args),
  revokeApiKey: (...args: unknown[]) => mockRevokeApiKey(...args),
}))

vi.mock('../../../services/webhooksApi', () => ({
  listWebhooks: (...args: unknown[]) => mockListWebhooks(...args),
  createWebhook: (...args: unknown[]) => mockCreateWebhook(...args),
  getAvailableEventTypes: (...args: unknown[]) => mockGetAvailableEventTypes(...args),
}))

describe('ApiKeysPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockUseConsole.mockReturnValue({ activeOrgId: 'org-123' })
    mockListApiKeys.mockResolvedValue([])
    mockListWebhooks.mockResolvedValue([])
    mockGetAvailableEventTypes.mockResolvedValue({
      categories: [
        {
          name: 'Application',
          events: [
            { type: 'application.approved', description: 'application approved' },
            { type: 'application.rejected', description: 'application rejected' },
          ],
        },
        {
          name: 'Credential',
          events: [
            { type: 'credential.offered', description: 'credential offered' },
            { type: 'credential.issued', description: 'credential issued' },
            { type: 'credential.revoked', description: 'credential revoked' },
          ],
        },
        {
          name: 'Verification',
          events: [
            { type: 'verification.requested', description: 'verification requested' },
          ],
        },
      ],
    })
    mockCreateApiKey.mockResolvedValue({
      id: 'key-new',
      name: 'Gateway Partner',
      key: 'pk_live_secret',
      key_prefix: 'pk_live_',
      scopes: ['flows:execute'],
      status: 'active',
      created_at: '2026-04-20T10:00:00Z',
    })
    mockCreateWebhook.mockResolvedValue({
      id: 'wh-new',
      url: 'https://partner.example.com/callbacks',
      event_types: ['application.approved'],
      secret: 'whsec_test',
      enabled: true,
    })
    mockRevokeApiKey.mockResolvedValue({ status: 'revoked' })
  })

  it('renders snake_case api key data and shows associated callback', async () => {
    mockListApiKeys.mockResolvedValueOnce([
      {
        id: 'key-1',
        name: 'Partner A',
        key_prefix: 'pk_live_',
        scopes: null,
        status: 'active',
        created_at: '2026-04-20T09:00:00Z',
        last_used_at: null,
      },
    ])
    mockListWebhooks.mockResolvedValueOnce([
      {
        id: 'wh-1',
        url: 'https://partner.example.com/callbacks',
        description: 'Partner callback [api-key:key-1]',
        event_types: ['credential.issued'],
        enabled: true,
      },
    ])

    renderWithoutRouter(
      <MemoryRouter>
        <ApiKeysPage />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByText('Partner A')).toBeInTheDocument()
    })

    expect(screen.getByText('https://partner.example.com/callbacks')).toBeInTheDocument()
    expect(screen.getByText('No scopes assigned')).toBeInTheDocument()
  })

  it('shows callback status as unavailable when webhooks cannot be loaded', async () => {
    mockListApiKeys.mockResolvedValueOnce([
      {
        id: 'key-1',
        name: 'Partner A',
        key_prefix: 'pk_live_',
        scopes: ['flows:execute'],
        status: 'active',
      },
    ])
    mockListWebhooks.mockRejectedValueOnce(new Error('webhook service unavailable'))

    renderWithoutRouter(
      <MemoryRouter>
        <ApiKeysPage />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByText('Partner A')).toBeInTheDocument()
    })

    expect(screen.getByText(/Callback status could not be loaded/i)).toBeInTheDocument()
    expect(screen.getAllByText('Unavailable').length).toBeGreaterThanOrEqual(2)
  })

  it('offers the published wallet registry API-key scopes', async () => {
    const { user } = renderWithoutRouter(
      <MemoryRouter>
        <ApiKeysPage />
      </MemoryRouter>
    )

    await user.click(await screen.findByRole('button', {
      name: /create api key|generate api key|deploy\.apiKeysPage\.generateKey/i,
    }))

    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getByText('Read wallet registry')).toBeInTheDocument()
    expect(within(dialog).getByText('Manage wallet registry')).toBeInTheDocument()
  })

  it('creates an api key and paired callback in one flow', async () => {
    const { user } = renderWithoutRouter(
      <MemoryRouter>
        <ApiKeysPage />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /create api key|generate api key|deploy\.apiKeysPage\.generateKey/i })).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: /create api key|generate api key|deploy\.apiKeysPage\.generateKey/i }))

    const dialog = screen.getByRole('dialog')
    await user.type(within(dialog).getByLabelText('Key name'), 'Gateway Partner')
    await user.type(within(dialog).getByLabelText('Callback URL'), 'https://partner.example.com/callbacks')
    await user.click(within(dialog).getByRole('button', { name: 'Create integration key' }))

    await waitFor(() => {
      expect(mockCreateApiKey).toHaveBeenCalledWith('org-123', expect.objectContaining({
        name: 'Gateway Partner',
        scopes: expect.arrayContaining(['flows:execute']),
      }))
    })

    expect(mockCreateWebhook).toHaveBeenCalledWith('org-123', expect.objectContaining({
      url: 'https://partner.example.com/callbacks',
      eventTypes: expect.arrayContaining(['application.approved']),
      description: expect.stringContaining('[api-key:key-new]'),
    }))

    await waitFor(() => {
      expect(screen.getByText('Integration provisioned')).toBeInTheDocument()
      expect(screen.getByDisplayValue('pk_live_secret')).toBeInTheDocument()
    })
  })

  it('offers only callback events advertised by the Rust catalog', async () => {
    const { user } = renderWithoutRouter(
      <MemoryRouter>
        <ApiKeysPage />
      </MemoryRouter>
    )

    await user.click(await screen.findByRole('button', {
      name: /create api key|generate api key|deploy\.apiKeysPage\.generateKey/i,
    }))

    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getByText('credential offered')).toBeInTheDocument()
    expect(within(dialog).getByText('verification requested')).toBeInTheDocument()
    expect(within(dialog).queryByText('Verification completed')).not.toBeInTheDocument()
    expect(within(dialog).queryByText('Application submitted')).not.toBeInTheDocument()
  })

  it('offers the public admissions and webhook evidence scopes', async () => {
    const { user } = renderWithoutRouter(
      <MemoryRouter>
        <ApiKeysPage />
      </MemoryRouter>
    )

    await user.click(await screen.findByRole('button', {
      name: /create api key|generate api key|deploy\.apiKeysPage\.generateKey/i,
    }))

    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getByText('Read applications')).toBeInTheDocument()
    expect(within(dialog).getByText('Approve applications')).toBeInTheDocument()
    expect(within(dialog).getByText('Read webhook delivery history')).toBeInTheDocument()
  })

  it('does not provision a key with an unvalidated callback catalog', async () => {
    mockGetAvailableEventTypes.mockRejectedValueOnce(new Error('catalog unavailable'))
    const { user } = renderWithoutRouter(
      <MemoryRouter>
        <ApiKeysPage />
      </MemoryRouter>
    )

    await user.click(await screen.findByRole('button', {
      name: /create api key|generate api key|deploy\.apiKeysPage\.generateKey/i,
    }))

    const dialog = screen.getByRole('dialog')
    await user.type(within(dialog).getByLabelText('Key name'), 'Unsafe callback')
    await user.type(within(dialog).getByLabelText('Callback URL'), 'https://partner.example.com/callbacks')
    await user.click(within(dialog).getByRole('button', { name: 'Create integration key' }))

    expect(await screen.findByText(/webhook event types are unavailable/i)).toBeInTheDocument()
    expect(mockCreateApiKey).not.toHaveBeenCalled()
    expect(mockCreateWebhook).not.toHaveBeenCalled()
  })

  it('creates an api key without claiming a callback was provisioned when callback is disabled', async () => {
    const { user } = renderWithoutRouter(
      <MemoryRouter>
        <ApiKeysPage />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /create api key|generate api key|deploy\.apiKeysPage\.generateKey/i })).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: /create api key|generate api key|deploy\.apiKeysPage\.generateKey/i }))

    const dialog = screen.getByRole('dialog')
    await user.type(within(dialog).getByLabelText('Key name'), 'Gateway Partner')
    await user.click(within(dialog).getByLabelText('Provision associated callback'))
    await user.click(within(dialog).getByRole('button', { name: 'Create integration key' }))

    await waitFor(() => {
      expect(mockCreateApiKey).toHaveBeenCalledWith('org-123', expect.objectContaining({
        name: 'Gateway Partner',
        scopes: expect.arrayContaining(['flows:execute']),
      }))
    })

    expect(mockCreateWebhook).not.toHaveBeenCalled()
    await waitFor(() => {
      expect(screen.getByText('Integration provisioned')).toBeInTheDocument()
      expect(screen.getByText(/No callback endpoint was provisioned/i)).toBeInTheDocument()
      expect(screen.queryByText(/Callback endpoint provisioned for asynchronous events/i)).not.toBeInTheDocument()
    })
  })

  it('opens and confirms revoke confirmation dialog', async () => {
    mockListApiKeys.mockResolvedValueOnce([
      {
        id: 'key-1',
        name: 'Partner A',
        key_prefix: 'pk_live_',
        scopes: ['flows:execute'],
        status: 'active',
        created_at: '2026-04-20T09:00:00Z',
        last_used_at: null,
      },
    ])

    const { user } = renderWithoutRouter(
      <MemoryRouter>
        <ApiKeysPage />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByText('Partner A')).toBeInTheDocument()
    })

    const revokeButton = screen.getByRole('button', { name: /revoke key/i })
    await user.click(revokeButton)

    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument()
    })

    const confirmDialog = screen.getByRole('dialog')
    const confirmButton = within(confirmDialog).getByRole('button', { name: /revoke/i })
    await user.click(confirmButton)

    await waitFor(() => {
      expect(mockRevokeApiKey).toHaveBeenCalledWith('org-123', 'key-1')
    })
  })
})
