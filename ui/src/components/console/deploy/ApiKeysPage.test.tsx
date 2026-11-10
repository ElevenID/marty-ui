import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router'
import { http, HttpResponse } from 'msw'
import { act, screen, waitFor, within } from '@testing-library/react'
import { renderWithoutRouter, renderWithRouter } from '../../../test/utils'
import { server } from '../../../test/mocks/server'
import ApiKeysPage from './ApiKeysPage'

const {
  mockListApiKeys,
  mockCreateApiKey,
  mockRevokeApiKey,
  mockListWebhooks,
  mockCreateWebhook,
  mockGetAvailableEventTypes,
  mockUseConsole,
  mockUseAuth,
  mockUsePermissions,
} = vi.hoisted(() => ({
  mockListApiKeys: vi.fn(),
  mockCreateApiKey: vi.fn(),
  mockRevokeApiKey: vi.fn(),
  mockListWebhooks: vi.fn(),
  mockCreateWebhook: vi.fn(),
  mockGetAvailableEventTypes: vi.fn(),
  mockUseConsole: vi.fn(),
  mockUseAuth: vi.fn(),
  mockUsePermissions: vi.fn(),
}))

vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => mockUseConsole(),
}))

vi.mock('../../../hooks/useAuth', () => ({
  useAuth: () => mockUseAuth(),
}))

vi.mock('../../../hooks/usePermissions', () => ({
  usePermissions: () => mockUsePermissions(),
}))

function setPermissions(grants: string[], isLoading = false) {
  mockUsePermissions.mockReturnValue({
    can: (resource: string, action: string) => grants.includes(`${resource}:${action}`),
    isLoading,
    roles: [{ name: 'custom-integration-role' }],
  })
}

vi.mock('../../../services/apiKeysApi', () => ({
  listApiKeys: (...args: unknown[]) => mockListApiKeys(...args),
  createApiKey: (...args: unknown[]) => mockCreateApiKey(...args),
  revokeApiKey: (...args: unknown[]) => mockRevokeApiKey(...args),
}))

vi.mock('../../../services/webhooksApi', () => ({
  listWebhooks: (...args: unknown[]) => mockListWebhooks(...args),
  createWebhookConfiguration: (...args: unknown[]) => mockCreateWebhook(...args),
  getAvailableEventTypes: (...args: unknown[]) => mockGetAvailableEventTypes(...args),
}))

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail })
  return { promise, resolve, reject }
}

const createAction = /create api key|generate api key|deploy\.apiKeysPage\.generateKey/i

describe('ApiKeysPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockUseConsole.mockReturnValue({ activeOrgId: 'org-123' })
    mockUseAuth.mockReturnValue({ isAuthenticated: true, user: { user_id: 'user-123' } })
    setPermissions(['api-key:view', 'api-key:create', 'api-key:revoke', 'webhook:view', 'webhook:create'])
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
    expect(screen.getByText('Active gateway keys').parentElement).toHaveStyle({ alignItems: 'center' })
    expect(screen.getByText('Partner A')).toHaveStyle({ fontWeight: 600 })
    expect(document.querySelector('[alignitems], [fontweight]')).toBeNull()
  })

  it('loads native callback events for the selected organization when the session default is only an applicant', async () => {
    const actual = await vi.importActual<typeof import('../../../services/webhooksApi')>('../../../services/webhooksApi')
    mockGetAvailableEventTypes.mockImplementation(actual.getAvailableEventTypes)
    mockUseAuth.mockReturnValue({ isAuthenticated: true, user: { user_id: 'user-123' }, organizationId: 'org-applicant' })
    const organizations: Array<string | null> = []
    server.use(http.get('http://localhost:8000/v1/webhooks/event-types', ({ request }) => {
      const organizationId = new URL(request.url).searchParams.get('organization_id')
      organizations.push(organizationId)
      return organizationId === 'org-123' || organizationId === 'org-456'
        ? HttpResponse.json({ event_types: [organizationId === 'org-123' ? 'credential.offered' : 'application.approved'] })
        : HttpResponse.json({ error: 'forbidden', error_description: 'Missing required permission: webhook:view' }, { status: 403 })
    }))

    const { user, rerender } = renderWithRouter(<ApiKeysPage />)
    await user.click(await screen.findByRole('button', { name: createAction }))
    expect(await screen.findByRole('checkbox', { name: 'credential offered' })).toBeInTheDocument()
    expect(screen.queryByText(/Webhook event types could not be loaded/)).not.toBeInTheDocument()

    mockUseConsole.mockReturnValue({ activeOrgId: 'org-456' })
    rerender(<ApiKeysPage />)
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await user.click(await screen.findByRole('button', { name: createAction }))
    expect(await screen.findByRole('checkbox', { name: 'application approved' })).toBeInTheDocument()
    expect(screen.queryByRole('checkbox', { name: 'credential offered' })).not.toBeInTheDocument()
    expect(organizations).toEqual(['org-123', 'org-456'])
    expect(mockCreateApiKey).not.toHaveBeenCalled()
    expect(mockCreateWebhook).not.toHaveBeenCalled()
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
    expect(screen.queryByText('No paired callback')).not.toBeInTheDocument()
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
      }), expect.objectContaining({ isCurrent: expect.any(Function) }))
    })

    expect(mockCreateWebhook).toHaveBeenCalledWith('org-123', expect.objectContaining({
      url: 'https://partner.example.com/callbacks',
      eventTypes: expect.arrayContaining(['application.approved']),
      description: expect.stringContaining('[api-key:key-new]'),
    }), expect.objectContaining({ isCurrent: expect.any(Function) }))

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
      }), expect.objectContaining({ isCurrent: expect.any(Function) }))
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

  it('shows a retryable load error without claiming the organization has no keys', async () => {
    mockListApiKeys.mockRejectedValueOnce(new Error('Keys are temporarily unavailable'))
    const { user } = renderWithRouter(<ApiKeysPage />)
    expect(await screen.findByText('Keys are temporarily unavailable')).toBeInTheDocument()
    expect(screen.queryByText('No API keys configured')).not.toBeInTheDocument()
    expect(screen.getAllByText('Unavailable')).toHaveLength(3)
    expect(screen.getByRole('button', { name: createAction })).toBeDisabled()

    await user.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('No API keys configured')).toBeInTheDocument()
    expect(mockListApiKeys).toHaveBeenCalledTimes(2)
    expect(screen.getByRole('button', { name: createAction })).toBeEnabled()
  })

  it('does not load or create keys without an active organization', async () => {
    mockUseConsole.mockReturnValue({ activeOrgId: null })
    renderWithRouter(<ApiKeysPage />)
    expect(await screen.findByText('Select an organization to manage API keys.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: createAction })).toBeDisabled()
    expect(mockListApiKeys).not.toHaveBeenCalled()
    expect(mockListWebhooks).not.toHaveBeenCalled()
    expect(mockGetAvailableEventTypes).not.toHaveBeenCalled()
  })

  it('discards the creation draft when the organization changes', async () => {
    const { user, rerender } = renderWithRouter(<ApiKeysPage />)
    await user.click(await screen.findByRole('button', { name: createAction }))
    await user.type(screen.getByLabelText('Key name'), 'Previous organization')

    mockUseConsole.mockReturnValue({ activeOrgId: 'org-456' })
    rerender(<ApiKeysPage />)
    await waitFor(() => expect(mockListApiKeys).toHaveBeenLastCalledWith('org-456'))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: createAction }))
    expect(screen.getByLabelText('Key name')).toHaveValue('')
    expect(mockCreateApiKey).not.toHaveBeenCalled()
  })

  it('does not start a callback or show a secret after a pending key request loses its organization', async () => {
    const request = deferred<unknown>()
    mockCreateApiKey.mockReturnValueOnce(request.promise)
    const { user, rerender } = renderWithRouter(<ApiKeysPage />)
    await user.click(await screen.findByRole('button', { name: createAction }))
    await user.type(screen.getByLabelText('Key name'), 'Previous organization')
    await user.type(screen.getByLabelText('Callback URL'), 'https://partner.example.com/callbacks')
    await user.click(screen.getByRole('button', { name: 'Create integration key' }))
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled()
    expect(screen.getByLabelText('Key name')).toBeDisabled()
    await user.keyboard('{Escape}')
    expect(screen.getByRole('dialog')).toBeInTheDocument()

    mockUseConsole.mockReturnValue({ activeOrgId: 'org-456' })
    rerender(<ApiKeysPage />)
    await waitFor(() => expect(mockListApiKeys).toHaveBeenLastCalledWith('org-456'))
    await user.click(screen.getByRole('button', { name: createAction }))
    await user.type(screen.getByLabelText('Key name'), 'Current organization')
    await act(async () => request.resolve({ id: 'old-key', key: 'old-secret', name: 'Previous organization' }))

    expect(mockCreateApiKey).toHaveBeenCalledOnce()
    expect(mockCreateApiKey.mock.calls[0][0]).toBe('org-123')
    expect(mockCreateWebhook).not.toHaveBeenCalled()
    expect(screen.queryByDisplayValue('old-secret')).not.toBeInTheDocument()
    expect(screen.getByLabelText('Key name')).toHaveValue('Current organization')
    expect(screen.getByRole('button', { name: 'Create integration key' })).toBeEnabled()
  })

  it.each(['resolve', 'reject'] as const)('ignores a late callback %s after switching organizations', async (completion) => {
    const request = deferred<unknown>()
    mockCreateWebhook.mockReturnValueOnce(request.promise)
    const { user, rerender } = renderWithRouter(<ApiKeysPage />)
    await user.click(await screen.findByRole('button', { name: createAction }))
    await user.type(screen.getByLabelText('Key name'), 'Previous organization')
    await user.type(screen.getByLabelText('Callback URL'), 'https://partner.example.com/callbacks')
    await user.click(screen.getByRole('button', { name: 'Create integration key' }))
    await waitFor(() => expect(mockCreateWebhook).toHaveBeenCalledOnce())

    mockUseConsole.mockReturnValue({ activeOrgId: 'org-456' })
    rerender(<ApiKeysPage />)
    await waitFor(() => expect(mockListApiKeys).toHaveBeenLastCalledWith('org-456'))
    await user.click(screen.getByRole('button', { name: createAction }))
    await act(async () => {
      if (completion === 'resolve') request.resolve({ id: 'old-callback', secret: 'old-callback-secret' })
      else request.reject(new Error('Previous callback failed'))
    })

    expect(screen.getByLabelText('Key name')).toHaveValue('')
    expect(screen.queryByText('Integration provisioned')).not.toBeInTheDocument()
    expect(screen.queryByText(/Previous callback failed/)).not.toBeInTheDocument()
    expect(screen.queryByDisplayValue('old-callback-secret')).not.toBeInTheDocument()
    expect(mockCreateWebhook.mock.calls[0][0]).toBe('org-123')
  })

  it('keeps clipboard failures visible inside the provisioned-key dialog', async () => {
    const { user } = renderWithRouter(<ApiKeysPage />)
    await user.click(await screen.findByRole('button', { name: createAction }))
    await user.type(screen.getByLabelText('Key name'), 'Partner')
    await user.click(screen.getByLabelText('Provision associated callback'))
    await user.click(screen.getByRole('button', { name: 'Create integration key' }))
    await screen.findByText('Integration provisioned')
    vi.spyOn(navigator.clipboard, 'writeText').mockRejectedValueOnce(new Error('Clipboard denied'))
    await user.click(screen.getByRole('button', { name: 'Copy API key' }))

    const dialog = screen.getByRole('dialog')
    expect(await within(dialog).findByText('Unable to copy api key.')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('API key')).toHaveValue('pk_live_secret')
  })

  it('keeps a failed revocation in its confirmation dialog for retry', async () => {
    mockListApiKeys.mockResolvedValue([{ id: 'key-1', name: 'Partner', scopes: [], status: 'active' }])
    mockRevokeApiKey.mockRejectedValueOnce(new Error('Revocation unavailable'))
    const { user } = renderWithRouter(<ApiKeysPage />)
    await user.click(await screen.findByRole('button', { name: 'Revoke key' }))
    await user.click(screen.getByRole('button', { name: 'Revoke' }))
    expect(await screen.findByText('Revocation unavailable')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Revoke' })).toBeEnabled()
  })

  it.each([
    { grant: 'api-key:view', create: false, revoke: false },
    { grant: 'api-key:create', create: true, revoke: false },
    { grant: 'api-key:revoke', create: false, revoke: true },
    { grant: 'api-key:delete', create: false, revoke: false },
  ])('checks the exact custom-role grant $grant for API key actions', async ({ grant, create, revoke }) => {
    setPermissions(['api-key:view', 'webhook:view', grant])
    mockListApiKeys.mockResolvedValue([{ id: 'key-1', name: 'Partner', status: 'active' }])
    renderWithRouter(<ApiKeysPage />)
    const revokeButton = await screen.findByRole('button', { name: 'Revoke key' })
    const createButton = screen.getByRole('button', { name: createAction })
    expect(createButton).toHaveProperty('disabled', !create)
    expect(revokeButton).toHaveProperty('disabled', !revoke)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(mockCreateApiKey).not.toHaveBeenCalled()
    expect(mockRevokeApiKey).not.toHaveBeenCalled()
  })

  it('loads API keys without requesting callback information outside the current grants', async () => {
    setPermissions(['api-key:view'])
    mockListApiKeys.mockResolvedValue([{ id: 'key-1', name: 'Limited partner', key_prefix: 'fixture_', status: 'active' }])
    renderWithRouter(<ApiKeysPage />)

    const row = await screen.findByRole('row', { name: /Limited partner/ })
    expect(mockListWebhooks).not.toHaveBeenCalled()
    expect(mockGetAvailableEventTypes).not.toHaveBeenCalled()
    expect(within(row).getByText('Unavailable')).toBeInTheDocument()
    expect(within(row).queryByText('No paired callback')).not.toBeInTheDocument()
    expect(screen.getByText(/Webhook viewing permission is required/)).toBeInTheDocument()
    expect(screen.queryByText(/Callback status could not be loaded/)).not.toBeInTheDocument()
  })

  it('keeps key creation usable when webhook creation is allowed without webhook viewing', async () => {
    setPermissions(['api-key:view', 'api-key:create', 'webhook:create'])
    const { user } = renderWithRouter(<ApiKeysPage />)
    await user.click(await screen.findByRole('button', { name: createAction }))
    expect(screen.getByLabelText('Provision associated callback')).toBeDisabled()
    expect(screen.getByLabelText('Provision associated callback')).not.toBeChecked()
    expect(screen.queryByLabelText('Callback URL')).not.toBeInTheDocument()
    await user.type(screen.getByLabelText('Key name'), 'Key-only partner')
    await user.click(screen.getByRole('button', { name: 'Create integration key' }))

    expect(await screen.findByLabelText('API key')).toHaveValue('pk_live_secret')
    expect(mockCreateApiKey).toHaveBeenCalledTimes(1)
    expect(mockCreateWebhook).not.toHaveBeenCalled()
    expect(mockListWebhooks).not.toHaveBeenCalled()
    expect(mockGetAvailableEventTypes).not.toHaveBeenCalled()
  })

  it('withdraws loaded callback information when viewing permission changes and restores it after reauthorization', async () => {
    mockListApiKeys.mockResolvedValue([{ id: 'key-1', name: 'Partner', status: 'active' }])
    mockListWebhooks.mockResolvedValue([{
      id: 'wh-1', url: 'https://partner.example.com/private-callback',
      description: 'Partner callback [api-key:key-1]', event_types: ['credential.issued'], enabled: true,
    }])
    const { rerender } = renderWithRouter(<ApiKeysPage />)
    await screen.findByText('https://partner.example.com/private-callback')
    expect(mockListWebhooks).toHaveBeenCalledTimes(1)
    expect(mockGetAvailableEventTypes).toHaveBeenCalledTimes(1)

    setPermissions(['api-key:view', 'api-key:create'])
    rerender(<ApiKeysPage />)
    expect(screen.queryByText('https://partner.example.com/private-callback')).not.toBeInTheDocument()
    expect(screen.getByText(/Webhook viewing permission is required/)).toBeInTheDocument()
    await screen.findByRole('row', { name: /Partner/ })
    expect(mockListWebhooks).toHaveBeenCalledTimes(1)
    expect(mockGetAvailableEventTypes).toHaveBeenCalledTimes(1)

    setPermissions(['api-key:view', 'api-key:create', 'webhook:view'])
    rerender(<ApiKeysPage />)
    await screen.findByText('https://partner.example.com/private-callback')
    expect(mockListWebhooks).toHaveBeenCalledTimes(2)
    expect(mockGetAvailableEventTypes).toHaveBeenCalledTimes(2)
    expect(screen.queryByText(/Webhook viewing permission is required/)).not.toBeInTheDocument()
  })

  it('lets a key creator without webhook-create permission create a key without a callback', async () => {
    setPermissions(['api-key:view', 'api-key:create', 'webhook:view'])
    const { user } = renderWithRouter(<ApiKeysPage />)
    await user.click(await screen.findByRole('button', { name: createAction }))
    const callbackSwitch = screen.getByLabelText('Provision associated callback')
    expect(callbackSwitch).not.toBeChecked()
    expect(callbackSwitch).toBeDisabled()
    expect(screen.getByText('Creating an associated callback requires webhook creation permission.')).toBeInTheDocument()
    expect(screen.queryByLabelText('Callback URL')).not.toBeInTheDocument()
    await user.type(screen.getByLabelText('Key name'), 'Key-only partner')
    await user.click(screen.getByRole('button', { name: 'Create integration key' }))

    expect(await screen.findByLabelText('API key')).toHaveValue('pk_live_secret')
    expect(mockCreateApiKey).toHaveBeenCalledWith('org-123', expect.objectContaining({ name: 'Key-only partner' }), expect.objectContaining({ isCurrent: expect.any(Function) }))
    expect(mockCreateWebhook).not.toHaveBeenCalled()
  })

  it('waits for resolved permissions and resets the draft while new-organization permissions load', async () => {
    const grants = ['api-key:view', 'api-key:create', 'api-key:revoke', 'webhook:view', 'webhook:create']
    setPermissions(grants, true)
    const { user, rerender } = renderWithRouter(<ApiKeysPage />)
    await screen.findByText('No API keys configured')
    expect(screen.getByRole('button', { name: createAction })).toBeDisabled()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()

    setPermissions(grants)
    rerender(<ApiKeysPage />)
    await user.click(screen.getByRole('button', { name: createAction }))
    await user.type(screen.getByLabelText('Key name'), 'Previous organization draft')
    mockUseConsole.mockReturnValue({ activeOrgId: 'org-456' })
    setPermissions(grants, true)
    rerender(<ApiKeysPage />)
    await waitFor(() => expect(mockListApiKeys).toHaveBeenLastCalledWith('org-456'))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: createAction })).toBeDisabled()

    setPermissions(['api-key:view', 'webhook:view'])
    rerender(<ApiKeysPage />)
    expect(screen.getByRole('button', { name: createAction })).toBeDisabled()
    expect(mockCreateApiKey).not.toHaveBeenCalled()
    expect(mockCreateWebhook).not.toHaveBeenCalled()
  })

  it('blocks an open creation form when its action permission becomes unavailable', async () => {
    const { user, rerender } = renderWithRouter(<ApiKeysPage />)
    await user.click(await screen.findByRole('button', { name: createAction }))
    await user.type(screen.getByLabelText('Key name'), 'Partner')
    await user.click(screen.getByLabelText('Provision associated callback'))
    setPermissions(['api-key:view', 'webhook:view'])
    rerender(<ApiKeysPage />)

    expect(screen.getByText('You do not have permission to create API keys in this organization.')).toBeInTheDocument()
    expect(screen.getByLabelText('Key name')).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Create integration key' })).toBeDisabled()
    expect(mockCreateApiKey).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeEnabled()
  })

  it('discards a revocation confirmation when its permission becomes unavailable', async () => {
    mockListApiKeys.mockResolvedValue([{ id: 'key-1', name: 'Partner', status: 'active' }])
    const { user, rerender } = renderWithRouter(<ApiKeysPage />)
    await user.click(await screen.findByRole('button', { name: 'Revoke key' }))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    setPermissions(['api-key:view', 'api-key:revoke'], true)
    rerender(<ApiKeysPage />)
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(screen.getByRole('button', { name: 'Revoke key' })).toBeDisabled()
    setPermissions(['api-key:view', 'api-key:revoke'])
    rerender(<ApiKeysPage />)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(mockRevokeApiKey).not.toHaveBeenCalled()
  })

  it('rechecks callback permission after key creation and keeps the already-created key', async () => {
    const request = deferred<unknown>()
    mockCreateApiKey.mockReturnValueOnce(request.promise)
    const { user, rerender } = renderWithRouter(<ApiKeysPage />)
    await user.click(await screen.findByRole('button', { name: createAction }))
    await user.type(screen.getByLabelText('Key name'), 'Partner')
    await user.type(screen.getByLabelText('Callback URL'), 'https://partner.example.com/callbacks')
    await user.click(screen.getByRole('button', { name: 'Create integration key' }))
    setPermissions(['api-key:view', 'api-key:create', 'webhook:view'])
    rerender(<ApiKeysPage />)
    await act(async () => request.resolve({ id: 'key-new', name: 'Partner', key: 'created-key-secret' }))

    expect(await screen.findByLabelText('API key')).toHaveValue('created-key-secret')
    expect(screen.getByText(/Callback creation was skipped because your creation permissions are no longer available/)).toBeInTheDocument()
    expect(mockCreateWebhook).not.toHaveBeenCalled()
    expect(mockCreateApiKey).toHaveBeenCalledOnce()
  })

  it('discards pending creation results when the native account changes within the same organization', async () => {
    mockUseAuth.mockReturnValue({ isAuthenticated: true, user: { user_id: 'user-123', sub: 'unchanged-sub' } })
    const request = deferred<unknown>()
    mockCreateApiKey.mockReturnValueOnce(request.promise)
    const { user, rerender } = renderWithRouter(<ApiKeysPage />)
    await user.click(await screen.findByRole('button', { name: createAction }))
    await user.type(screen.getByLabelText('Key name'), 'Previous account')
    await user.type(screen.getByLabelText('Callback URL'), 'https://partner.example.com/callbacks')
    await user.click(screen.getByRole('button', { name: 'Create integration key' }))

    mockUseAuth.mockReturnValue({ isAuthenticated: true, user: { user_id: 'user-456', sub: 'unchanged-sub' } })
    rerender(<ApiKeysPage />)
    await act(async () => request.resolve({ id: 'old-key', key: 'previous-account-secret' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.queryByDisplayValue('previous-account-secret')).not.toBeInTheDocument()
    expect(mockCreateWebhook).not.toHaveBeenCalled()
  })

  it.each(['resolve', 'reject'] as const)('does not show a previous dialog clipboard %s on a replacement key', async (completion) => {
    const { user } = renderWithRouter(<ApiKeysPage />)
    await user.click(await screen.findByRole('button', { name: createAction }))
    await user.type(screen.getByLabelText('Key name'), 'First key')
    await user.click(screen.getByLabelText('Provision associated callback'))
    await user.click(screen.getByRole('button', { name: 'Create integration key' }))
    await screen.findByLabelText('API key')
    const request = deferred<void>()
    const copy = vi.spyOn(navigator.clipboard, 'writeText').mockReturnValueOnce(request.promise)
    await user.click(screen.getByRole('button', { name: 'Copy API key' }))
    expect(copy).toHaveBeenLastCalledWith('pk_live_secret')
    await waitFor(() => expect(screen.getByRole('button', { name: 'Done' })).toBeEnabled())
    await user.click(screen.getByRole('button', { name: 'Done' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())

    mockCreateApiKey.mockResolvedValue({ id: 'key-second', name: 'Second key', key: 'replacement-secret' })
    await user.click(screen.getByRole('button', { name: createAction }))
    await user.type(screen.getByLabelText('Key name'), 'Second key')
    await user.click(screen.getByLabelText('Provision associated callback'))
    await user.click(screen.getByRole('button', { name: 'Create integration key' }))
    expect(await screen.findByLabelText('API key')).toHaveValue('replacement-secret')
    await act(async () => {
      if (completion === 'resolve') request.resolve()
      else request.reject(new Error('Previous clipboard request denied'))
    })

    expect(screen.queryByText('API key copied to clipboard.')).not.toBeInTheDocument()
    expect(screen.queryByText('Unable to copy api key.')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Copy API key' }))
    expect(copy).toHaveBeenLastCalledWith('replacement-secret')
    expect(await screen.findByText('API key copied to clipboard.')).toBeInTheDocument()
  })
})
