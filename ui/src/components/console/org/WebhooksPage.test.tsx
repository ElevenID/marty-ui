import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router'
import { http, HttpResponse } from 'msw'
import { act, screen, waitFor, within } from '@testing-library/react'
import { renderWithoutRouter, renderWithRouter } from '../../../test/utils'
import { server } from '../../../test/mocks/server'
import WebhooksPage from './WebhooksPage'

const {
  mockListWebhooks,
  mockGetAvailableEventTypes,
  mockCreateWebhook,
  mockDeleteWebhook,
  mockTestWebhook,
  mockUpdateWebhook,
  mockUseConsole,
  mockUseAuth,
  mockUsePermissions,
} = vi.hoisted(() => ({
  mockListWebhooks: vi.fn(),
  mockGetAvailableEventTypes: vi.fn(),
  mockCreateWebhook: vi.fn(),
  mockDeleteWebhook: vi.fn(),
  mockTestWebhook: vi.fn(),
  mockUpdateWebhook: vi.fn(),
  mockUseConsole: vi.fn(),
  mockUseAuth: vi.fn(),
  mockUsePermissions: vi.fn(),
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

vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => mockUseConsole(),
}))

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail })
  return { promise, resolve, reject }
}

const webhook = {
  id: 'wh-1',
  name: 'Audit receiver',
  url: 'https://audit.example.com/events',
  description: 'Audit sink',
  event_types: ['audit.security_event'],
  enabled: true,
}

vi.mock('../../../services/webhooksApi', () => ({
  listWebhooks: (...args: unknown[]) => mockListWebhooks(...args),
  getAvailableEventTypes: (...args: unknown[]) => mockGetAvailableEventTypes(...args),
  createWebhookConfiguration: (...args: unknown[]) => mockCreateWebhook(...args),
  deleteWebhookConfiguration: (...args: unknown[]) => mockDeleteWebhook(...args),
  testWebhook: (...args: unknown[]) => mockTestWebhook(...args),
  updateWebhookConfiguration: (...args: unknown[]) => mockUpdateWebhook(...args),
}))

describe('WebhooksPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockUseConsole.mockReturnValue({ activeOrgId: 'org-123' })
    mockUseAuth.mockReturnValue({ isAuthenticated: true, user: { user_id: 'user-123' } })
    setPermissions(['webhook:view', 'webhook:create', 'webhook:edit', 'webhook:delete', 'webhook:test'])
    mockListWebhooks.mockResolvedValue([])
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
        name: 'Primary audit receiver',
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
    expect(screen.getByText('Primary audit receiver')).toBeInTheDocument()
    expect(screen.getByText('audit.security_event')).toBeInTheDocument()
    expect(screen.getByText('Active')).toBeInTheDocument()
    expect(screen.getByText('Async callback endpoints').parentElement).toHaveStyle({ alignItems: 'center' })
    expect(document.querySelector('[alignitems]')).toBeNull()
  })

  it('loads native event options in the selected owner organization rather than the session default', async () => {
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

    const { user, rerender } = renderWithRouter(<WebhooksPage />)
    await waitFor(() => expect(screen.getByRole('button', { name: /add webhook/i })).toBeEnabled())
    await user.click(await screen.findByRole('button', { name: /add webhook/i }))
    expect(await screen.findByRole('checkbox', { name: /credential offered/i })).toBeInTheDocument()
    expect(screen.queryByText(/Missing required permission/)).not.toBeInTheDocument()

    mockUseConsole.mockReturnValue({ activeOrgId: 'org-456' })
    rerender(<WebhooksPage />)
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await waitFor(() => expect(screen.getByRole('button', { name: /add webhook/i })).toBeEnabled())
    await user.click(await screen.findByRole('button', { name: /add webhook/i }))
    expect(await screen.findByRole('checkbox', { name: /application approved/i })).toBeInTheDocument()
    expect(screen.queryByRole('checkbox', { name: /credential offered/i })).not.toBeInTheDocument()
    expect(organizations).toEqual(['org-123', 'org-456'])
    expect(mockCreateWebhook).not.toHaveBeenCalled()
  })

  it('opens and confirms webhook delete confirmation dialog', async () => {
    mockListWebhooks.mockResolvedValueOnce([
      {
        id: 'wh-1',
        name: 'Primary audit receiver',
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
      expect(mockDeleteWebhook).toHaveBeenCalledWith('org-123', 'wh-1')
    })
  })

  it('requires and submits the native webhook name', async () => {
    mockListWebhooks.mockResolvedValue([])
    mockCreateWebhook.mockResolvedValue({ signing_secret: 'new-secret' })

    const { user } = renderWithoutRouter(
      <MemoryRouter>
        <WebhooksPage />
      </MemoryRouter>
    )

    await user.click(await screen.findByRole('button', { name: /add webhook/i }))
    await user.type(screen.getByLabelText(/webhook url/i), 'https://partner.example.com/events')
    await user.click(screen.getByRole('button', { name: /create webhook/i }))
    expect(await screen.findByText('Enter a webhook name.')).toBeInTheDocument()
    expect(mockCreateWebhook).not.toHaveBeenCalled()

    await user.type(screen.getByLabelText(/webhook name/i), 'Admissions receiver')
    await user.click(screen.getByRole('button', { name: /create webhook/i }))

    await waitFor(() => {
      expect(mockCreateWebhook).toHaveBeenCalledWith(
        'org-123',
        expect.objectContaining({
          name: 'Admissions receiver',
          url: 'https://partner.example.com/events',
        }),
      )
    })
  })

  it('preserves a disabled webhook when editing its description', async () => {
    mockListWebhooks.mockResolvedValue([{ ...webhook, enabled: false }])
    const { user } = renderWithRouter(<WebhooksPage />)
    await user.click(await screen.findByRole('button', { name: 'Edit webhook' }))
    await user.clear(screen.getByLabelText('Description'))
    await user.type(screen.getByLabelText('Description'), 'Updated audit sink')
    await user.click(screen.getByRole('button', { name: 'Update webhook' }))

    await waitFor(() => expect(mockUpdateWebhook).toHaveBeenCalledWith('org-123', 'wh-1', expect.objectContaining({
      description: 'Updated audit sink', enabled: false,
    })))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(screen.getByText('Disabled')).toBeInTheDocument()
  })

  it('reports a failed test callback and prevents duplicate requests while pending', async () => {
    mockListWebhooks.mockResolvedValue([webhook])
    const request = deferred<unknown>()
    mockTestWebhook.mockReturnValueOnce(request.promise)
    const { user } = renderWithRouter(<WebhooksPage />)
    await user.click(await screen.findByRole('button', { name: 'Send test callback' }))
    expect(screen.getByRole('button', { name: 'Requesting test callback' })).toBeDisabled()
    expect(mockTestWebhook).toHaveBeenCalledOnce()
    await act(async () => request.reject(new Error('Receiver unavailable')))

    expect(await screen.findByText('Receiver unavailable')).toBeInTheDocument()
    expect(screen.queryByText(/Test delivery requested/)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Send test callback' })).toBeEnabled()
  })

  it('keeps the creation dialog and inputs locked while saving, then shows completion without a returned secret', async () => {
    const request = deferred<unknown>()
    mockCreateWebhook.mockReturnValueOnce(request.promise)
    const { user } = renderWithRouter(<WebhooksPage />)
    await user.click(await screen.findByRole('button', { name: /add webhook/i }))
    await user.type(screen.getByLabelText('Webhook name'), 'Audit receiver')
    await user.type(screen.getByLabelText('Webhook URL'), 'https://audit.example.com/events')
    await user.click(screen.getByRole('button', { name: 'Create webhook' }))
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Saving…' })).toBeDisabled()
    expect(screen.getByLabelText('Webhook name')).toBeDisabled()
    await user.keyboard('{Escape}')
    expect(screen.getByRole('dialog')).toBeInTheDocument()

    await act(async () => request.resolve({ id: 'wh-new' }))
    expect(await screen.findByText('Webhook created successfully.')).toBeInTheDocument()
    expect(screen.getByText('No signing secret was returned.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Create webhook' })).not.toBeInTheDocument()
    expect(mockCreateWebhook).toHaveBeenCalledOnce()
    await user.click(screen.getByRole('button', { name: 'Close', exact: true }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: /add webhook/i }))
    expect(screen.getByLabelText('Webhook name')).toHaveValue('')
  })

  it.each(['resolve', 'reject'] as const)('discards late webhook creation %s after an organization switch', async (completion) => {
    const request = deferred<unknown>()
    mockCreateWebhook.mockReturnValueOnce(request.promise)
    const { user, rerender } = renderWithRouter(<WebhooksPage />)
    await user.click(await screen.findByRole('button', { name: /add webhook/i }))
    await user.type(screen.getByLabelText('Webhook name'), 'Previous receiver')
    await user.type(screen.getByLabelText('Webhook URL'), 'https://audit.example.com/events')
    await user.click(screen.getByRole('button', { name: 'Create webhook' }))

    mockUseConsole.mockReturnValue({ activeOrgId: 'org-456' })
    rerender(<WebhooksPage />)
    await waitFor(() => expect(mockListWebhooks).toHaveBeenLastCalledWith('org-456'))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /add webhook/i }))
    await user.type(screen.getByLabelText('Webhook name'), 'Current receiver')
    await act(async () => {
      if (completion === 'resolve') request.resolve({ id: 'previous-webhook', signing_secret: 'previous-secret' })
      else request.reject(new Error('Previous receiver failed'))
    })

    expect(screen.getByLabelText('Webhook name')).toHaveValue('Current receiver')
    expect(screen.getByRole('button', { name: 'Create webhook' })).toBeEnabled()
    expect(screen.queryByDisplayValue('previous-secret')).not.toBeInTheDocument()
    expect(screen.queryByText('Previous receiver failed')).not.toBeInTheDocument()
    expect(mockCreateWebhook).toHaveBeenCalledOnce()
    expect(mockCreateWebhook.mock.calls[0][0]).toBe('org-123')
  })

  it('discards the prior organization delete target before it can be confirmed', async () => {
    mockListWebhooks.mockImplementation((organizationId: string) => Promise.resolve(
      organizationId === 'org-123' ? [webhook] : [],
    ))
    const { user, rerender } = renderWithRouter(<WebhooksPage />)
    await user.click(await screen.findByRole('button', { name: 'Delete webhook' }))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    mockUseConsole.mockReturnValue({ activeOrgId: 'org-456' })
    rerender(<WebhooksPage />)

    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(await screen.findByText('No webhooks configured')).toBeInTheDocument()
    expect(mockDeleteWebhook).not.toHaveBeenCalled()
  })

  it('offers retry on a load failure without displaying an empty webhook list', async () => {
    mockListWebhooks.mockRejectedValueOnce(new Error('Webhooks are temporarily unavailable'))
    const { user } = renderWithRouter(<WebhooksPage />)
    expect(await screen.findByText('Webhooks are temporarily unavailable')).toBeInTheDocument()
    expect(screen.queryByText('No webhooks configured')).not.toBeInTheDocument()
    expect(screen.getAllByText('Unavailable')).toHaveLength(3)
    expect(screen.getByRole('button', { name: /add webhook/i })).toBeDisabled()

    await user.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('No webhooks configured')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /add webhook/i })).toBeEnabled()
  })

  it('does not load endpoints without an active organization', async () => {
    mockUseConsole.mockReturnValue({ activeOrgId: null })
    renderWithRouter(<WebhooksPage />)
    expect(await screen.findByText('Select an organization to manage webhooks.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /add webhook/i })).toBeDisabled()
    expect(mockListWebhooks).not.toHaveBeenCalled()
    expect(mockGetAvailableEventTypes).not.toHaveBeenCalled()
  })

  it('shows a rejected clipboard request inside the secret dialog', async () => {
    mockCreateWebhook.mockResolvedValue({ id: 'wh-new', signing_secret: 'webhook-secret' })
    const { user } = renderWithRouter(<WebhooksPage />)
    await user.click(await screen.findByRole('button', { name: /add webhook/i }))
    await user.type(screen.getByLabelText('Webhook name'), 'Audit receiver')
    await user.type(screen.getByLabelText('Webhook URL'), 'https://audit.example.com/events')
    await user.click(screen.getByRole('button', { name: 'Create webhook' }))
    await screen.findByLabelText('Webhook secret')
    vi.spyOn(navigator.clipboard, 'writeText').mockRejectedValueOnce(new Error('Clipboard denied'))
    await user.click(screen.getByRole('button', { name: 'Copy webhook secret' }))

    const dialog = screen.getByRole('dialog')
    expect(await within(dialog).findByText('Unable to copy webhook secret.')).toBeInTheDocument()
    expect(within(dialog).getByLabelText('Webhook secret')).toHaveValue('webhook-secret')
  })

  it.each(['view', 'create', 'edit', 'delete', 'test', 'execute'])('checks the exact custom-role webhook:%s grant for each action', async (action) => {
    setPermissions(['webhook:view', `webhook:${action}`])
    mockListWebhooks.mockResolvedValue([webhook])
    renderWithRouter(<WebhooksPage />)
    await screen.findByText('Audit receiver')
    const buttons = {
      create: screen.getByRole('button', { name: /add webhook/i }),
      edit: screen.getByRole('button', { name: 'Edit webhook' }),
      delete: screen.getByRole('button', { name: 'Delete webhook' }),
      test: screen.getByRole('button', { name: 'Send test callback' }),
    }
    for (const [grant, button] of Object.entries(buttons)) {
      expect(button).toHaveProperty('disabled', grant !== action)
    }
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(mockCreateWebhook).not.toHaveBeenCalled()
    expect(mockUpdateWebhook).not.toHaveBeenCalled()
    expect(mockDeleteWebhook).not.toHaveBeenCalled()
    expect(mockTestWebhook).not.toHaveBeenCalled()
  })

  it('waits for resolved permissions and clears an edit dialog while new-organization permissions load', async () => {
    const grants = ['webhook:view', 'webhook:create', 'webhook:edit', 'webhook:delete', 'webhook:test']
    setPermissions(grants, true)
    mockListWebhooks.mockResolvedValue([webhook])
    const { user, rerender } = renderWithRouter(<WebhooksPage />)
    await screen.findByText('Audit receiver')
    for (const action of [/add webhook/i, 'Edit webhook', 'Delete webhook', 'Send test callback']) {
      expect(screen.getByRole('button', { name: action })).toBeDisabled()
    }
    setPermissions(grants)
    rerender(<WebhooksPage />)
    await user.click(screen.getByRole('button', { name: 'Edit webhook' }))
    await user.type(screen.getByLabelText('Description'), ' previous draft')

    mockUseConsole.mockReturnValue({ activeOrgId: 'org-456' })
    setPermissions(grants, true)
    rerender(<WebhooksPage />)
    await waitFor(() => expect(mockListWebhooks).toHaveBeenLastCalledWith('org-456'))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    await screen.findByText('Audit receiver')
    expect(screen.getByRole('button', { name: 'Edit webhook' })).toBeDisabled()
    setPermissions(['webhook:view'])
    rerender(<WebhooksPage />)
    expect(screen.getByRole('button', { name: 'Edit webhook' })).toBeDisabled()
    expect(screen.getByRole('button', { name: /add webhook/i })).toBeDisabled()
    expect(mockUpdateWebhook).not.toHaveBeenCalled()
    expect(mockCreateWebhook).not.toHaveBeenCalled()
  })

  it.each(['create', 'edit'])('blocks an open webhook %s form when its permission becomes unavailable', async (action) => {
    mockListWebhooks.mockResolvedValue([webhook])
    const { user, rerender } = renderWithRouter(<WebhooksPage />)
    await screen.findByText('Audit receiver')
    await user.click(screen.getByRole('button', { name: action === 'edit' ? 'Edit webhook' : /add webhook/i }))
    setPermissions(['webhook:view'])
    rerender(<WebhooksPage />)
    expect(screen.getByText(`You do not have permission to ${action} webhooks in this organization.`)).toBeInTheDocument()
    expect(screen.getByLabelText('Webhook name')).toBeDisabled()
    const submit = screen.getByRole('button', { name: action === 'edit' ? 'Update webhook' : 'Create webhook' })
    expect(submit).toBeDisabled()
    expect(mockCreateWebhook).not.toHaveBeenCalled()
    expect(mockUpdateWebhook).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeEnabled()
  })

  it('discards a delete confirmation when its permission becomes unavailable', async () => {
    mockListWebhooks.mockResolvedValue([webhook])
    const { user, rerender } = renderWithRouter(<WebhooksPage />)
    await user.click(await screen.findByRole('button', { name: 'Delete webhook' }))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    setPermissions(['webhook:view', 'webhook:delete'], true)
    rerender(<WebhooksPage />)
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(screen.getByRole('button', { name: 'Delete webhook' })).toBeDisabled()
    setPermissions(['webhook:view', 'webhook:delete'])
    rerender(<WebhooksPage />)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(mockDeleteWebhook).not.toHaveBeenCalled()
  })

  it('discards pending creation results when the native account changes within the same organization', async () => {
    mockUseAuth.mockReturnValue({ isAuthenticated: true, user: { user_id: 'user-123', sub: 'unchanged-sub' } })
    const request = deferred<unknown>()
    mockCreateWebhook.mockReturnValueOnce(request.promise)
    const { user, rerender } = renderWithRouter(<WebhooksPage />)
    await user.click(await screen.findByRole('button', { name: /add webhook/i }))
    await user.type(screen.getByLabelText('Webhook name'), 'Previous account receiver')
    await user.type(screen.getByLabelText('Webhook URL'), 'https://audit.example.com/events')
    await user.click(screen.getByRole('button', { name: 'Create webhook' }))

    mockUseAuth.mockReturnValue({ isAuthenticated: true, user: { user_id: 'user-456', sub: 'unchanged-sub' } })
    rerender(<WebhooksPage />)
    await act(async () => request.resolve({ id: 'previous-webhook', signing_secret: 'previous-account-secret' }))
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.queryByDisplayValue('previous-account-secret')).not.toBeInTheDocument()
  })

  it.each(['resolve', 'reject'] as const)('does not show a previous dialog clipboard %s on a replacement webhook secret', async (completion) => {
    mockCreateWebhook.mockResolvedValue({ id: 'wh-first', signing_secret: 'first-secret' })
    const { user } = renderWithRouter(<WebhooksPage />)
    await user.click(await screen.findByRole('button', { name: /add webhook/i }))
    await user.type(screen.getByLabelText('Webhook name'), 'First receiver')
    await user.type(screen.getByLabelText('Webhook URL'), 'https://audit.example.com/events')
    await user.click(screen.getByRole('button', { name: 'Create webhook' }))
    await screen.findByLabelText('Webhook secret')
    const request = deferred<void>()
    const copy = vi.spyOn(navigator.clipboard, 'writeText').mockReturnValueOnce(request.promise)
    await user.click(screen.getByRole('button', { name: 'Copy webhook secret' }))
    expect(copy).toHaveBeenLastCalledWith('first-secret')
    await waitFor(() => expect(screen.getByRole('button', { name: 'Close', exact: true })).toBeEnabled())
    await user.click(screen.getByRole('button', { name: 'Close', exact: true }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())

    mockCreateWebhook.mockResolvedValue({ id: 'wh-second', signing_secret: 'replacement-secret' })
    await user.click(screen.getByRole('button', { name: /add webhook/i }))
    await user.type(screen.getByLabelText('Webhook name'), 'Second receiver')
    await user.type(screen.getByLabelText('Webhook URL'), 'https://audit.example.com/events')
    await user.click(screen.getByRole('button', { name: 'Create webhook' }))
    expect(await screen.findByLabelText('Webhook secret')).toHaveValue('replacement-secret')
    await act(async () => {
      if (completion === 'resolve') request.resolve()
      else request.reject(new Error('Previous clipboard request denied'))
    })

    expect(screen.queryByText('Webhook secret copied to clipboard.')).not.toBeInTheDocument()
    expect(screen.queryByText('Unable to copy webhook secret.')).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Copy webhook secret' }))
    expect(copy).toHaveBeenLastCalledWith('replacement-secret')
    expect(await screen.findByText('Webhook secret copied to clipboard.')).toBeInTheDocument()
  })
})
