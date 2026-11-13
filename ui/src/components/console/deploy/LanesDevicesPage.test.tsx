import { beforeEach, describe, expect, it, vi } from 'vitest'
import { act, screen, waitFor, within } from '@testing-library/react'
import { renderWithRouter } from '../../../test/utils'
import LanesDevicesPage from './LanesDevicesPage'

const { listDevices, useAuth, useConsole } = vi.hoisted(() => ({
  listDevices: vi.fn(), useAuth: vi.fn(), useConsole: vi.fn(),
}))
vi.mock('../../../services/devicesApi', () => ({ listOrganizationDevices: (...args: unknown[]) => listDevices(...args) }))
vi.mock('../../../hooks/useAuth', () => ({ useAuth: () => useAuth() }))
vi.mock('../../../contexts/ConsoleContext', () => ({ useConsole: () => useConsole() }))

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail })
  return { promise, resolve, reject }
}
const device = (id = 'registration-1', overrides = {}) => ({
  id, user_id: 'user-a', organization_id: 'org-a', device_id: `client-${id}`,
  platform: 'android', device_model: 'Test phone', app_version: '1.2', is_active: true,
  created_at: '2026-11-01T12:00:00Z', updated_at: '2026-11-01T12:00:00Z',
  ...overrides,
})
const renderPage = () => renderWithRouter(<LanesDevicesPage />, { initialEntries: ['/console/org/deploy/lanes'] })

beforeEach(() => {
  vi.clearAllMocks()
  useAuth.mockReturnValue({ isAuthenticated: true, isLoading: false, user: { user_id: 'user-a', sub: 'old-alias' }, organizationId: 'session-org' })
  useConsole.mockReturnValue({ activeOrgId: 'org-a' })
  listDevices.mockResolvedValue([])
})

describe('registered devices in the selected organization', () => {
  it('renders the pending native array safely and shows real registrations without fictional lane controls', async () => {
    const pending = deferred<unknown[]>()
    listDevices.mockReturnValueOnce(pending.promise)
    renderPage()
    expect(screen.getByRole('progressbar', { name: 'Loading devices' })).toBeInTheDocument()
    expect(screen.queryByText('You have no device registrations in this organization.')).not.toBeInTheDocument()
    await act(async () => pending.resolve([device(), device('registration-2', { is_active: false, device_model: undefined, platform: 'web' })]))
    expect(await screen.findByText('client-registration-1')).toBeInTheDocument()
    expect(screen.getByText('client-registration-2')).toBeInTheDocument()
    expect(screen.getByText('Active')).toBeInTheDocument()
    expect(screen.getByText('Inactive')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /add lane/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /add lane|configure|view devices/i })).not.toBeInTheDocument()
    expect(screen.queryByText(/online|degraded|offline/i)).not.toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Registered devices' })).toHaveAttribute('tabindex', '0')
    expect(listDevices).toHaveBeenCalledWith('org-a', expect.objectContaining({ userId: 'user-a' }))
  })

  it('labels search, searches the native model/platform/id, and clears a filtered empty state', async () => {
    listDevices.mockResolvedValue([device(), device('registration-2', { device_model: undefined, platform: 'ios' })])
    const { user } = renderPage()
    await screen.findByText('client-registration-1')
    await user.type(screen.getByRole('textbox', { name: 'Search devices' }), 'IOS')
    expect(screen.queryByText('client-registration-1')).not.toBeInTheDocument()
    expect(screen.getByText('client-registration-2')).toBeInTheDocument()
    await user.clear(screen.getByRole('textbox', { name: 'Search devices' }))
    await user.type(screen.getByRole('textbox', { name: 'Search devices' }), 'missing')
    expect(screen.getByText('No devices match your search.')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Clear search' }))
    expect(screen.getByText('client-registration-1')).toBeInTheDocument()
  })

  it('keeps failed inventory separate from empty inventory and retries a blank failure', async () => {
    listDevices.mockRejectedValueOnce(new Error('')).mockResolvedValueOnce([])
    const { user } = renderPage()
    const error = await screen.findByRole('alert')
    expect(error).toHaveTextContent('Failed to load devices')
    expect(screen.queryByText('You have no device registrations in this organization.')).not.toBeInTheDocument()
    await user.click(within(error).getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('You have no device registrations in this organization.')).toBeInTheDocument()
  })

  it.each(['organization', 'account'])('discards old %s results and failures without ending the new loading state', async scope => {
    const oldRequest = deferred<unknown[]>()
    const nextRequest = deferred<unknown[]>()
    listDevices.mockReturnValueOnce(oldRequest.promise).mockReturnValueOnce(nextRequest.promise)
    const { rerender } = renderPage()
    const oldScope = listDevices.mock.calls[0][1]
    if (scope === 'organization') useConsole.mockReturnValue({ activeOrgId: 'org-b' })
    else useAuth.mockReturnValue({ isAuthenticated: true, user: { user_id: 'user-b', sub: 'old-alias' } })
    rerender(<LanesDevicesPage />)
    await waitFor(() => expect(listDevices).toHaveBeenCalledTimes(2))
    expect(oldScope.isCurrent()).toBe(false)
    await act(async () => oldRequest.reject(new Error('Old scope unavailable')))
    expect(screen.queryByText('Old scope unavailable')).not.toBeInTheDocument()
    expect(screen.getByRole('progressbar')).toBeInTheDocument()
    await act(async () => nextRequest.resolve([device('new-registration')]))
    expect(await screen.findByText('client-new-registration')).toBeInTheDocument()
  })

  it('withdraws loaded records immediately on an account change and does not fetch without a session or selected organization', async () => {
    listDevices.mockResolvedValueOnce([device()])
    const { rerender } = renderPage()
    await screen.findByText('client-registration-1')
    useAuth.mockReturnValue({ isAuthenticated: false, user: null })
    rerender(<LanesDevicesPage />)
    expect(screen.queryByText('client-registration-1')).not.toBeInTheDocument()
    expect(screen.getByText('Sign in to view your registered devices.')).toBeInTheDocument()
    useAuth.mockReturnValue({ isAuthenticated: true, user: { user_id: 'user-b' } })
    useConsole.mockReturnValue({ activeOrgId: null })
    rerender(<LanesDevicesPage />)
    expect(screen.getByText('Select an organization to view your device registrations.')).toBeInTheDocument()
    expect(listDevices).toHaveBeenCalledTimes(1)
  })
})
