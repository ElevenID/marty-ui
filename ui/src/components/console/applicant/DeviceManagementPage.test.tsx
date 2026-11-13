import { beforeEach, describe, expect, it, vi } from 'vitest'
import { act, screen, waitFor, within } from '@testing-library/react'
import { renderWithRouter } from '../../../test/utils'
import DeviceManagementPage from './DeviceManagementPage'

const { listDevices, unregisterDevice, useAuth } = vi.hoisted(() => ({
  listDevices: vi.fn(), unregisterDevice: vi.fn(), useAuth: vi.fn(),
}))
vi.mock('../../../services/devicesApi', () => ({
  listDevices: (...args: unknown[]) => listDevices(...args),
  unregisterDevice: (...args: unknown[]) => unregisterDevice(...args),
}))
vi.mock('../../../hooks/useAuth', () => ({ useAuth: () => useAuth() }))
function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: Error) => void
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail })
  return { promise, resolve, reject }
}
const device = (id = 'registration-1', overrides = {}) => ({
  id, user_id: 'user-a', device_id: `client-${id}`, platform: 'android',
  device_model: 'Test phone', app_version: '1.2', is_active: true,
  created_at: '2026-11-01T12:00:00Z', updated_at: '2026-11-01T12:00:00Z',
  ...overrides,
})

beforeEach(() => {
  vi.clearAllMocks()
  useAuth.mockReturnValue({ isAuthenticated: true, isLoading: false, user: { user_id: 'user-a', sub: 'legacy-alias' } })
  listDevices.mockResolvedValue([device()])
  unregisterDevice.mockResolvedValue({ success: true })
})

describe('native applicant device registrations', () => {
  it('shows a native bare array, records inactive status, and makes no public-key security claim', async () => {
    listDevices.mockResolvedValue([device(), device('registration-2', { is_active: false, device_model: undefined, last_seen_at: 'invalid' })])
    renderWithRouter(<DeviceManagementPage />)
    await screen.findByText('client-registration-1')
    expect(screen.getByText('client-registration-2')).toBeInTheDocument()
    expect(screen.getByText('Inactive')).toBeInTheDocument()
    expect(screen.queryByText('Security')).not.toBeInTheDocument()
    expect(screen.queryByText('Basic')).not.toBeInTheDocument()
    expect(screen.queryByText('Secured')).not.toBeInTheDocument()
    expect(screen.queryByText('Invalid Date')).not.toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: /Unregister device/ })).toHaveLength(1)
    expect(screen.getByRole('region', { name: 'Registered devices' })).toHaveAttribute('tabindex', '0')
    expect(listDevices).toHaveBeenCalledWith(null, expect.objectContaining({ userId: 'user-a' }))
  })

  it('deactivates the registration id once, preserves history, and prevents closing during submission', async () => {
    const pending = deferred<{ success: boolean }>()
    unregisterDevice.mockReturnValueOnce(pending.promise)
    const { user } = renderWithRouter(<DeviceManagementPage />)
    await user.click(await screen.findByRole('button', { name: 'Unregister device client-registration-1' }))
    const dialog = screen.getByRole('dialog', { name: 'Unregister Device?' })
    expect(dialog.querySelector('p div')).toBeNull()
    await user.dblClick(within(dialog).getByRole('button', { name: 'Unregister', exact: true }))
    expect(unregisterDevice).toHaveBeenCalledTimes(1)
    expect(unregisterDevice).toHaveBeenCalledWith('registration-1')
    expect(within(dialog).getByRole('button', { name: 'Cancel' })).toBeDisabled()
    await user.keyboard('{Escape}')
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    await act(async () => pending.resolve({ success: true }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(screen.getByText('client-registration-1')).toBeInTheDocument()
    expect(screen.getByText('Inactive')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Unregister device client-registration-1' })).not.toBeInTheDocument()
  })

  it('retains a failed confirmation and allows Retry with a readable blank-error fallback', async () => {
    unregisterDevice.mockRejectedValueOnce(new Error('')).mockResolvedValueOnce({ success: true })
    const { user } = renderWithRouter(<DeviceManagementPage />)
    await user.click(await screen.findByRole('button', { name: 'Unregister device client-registration-1' }))
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Unregister', exact: true }))
    const dialog = screen.getByRole('dialog')
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('Failed to unregister the device. Try again.')
    await user.click(within(dialog).getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(unregisterDevice).toHaveBeenCalledTimes(2)
    expect(screen.getByText('Inactive')).toBeInTheDocument()
  })

  it('does not show an empty or old inventory during a failed refresh and retries in place', async () => {
    listDevices.mockRejectedValueOnce(new Error('')).mockResolvedValueOnce([device()])
    const { user } = renderWithRouter(<DeviceManagementPage />)
    const alert = await screen.findByText('Failed to load devices')
    expect(screen.queryByText('No Devices Registered')).not.toBeInTheDocument()
    await user.click(within(alert.closest('[role="alert"]') as HTMLElement).getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('client-registration-1')).toBeInTheDocument()
  })

  it('rejects former account loads without finishing the current account request', async () => {
    const oldRequest = deferred<unknown[]>()
    const nextRequest = deferred<unknown[]>()
    listDevices.mockReturnValueOnce(oldRequest.promise).mockReturnValueOnce(nextRequest.promise)
    const { rerender } = renderWithRouter(<DeviceManagementPage />)
    const oldScope = listDevices.mock.calls[0][1]
    useAuth.mockReturnValue({ isAuthenticated: true, user: { user_id: 'user-b', sub: 'legacy-alias' } })
    rerender(<DeviceManagementPage />)
    await waitFor(() => expect(listDevices).toHaveBeenCalledTimes(2))
    expect(oldScope.isCurrent()).toBe(false)
    await act(async () => oldRequest.resolve([device('former')]))
    expect(screen.queryByText('client-former')).not.toBeInTheDocument()
    expect(screen.getByRole('progressbar')).toBeInTheDocument()
    await act(async () => nextRequest.resolve([device('current')]))
    expect(await screen.findByText('client-current')).toBeInTheDocument()
  })

  it.each(['success', 'failure'])('isolates a delayed delete %s from a replacement account dialog', async outcome => {
    const pending = deferred<{ success: boolean }>()
    unregisterDevice.mockReturnValueOnce(pending.promise)
    const { user, rerender } = renderWithRouter(<DeviceManagementPage />)
    await user.click(await screen.findByRole('button', { name: 'Unregister device client-registration-1' }))
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Unregister', exact: true }))
    listDevices.mockResolvedValueOnce([device('replacement', { user_id: 'user-b' })])
    useAuth.mockReturnValue({ isAuthenticated: true, user: { user_id: 'user-b', sub: 'legacy-alias' } })
    rerender(<DeviceManagementPage />)
    await user.click(await screen.findByRole('button', { name: 'Unregister device client-replacement' }))
    await act(async () => outcome === 'success' ? pending.resolve({ success: true }) : pending.reject(new Error('Former account failure')))
    const dialog = screen.getByRole('dialog')
    expect(dialog).toHaveTextContent('client-replacement')
    expect(dialog).not.toHaveTextContent('Former account failure')
    expect(within(dialog).getByRole('button', { name: 'Unregister', exact: true })).toBeEnabled()
    expect(screen.queryByText('client-registration-1')).not.toBeInTheDocument()
  })

  it('hides account data and confirmation on sign-out without making an anonymous request', async () => {
    const { user, rerender } = renderWithRouter(<DeviceManagementPage />)
    await user.click(await screen.findByRole('button', { name: 'Unregister device client-registration-1' }))
    useAuth.mockReturnValue({ isAuthenticated: false, user: null })
    rerender(<DeviceManagementPage />)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(screen.queryByText('client-registration-1')).not.toBeInTheDocument()
    expect(screen.getByText('Sign in to view your registered devices.')).toBeInTheDocument()
    expect(listDevices).toHaveBeenCalledTimes(1)
    expect(unregisterDevice).not.toHaveBeenCalled()
  })
})
