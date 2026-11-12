import { beforeEach, describe, expect, it, vi } from 'vitest'
import { listDevices, listOrganizationDevices, unregisterDevice } from '../devicesApi'
const { get, del } = vi.hoisted(() => ({ get: vi.fn(), del: vi.fn() }))
vi.mock('../api', () => ({ get, del, post: vi.fn() }))
const device = (id: string, overrides = {}) => ({
  id, user_id: 'user-a', organization_id: 'org-a', device_id: `client-${id}`,
  platform: 'android', is_active: true, created_at: '2026-11-01T12:00:00Z',
  ...overrides,
})
beforeEach(() => { vi.clearAllMocks() })

describe('native device registration contract', () => {
  it('collects the current user bare-array inventory across all native pages and retains inactive records', async () => {
    const first = Array.from({ length: 100 }, (_, index) => device(`registration-${index}`))
    get.mockResolvedValueOnce(first).mockResolvedValueOnce([device('older', { is_active: false })])
    const result = await listDevices(null, { userId: 'user-a' })
    expect(result).toHaveLength(101)
    expect(result[100].is_active).toBe(false)
    expect(get).toHaveBeenNthCalledWith(1, '/v1/devices?limit=100&offset=0')
    expect(get).toHaveBeenNthCalledWith(2, '/v1/devices?limit=100&offset=100')
  })

  it('keeps the organization filter on every page and validates account and organization scope', async () => {
    const first = Array.from({ length: 100 }, (_, index) => device(`registration-${index}`))
    get.mockResolvedValueOnce(first).mockResolvedValueOnce([])
    expect(await listOrganizationDevices(' org-a ', { userId: 'user-a' })).toHaveLength(100)
    expect(get).toHaveBeenLastCalledWith('/v1/devices?organization_id=org-a&limit=100&offset=100')
    get.mockResolvedValueOnce([device('foreign', { organization_id: 'org-b' })])
    await expect(listOrganizationDevices('org-a')).rejects.toThrow('invalid response')
    get.mockResolvedValueOnce([device('foreign', { user_id: 'user-b' })])
    await expect(listDevices(null, { userId: 'user-a' })).rejects.toThrow('invalid response')
  })

  it('rejects malformed, duplicate, or partially failed inventories rather than presenting empty or partial success', async () => {
    for (const malformed of [null, {}, { devices: [] }, [null], [device('bad', { is_active: 'false' })]]) {
      get.mockResolvedValueOnce(malformed)
      await expect(listDevices()).rejects.toThrow('invalid response')
    }
    const first = Array.from({ length: 100 }, (_, index) => device(`registration-${index}`))
    get.mockResolvedValueOnce(first).mockResolvedValueOnce([first[0]])
    await expect(listDevices()).rejects.toThrow('changed while loading')
    get.mockResolvedValueOnce(first).mockRejectedValueOnce(new Error('Later page unavailable'))
    await expect(listDevices()).rejects.toThrow('Later page unavailable')
  })

  it('stops pagination when the authenticated page scope has changed', async () => {
    let current = true
    get.mockImplementationOnce(async () => {
      current = false
      return Array.from({ length: 100 }, (_, index) => device(`registration-${index}`))
    })
    await expect(listDevices(null, { isCurrent: () => current })).rejects.toMatchObject({ name: 'AbortError' })
    expect(get).toHaveBeenCalledTimes(1)
  })

  it('preserves a client-supplied device id admitted by the native nonempty byte contract', async () => {
    get.mockResolvedValueOnce([device('registration-1', { device_id: '   ' })])
    expect((await listDevices())[0].device_id).toBe('   ')
  })

  it('requires an organization for the organization list and registration id for deactivation', async () => {
    await expect(listOrganizationDevices('undefined')).rejects.toMatchObject({ code: 'ORG_REQUIRED' })
    await expect(listDevices('')).rejects.toMatchObject({ code: 'ORG_REQUIRED' })
    await expect(unregisterDevice('')).rejects.toThrow('registration ID is required')
    expect(get).not.toHaveBeenCalled()
    expect(del).not.toHaveBeenCalled()
    del.mockResolvedValueOnce({ success: true })
    await unregisterDevice('registration/a')
    expect(del).toHaveBeenCalledWith('/v1/devices/registration%2Fa')
  })
})
