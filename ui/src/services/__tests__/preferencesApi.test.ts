import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { server } from '@test/mocks/server'
import { http, HttpResponse } from 'msw'

import { getPreferences } from '../preferencesApi'

describe('preferencesApi', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })
  afterEach(() => vi.restoreAllMocks())

  it('disables caching when loading console preferences', async () => {
    // MSW's HTTP transport cannot observe browser-only fetch cache/cookie options.
    const fetchSpy = vi.spyOn(window, 'fetch')

    server.use(
      http.get('/v1/me/preferences', () => {
        return HttpResponse.json({
          last_view_mode: 'applicant',
          last_active_org_id: null,
        })
      })
    )

    const result = await getPreferences()

    expect(result.last_view_mode).toBe('applicant')
    expect(result.last_active_org_id).toBeNull()
    expect(fetchSpy).toHaveBeenCalledWith('/v1/me/preferences', expect.objectContaining({
      credentials: 'include',
      cache: 'no-store',
    }))
  })
})
