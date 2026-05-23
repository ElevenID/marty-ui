import { describe, it, expect, vi, beforeEach } from 'vitest'
import { server } from '@test/mocks/server'
import { http, HttpResponse } from 'msw'

import { getPreferences } from '../preferencesApi'

describe('preferencesApi', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('disables caching when loading console preferences', async () => {
    let requestCredentials: RequestCredentials | undefined
    let requestCache: RequestCache | undefined

    server.use(
      http.get('/v1/me/preferences', ({ request }) => {
        requestCredentials = request.credentials
        requestCache = request.cache
        return HttpResponse.json({
          last_view_mode: 'applicant',
          last_active_org_id: null,
        })
      })
    )

    const result = await getPreferences()

    expect(result.last_view_mode).toBe('applicant')
    expect(result.last_active_org_id).toBeNull()
    expect(requestCredentials).toBe('include')
    expect(requestCache).toBe('no-store')
  })
})
