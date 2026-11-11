/**
 * API Contract Tests for Authentication Service
 * 
 * Tests that API calls are made with correct:
 * - HTTP methods
 * - Request paths
 * - Headers
 * - Response handling
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { server } from '@test/mocks/server'
import { http, HttpResponse } from 'msw'
import {
  getCurrentUser,
  isAuthenticated,
  getUserOrganizations,
  startPasskeyEnrollment,
  updateProfilePicture,
} from '../authApi'
import { redirectBrowser } from '../../application/routing/appHandoff'
vi.mock('../../application/routing/appHandoff', () => ({ redirectBrowser: vi.fn() }))
import { mockUsers, mockOrganization } from '@test/mocks/fixtures'

describe('authApi', () => {
  it('starts passkey enrollment with a cookie-bearing JSON POST before navigating', async () => {
    const fetchSpy = vi.spyOn(window, 'fetch')
    let payload: unknown
    server.use(http.post('/v1/auth/passkeys/enroll', async ({ request }) => {
      expect(request.headers.get('content-type')).toBe('application/json')
      payload = await request.json()
      return HttpResponse.json({ authorization_url: 'https://identity.example/auth?kc_action=webauthn-register-passwordless' })
    }))
    await startPasskeyEnrollment('/console/profile')
    expect(fetchSpy).toHaveBeenCalledWith('/v1/auth/passkeys/enroll', expect.objectContaining({
      method: 'POST',
      credentials: 'include',
      cache: 'no-store',
    }))
    expect(payload).toEqual({ redirect_uri: '/console/profile' })
    expect(redirectBrowser).toHaveBeenCalledWith('https://identity.example/auth?kc_action=webauthn-register-passwordless', { replace: false })
  })

  it('does not navigate when enrollment is unavailable', async () => {
    server.use(http.post('/v1/auth/passkeys/enroll', () => HttpResponse.json({ detail: 'Sign in again' }, { status: 409 })))
    await expect(startPasskeyEnrollment()).rejects.toThrow('Sign in again')
    expect(redirectBrowser).not.toHaveBeenCalled()
  })

  it('reports a native enrollment email without navigating or exposing its link', async () => {
    server.use(http.post('/v1/auth/passkeys/enroll', async ({ request }) => {
      expect(await request.json()).toEqual({ redirect_uri: '/console/applicant/profile' })
      return HttpResponse.json({ email_sent: true })
    }))
    await expect(startPasskeyEnrollment()).resolves.toEqual({ email_sent: true })
    expect(redirectBrowser).not.toHaveBeenCalled()
  })
  beforeEach(() => {
    vi.clearAllMocks()
  })
  afterEach(() => vi.restoreAllMocks())

  describe('getCurrentUser', () => {
    it('should fetch current user successfully', async () => {
      const result = await getCurrentUser()

      expect(result.authenticated).toBe(true)
      expect(result.user.id).toBe(mockUsers.admin.id)
      expect(result.user.username).toBe(mockUsers.admin.username)
      expect(result.user.capabilities).toEqual(mockUsers.admin.capabilities)
    })

    it('should handle 401 unauthorized', async () => {
      server.use(
        http.get('/v1/auth/me', () => {
          return HttpResponse.json(
            { error: { message: 'Unauthorized' } },
            { status: 401 }
          )
        })
      )

      const result = await getCurrentUser()

      expect(result.authenticated).toBe(false)
      expect(result.user).toBeNull()
    })

    it('rejects a network failure without claiming the session is unauthenticated', async () => {
      server.use(
        http.get('/v1/auth/me', () => {
          return HttpResponse.error()
        })
      )

      await expect(getCurrentUser()).rejects.toThrow()
    })

    it('recognizes an explicit signed-out session', async () => {
      server.use(http.get('/v1/auth/me', () => HttpResponse.json({ authenticated: false, user: null })))
      await expect(getCurrentUser()).resolves.toEqual({ authenticated: false, user: null })
    })

    it.each([403, 503])('rejects HTTP %s without claiming the session is unauthenticated', async status => {
      server.use(http.get('/v1/auth/me', () => HttpResponse.json({ detail: 'Session unavailable' }, { status })))
      await expect(getCurrentUser()).rejects.toThrow(`HTTP error! status: ${status}`)
    })

    it.each([null, {}, { authenticated: 'true', user: mockUsers.admin }, { authenticated: true, user: {} }])('rejects an unconfirmed identity response: %j', async payload => {
      server.use(http.get('/v1/auth/me', () => HttpResponse.json(payload)))
      await expect(getCurrentUser()).rejects.toThrow('The account response could not be read.')
    })

    it('should include credentials in request', async () => {
      // These options belong to fetch, not the HTTP request reconstructed by
      // MSW 3's Node transport. Observe the caller while MSW handles the reply.
      const fetchSpy = vi.spyOn(window, 'fetch')

      server.use(
        http.get('/v1/auth/me', () => {
          return HttpResponse.json({ authenticated: true, user: mockUsers.admin })
        })
      )

      await getCurrentUser()

      expect(fetchSpy).toHaveBeenCalledWith('/v1/auth/me', expect.objectContaining({
        credentials: 'include',
        cache: 'no-store',
      }))
    })
  })

  describe('updateProfilePicture', () => {
    it('sends the encoded picture in a cookie-bearing JSON PATCH', async () => {
      const fetchSpy = vi.spyOn(window, 'fetch')
      const picture = 'data:image/png;base64,bmV3IHBpY3R1cmU='
      let payload: unknown
      server.use(http.patch('/v1/auth/me', async ({ request }) => {
        expect(request.headers.get('content-type')).toBe('application/json')
        payload = await request.json()
        return HttpResponse.json({ ok: true })
      }))
      await expect(updateProfilePicture(picture)).resolves.toEqual({ success: true })
      expect(payload).toEqual({ picture })
      expect(fetchSpy).toHaveBeenCalledWith('/v1/auth/me', expect.objectContaining({
        method: 'PATCH', credentials: 'include', body: JSON.stringify({ picture }),
      }))
    })

    it('refuses an oversized serialized picture before dispatching a PATCH', async () => {
      const fetchSpy = vi.spyOn(window, 'fetch')
      vi.spyOn(console, 'error').mockImplementation(() => {})
      await expect(updateProfilePicture(`data:image/png;base64,${'A'.repeat(2 * 1024 * 1024)}`))
        .resolves.toEqual({ success: false, error: 'Image must be 1.5 MB or smaller.' })
      expect(fetchSpy).not.toHaveBeenCalled()
    })
  })

  describe('isAuthenticated', () => {
    it('should return true when user is authenticated', async () => {
      server.use(
        http.get('/v1/auth/me', () => {
          return HttpResponse.json({
            authenticated: true,
            user: mockUsers.admin,
          })
        })
      )

      const result = await isAuthenticated()

      expect(result).toBe(true)
    })

    it('should return false when not authenticated', async () => {
      server.use(
        http.get('/v1/auth/me', () => {
          return HttpResponse.json(
            { error: { message: 'Unauthorized' } },
            { status: 401 }
          )
        })
      )

      const result = await isAuthenticated()

      expect(result).toBe(false)
    })
  })

  describe('getUserOrganizations', () => {
    it('should fetch user organizations', async () => {
      const fetchSpy = vi.spyOn(window, 'fetch')

      server.use(
        http.get('/v1/auth/me/organizations', () => {
          return HttpResponse.json({
            organizations: [mockOrganization],
          })
        })
      )

      const orgs = await getUserOrganizations()

      expect(orgs).toHaveLength(1)
      expect(orgs[0].id).toBe(mockOrganization.id)
      expect(orgs[0].name).toBe(mockOrganization.name)
      expect(fetchSpy).toHaveBeenCalledWith('/v1/auth/me/organizations', expect.objectContaining({
        credentials: 'include',
        cache: 'no-store',
      }))
    })

    it('should return empty array on error', async () => {
      server.use(
        http.get('/v1/auth/me/organizations', () => {
          return HttpResponse.json(
            { error: { message: 'Forbidden' } },
            { status: 403 }
          )
        })
      )

      const orgs = await getUserOrganizations()

      expect(orgs).toEqual([])
    })

    it('should handle empty organizations list', async () => {
      server.use(
        http.get('/v1/auth/me/organizations', () => {
          return HttpResponse.json({ organizations: [] })
        })
      )

      const orgs = await getUserOrganizations()

      expect(orgs).toEqual([])
    })
  })

  describe('login/logout redirects', () => {
    it('should use relative paths for auth endpoints', () => {
      // These functions trigger window redirects
      // Testing that they use correct paths
      // Actual redirect testing would require integration tests
    })
  })
})
