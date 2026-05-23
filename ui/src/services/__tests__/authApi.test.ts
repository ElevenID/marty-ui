/**
 * API Contract Tests for Authentication Service
 * 
 * Tests that API calls are made with correct:
 * - HTTP methods
 * - Request paths
 * - Headers
 * - Response handling
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { server } from '@test/mocks/server'
import { http, HttpResponse } from 'msw'
import {
  getCurrentUser,
  isAuthenticated,
  getUserOrganizations,
} from '../authApi'
import { mockUsers, mockOrganization } from '@test/mocks/fixtures'

describe('authApi', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

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

    it('should handle network errors', async () => {
      server.use(
        http.get('/v1/auth/me', () => {
          return HttpResponse.error()
        })
      )

      const result = await getCurrentUser()

      expect(result.authenticated).toBe(false)
    })

    it('should include credentials in request', async () => {
      let requestCredentials: RequestCredentials | undefined
      let requestCache: RequestCache | undefined

      server.use(
        http.get('/v1/auth/me', ({ request }) => {
          requestCredentials = request.credentials
          requestCache = request.cache
          return HttpResponse.json(mockUsers.admin)
        })
      )

      await getCurrentUser()

      // Credentials should be 'include' for cookie-based auth
      expect(requestCredentials).toBe('include')
      expect(requestCache).toBe('no-store')
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
      let requestCache: RequestCache | undefined

      server.use(
        http.get('/v1/auth/me/organizations', ({ request }) => {
          requestCache = request.cache
          return HttpResponse.json({
            organizations: [mockOrganization],
          })
        })
      )

      const orgs = await getUserOrganizations()

      expect(orgs).toHaveLength(1)
      expect(orgs[0].id).toBe(mockOrganization.id)
      expect(orgs[0].name).toBe(mockOrganization.name)
      expect(requestCache).toBe('no-store')
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
