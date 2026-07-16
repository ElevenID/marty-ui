import { describe, expect, it, vi } from 'vitest'
import {
  evaluateApplicantConsolePolicy,
  evaluateOrgConsolePolicy,
  evaluateProtectedRoutePolicy,
  resolveCapabilityChecker,
} from './guardPolicy'

describe('guardPolicy', () => {
  describe('resolveCapabilityChecker', () => {
    it('uses provided capability callback when available', () => {
      const hasCapability = vi.fn((capability: string) => capability === 'org:view')
      const can = resolveCapabilityChecker({
        hasCapability,
        user: { capabilities: { 'admin:platform': true } },
      })

      expect(can('org:view')).toBe(true)
      expect(can('admin:platform')).toBe(false)
      expect(hasCapability).toHaveBeenCalledTimes(2)
    })

    it('falls back to the user capability map', () => {
      const can = resolveCapabilityChecker({
        user: { capabilities: { 'admin:platform': true } },
      })

      expect(can('admin:platform')).toBe(true)
      expect(can('org:view')).toBe(false)
    })
  })

  describe('evaluateProtectedRoutePolicy', () => {
    it('returns loading while auth is loading', () => {
      expect(
        evaluateProtectedRoutePolicy({
          isLoading: true,
          isAuthenticated: false,
        })
      ).toEqual({ kind: 'loading' })
    })

    it('redirects unauthenticated users to login', () => {
      expect(
        evaluateProtectedRoutePolicy({
          isLoading: false,
          isAuthenticated: false,
          redirectTo: '/signin',
        })
      ).toEqual({
        kind: 'redirect',
        destination: '/signin',
        reason: 'unauthenticated',
      })
    })

    it('allows authenticated users without capability requirements', () => {
      expect(
        evaluateProtectedRoutePolicy({
          isLoading: false,
          isAuthenticated: true,
        })
      ).toEqual({ kind: 'allow' })
    })

    it('redirects unauthorized users when a required capability is missing', () => {
      expect(
        evaluateProtectedRoutePolicy({
          isLoading: false,
          isAuthenticated: true,
          user: { capabilities: { apply: true } },
          requiredCapabilities: ['org:view'],
          unauthorizedRedirect: '/nope',
        })
      ).toEqual({
        kind: 'redirect',
        destination: '/nope',
        reason: 'unauthorized',
      })
    })

    it('allows users when any required capability matches', () => {
      expect(
        evaluateProtectedRoutePolicy({
          isLoading: false,
          isAuthenticated: true,
          user: { capabilities: { 'org:view': true } },
          requiredCapabilities: ['admin:platform', 'org:view'],
        })
      ).toEqual({ kind: 'allow' })
    })

    it('requires all capabilities when configured', () => {
      expect(
        evaluateProtectedRoutePolicy({
          isLoading: false,
          isAuthenticated: true,
          user: { capabilities: { 'org:view': true } },
          requiredCapabilities: ['admin:platform', 'org:view'],
          requireAllCapabilities: true,
        })
      ).toEqual({
        kind: 'redirect',
        destination: '/',
        reason: 'unauthorized',
      })
    })
  })

  describe('evaluateApplicantConsolePolicy', () => {
    it('returns loading while console state initializes', () => {
      expect(evaluateApplicantConsolePolicy({ consoleLoading: true })).toEqual({ kind: 'loading' })
    })

    it('allows access once console state is ready', () => {
      expect(evaluateApplicantConsolePolicy({ consoleLoading: false })).toEqual({ kind: 'allow' })
    })
  })

  describe('evaluateOrgConsolePolicy', () => {
    it('returns loading while console state initializes', () => {
      expect(
        evaluateOrgConsolePolicy({
          consoleLoading: true,
          mode: 'org',
          activeOrgId: null,
        })
      ).toEqual({ kind: 'loading' })
    })

    it('redirects org mode users without an active org', () => {
      expect(
        evaluateOrgConsolePolicy({
          consoleLoading: false,
          mode: 'org',
          activeOrgId: null,
          setupRedirect: '/console/org/setup',
        })
      ).toEqual({
        kind: 'redirect',
        destination: '/console/org/setup',
        reason: 'missing-org-selection',
      })
    })

    it('allows org mode users with an active organization', () => {
      expect(
        evaluateOrgConsolePolicy({
          consoleLoading: false,
          mode: 'org',
          activeOrgId: 'org-123',
        })
      ).toEqual({ kind: 'allow' })
    })

    it('redirects applicant mode users without an active organization', () => {
      expect(
        evaluateOrgConsolePolicy({
          consoleLoading: false,
          mode: 'applicant',
          activeOrgId: null,
        })
      ).toEqual({
        kind: 'redirect',
        destination: '/console/org/setup',
        reason: 'missing-org-selection',
      })
    })
  })
})
