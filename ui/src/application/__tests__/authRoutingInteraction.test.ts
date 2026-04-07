/**
 * Interaction tests: Authentication & Routing Journey
 *
 * Exercises the cross-module auth flow through the headless layer:
 *
 *   1. OIDC callback → exchange code → refresh user → resolve redirect
 *   2. Console bootstrap → mode selection → org switching
 *   3. Guard policy evaluation for protected routes
 */

import { describe, expect, it, vi } from 'vitest';

import {
  completeAuthCallback,
  getAuthCallbackErrorFromParams,
  getAuthCallbackCodeState,
  decodeAuthCallbackState,
  resolveAuthCallbackRedirect,
  waitForAuthCallbackConsole,
} from '../routing/authCallback';
import {
  evaluateProtectedRoutePolicy,
  evaluateOrgConsolePolicy,
  resolveCapabilityChecker,
} from '../routing/guardPolicy';
import {
  resolveConsoleBootstrap,
  resolveModeChange,
  resolveActiveOrgSelection,
} from '../session/consoleSession';
import {
  parseOrganizationClaim,
  normalizeCapabilities,
} from '../session/authSession';

describe('Auth Callback → Session Bootstrap → Route Guard', () => {
  it('complete OIDC callback, bootstrap console, then guard allows entry', async () => {
    // ── Step 1: Simulate OIDC callback URL params ───────────
    const searchParams = new URLSearchParams('code=auth-code-123&state=' + btoa(JSON.stringify({ returnTo: '/console/org' })));

    const error = getAuthCallbackErrorFromParams(searchParams);
    expect(error).toBeNull();

    const { code, state } = getAuthCallbackCodeState(searchParams);
    expect(code).toBe('auth-code-123');

    const stateData = decodeAuthCallbackState(state);
    expect(stateData.returnTo).toBe('/console/org');

    // ── Step 2: Complete the callback flow ──────────────────
    const consoleContext = { isLoading: false, mode: 'org', activeOrgId: 'org-1' };
    const result = await completeAuthCallback({
      searchParams,
      refreshUser: vi.fn().mockResolvedValue(undefined),
      consoleContext,
      getDefaultLandingPath: () => '/console/applicant/catalog',
      exchangeAuthCallback: vi.fn().mockResolvedValue({ session_id: 'sess-1' }),
      sleep: vi.fn().mockResolvedValue(undefined),
    });

    expect(result.error).toBeNull();
    expect(result.redirectTo).toBe('/console/org');

    // ── Step 3: Parse token claims → bootstrap session ──────
    const orgClaim = { 'org-1': { name: 'Acme Corp' }, 'org-2': { name: 'Beta' } };
    const parsed = parseOrganizationClaim(orgClaim);
    expect(parsed.organizations).toHaveLength(2);

    const caps = normalizeCapabilities(['org:view', 'org:manage', 'org:issue']);
    expect(caps['org:view']).toBe(true);
    expect(caps['org:manage']).toBe(true);

    const consoleBootstrap = resolveConsoleBootstrap({
      preferences: { last_view_mode: 'org', last_active_org_id: 'org-1' },
      memberships: parsed.organizations,
      localStoredOrgId: null,
    });
    expect(consoleBootstrap.mode).toBe('org');
    expect(consoleBootstrap.activeOrgId).toBe('org-1');

    // ── Step 4: Guard policy allows authenticated user ──────
    const guardResult = evaluateProtectedRoutePolicy({
      isLoading: false,
      isAuthenticated: true,
      user: { capabilities: caps },
      requiredCapabilities: ['org:view'],
    });
    expect(guardResult.kind).toBe('allow');
  });

  it('callback error parameter is surfaced', async () => {
    const searchParams = new URLSearchParams('error=access_denied&error_description=User+cancelled');
    const result = await completeAuthCallback({
      searchParams,
      refreshUser: vi.fn(),
      consoleContext: { isLoading: false },
      getDefaultLandingPath: () => '/',
    });

    expect(result.error).toBe('User cancelled');
    expect(result.redirectTo).toBeNull();
  });

  it('guard redirects unauthenticated users to login', () => {
    const result = evaluateProtectedRoutePolicy({
      isLoading: false,
      isAuthenticated: false,
    });
    expect(result.kind).toBe('redirect');
    expect(result.destination).toBe('/login');
    expect(result.reason).toBe('unauthenticated');
  });

  it('guard redirects unauthorized users when all capabilities are required', () => {
    const result = evaluateProtectedRoutePolicy({
      isLoading: false,
      isAuthenticated: true,
      user: { capabilities: { 'org:view': true } },
      requiredCapabilities: ['org:view', 'org:manage'],
      requireAllCapabilities: true,
      unauthorizedRedirect: '/no-access',
    });
    expect(result.kind).toBe('redirect');
    expect(result.destination).toBe('/no-access');
    expect(result.reason).toBe('unauthorized');
  });

  it('guard shows loading while auth state initializes', () => {
    expect(evaluateProtectedRoutePolicy({ isLoading: true, isAuthenticated: false })).toEqual({ kind: 'loading' });
  });
});

describe('Console Mode Switching', () => {
  const MEMBERSHIPS = [
    { id: 'org-1', name: 'Acme' },
    { id: 'org-2', name: 'Beta' },
  ];

  it('switches from applicant to org mode with active org', () => {
    const change = resolveModeChange({
      newMode: 'org',
      activeOrgId: 'org-1',
      memberships: MEMBERSHIPS,
    });

    expect(change.mode).toBe('org');
    expect(change.activeOrgId).toBe('org-1');
    expect(change.destination).toBe('/console/org');
    expect(change.persistence.last_view_mode).toBe('org');
  });

  it('switches to org mode with single membership auto-selects org', () => {
    const change = resolveModeChange({
      newMode: 'org',
      activeOrgId: null,
      memberships: [{ id: 'org-only', name: 'Only Org' }],
    });

    expect(change.activeOrgId).toBe('org-only');
    expect(change.destination).toBe('/console/org');
  });

  it('switches to org mode without membership redirects to setup', () => {
    const change = resolveModeChange({
      newMode: 'org',
      activeOrgId: null,
      memberships: [],
    });

    expect(change.activeOrgId).toBeNull();
    expect(change.destination).toBe('/console/org/setup');
  });

  it('switches back to applicant mode', () => {
    const change = resolveModeChange({
      newMode: 'applicant',
      activeOrgId: 'org-1',
      memberships: MEMBERSHIPS,
    });

    expect(change.mode).toBe('applicant');
    expect(change.activeOrgId).toBeNull();
    expect(change.destination).toBe('/console/applicant/catalog');
  });

  it('validates active org selection against memberships', () => {
    const valid = resolveActiveOrgSelection({
      orgId: 'org-1',
      currentMode: 'org',
      memberships: MEMBERSHIPS,
    });
    expect(valid.valid).toBe(true);

    const invalid = resolveActiveOrgSelection({
      orgId: 'org-unknown',
      currentMode: 'org',
      memberships: MEMBERSHIPS,
    });
    expect(invalid.valid).toBe(false);
  });
});

describe('Org Console Route Guard', () => {
  it('loading state defers rendering', () => {
    expect(evaluateOrgConsolePolicy({ consoleLoading: true })).toEqual({ kind: 'loading' });
  });

  it('org mode with active org allows entry', () => {
    const result = evaluateOrgConsolePolicy({
      consoleLoading: false,
      mode: 'org',
      activeOrgId: 'org-1',
    });
    expect(result.kind).toBe('allow');
  });

  it('org mode without active org redirects to setup', () => {
    const result = evaluateOrgConsolePolicy({
      consoleLoading: false,
      mode: 'org',
      activeOrgId: null,
    });
    expect(result).toMatchObject({ kind: 'redirect', destination: '/console/org/setup' });
  });
});
