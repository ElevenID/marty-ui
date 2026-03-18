import { describe, expect, it } from 'vitest';

import {
  ADMIN_DASHBOARD_DEFAULT_HEALTH,
  ADMIN_DASHBOARD_DEFAULT_STATS,
  buildAdminImpersonationUrl,
  buildAdminDashboardFallbackVendor,
  filterAdminVendors,
  getAdminTierColor,
  resolveAdminImpersonationBase,
  resolveAdminImpersonationResult,
  resolveAdminDashboardHealth,
  resolveAdminDashboardStats,
} from './adminDashboardFlow';

describe('adminDashboardFlow helpers', () => {
  it('builds a fallback vendor record', () => {
    expect(buildAdminDashboardFallbackVendor('2026-03-17T00:00:00.000Z')).toMatchObject({
      id: 'vendor-001',
      organizationName: 'Demo Vendor Corp',
      createdAt: '2026-03-17T00:00:00.000Z',
    });
  });

  it('merges stats and maps health into dashboard defaults', () => {
    expect(resolveAdminDashboardStats({ passport: 7 })).toEqual({
      ...ADMIN_DASHBOARD_DEFAULT_STATS,
      passport: 7,
    });

    expect(resolveAdminDashboardHealth({ status: 'healthy' })).toEqual({
      issuer_api: 'healthy',
      passport_engine: 'healthy',
      mdl_engine: 'healthy',
      mdoc_engine: 'healthy',
      inspection_system: 'healthy',
    });

    expect(resolveAdminDashboardHealth(null)).toEqual(ADMIN_DASHBOARD_DEFAULT_HEALTH);
  });

  it('filters vendors and resolves tier colors', () => {
    const vendors = [
      { id: '1', email: 'alpha@example.com', organizationName: 'Alpha Org', username: 'alpha' },
      { id: '2', email: 'beta@example.com', organizationName: 'Beta Org', username: 'beta' },
    ];

    expect(filterAdminVendors(vendors, 'beta')).toEqual([vendors[1]]);
    expect(filterAdminVendors(vendors, '')).toEqual(vendors);
    expect(getAdminTierColor('PROFESSIONAL')).toBe('primary');
    expect(getAdminTierColor('UNKNOWN')).toBe('default');
  });

  it('builds impersonation config, urls, and result actions', () => {
    expect(resolveAdminImpersonationBase({
      authServerUrl: 'https://kc.example',
      realm: 'demo',
    })).toEqual({
      authServerUrl: 'https://kc.example',
      realm: 'demo',
    });

    expect(buildAdminImpersonationUrl({
      vendorId: 'vendor-7',
      authServerUrl: 'https://kc.example',
      realm: 'demo',
    })).toBe('https://kc.example/admin/realms/demo/users/vendor-7/impersonation');

    expect(resolveAdminImpersonationResult(
      { redirect: 'https://kc.example/session' },
      { email: 'vendor@example.com' }
    )).toEqual({
      action: 'open-tab',
      redirectUrl: 'https://kc.example/session',
      successMessage: 'Now impersonating vendor@example.com. Check the new tab.',
    });

    expect(resolveAdminImpersonationResult({}, { email: 'vendor@example.com' })).toEqual({
      action: 'reload',
      redirectUrl: null,
      successMessage: 'Impersonation session started for vendor@example.com',
    });
  });
});