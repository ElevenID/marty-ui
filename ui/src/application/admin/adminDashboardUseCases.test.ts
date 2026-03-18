import { describe, expect, it, vi } from 'vitest';

import { impersonateAdminVendor, loadAdminDashboardBootstrap } from './adminDashboardUseCases';

describe('adminDashboardUseCases', () => {
  it('loads stats, health, and vendors together', async () => {
    await expect(loadAdminDashboardBootstrap({
      getAdminStats: vi.fn().mockResolvedValue({ passport: 12, verifications: 9 }),
      getAdminHealth: vi.fn().mockResolvedValue({ status: 'healthy' }),
      getAdminVendors: vi.fn().mockResolvedValue([{ id: 'vendor-1', email: 'vendor@example.com' }]),
    })).resolves.toEqual({
      stats: {
        passport: 12,
        mdl: 0,
        mdoc: 0,
        verifications: 9,
      },
      health: {
        issuer_api: 'healthy',
        passport_engine: 'healthy',
        mdl_engine: 'healthy',
        mdoc_engine: 'healthy',
        inspection_system: 'healthy',
      },
      vendors: [{ id: 'vendor-1', email: 'vendor@example.com' }],
      vendorError: null,
    });
  });

  it('falls back safely when vendors fail to load', async () => {
    await expect(loadAdminDashboardBootstrap({
      getAdminStats: vi.fn().mockRejectedValue(new Error('stats failed')),
      getAdminHealth: vi.fn().mockRejectedValue(new Error('health failed')),
      getAdminVendors: vi.fn().mockRejectedValue({ response: { error: { user_message: 'Failed to load vendors' } } }),
      nowIso: '2026-03-17T00:00:00.000Z',
    })).resolves.toMatchObject({
      vendorError: 'Failed to load vendors',
      vendors: [
        expect.objectContaining({
          id: 'vendor-001',
          createdAt: '2026-03-17T00:00:00.000Z',
        }),
      ],
    });
  });

  it('executes vendor impersonation and returns the next UI action', async () => {
    await expect(impersonateAdminVendor({
      vendor: { id: 'vendor-1', email: 'vendor@example.com' },
      keycloak: { token: 'admin-token' },
      authServerUrl: 'https://kc.example',
      realm: 'demo',
      postAdminImpersonation: vi.fn().mockResolvedValue({ redirect: 'https://kc.example/impersonated' }),
    })).resolves.toEqual({
      action: 'open-tab',
      redirectUrl: 'https://kc.example/impersonated',
      successMessage: 'Now impersonating vendor@example.com. Check the new tab.',
    });
  });
});