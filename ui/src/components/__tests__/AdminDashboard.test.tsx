import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@test/utils';

import AdminDashboard from '../AdminDashboard';

const {
  mockNavigate,
  mockShowError,
  mockLoadAdminDashboardBootstrap,
} = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockShowError: vi.fn(),
  mockLoadAdminDashboardBootstrap: vi.fn(),
}));

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({
    keycloak: {
      token: 'admin-token',
      realm: 'demo',
      authServerUrl: 'https://kc.example',
    },
  }),
}));

vi.mock('../../hooks/useNotifications', () => ({
  useNotifications: () => ({
    showSuccess: vi.fn(),
    showError: mockShowError,
  }),
}));

vi.mock('../../application/admin', async () => {
  const actual = await vi.importActual<typeof import('../../application/admin')>('../../application/admin');
  return {
    ...actual,
    loadAdminDashboardBootstrap: (...args: unknown[]) => mockLoadAdminDashboardBootstrap(...args),
  };
});

describe('AdminDashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLoadAdminDashboardBootstrap.mockResolvedValue({
      stats: {
        passport: 5,
        mdl: 2,
        mdoc: 1,
        verifications: 9,
      },
      health: {
        issuer_api: 'healthy',
        passport_engine: 'healthy',
        mdl_engine: 'healthy',
        mdoc_engine: 'healthy',
        inspection_system: 'healthy',
      },
      vendors: [{
        id: 'vendor-1',
        email: 'vendor@example.com',
        organizationName: 'Vendor Org',
        tier: 'PROFESSIONAL',
        enabled: true,
        createdAt: '2026-03-17T00:00:00.000Z',
      }],
      vendorError: null,
    });
  });

  it('loads bootstrap data and renders vendors', async () => {
    render(<AdminDashboard />);

    expect(await screen.findByText('Vendor Org')).toBeInTheDocument();
    expect(screen.getByText('5')).toBeInTheDocument();
    expect(mockLoadAdminDashboardBootstrap).toHaveBeenCalledTimes(1);
  });
});
