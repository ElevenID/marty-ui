import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@test/utils';

import ImpersonationBanner from '../ImpersonationBanner';

const { mockUseAuth, mockLogout, mockFocus } = vi.hoisted(() => ({
  mockUseAuth: vi.fn(),
  mockLogout: vi.fn(),
  mockFocus: vi.fn(),
}));

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => mockUseAuth(),
}));

describe('ImpersonationBanner', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockUseAuth.mockReturnValue({
      logout: mockLogout,
      impersonation: null,
    });
    Object.defineProperty(window, 'opener', {
      configurable: true,
      value: { closed: false, focus: mockFocus },
    });
  });

  it('does not render when impersonation is inactive', () => {
    render(<ImpersonationBanner />);

    expect(screen.queryByText('Admin impersonation active')).not.toBeInTheDocument();
  });

  it('renders the active impersonation details', () => {
    mockUseAuth.mockReturnValue({
      logout: mockLogout,
      impersonation: {
        active: true,
        admin_display_name: 'Admin User',
        target_email: 'vendor@example.com',
        organization_name: 'Vendor Org',
        started_at: '2026-04-16T02:00:00.000Z',
        launch_mode: 'new-tab',
      },
    });

    render(<ImpersonationBanner />);

    expect(screen.getByText('Admin impersonation active')).toBeInTheDocument();
    expect(screen.getByText(/Admin User is viewing Vendor Org as vendor@example.com\./)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Return to admin' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Exit impersonation' })).toBeInTheDocument();
  });

  it('focuses the admin window when returning to admin', async () => {
    mockUseAuth.mockReturnValue({
      logout: mockLogout,
      impersonation: {
        active: true,
        admin_display_name: 'Admin User',
        target_email: 'vendor@example.com',
        organization_name: 'Vendor Org',
        launch_mode: 'new-tab',
      },
    });

    const { user } = render(<ImpersonationBanner />);
    await user.click(screen.getByRole('button', { name: 'Return to admin' }));

    expect(mockFocus).toHaveBeenCalledTimes(1);
    expect(mockLogout).not.toHaveBeenCalled();
  });

  it('logs out when exiting impersonation', async () => {
    mockUseAuth.mockReturnValue({
      logout: mockLogout,
      impersonation: {
        active: true,
        admin_display_name: 'Admin User',
        target_email: 'vendor@example.com',
        organization_name: 'Vendor Org',
        launch_mode: 'same-tab',
      },
    });

    const { user } = render(<ImpersonationBanner />);
    await user.click(screen.getByRole('button', { name: 'Exit impersonation' }));

    expect(mockLogout).toHaveBeenCalledTimes(1);
  });
});
