import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, waitFor } from '@test/utils';

import LoginPage from '../LoginPage';

const { mockNavigate, mockLocation, mockUseAuth } = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockLocation: vi.fn(),
  mockUseAuth: vi.fn(),
}));

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useLocation: () => mockLocation(),
  };
});

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => mockUseAuth(),
}));

describe('LoginPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLocation.mockReturnValue({ state: null });
    mockUseAuth.mockReturnValue({
      isAuthenticated: false,
      isLoading: false,
      login: vi.fn(),
    });
  });

  it('triggers login for unauthenticated users', async () => {
    const login = vi.fn();
    mockUseAuth.mockReturnValue({
      isAuthenticated: false,
      isLoading: false,
      login,
    });

    render(<LoginPage />);

    await waitFor(() => {
      expect(login).toHaveBeenCalledTimes(1);
    });
    expect(mockNavigate).not.toHaveBeenCalled();
  });

  it('redirects authenticated users to the location state destination', async () => {
    mockLocation.mockReturnValue({ state: { from: { pathname: '/console/org' } } });
    mockUseAuth.mockReturnValue({
      isAuthenticated: true,
      isLoading: false,
      login: vi.fn(),
    });

    render(<LoginPage />);

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/console/org', { replace: true });
    });
  });

  it('waits while auth state is still loading', async () => {
    const login = vi.fn();
    mockUseAuth.mockReturnValue({
      isAuthenticated: false,
      isLoading: true,
      login,
    });

    render(<LoginPage />);

    await waitFor(() => {
      expect(login).not.toHaveBeenCalled();
      expect(mockNavigate).not.toHaveBeenCalled();
    });
  });
});