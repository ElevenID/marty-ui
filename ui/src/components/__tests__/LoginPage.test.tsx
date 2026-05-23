import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, waitFor } from '@test/utils';

import LoginPage from '../LoginPage';

const { mockNavigate, mockLocation, mockUseAuth } = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockLocation: vi.fn(),
  mockUseAuth: vi.fn(),
}));

vi.mock('../../application/routing/appHandoff', () => ({
  shouldBrowserRedirect: () => false,
  redirectBrowser: vi.fn(),
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
    mockLocation.mockReturnValue({ state: null, search: '' });
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
    mockLocation.mockReturnValue({ state: { from: { pathname: '/console/org' } }, search: '' });
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

  it('uses the next query param as the login redirect target', async () => {
    const login = vi.fn();
    mockLocation.mockReturnValue({
      state: null,
      search: '?next=%2Fconsole%2Fapplicant%2Fcatalog%3Fcanvas_lti_state%3Dstate-1',
    });
    mockUseAuth.mockReturnValue({
      isAuthenticated: false,
      isLoading: false,
      login,
    });

    render(<LoginPage />);

    await waitFor(() => {
      expect(login).toHaveBeenCalledWith('/console/applicant/catalog?canvas_lti_state=state-1');
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
