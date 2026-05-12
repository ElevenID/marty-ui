import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';

import AuthCallback from '../AuthCallback';

const { mockNavigate, mockSearchParams, mockRefreshUser, mockConsoleContext, mockGetDefaultLandingPath, mockGet } = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockSearchParams: vi.fn(),
  mockRefreshUser: vi.fn(),
  mockConsoleContext: vi.fn(),
  mockGetDefaultLandingPath: vi.fn(),
  mockGet: vi.fn(),
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
    useSearchParams: () => [mockSearchParams()],
  };
});

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({
    refreshUser: mockRefreshUser,
  }),
}));

vi.mock('../../contexts/ConsoleContext', () => ({
  useConsole: () => mockConsoleContext(),
  getDefaultLandingPath: (...args: unknown[]) => mockGetDefaultLandingPath(...args),
}));

vi.mock('../../services/api', () => ({
  get: (...args: unknown[]) => mockGet(...args),
}));

describe('AuthCallback', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRefreshUser.mockResolvedValue(undefined);
    mockConsoleContext.mockReturnValue({ isLoading: false, mode: 'applicant' });
    mockGetDefaultLandingPath.mockReturnValue('/console/applicant/catalog');
    mockGet.mockResolvedValue({ ok: true });
  });

  it('renders callback errors from the query string', async () => {
    mockSearchParams.mockReturnValue(new URLSearchParams('error=access_denied&error_description=Denied'));

    render(<AuthCallback />);

    expect(await screen.findByText('Denied')).toBeInTheDocument();
    expect(mockNavigate).not.toHaveBeenCalled();
  });

  it('completes authentication and navigates to the decoded return path', async () => {
    mockSearchParams.mockReturnValue(
      new URLSearchParams(`code=abc&state=${encodeURIComponent(btoa(JSON.stringify({ returnTo: '/console/org' })))}`),
    );

    render(<AuthCallback />);

    await waitFor(() => {
      expect(mockGet).toHaveBeenCalledWith('/v1/auth/callback?code=abc&state=' + encodeURIComponent(btoa(JSON.stringify({ returnTo: '/console/org' }))));
      expect(mockRefreshUser).toHaveBeenCalled();
      expect(mockNavigate).toHaveBeenCalledWith('/console/org', { replace: true });
    });
  });

  it('falls back to the smart landing path when state returns to root', async () => {
    mockSearchParams.mockReturnValue(
      new URLSearchParams(`code=abc&state=${encodeURIComponent(btoa(JSON.stringify({ returnTo: '/' })))}`),
    );

    render(<AuthCallback />);

    await waitFor(() => {
      expect(mockGetDefaultLandingPath).toHaveBeenCalledWith({ isLoading: false, mode: 'applicant' }, '/console/applicant/catalog');
      expect(mockNavigate).toHaveBeenCalledWith('/console/applicant/catalog', { replace: true });
    });
  });

  it('renders exchange failures as authentication errors', async () => {
    mockSearchParams.mockReturnValue(new URLSearchParams('code=abc'));
    mockGet.mockRejectedValue(new Error('Authentication failed'));

    render(<AuthCallback />);

    expect(await screen.findByText('Authentication failed')).toBeInTheDocument();
  });

  it('does not reprocess the same callback when console context changes after login', async () => {
    const encodedState = encodeURIComponent(btoa(JSON.stringify({ returnTo: '/console/org' })));
    const consoleStates = [
      { isLoading: false, mode: 'applicant' },
      { isLoading: false, mode: 'org', activeOrgId: 'org-1', memberships: [{ id: 'org-1', name: 'Acme' }] },
    ];
    let consoleStateIndex = 0;

    mockSearchParams.mockReturnValue(new URLSearchParams(`code=abc&state=${encodedState}`));
    mockConsoleContext.mockImplementation(() => consoleStates[consoleStateIndex]);

    const view = render(<AuthCallback />);

    await waitFor(() => {
      expect(mockGet).toHaveBeenCalledTimes(1);
      expect(mockRefreshUser).toHaveBeenCalledTimes(1);
    });

    consoleStateIndex = 1;
    view.rerender(<AuthCallback />);

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/console/org', { replace: true });
    });

    expect(mockGet).toHaveBeenCalledTimes(1);
    expect(mockRefreshUser).toHaveBeenCalledTimes(1);
  });
});
