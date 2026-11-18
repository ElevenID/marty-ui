import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';

import AuthCallback from '../AuthCallback';

const { mockNavigate, mockSearchParams, mockCompleteLoginCallback, mockConsoleContext, mockGetDefaultLandingPath } = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockSearchParams: vi.fn(),
  mockCompleteLoginCallback: vi.fn(),
  mockConsoleContext: vi.fn(),
  mockGetDefaultLandingPath: vi.fn(),
}));

vi.mock('../../application/routing/appHandoff', () => ({
  shouldBrowserRedirect: () => false,
  redirectBrowser: vi.fn(),
}));

vi.mock('react-router', async () => {
  const actual = await vi.importActual<typeof import('react-router')>('react-router');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useSearchParams: () => [mockSearchParams()],
  };
});

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({
    completeLoginCallback: mockCompleteLoginCallback,
    user: { user_id: 'user-1' },
    isAuthenticated: true,
    isLoading: false,
  }),
}));

vi.mock('../../contexts/ConsoleContext', () => ({
  useConsole: () => mockConsoleContext(),
  getDefaultLandingPath: (...args: unknown[]) => mockGetDefaultLandingPath(...args),
}));

describe('AuthCallback', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockCompleteLoginCallback.mockResolvedValue({ principalId: 'user-1' });
    mockConsoleContext.mockReturnValue({ isLoading: false, mode: 'applicant' });
    mockGetDefaultLandingPath.mockReturnValue('/console/applicant/catalog');
  });

  it.each(['loading', 'error'])('centers the %s view without leaking layout props to the DOM', async state => {
    mockSearchParams.mockReturnValue(new URLSearchParams(state === 'error'
      ? 'error=access_denied&error_description=Denied' : 'code=abc'));
    mockCompleteLoginCallback.mockReturnValue(new Promise(() => {}));

    render(<AuthCallback />);

    const content = await screen.findByRole(state === 'error' ? 'alert' : 'progressbar');
    const layout = content.parentElement!;
    const layoutProps = ['display', 'flexdirection', 'alignitems', 'justifycontent', 'minheight'];
    expect(layout.getAttributeNames().filter(name => layoutProps.includes(name))).toEqual([]);
    expect(layout).toHaveStyle({
      display: 'flex', 'flex-direction': 'column', 'align-items': 'center',
      'justify-content': 'center', 'min-height': `${window.innerHeight / 2}px`,
    });
    expect(mockNavigate).not.toHaveBeenCalled();
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
      expect(mockCompleteLoginCallback).toHaveBeenCalledWith(expect.objectContaining({
        code: 'abc', state: btoa(JSON.stringify({ returnTo: '/console/org' })),
      }));
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
    mockCompleteLoginCallback.mockRejectedValue(new Error('Authentication failed'));

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
      expect(mockCompleteLoginCallback).toHaveBeenCalledTimes(1);
    });

    consoleStateIndex = 1;
    view.rerender(<AuthCallback />);

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/console/org', { replace: true });
    });

    expect(mockCompleteLoginCallback).toHaveBeenCalledTimes(1);
  });
});
