import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { renderWithRouter, screen, waitFor } from '@test/utils';

import InviteAcceptPage from '../InviteAcceptPage';
import { redirectBrowser } from '../../application/routing/appHandoff';

const {
  mockNavigate,
  mockSearchParams,
  mockUseAuth,
  mockValidateOrganizationInvitation,
  mockAcceptOrganizationInvitation,
} = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockSearchParams: vi.fn(),
  mockUseAuth: vi.fn(),
  mockValidateOrganizationInvitation: vi.fn(),
  mockAcceptOrganizationInvitation: vi.fn(),
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
  useAuth: () => mockUseAuth(),
}));

vi.mock('../../services/organizationsApi', () => ({
  acceptOrganizationInvitation: (...args: unknown[]) => mockAcceptOrganizationInvitation(...args),
  validateOrganizationInvitation: (...args: unknown[]) => mockValidateOrganizationInvitation(...args),
}));

vi.mock('../../application/routing/appHandoff', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../application/routing/appHandoff')>(),
  redirectBrowser: vi.fn(() => true),
}));

function renderInvitation() {
  return renderWithRouter(<InviteAcceptPage />, { initialEntries: ['/invite/accept?token=token-1'] });
}

describe('InviteAcceptPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSearchParams.mockReturnValue(new URLSearchParams('token=token-1'));
    mockUseAuth.mockReturnValue({
      isAuthenticated: false,
      login: vi.fn(),
    });
    mockValidateOrganizationInvitation.mockResolvedValue({
      valid: true,
      organization_name: 'Acme Travel',
      email: 'person@example.com',
      expires_at: '2030-01-01T00:00:00.000Z',
      available_credentials: ['Passport'],
    });
    mockAcceptOrganizationInvitation.mockResolvedValue({
      organization_id: 'org-1',
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('redirects authenticated users directly into the join flow', async () => {
    mockUseAuth.mockReturnValue({
      isAuthenticated: true,
      login: vi.fn(),
    });

    renderInvitation();

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/organizations/join?inviteToken=token-1', { replace: true });
    });
    expect(mockValidateOrganizationInvitation).not.toHaveBeenCalled();
    expect(redirectBrowser).not.toHaveBeenCalled();
  });

  it('shows login-required state and stores returnUrl before login', async () => {
    const login = vi.fn();
    mockUseAuth.mockReturnValue({
      isAuthenticated: false,
      login,
    });

    const { user } = renderInvitation();

    expect(await screen.findByTestId('invite-login-required')).toBeInTheDocument();
    await user.click(screen.getByTestId('login-to-accept-btn'));

    expect(sessionStorage.getItem('returnUrl')).toBe('/organizations/join?inviteToken=token-1');
    expect(login).toHaveBeenCalledWith('/organizations/join?inviteToken=token-1');
  });

  it('shows an invalid state when no invitation token is provided', async () => {
    mockSearchParams.mockReturnValue(new URLSearchParams(''));

    renderInvitation();

    expect(await screen.findByTestId('invite-error')).toBeInTheDocument();
    expect(screen.getByText('No invitation token provided')).toBeInTheDocument();
    expect(mockValidateOrganizationInvitation).not.toHaveBeenCalled();
  });

  it('loads the website document when leaving an invalid invitation for home', async () => {
    mockSearchParams.mockReturnValue(new URLSearchParams(''));
    const { user } = renderInvitation();

    await user.click(await screen.findByRole('button', { name: 'Go Home' }));

    expect(redirectBrowser).toHaveBeenCalledWith('/', { replace: false });
    expect(mockNavigate).not.toHaveBeenCalled();
  });
});
