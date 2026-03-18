import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';

import InviteAcceptPage from '../InviteAcceptPage';

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

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
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

    render(<InviteAcceptPage />);

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/organizations/join?inviteToken=token-1', { replace: true });
    });
    expect(mockValidateOrganizationInvitation).not.toHaveBeenCalled();
  });

  it('shows login-required state and stores returnUrl before login', async () => {
    const login = vi.fn();
    mockUseAuth.mockReturnValue({
      isAuthenticated: false,
      login,
    });

    const { user } = render(<InviteAcceptPage />);

    expect(await screen.findByTestId('invite-login-required')).toBeInTheDocument();
    await user.click(screen.getByTestId('login-to-accept-btn'));

    expect(sessionStorage.getItem('returnUrl')).toBe('/organizations/join?inviteToken=token-1');
    expect(login).toHaveBeenCalledTimes(1);
  });

  it('shows an invalid state when no invitation token is provided', async () => {
    mockSearchParams.mockReturnValue(new URLSearchParams(''));

    render(<InviteAcceptPage />);

    expect(await screen.findByTestId('invite-error')).toBeInTheDocument();
    expect(screen.getByText('No invitation token provided')).toBeInTheDocument();
    expect(mockValidateOrganizationInvitation).not.toHaveBeenCalled();
  });
});