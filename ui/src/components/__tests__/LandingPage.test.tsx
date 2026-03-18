import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';

import LandingPage from '../LandingPage';

const { mockNavigate, mockSearchParams, mockSetSearchParams, mockUseAuth, mockUseBranding } = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockSearchParams: vi.fn(),
  mockSetSearchParams: vi.fn(),
  mockUseAuth: vi.fn(),
  mockUseBranding: vi.fn(),
}));

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useSearchParams: () => [mockSearchParams(), mockSetSearchParams],
  };
});

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (_key: string, fallback?: string) => fallback || _key,
  }),
}));

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => mockUseAuth(),
}));

vi.mock('../../hooks/useBranding', () => ({
  useBranding: () => mockUseBranding(),
}));

vi.mock('../seo', () => ({
  SEOHead: () => null,
  organizationSchema: () => ({}),
}));

vi.mock('../diagrams', () => ({
  UnifiedIdentityFlowDiagram: () => <div>Unified Identity Flow</div>,
  StandardsStackDiagram: () => <div>Standards Stack</div>,
}));

describe('LandingPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSearchParams.mockReturnValue(new URLSearchParams(''));
    mockUseAuth.mockReturnValue({
      isAuthenticated: false,
      isLoading: false,
      register: vi.fn(),
    });
    mockUseBranding.mockReturnValue({
      branding: { appName: 'ElevenID LLC' },
    });
  });

  it('redirects authenticated users to the applicant console', async () => {
    mockUseAuth.mockReturnValue({
      isAuthenticated: true,
      isLoading: false,
      register: vi.fn(),
    });

    render(<LandingPage />);

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/console/applicant', { replace: true });
    });
  });

  it('shows a loading state while auth is being resolved', () => {
    mockUseAuth.mockReturnValue({
      isAuthenticated: false,
      isLoading: true,
      register: vi.fn(),
    });

    render(<LandingPage />);

    expect(screen.getByText('Loading...')).toBeInTheDocument();
    expect(mockNavigate).not.toHaveBeenCalled();
  });

  it('displays auth_error messages and clears them from the URL', async () => {
    mockSearchParams.mockReturnValue(new URLSearchParams('auth_error=Login+failed%3A+access_denied&foo=bar'));

    render(<LandingPage />);

    expect(await screen.findByText('Login failed: access_denied')).toBeInTheDocument();
    expect(mockSetSearchParams).toHaveBeenCalledTimes(1);

    const [nextParams, options] = mockSetSearchParams.mock.calls[0];
    expect(nextParams).toBeInstanceOf(URLSearchParams);
    expect(nextParams.get('auth_error')).toBeNull();
    expect(nextParams.get('foo')).toBe('bar');
    expect(options).toEqual({ replace: true });
  });
});