import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, waitFor } from '@test/utils';

import ApplyPage from '../ApplyPage';

const { mockNavigate, mockUseParams, mockSearchParams, mockLocationState, mockUseAuth } = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockUseParams: vi.fn(),
  mockSearchParams: vi.fn(),
  mockLocationState: vi.fn(),
  mockUseAuth: vi.fn(),
}));

vi.mock('../../application/routing/appHandoff', () => ({
  shouldBrowserRedirect: () => false,
  redirectBrowser: (destination: string) => {
    window.location.href = destination;
  },
}));

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    useParams: () => mockUseParams(),
    useSearchParams: () => [mockSearchParams()],
    useLocation: () => ({ state: mockLocationState() }),
  };
});

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => mockUseAuth(),
}));

describe('ApplyPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.clear();
    mockUseParams.mockReturnValue({ credentialType: 'mdl' });
    mockSearchParams.mockReturnValue(new URLSearchParams('org_id=org-1'));
    mockLocationState.mockReturnValue({ credential: { id: 'cfg-1' } });
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: {
        ...window.location,
        pathname: '/apply/mdl',
        search: '?org_id=org-1',
        href: 'http://localhost/apply/mdl?org_id=org-1',
      },
    });
  });

  it('redirects unauthenticated users and stores apply context', async () => {
    mockUseAuth.mockReturnValue({
      user: null,
      isAuthenticated: false,
      isLoading: false,
    });

    render(<ApplyPage />);

    await waitFor(() => {
      expect(window.location.href).toBe('/login?return_to=%2Fapply%2Fmdl%3Forg_id%3Dorg-1');
    });

    expect(JSON.parse(sessionStorage.getItem('applyContext') || '{}')).toMatchObject({
      credentialType: 'mdl',
      orgId: 'org-1',
      returnUrl: '/apply/mdl?org_id=org-1',
    });
  });

  it('navigates authenticated users into org join flow when needed', async () => {
    mockUseAuth.mockReturnValue({
      user: { organization_id: 'org-2' },
      isAuthenticated: true,
      isLoading: false,
    });

    render(<ApplyPage />);

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/console/applicant?org_required=org-1', undefined);
    });

    expect(sessionStorage.getItem('joinOrgId')).toBe('org-1');
  });

  it('navigates authenticated users into a specific credential apply route', async () => {
    mockUseAuth.mockReturnValue({
      user: { organization_id: 'org-1' },
      isAuthenticated: true,
      isLoading: false,
    });

    render(<ApplyPage />);

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith('/console/applicant/apply/mdl', {
        state: { credential: { id: 'cfg-1' } },
      });
    });
  });
});
