import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor, within } from '@test/utils';

import CredentialCatalog from '../applicant/CredentialCatalog';

const { mockNavigate, mockGet, mockGetApplicantByUser } = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockGet: vi.fn(),
  mockGetApplicantByUser: vi.fn(),
}));

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string, options?: any) => options?.count !== undefined ? `${key}:${options.count}` : key }),
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
    organizationId: 'org-1',
    organizationName: 'Acme Org',
    user: { user_id: 'user-1' },
  }),
}));

vi.mock('../../contexts/PreviewContext', () => ({
  usePreview: () => ({ isPreview: false }),
}));

vi.mock('../../services/api', () => ({
  get: mockGet,
}));

vi.mock('../../services/applicantApi', () => ({
  getApplicantByUser: mockGetApplicantByUser,
}));

describe('CredentialCatalog', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGet.mockImplementation((endpoint: string) => {
      if (endpoint.includes('/v1/credential-templates')) {
        return Promise.resolve([
          {
            id: 'cfg-1',
            credential_type: 'MemberCredential',
            name: 'Member Login Credential',
            description: 'Platform login credential',
            claims: [],
            status: 'active',
          },
          {
            id: 'cfg-2',
            credential_type: 'passport',
            name: 'Digital Passport',
            description: 'Travel credential',
            claims: [],
            status: 'active',
          },
        ]);
      }

      if (endpoint.includes('/v1/applicants/profiles/app-1/applications')) {
        return Promise.resolve([
          { credential_configuration_id: 'cfg-2' },
        ]);
      }

      return Promise.resolve([]);
    });
    mockGetApplicantByUser.mockResolvedValue({ id: 'app-1' });
  });

  it('loads credentials, marks existing applications, filters, and navigates with serializable state', async () => {
    const { user } = render(<CredentialCatalog />);

    await waitFor(() => {
      expect(screen.getByTestId('credential-card-cfg-1')).toBeInTheDocument();
      expect(screen.getByTestId('credential-card-cfg-2')).toBeInTheDocument();
    });

    expect(screen.getByTestId('credential-card-cfg-2')).toHaveAttribute('data-credential-status', 'applied');

    await user.type(within(screen.getByTestId('credential-search')).getByRole('textbox'), 'member');

    await waitFor(() => {
      expect(screen.getByTestId('credential-card-cfg-1')).toBeInTheDocument();
      expect(screen.queryByTestId('credential-card-cfg-2')).not.toBeInTheDocument();
    });

    const memberCard = screen.getByTestId('credential-card-cfg-1');
    await user.click(within(memberCard).getByTestId('apply-btn'));

    expect(mockNavigate).toHaveBeenCalledWith('/apply/cfg-1', {
      state: {
        credential: expect.objectContaining({
          id: 'cfg-1',
          name: 'Member Login Credential',
        }),
      },
    });
  });
});
