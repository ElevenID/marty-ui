import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@test/utils';

import ApplicationForm from '../applicant/ApplicationForm';

const {
  mockNavigate,
  mockGet,
  mockGetApplicant,
  mockGetApplicantByUser,
  mockCreateApplicant,
  mockCreateApplication,
  mockAutoIssueApplication,
  mockSubmitApplication,
  mockUpdateApplicantProfile,
  mockEnrollBiometric,
  mockListApplications,
} = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockGet: vi.fn(),
  mockGetApplicant: vi.fn(),
  mockGetApplicantByUser: vi.fn(),
  mockCreateApplicant: vi.fn(),
  mockCreateApplication: vi.fn(),
  mockAutoIssueApplication: vi.fn(),
  mockSubmitApplication: vi.fn(),
  mockUpdateApplicantProfile: vi.fn(),
  mockEnrollBiometric: vi.fn(),
  mockListApplications: vi.fn(),
}));

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useParams: () => ({ credentialType: undefined }),
    useNavigate: () => mockNavigate,
    useLocation: () => ({
      state: {
        credential: {
          id: 'cfg-1',
          credential_type: 'MemberCredential',
          display_name: 'ElevenID Login Credential',
          name: 'ElevenID Login Credential',
          description: 'A free, instant credential.',
          required_fields: [],
          optional_fields: [],
          custom_fields: [],
          field_validation_rules: {},
        },
      },
    }),
  };
});

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({
    user: {
      user_id: 'user-1',
      applicant_id: 'app-1',
      email: 'user@example.com',
      given_name: 'Ada',
      family_name: 'Lovelace',
      organization_name: 'Acme Org',
      roles: ['applicant'],
    },
    organizationId: 'org-1',
  }),
}));

vi.mock('../../contexts/PreviewContext', () => ({
  usePreview: () => ({ isPreview: false }),
}));

vi.mock('../../services/api', () => ({
  get: mockGet,
}));

vi.mock('../../services/applicantApi', () => ({
  getApplicant: mockGetApplicant,
  getApplicantByUser: mockGetApplicantByUser,
  createApplicant: mockCreateApplicant,
  createApplication: mockCreateApplication,
  autoIssueApplication: mockAutoIssueApplication,
  listApplications: mockListApplications,
  submitApplication: mockSubmitApplication,
  updateApplicantProfile: mockUpdateApplicantProfile,
  enrollBiometric: mockEnrollBiometric,
}));

vi.mock('../console/applicant/ClaimCredentialDialog', () => ({
  default: ({ open, applicationId, offerData }: { open: boolean; applicationId: string; offerData: any }) => (
    open ? <div data-testid="claim-credential-dialog">{applicationId}:{offerData?.offer_url}</div> : null
  ),
}));

describe('ApplicationForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetApplicant.mockResolvedValue({ id: 'app-1' });
    mockGetApplicantByUser.mockResolvedValue(null);
    mockCreateApplicant.mockResolvedValue({ id: 'app-created' });
    mockCreateApplication.mockResolvedValue({ id: 'application-1' });
    mockListApplications.mockResolvedValue({ applications: [] });
    mockAutoIssueApplication.mockResolvedValue({
      id: 'issued-1',
      credential_offer_uri: 'openid-credential-offer://offer',
      credential_offer_uris: { apple: 'apple://offer' },
      offer_expires_at: '2026-03-17T00:00:00.000Z',
    });
  });

  it('runs the one-click credential issuance flow for member credentials', async () => {
    const { user } = render(<ApplicationForm />);

    expect(screen.getByText('ElevenID Login Credential')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Add to Wallet' }));

    await waitFor(() => {
      expect(mockCreateApplication).toHaveBeenCalledWith(expect.objectContaining({
        applicant_id: 'app-1',
        credential_configuration_id: 'cfg-1',
        issuing_authority: 'ElevenID LLC',
      }));
      expect(mockAutoIssueApplication).toHaveBeenCalledWith('application-1');
      expect(screen.getByTestId('claim-credential-dialog')).toHaveTextContent('issued-1:openid-credential-offer://offer');
    });
  });
});
