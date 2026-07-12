import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@test/utils';

import ApplicationForm from '../applicant/ApplicationForm';

const {
  mockNavigate,
  mockGet,
  mockPost,
  mockGetApplicant,
  mockGetApplicantByUser,
  mockCreateApplicant,
  mockCreateApplication,
  mockGenerateIssuanceOffer,
  mockSubmitApplication,
  mockUpdateApplicantProfile,
  mockEnrollBiometric,
  mockListApplications,
  mockListApplicantApplicationsForProfile,
  mockSupersedeApplication,
  mockWalletPreferenceState,
  mockLocationState,
} = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockGet: vi.fn(),
  mockPost: vi.fn(),
  mockGetApplicant: vi.fn(),
  mockGetApplicantByUser: vi.fn(),
  mockCreateApplicant: vi.fn(),
  mockCreateApplication: vi.fn(),
  mockGenerateIssuanceOffer: vi.fn(),
  mockSubmitApplication: vi.fn(),
  mockUpdateApplicantProfile: vi.fn(),
  mockEnrollBiometric: vi.fn(),
  mockListApplications: vi.fn(),
  mockListApplicantApplicationsForProfile: vi.fn(),
  mockSupersedeApplication: vi.fn(),
  mockWalletPreferenceState: { walletIds: ['wallet-1'] as string[] },
  mockLocationState: {
    params: { credentialType: undefined as string | undefined },
    location: {
      state: {
        credential: {
          id: 'cfg-1',
          application_template_id: 'app-template-1',
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
      search: '',
    } as any,
  },
}));

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useParams: () => mockLocationState.params,
    useNavigate: () => mockNavigate,
    useLocation: () => mockLocationState.location,
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
  post: mockPost,
}));

vi.mock('../../services/applicantApi', () => ({
  getMyApplicantProfile: mockGetApplicant,
  upsertMyApplicantProfile: mockCreateApplicant,
  createApplication: mockCreateApplication,
  listApplications: mockListApplications,
  submitApplication: mockSubmitApplication,
  withdrawApplication: mockSupersedeApplication,
  enrollMyBiometric: mockEnrollBiometric,
}));

vi.mock('../../services/credentialsApi', () => ({
  generateIssuanceOffer: mockGenerateIssuanceOffer,
}));

vi.mock('../../hooks/useWalletPreferences', () => ({
  default: () => ({
    walletIds: mockWalletPreferenceState.walletIds,
  }),
}));

vi.mock('../console/applicant/ClaimCredentialDialog', () => ({
  default: ({ open, applicationId, offerData }: { open: boolean; applicationId: string; offerData: any }) => (
    open ? <div data-testid="claim-credential-dialog">{applicationId}:{offerData?.offer_url}</div> : null
  ),
}));

describe('ApplicationForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockLocationState.params = { credentialType: undefined };
    mockLocationState.location = {
      state: {
        credential: {
          id: 'cfg-1',
          application_template_id: 'app-template-1',
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
      search: '',
    };
    mockGetApplicant.mockResolvedValue({ id: 'app-1' });
    mockGetApplicantByUser.mockResolvedValue(null);
    mockCreateApplicant.mockResolvedValue({ id: 'app-created' });
    mockCreateApplication.mockResolvedValue({ id: 'application-1' });
    mockListApplications.mockResolvedValue({ applications: [] });
    mockListApplicantApplicationsForProfile.mockResolvedValue([]);
    mockSupersedeApplication.mockResolvedValue({ id: 'application-existing', status: 'WITHDRAWN' });
    mockSubmitApplication.mockResolvedValue({
      id: 'application-1',
      reference_number: 'APP-20260317-SUBMITTED',
    });
    mockGenerateIssuanceOffer.mockResolvedValue({
      id: 'issued-1',
      credential_offer_uri: 'openid-credential-offer://offer',
      credential_offer_uris: { apple: 'apple://offer' },
      offer_expires_at: '2026-03-17T00:00:00.000Z',
    });
    mockWalletPreferenceState.walletIds = ['wallet-1'];
  });

  it('explains Canvas-only credential applications with launch context and completion checks', () => {
    mockLocationState.location = {
      search: '?canvas_lti_state=state-1',
      state: {
        credential: {
          id: 'cfg-canvas',
          credential_type: 'canvas_course_badge',
          display_name: 'Canvas Quiz Badge',
          name: 'Canvas Quiz Badge',
          description: 'Issued after the Canvas completion check passes.',
          required_fields: [],
          optional_fields: [],
          custom_fields: [],
          field_validation_rules: {},
        },
        applicationTemplate: {
          id: 'app-template-1',
          evidence_requirements: [
            {
              evidence_type: 'canvas.quiz_score',
              pass_rule: { min_score_percent: 80 },
              scope: { course_id: '1', quiz_id: 'quiz-1' },
            },
          ],
        },
        canvasLtiSession: {
          state: 'state-1',
          canvas_account_id: 'canvas-account-1',
          application_template_id: 'app-template-1',
          credential_template_id: 'cfg-canvas',
          verified_launch: {
            subject: 'canvas-user-1',
            learner_identity: {
              email: 'learner@example.edu',
              name: 'ElevenID Test',
            },
            context: {
              id: '1',
              title: 'ElevenID LTI Test Course',
            },
            raw_claims: {
              'https://purl.imsglobal.org/spec/lti/claim/resource_link': {
                id: 'quiz-1',
                title: 'Final Quiz',
              },
            },
            roles: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Learner'],
          },
        },
        canvasLtiBootstrap: {
          application_id: 'application-1',
          application_status: 'draft',
          created: true,
        },
      },
    };

    render(<ApplicationForm />);

    expect(screen.getByText('Canvas Quiz Badge')).toBeInTheDocument();
    expect(screen.getByTestId('canvas-application-context')).toBeInTheDocument();
    expect(screen.getByText('Course completion requirement')).toBeInTheDocument();
    expect(screen.getByText('No additional form fields are required. Review the course details below, then submit the application so the credential can be checked and issued.')).toBeInTheDocument();
    expect(screen.getByText('ElevenID LTI Test Course')).toBeInTheDocument();
    expect(screen.getByText('Final Quiz')).toBeInTheDocument();
    expect(screen.getByText('Quiz Score')).toBeInTheDocument();
    expect(screen.getByText('minimum score 80% - course 1 - quiz quiz-1')).toBeInTheDocument();
    expect(screen.queryByText('applicationForm.steps.review')).not.toBeInTheDocument();
  });

  it('does not load org-scoped templates for Canvas LTI learners', async () => {
    mockLocationState.params = { credentialType: 'cfg-canvas' };
    mockLocationState.location = {
      search: '?canvas_lti_state=state-1',
      state: null,
    };
    mockGet.mockImplementation(async (url: string) => {
      if (url.includes('/v1/integrations/canvas/lti/experience-sessions/state-1')) {
        return {
          state: 'state-1',
          organization_id: 'org-issuer',
          canvas_account_id: 'canvas-account-1',
          application_template_id: 'app-template-1',
          credential_template_id: 'cfg-canvas',
          verified_launch: {
            subject: 'canvas-user-1',
            learner_identity: {
              email: 'learner@example.edu',
              name: 'ElevenID Test Learner',
            },
            context: {
              title: 'ElevenID LTI Test Course',
            },
            raw_claims: {},
            roles: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Learner'],
          },
        };
      }
      throw new Error('Not a member of this organization');
    });
    mockPost.mockResolvedValue({
      application_id: 'application-1',
      application_status: 'draft',
      created: true,
      organization_id: 'org-issuer',
      credential_template_id: 'cfg-canvas',
    });

    render(<ApplicationForm />);

    await waitFor(() => {
      expect(mockGet).toHaveBeenCalledWith('/v1/integrations/canvas/lti/experience-sessions/state-1');
      expect(screen.getByTestId('canvas-application-context')).toBeInTheDocument();
    });

    expect(mockGet).not.toHaveBeenCalledWith(expect.stringContaining('/v1/credential-templates/'));
    expect(mockGet).not.toHaveBeenCalledWith(expect.stringContaining('/v1/application-templates/'));
    expect(screen.queryByText('Not a member of this organization')).not.toBeInTheDocument();
  });

  it('runs the one-click credential issuance flow for member credentials', async () => {
    const { user } = render(<ApplicationForm />);

    expect(screen.getByText('ElevenID Login Credential')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Add to Wallet' }));

    await waitFor(() => {
      expect(mockCreateApplication).toHaveBeenCalledWith(expect.objectContaining({
        organization_id: 'org-1',
        application_template_id: 'app-template-1',
        form_data: expect.any(Object),
      }));
      expect(mockSubmitApplication).toHaveBeenCalledWith('application-1');
      expect(mockGenerateIssuanceOffer).toHaveBeenCalledWith('application-1');
      expect(screen.getByTestId('claim-credential-dialog')).toHaveTextContent('issued-1:openid-credential-offer://offer');
    });
  });

  it('submits the application but waits for wallet selection before generating an offer', async () => {
    mockWalletPreferenceState.walletIds = [];

    const { user } = render(<ApplicationForm />);

    await user.click(screen.getByRole('button', { name: 'Add to Wallet' }));

    await waitFor(() => {
      expect(mockCreateApplication).toHaveBeenCalledWith(expect.objectContaining({
        organization_id: 'org-1',
        application_template_id: 'app-template-1',
      }));
      expect(mockSubmitApplication).toHaveBeenCalledWith('application-1');
      expect(mockGenerateIssuanceOffer).not.toHaveBeenCalled();
      expect(screen.getByTestId('claim-credential-dialog')).toHaveTextContent('application-1:');
    });
  });
});
