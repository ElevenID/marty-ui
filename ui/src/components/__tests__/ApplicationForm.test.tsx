import { describe, expect, it, vi, beforeEach } from 'vitest';
import { act, fireEvent, render, renderWithRouter, screen, waitFor } from '@test/utils';
import { Link, Route, Routes } from 'react-router';

import ApplicationForm from '../applicant/ApplicationForm';
import { storeCanvasLtiSession } from '../../services/canvasLtiExperience';

const {
  mockNavigate,
  mockGet,
  mockPost,
  mockGetApplicant,
  mockGetApplicantByUser,
  mockCreateApplicant,
  mockCreateApplication,
  mockSubmitApplicationEvidence,
  mockGenerateIssuanceOffer,
  mockSubmitApplication,
  mockUpdateApplicantProfile,
  mockEnrollBiometric,
  mockListApplications,
  mockListApplicantApplicationsForProfile,
  mockSupersedeApplication,
  mockWalletPreferenceState,
  mockAuthState,
  mockLocationState,
  mockPreview,
} = vi.hoisted(() => ({
  mockNavigate: vi.fn(),
  mockGet: vi.fn(),
  mockPost: vi.fn(),
  mockGetApplicant: vi.fn(),
  mockGetApplicantByUser: vi.fn(),
  mockCreateApplicant: vi.fn(),
  mockCreateApplication: vi.fn(),
  mockSubmitApplicationEvidence: vi.fn(),
  mockGenerateIssuanceOffer: vi.fn(),
  mockSubmitApplication: vi.fn(),
  mockUpdateApplicantProfile: vi.fn(),
  mockEnrollBiometric: vi.fn(),
  mockListApplications: vi.fn(),
  mockListApplicantApplicationsForProfile: vi.fn(),
  mockSupersedeApplication: vi.fn(),
  mockWalletPreferenceState: { walletIds: ['wallet-1'] as string[] },
  mockAuthState: { organizationId: 'org-1' },
  mockPreview: { isPreview: false },
  mockLocationState: {
    liveRouter: false,
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
        applicationTemplate: {
          id: 'app-template-1',
          status: 'ACTIVE',
          credential_template_id: 'cfg-1',
          form_fields: [{ field_id: 'email', label: 'Email', field_type: 'EMAIL', required: true }],
        },
      },
      search: '',
    } as any,
  },
}));

vi.mock('react-i18next', () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

vi.mock('react-router', async () => {
  const actual = await vi.importActual<typeof import('react-router')>('react-router');
  return {
    ...actual,
    useParams: () => mockLocationState.liveRouter ? actual.useParams() : mockLocationState.params,
    useNavigate: () => mockLocationState.liveRouter ? actual.useNavigate() : mockNavigate,
    useLocation: () => mockLocationState.liveRouter ? actual.useLocation() : mockLocationState.location,
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
    organizationId: mockAuthState.organizationId,
  }),
}));

vi.mock('../../contexts/PreviewContext', () => ({
  usePreview: () => mockPreview,
}));

vi.mock('../../services/api', () => ({
  get: mockGet,
  post: mockPost,
}));

vi.mock('../../services/applicantApi', () => ({
  getMyApplicantProfile: mockGetApplicant,
  upsertMyApplicantProfile: mockCreateApplicant,
  createApplication: mockCreateApplication,
  submitApplicationEvidence: mockSubmitApplicationEvidence,
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
  default: ({ open, onClose, applicationId, offerData, organizationId }: { open: boolean; onClose: () => void; applicationId: string; offerData: any; organizationId?: string }) => (
    open ? (
      <div data-testid="claim-credential-dialog" data-organization-id={organizationId}>
        {applicationId}:{offerData?.offer_url}
        <button onClick={onClose}>Close claim dialog</button>
      </div>
    ) : null
  ),
}));

function canvasApplicationLocationState() {
  return {
    search: '?canvas_lti_state=current',
    state: {
      credential: {
        id: 'cfg-canvas',
        credential_type: 'open_badge',
        display_name: 'Canvas Achievement Badge',
        required_fields: [],
        optional_fields: [],
        custom_fields: [],
        field_validation_rules: {},
      },
      applicationTemplate: {
        id: 'app-template-1',
        evidence_requirements: [{
          requirement_id: 'course-complete',
          source: 'canvas_rest',
          fact_type: 'canvas.course_completion',
          pass_rule: { completed: true },
          scope: { course_id: 'course-1' },
          required: true,
        }],
      },
      canvasLtiSession: {
        canvas_account_id: 'canvas-account-1',
        canvas_platform_id: 'platform-1',
        canvas_program_binding_id: 'binding-1',
        application_template_id: 'app-template-1',
        credential_template_id: 'cfg-canvas',
        canvas_context: { course_id: 'course-1', title: 'Portable Canvas Course' },
        identity_mapping_status: 'linked',
        roles: ['Learner'],
      },
      canvasLtiBootstrap: {
        application_id: 'application-canvas-1',
        application_status: 'pending',
        created: true,
      },
    },
  };
}

function canvasClaimStatus(claimed = false) {
  return {
    application_status: claimed ? 'claimed' : 'approved',
    sync: { status: 'succeeded' },
    evidence: {
      required_count: 1,
      current_authoritative_count: 1,
      verified_authoritative_count: 1,
      verified_required_count: 1,
      status: 'verified',
    },
    policy: { status: 'permitted' },
    claim: claimed
      ? { status: 'claimed', unsigned: false, available: false }
      : { status: 'ready_to_claim', unsigned: true, available: true },
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

describe('ApplicationForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockPreview.isPreview = false;
    sessionStorage.clear();
    storeCanvasLtiSession({
      session_token: 'canvas-session-token',
      expires_at: '2099-01-01T00:00:00.000Z',
    });
    mockLocationState.params = { credentialType: undefined };
    mockLocationState.liveRouter = false;
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
        applicationTemplate: {
          id: 'app-template-1',
          status: 'ACTIVE',
          credential_template_id: 'cfg-1',
          form_fields: [{ field_id: 'email', label: 'Email', field_type: 'EMAIL', required: true }],
        },
      },
      search: '',
    };
    mockGetApplicant.mockResolvedValue({ id: 'app-1' });
    mockGetApplicantByUser.mockResolvedValue(null);
    mockCreateApplicant.mockResolvedValue({ id: 'app-created' });
    mockCreateApplication.mockResolvedValue({ id: 'application-1' });
    mockSubmitApplicationEvidence.mockResolvedValue({ id: 'evidence-1', status: 'ACTIVE' });
    mockListApplications.mockResolvedValue({ items: [], total: 0, limit: 100, offset: 0 });
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
    mockAuthState.organizationId = 'org-1';
  });

  it.each([false, true])('simulates preview submission without applicant, credential or evidence writes (one click=%s)', async (oneClick) => {
    mockPreview.isPreview = true;
    mockLocationState.location.search = '?canvas_lti_state=stale-launch&application_template_id=stale-template';
    const { user } = render(<ApplicationForm previewContext={{
      credential: { id: 'preview-credential', credential_type: oneClick ? 'MemberCredential' : 'EmployeeCredential',
        required_fields: [], optional_fields: [], custom_fields: [], field_validation_rules: {} },
      applicationTemplate: { id: 'preview-template', name: 'Actual preview template', credential_template_id: 'preview-credential',
        status: 'DRAFT', form_fields: oneClick ? [{ field_id: 'email', field_type: 'EMAIL', required: true }] : [], evidence_requirements: [] },
    }} />);
    expect(screen.getByText('Actual preview template')).toBeInTheDocument();
    expect(screen.queryByText('ElevenID Login Credential')).not.toBeInTheDocument();
    expect(mockGet).not.toHaveBeenCalled();
    if (oneClick) {
      expect(screen.queryByText(/^Instant/)).not.toBeInTheDocument();
      await user.click(screen.getByRole('button', { name: 'Add to Wallet' }));
    } else {
      if (screen.queryByTestId('next-step-btn')) await user.click(screen.getByTestId('next-step-btn'));
      await user.click(screen.getByTestId('accept-terms-checkbox'));
      await user.click(screen.getByTestId('submit-application-btn'));
    }
    expect(await screen.findByTestId('application-submitted')).toHaveTextContent('applicationForm.success.previewTitle');
    for (const mutation of [mockCreateApplicant, mockCreateApplication, mockSubmitApplication,
      mockSubmitApplicationEvidence, mockUpdateApplicantProfile, mockEnrollBiometric, mockGenerateIssuanceOffer, mockPost]) {
      expect(mutation).not.toHaveBeenCalled();
    }
  });

  it('submits a live application to its API-provided issuer organization rather than the user home organization', async () => {
    mockAuthState.organizationId = 'home-org';
    mockLocationState.location.state = {
      credential: { id: 'issuer-credential', credential_type: 'EmployeeCredential', required_fields: [], optional_fields: [], custom_fields: [] },
      applicationTemplate: { id: 'issuer-application', organization_id: 'issuer-org', credential_template_id: 'issuer-credential',
        name: 'Issuer application', status: 'ACTIVE', form_fields: [{ field_id: 'member_id', label: 'Member ID', field_type: 'TEXT', required: true }], evidence_requirements: [] },
    };
    const { user } = render(<ApplicationForm />);
    await user.type(screen.getByRole('textbox', { name: /member id/i }), 'SYNTHETIC-ISSUER-MEMBER');
    if (screen.queryByTestId('next-step-btn')) await user.click(screen.getByTestId('next-step-btn'));
    await user.click(screen.getByTestId('accept-terms-checkbox'));
    await user.click(screen.getByTestId('submit-application-btn'));
    await waitFor(() => expect(mockCreateApplication).toHaveBeenCalledWith(expect.objectContaining({
      organization_id: 'issuer-org', application_template_id: 'issuer-application',
      form_data: { member_id: 'SYNTHETIC-ISSUER-MEMBER' },
    })));
  });

  it('explains Canvas-only credential applications with launch context and completion checks', async () => {
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
              requirement_id: 'quiz-score',
              source: 'canvas_rest',
              fact_type: 'canvas.quiz_score',
              pass_rule: { min_score_percent: 80 },
              scope: { course_id: '1', activity_id: 'quiz-1' },
              required: true,
            },
          ],
        },
        canvasLtiSession: {
          state: 'state-1',
          canvas_account_id: 'canvas-account-1',
          application_template_id: 'app-template-1',
          credential_template_id: 'cfg-canvas',
          canvas_context: {
            course_id: '1',
            title: 'ElevenID LTI Test Course',
          },
          learner_display_name: 'ElevenID Test',
          identity_mapping_status: 'linked',
          roles: ['Learner'],
        },
        canvasLtiBootstrap: {
          application_id: 'application-1',
          application_status: 'draft',
          created: true,
        },
      },
    };
    mockGet.mockResolvedValue({
      application_status: 'pending',
      sync: null,
      evidence: {
        required_count: 1,
        current_authoritative_count: 0,
        verified_authoritative_count: 0,
        verified_required_count: 0,
        status: 'not_observed',
      },
      policy: { status: 'not_evaluated' },
      claim: { status: 'not_available', unsigned: false, available: false },
    });

    render(<ApplicationForm />);

    expect(screen.getByText('Canvas Quiz Badge')).toBeInTheDocument();
    expect(screen.getByTestId('canvas-application-context')).toBeInTheDocument();
    expect(screen.getByText('Course completion requirement')).toBeInTheDocument();
    expect(screen.getByText('No additional form fields are required. Review the course details below, then submit the application so the credential can be checked and issued.')).toBeInTheDocument();
    expect(screen.getByText('ElevenID LTI Test Course')).toBeInTheDocument();
    expect(screen.getByText('Quiz Score')).toBeInTheDocument();
    expect(screen.getByText('minimum score 80% - course 1 - activity quiz-1')).toBeInTheDocument();
    expect(screen.getByText('Canvas identity linked')).toBeInTheDocument();
    expect(screen.queryByText('applicationForm.steps.review')).not.toBeInTheDocument();
    await waitFor(() => {
      expect(mockGet).toHaveBeenCalledWith(
        '/v1/integrations/canvas/lti/experience-sessions/current/evidence-status',
        { headers: { Authorization: 'Bearer canvas-session-token' } },
      );
    });
  });

  it('renders only server-verified Canvas evidence and a real unsigned pending claim', async () => {
    mockLocationState.location = canvasApplicationLocationState();
    mockGet.mockResolvedValue({
      application_status: 'pending',
      sync: {
        job_id: 'job-1',
        status: 'succeeded',
        requested_at: '2026-07-15T06:00:00Z',
        completed_at: '2026-07-15T06:00:03Z',
      },
      evidence: {
        required_count: 1,
        current_authoritative_count: 1,
        verified_authoritative_count: 1,
        verified_required_count: 1,
        status: 'verified',
      },
      policy: { status: 'permitted' },
      claim: { status: 'pending_claim', unsigned: true, available: false },
      raw_facts: [{ score: 100, access_token: 'must-not-render' }],
    });

    render(<ApplicationForm />);

    expect(await screen.findByTestId('canvas-authoritative-evidence-verified')).toHaveTextContent('Verified evidence 1/1');
    expect(screen.getByTestId('canvas-evidence-policy-permitted')).toBeInTheDocument();
    expect(screen.getByTestId('canvas-pending-claim')).toHaveTextContent('unsigned pending badge award');
    expect(screen.queryByTestId('canvas-claim-action')).not.toBeInTheDocument();
    expect(screen.queryByText('must-not-render')).not.toBeInTheDocument();
  });

  it.each([
    { context: 'Canvas issuer organization', issuerOrganizationId: 'org-canvas-issuer', expectedOrganizationId: 'org-canvas-issuer' },
    { context: 'authenticated organization fallback', issuerOrganizationId: undefined, expectedOrganizationId: 'org-1' },
  ])('queues a learner refresh and opens a server-authorized claim in the $context', async ({ issuerOrganizationId, expectedOrganizationId }) => {
    mockLocationState.location = canvasApplicationLocationState();
    mockLocationState.location.state.canvasLtiSession.organization_id = issuerOrganizationId;
    let queued = false;
    const readyStatus = {
      application_status: 'approved',
      sync: {
        job_id: 'job-complete',
        status: 'succeeded',
        requested_at: '2026-07-15T06:00:00Z',
        completed_at: '2026-07-15T06:00:03Z',
      },
      evidence: {
        required_count: 1,
        current_authoritative_count: 1,
        verified_authoritative_count: 1,
        verified_required_count: 1,
        status: 'verified',
      },
      policy: { status: 'permitted' },
      claim: { status: 'ready_to_claim', unsigned: true, available: true },
    };
    const queuedStatus = {
      ...readyStatus,
      sync: {
        job_id: 'job-refresh',
        status: 'queued',
        requested_at: '2026-07-15T06:01:00Z',
        completed_at: null,
      },
    };
    mockGet.mockImplementation(async () => (queued ? queuedStatus : readyStatus));
    mockPost.mockImplementation(async (url: string) => {
      if (url.endsWith('/experience-sessions/current/evidence-sync')) {
        queued = true;
        return queuedStatus;
      }
      throw new Error(`Unexpected POST ${url}`);
    });

    const { user } = render(<ApplicationForm />);

    await user.click(await screen.findByTestId('canvas-evidence-sync-action'));
    await waitFor(() => {
      expect(mockPost).toHaveBeenCalledWith(
        '/v1/integrations/canvas/lti/experience-sessions/current/evidence-sync',
        {},
        { headers: { Authorization: 'Bearer canvas-session-token' } },
      );
      expect(screen.getByTestId('canvas-evidence-sync-status')).toHaveTextContent('Canvas sync queued');
    });

    // Restore the exact server-reported claimable state; the UI never derives
    // it merely from a successful refresh request.
    queued = false;
    mockGet.mockResolvedValue(readyStatus);
    await user.click(screen.getByTestId('canvas-claim-action'));
    expect(screen.getByTestId('claim-credential-dialog')).toHaveTextContent('application-canvas-1');
    expect(screen.getByTestId('claim-credential-dialog')).toHaveAttribute('data-organization-id', expectedOrganizationId);
  });

  it('refreshes Canvas claim status after closing the dialog without issuing again', async () => {
    mockLocationState.location = canvasApplicationLocationState();
    mockGet.mockResolvedValue(canvasClaimStatus());
    const { user } = render(<ApplicationForm />);
    await user.click(await screen.findByTestId('canvas-claim-action'));
    expect(screen.getByTestId('claim-credential-dialog')).toHaveTextContent('application-canvas-1');

    mockGet.mockResolvedValue(canvasClaimStatus(true));
    await user.click(screen.getByRole('button', { name: 'Close claim dialog' }));

    expect(await screen.findByTestId('canvas-claim-complete')).toHaveTextContent('This Canvas badge has been claimed.');
    expect(screen.queryByTestId('canvas-claim-action')).not.toBeInTheDocument();
    expect(mockPost).not.toHaveBeenCalled();
    expect(mockGenerateIssuanceOffer).not.toHaveBeenCalled();
  });

  it.each(['focus', 'visibilitychange'])('refreshes the current Canvas claim on browser %s return', async (event) => {
    mockLocationState.location = canvasApplicationLocationState();
    mockGet.mockResolvedValue(canvasClaimStatus());
    const { user } = render(<ApplicationForm />);
    await user.click(await screen.findByTestId('canvas-claim-action'));

    mockGet.mockResolvedValue(canvasClaimStatus(true));
    fireEvent(event === 'focus' ? window : document, new Event(event));

    expect(await screen.findByTestId('canvas-claim-complete')).toBeInTheDocument();
    expect(screen.getByTestId('claim-credential-dialog')).toHaveTextContent('application-canvas-1');
    expect(mockPost).not.toHaveBeenCalled();
    expect(mockGenerateIssuanceOffer).not.toHaveBeenCalled();
  });

  it('does not treat closing a canceled wallet claim as successful issuance', async () => {
    mockLocationState.location = canvasApplicationLocationState();
    mockGet.mockResolvedValue(canvasClaimStatus());
    const { user } = render(<ApplicationForm />);
    await user.click(await screen.findByTestId('canvas-claim-action'));
    const readsBeforeClose = mockGet.mock.calls.length;
    await user.click(screen.getByRole('button', { name: 'Close claim dialog' }));

    await waitFor(() => expect(mockGet.mock.calls.length).toBeGreaterThan(readsBeforeClose));
    expect(screen.getByTestId('canvas-ready-to-claim')).toBeInTheDocument();
    expect(screen.queryByTestId('canvas-claim-complete')).not.toBeInTheDocument();
    expect(mockPost).not.toHaveBeenCalled();
    expect(mockGenerateIssuanceOffer).not.toHaveBeenCalled();
  });

  it('clears stale Canvas claim availability when the return status read fails', async () => {
    mockLocationState.location = canvasApplicationLocationState();
    mockGet.mockResolvedValue(canvasClaimStatus());
    const { user } = render(<ApplicationForm />);
    await user.click(await screen.findByTestId('canvas-claim-action'));

    mockGet.mockRejectedValue(new Error('Canvas launch session expired. Reopen from Canvas.'));
    await user.click(screen.getByRole('button', { name: 'Close claim dialog' }));

    expect(await screen.findByTestId('canvas-evidence-sync-error')).toHaveTextContent('Canvas launch session expired. Reopen from Canvas.');
    expect(screen.queryByTestId('canvas-ready-to-claim')).not.toBeInTheDocument();
    expect(screen.queryByTestId('canvas-claim-complete')).not.toBeInTheDocument();
    expect(screen.queryByTestId('canvas-authoritative-evidence-verified')).not.toBeInTheDocument();
    expect(mockPost).not.toHaveBeenCalled();
  });

  it('discards a late claim read after leaving the Canvas application and removes return listeners', async () => {
    mockLocationState.location = canvasApplicationLocationState();
    mockGet.mockResolvedValue(canvasClaimStatus());
    const first = render(<ApplicationForm />);
    await first.user.click(await screen.findByTestId('canvas-claim-action'));

    let finishOldRead!: (value: ReturnType<typeof canvasClaimStatus>) => void;
    mockGet.mockImplementation(() => new Promise((resolve) => { finishOldRead = resolve; }));
    const readsBeforeClose = mockGet.mock.calls.length;
    await first.user.click(screen.getByRole('button', { name: 'Close claim dialog' }));
    await waitFor(() => expect(mockGet.mock.calls.length).toBeGreaterThan(readsBeforeClose));
    first.unmount();
    const readsAfterUnmount = mockGet.mock.calls.length;
    fireEvent(window, new Event('focus'));
    fireEvent(document, new Event('visibilitychange'));
    expect(mockGet).toHaveBeenCalledTimes(readsAfterUnmount);

    mockLocationState.location = canvasApplicationLocationState();
    mockLocationState.location.state.canvasLtiBootstrap.application_id = 'application-canvas-2';
    mockGet.mockResolvedValue(canvasClaimStatus());
    const second = render(<ApplicationForm />);
    await second.user.click(await screen.findByTestId('canvas-claim-action'));
    await act(async () => { finishOldRead(canvasClaimStatus(true)); });

    expect(screen.getByTestId('claim-credential-dialog')).toHaveTextContent('application-canvas-2');
    expect(screen.getByTestId('canvas-ready-to-claim')).toBeInTheDocument();
    expect(screen.queryByTestId('canvas-claim-complete')).not.toBeInTheDocument();
    expect(mockPost).not.toHaveBeenCalled();
  });

  it('does not load org-scoped templates for Canvas LTI learners', async () => {
    mockLocationState.params = { credentialType: 'cfg-canvas' };
    mockLocationState.location = {
      search: '?canvas_lti_state=state-1',
      state: null,
    };
    mockGet.mockImplementation(async (url: string) => {
      if (url.includes('/v1/integrations/canvas/lti/experience-sessions/current')) {
        return {
          organization_id: 'org-issuer',
          canvas_account_id: 'canvas-account-1',
          application_template_id: 'app-template-1',
          credential_template_id: 'cfg-canvas',
          canvas_context: {
            course_id: '1',
            title: 'ElevenID LTI Test Course',
          },
          learner_display_name: 'ElevenID Test Learner',
          identity_mapping_status: 'linked',
          roles: ['Learner'],
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
      expect(mockGet).toHaveBeenCalledWith(
        '/v1/integrations/canvas/lti/experience-sessions/current',
        { headers: { Authorization: 'Bearer canvas-session-token' } },
      );
      expect(screen.getByTestId('canvas-application-context')).toBeInTheDocument();
    });

    expect(mockGet).not.toHaveBeenCalledWith(expect.stringContaining('/v1/credential-templates/'));
    expect(mockGet).not.toHaveBeenCalledWith(expect.stringContaining('/v1/application-templates/'));
    expect(screen.queryByText('Not a member of this organization')).not.toBeInTheDocument();
    await waitFor(() => {
      expect(mockPost).toHaveBeenCalledWith(
        '/v1/integrations/canvas/lti/experience-sessions/current/bootstrap',
        {
          applicant_identifier: 'user-1',
          applicant_data: {
            email: 'user@example.com',
            given_name: 'Ada',
            family_name: 'Lovelace',
            name: 'Ada Lovelace',
          },
        },
        { headers: { Authorization: 'Bearer canvas-session-token' } },
      );
    });
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

  it('keeps one-click membership wallet selection in the application organization before an offer exists', async () => {
    mockAuthState.organizationId = 'org-membership';
    mockWalletPreferenceState.walletIds = [];
    mockLocationState.location.state.credential.credential_type = 'open_badge';

    const { user } = render(<ApplicationForm />);
    await user.click(screen.getByTestId('credential-claim-action'));

    const dialog = await screen.findByTestId('claim-credential-dialog');
    expect(mockCreateApplication).toHaveBeenCalledWith(expect.objectContaining({
      organization_id: 'org-membership',
      application_template_id: 'app-template-1',
    }));
    expect(mockSubmitApplication).toHaveBeenCalledWith('application-1');
    expect(mockGenerateIssuanceOffer).not.toHaveBeenCalled();
    expect(dialog).toHaveTextContent('application-1:');
    expect(dialog).toHaveAttribute('data-organization-id', 'org-membership');
  });

  it('uploads required evidence through the same public API before browser submission', async () => {
    mockLocationState.location = {
      search: '',
      state: {
        credential: {
          id: 'cfg-evidence',
          application_template_id: 'app-template-evidence',
          credential_type: 'EmployeeCredential',
          display_name: 'Employee Credential',
          required_fields: [],
          optional_fields: [],
          custom_fields: [],
          field_validation_rules: {},
        },
        applicationTemplate: {
          id: 'app-template-evidence',
          credential_template_id: 'cfg-evidence',
          form_fields: [],
          evidence_requirements: [{
            evidence_id: 'identity_scan',
            evidence_type: 'DOCUMENT_SCAN',
            description: 'Identity scan',
            required: true,
            accepted_formats: ['image/png'],
          }],
        },
      },
    };

    const { user } = render(<ApplicationForm />);
    const fileInput = document.querySelector('input[type="file"]') as HTMLInputElement;
    expect(fileInput).toBeInTheDocument();
    await user.upload(fileInput, new File(['identity'], 'identity.png', { type: 'image/png' }));
    await user.click(screen.getByTestId('next-step-btn'));
    await user.click(screen.getByTestId('accept-terms-checkbox'));
    await user.click(screen.getByTestId('submit-application-btn'));

    await waitFor(() => {
      expect(mockSubmitApplicationEvidence).toHaveBeenCalledWith(
        'application-1',
        expect.objectContaining({
          evidence_requirement_id: 'identity_scan',
          media_type: 'image/png',
          filename: 'identity.png',
          content_base64: 'aWRlbnRpdHk=',
        }),
      );
      expect(mockSubmitApplication).toHaveBeenCalledWith('application-1');
    });
    expect(mockSubmitApplicationEvidence.mock.invocationCallOrder[0]).toBeLessThan(
      mockSubmitApplication.mock.invocationCallOrder[0],
    );
  });

  it.each(['credential route', 'application template query'])('resets the application and draft after a real %s navigation', async change => {
    mockLocationState.liveRouter = true;
    mockGet.mockImplementation(async (url: string) => {
      if (url.startsWith('/v1/credential-templates/')) {
        const id = url.split('/').at(-1);
        return { id, name: id, credential_type: 'EmployeeCredential', application_template_id: id === 'cfg-a' ? 'tpl-a' : 'tpl-b', claims: [] };
      }
      const id = url.split('/').at(-1);
      return {
        id, name: id === 'tpl-a' ? 'Application A' : 'Application B', status: 'ACTIVE', organization_id: 'org-1',
        credential_template_id: change === 'credential route' && id === 'tpl-b' ? 'cfg-b' : 'cfg-a',
        form_fields: [{ field_id: 'member_number', label: 'Member number', field_type: 'TEXT', required: true }],
      };
    });
    const destination = change === 'credential route'
      ? '/console/applicant/apply/cfg-b'
      : '/console/applicant/apply/cfg-a?application_template_id=tpl-b';
    const { user } = renderWithRouter(
      <Routes>
        <Route path="/console/applicant/apply/:credentialType" element={
          <><Link to={destination}>Choose another application</Link><ApplicationForm /></>
        } />
      </Routes>,
      { initialEntries: ['/console/applicant/apply/cfg-a'] },
    );
    await user.type(await screen.findByRole('textbox', { name: /member number/i }), 'DRAFT-A');
    await user.click(screen.getByTestId('next-step-btn'));
    await user.click(screen.getByTestId('accept-terms-checkbox'));
    await user.click(screen.getByRole('link', { name: 'Choose another application' }));

    expect(await screen.findByText('Application B')).toBeInTheDocument();
    expect(screen.queryByText('Application A')).not.toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: /member number/i })).toHaveValue('');
    expect(screen.queryByText('DRAFT-A')).not.toBeInTheDocument();
    expect(mockCreateApplication).not.toHaveBeenCalled();
  });

  it.each(['profile', 'duplicate lookup', 'failed duplicate lookup', 'creation', 'submission'])('stops one-click follow-up operations after leaving during %s', async phase => {
    const pending = deferred<any>();
    const request = phase === 'profile' ? mockGetApplicant
      : phase.includes('duplicate') ? mockListApplications
      : phase === 'creation' ? mockCreateApplication : mockSubmitApplication;
    request.mockReturnValueOnce(pending.promise);
    const view = render(<ApplicationForm />);
    await view.user.click(screen.getByRole('button', { name: 'Add to Wallet' }));
    await waitFor(() => expect(request).toHaveBeenCalledTimes(1));
    // ConsoleProvider replaces its whole child tree when the auth principal
    // or auth loading session changes; its unmount must stop these writes too.
    view.unmount();
    await act(async () => {
      if (phase === 'failed duplicate lookup') pending.reject(new Error('Old lookup failed'));
      else pending.resolve(phase.includes('duplicate') ? { items: [] } : { id: phase === 'profile' ? 'app-1' : 'application-1' });
    });

    if (phase === 'profile') expect(mockCreateApplicant).not.toHaveBeenCalled();
    if (phase === 'profile' || phase.includes('duplicate')) expect(mockCreateApplication).not.toHaveBeenCalled();
    if (phase !== 'submission') expect(mockSubmitApplication).not.toHaveBeenCalled();
    expect(mockGenerateIssuanceOffer).not.toHaveBeenCalled();
    expect(screen.queryByTestId('claim-credential-dialog')).not.toBeInTheDocument();
  });

  it('does not load an old linked template after its credential read completes on another route', async () => {
    mockLocationState.liveRouter = true;
    const oldCredential = deferred<any>();
    mockGet.mockImplementation(async (url: string) => {
      if (url === '/v1/credential-templates/cfg-a') return oldCredential.promise;
      if (url === '/v1/credential-templates/cfg-b') {
        return { id: 'cfg-b', name: 'Credential B', credential_type: 'EmployeeCredential', application_template_id: 'tpl-b', claims: [] };
      }
      return { id: 'tpl-b', name: 'Application B', credential_template_id: 'cfg-b', status: 'ACTIVE', form_fields: [] };
    });
    const { user } = renderWithRouter(
      <Routes>
        <Route path="/console/applicant/apply/:credentialType" element={
          <><Link to="/console/applicant/apply/cfg-b">Choose B</Link><ApplicationForm /></>
        } />
      </Routes>,
      { initialEntries: ['/console/applicant/apply/cfg-a'] },
    );
    await waitFor(() => expect(mockGet).toHaveBeenCalledWith('/v1/credential-templates/cfg-a'));
    await user.click(screen.getByRole('link', { name: 'Choose B' }));
    expect(await screen.findByText('Application B')).toBeInTheDocument();
    await act(async () => oldCredential.resolve({
      id: 'cfg-a', name: 'Credential A', credential_type: 'EmployeeCredential', application_template_id: 'tpl-a', claims: [],
    }));

    expect(mockGet).not.toHaveBeenCalledWith('/v1/application-templates/tpl-a');
    expect(screen.getByText('Application B')).toBeInTheDocument();
    expect(screen.queryByText('Credential A')).not.toBeInTheDocument();
  });

  it('keeps a current failed one-click request retryable', async () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {});
    mockCreateApplication.mockRejectedValueOnce(new Error('Create unavailable'));
    try {
      const { user } = render(<ApplicationForm />);
      await user.click(screen.getByRole('button', { name: 'Add to Wallet' }));
      expect(await screen.findByText('Create unavailable')).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Add to Wallet' })).toBeEnabled();
      await user.click(screen.getByRole('button', { name: 'Add to Wallet' }));

      expect(await screen.findByTestId('claim-credential-dialog')).toHaveTextContent('issued-1:openid-credential-offer://offer');
      expect(mockCreateApplication).toHaveBeenCalledTimes(2);
      expect(mockSubmitApplication).toHaveBeenCalledTimes(1);
      expect(mockGenerateIssuanceOffer).toHaveBeenCalledTimes(1);
    } finally {
      errors.mockRestore();
    }
  });

  it('does not submit or enroll biometrics after leaving during an evidence upload', async () => {
    mockLocationState.location.state.credential.credential_type = 'EmployeeCredential';
    mockLocationState.location.state.applicationTemplate = {
      id: 'app-template-1', credential_template_id: 'cfg-1', form_fields: [],
      evidence_requirements: [{ evidence_id: 'identity_scan', evidence_type: 'DOCUMENT_SCAN', description: 'Identity scan', required: true, accepted_formats: ['image/png'] }],
    };
    const evidence = deferred<any>();
    mockSubmitApplicationEvidence.mockReturnValueOnce(evidence.promise);
    const view = render(<ApplicationForm />);
    await view.user.upload(view.container.querySelector('input[type="file"]')!, new File(['identity'], 'identity.png', { type: 'image/png' }));
    await view.user.click(screen.getByTestId('next-step-btn'));
    await view.user.click(screen.getByTestId('accept-terms-checkbox'));
    await view.user.click(screen.getByTestId('submit-application-btn'));
    await waitFor(() => expect(mockSubmitApplicationEvidence).toHaveBeenCalledTimes(1));
    view.unmount();
    await act(async () => evidence.resolve({ id: 'evidence-1', status: 'ACTIVE' }));

    expect(mockSubmitApplication).not.toHaveBeenCalled();
    expect(mockEnrollBiometric).not.toHaveBeenCalled();
  });

  it('does not create a replacement request after leaving while duplicate withdrawal is pending', async () => {
    mockLocationState.location.state.credential.credential_type = 'EmployeeCredential';
    mockLocationState.location.state.applicationTemplate.form_fields = [];
    mockListApplications.mockResolvedValue({ items: [{ id: 'existing-application', credential_template_id: 'cfg-1', status: 'SUBMITTED' }] });
    const withdrawal = deferred<any>();
    mockSupersedeApplication.mockReturnValueOnce(withdrawal.promise);
    const view = render(<ApplicationForm />);
    await view.user.click(screen.getByTestId('accept-terms-checkbox'));
    await view.user.click(screen.getByTestId('submit-application-btn'));
    await view.user.click(await screen.findByRole('button', { name: 'Retire Previous and Submit' }));
    await waitFor(() => expect(mockSupersedeApplication).toHaveBeenCalledWith('existing-application', { reason: 'superseded_by_reapplication' }));

    view.unmount();
    await act(async () => withdrawal.resolve({ id: 'existing-application', status: 'WITHDRAWN' }));

    expect(mockCreateApplication).not.toHaveBeenCalled();
    expect(mockSubmitApplication).not.toHaveBeenCalled();
    expect(mockSubmitApplicationEvidence).not.toHaveBeenCalled();
    expect(mockEnrollBiometric).not.toHaveBeenCalled();
  });
});
