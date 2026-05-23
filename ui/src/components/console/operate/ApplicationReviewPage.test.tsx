import { describe, expect, it, vi, beforeEach } from 'vitest';
import { Route, Routes } from 'react-router-dom';
import { renderWithRouter, screen, waitFor } from '@test/utils';

import ApplicationReviewPage from './ApplicationReviewPage';

const mockGetApplication = vi.fn();
const mockGetApplicationEvidenceSummary = vi.fn();
const mockGetVettingChecks = vi.fn();
const mockRunEvidenceCheck = vi.fn();
const mockReviewOrganizationApplication = vi.fn();
const mockRequestApplicationInfo = vi.fn();
const mockAcquireReviewerLock = vi.fn();
const mockReleaseReviewerLock = vi.fn();
const mockListCredentialTemplates = vi.fn();

vi.mock('../../../hooks/useAuth', () => ({
  useAuth: () => ({
    user: {
      user_id: 'reviewer-1',
      name: 'Reviewer One',
      email: 'reviewer@example.test',
    },
  }),
}));

vi.mock('../../../services/applicantApi', () => ({
  getApplication: (...args) => mockGetApplication(...args),
  getApplicationEvidenceSummary: (...args) => mockGetApplicationEvidenceSummary(...args),
  getVettingChecks: (...args) => mockGetVettingChecks(...args),
  runApplicationExternalEvidenceApiCheck: (...args) => mockRunEvidenceCheck(...args),
  reviewOrganizationApplication: (...args) => mockReviewOrganizationApplication(...args),
  requestApplicationInfo: (...args) => mockRequestApplicationInfo(...args),
  acquireReviewerLock: (...args) => mockAcquireReviewerLock(...args),
  releaseReviewerLock: (...args) => mockReleaseReviewerLock(...args),
}));

vi.mock('../../../services/presentationPolicyApi', () => ({
  listCredentialTemplates: (...args) => mockListCredentialTemplates(...args),
}));

vi.mock('./IssuingSection', () => ({
  default: () => <div data-testid="issuing-section" />,
}));

vi.mock('./dialogs/ApproveDialog', () => ({
  default: () => null,
}));

vi.mock('./dialogs/RejectDialog', () => ({
  default: () => null,
}));

vi.mock('./dialogs/RequestInfoDialog', () => ({
  default: () => null,
}));

function renderPage() {
  return renderWithRouter(
    <Routes>
      <Route path="/console/org/operate/applications/:applicationId" element={<ApplicationReviewPage />} />
    </Routes>,
    { initialEntries: ['/console/org/operate/applications/app-1'] },
  );
}

describe('ApplicationReviewPage evidence policy controls', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetApplication.mockResolvedValue({
      id: 'app-1',
      applicant_id: 'applicant-1',
      applicant_email: 'ada@example.test',
      organization_id: 'org-1',
      credential_configuration_id: 'passport-credential',
      credential_display_name: 'Passport Credential',
      status: 'submitted',
      submitted_at: '2026-05-18T10:00:00Z',
      metadata: {},
    });
    mockGetVettingChecks.mockResolvedValue([]);
    mockGetApplicationEvidenceSummary.mockResolvedValue({
      application_id: 'app-1',
      organization_id: 'org-1',
      status: 'pending',
      evidence_facts: [],
      policy_decision: null,
      available_api_checks: [
        {
          check_id: 'passport-document-check',
          description: 'Passport document check',
          provider: 'passport_verifier',
          fact_type: 'passport.document_verified',
          auto_issue_on_permit: true,
        },
      ],
    });
    mockRunEvidenceCheck.mockResolvedValue({
      policy_decision: { allowed: true },
    });
    mockAcquireReviewerLock.mockResolvedValue({ locked: true, reviewer_id: 'reviewer-1' });
    mockReleaseReviewerLock.mockResolvedValue({});
    mockListCredentialTemplates.mockResolvedValue([]);
  });

  it('runs a configured external evidence API check from review', async () => {
    const { user } = renderPage();

    await user.click(await screen.findByRole('button', { name: /run passport document check/i }));

    await waitFor(() => {
      expect(mockRunEvidenceCheck).toHaveBeenCalledWith('app-1', 'passport-document-check', {
        issue_on_permit: true,
      });
    });
    expect(await screen.findByText(/policy permitted approval/i)).toBeInTheDocument();
  });
});
