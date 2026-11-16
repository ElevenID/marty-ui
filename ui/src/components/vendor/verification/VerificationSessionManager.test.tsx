import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor, within } from '@test/utils';
import userEvent from '@testing-library/user-event';
import { openDeepLink } from '../../../utils/deviceDetection';

import VerificationSessionManager from './VerificationSessionManager';

const {
  mockListFlowExecutions,
  mockStartVerificationFlow,
  mockGetVerificationFlowResult,
  mockGetVerificationFlowInstance,
  mockListPublicIssuerIdentities,
  mockListPresentationPolicies,
  mockListFlows,
} = vi.hoisted(() => ({
  mockListFlowExecutions: vi.fn(),
  mockStartVerificationFlow: vi.fn(),
  mockGetVerificationFlowResult: vi.fn(),
  mockGetVerificationFlowInstance: vi.fn(),
  mockListPublicIssuerIdentities: vi.fn(),
  mockListPresentationPolicies: vi.fn(),
  mockListFlows: vi.fn(),
}));

vi.mock('../../../utils/deviceDetection', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../utils/deviceDetection')>(),
  openDeepLink: vi.fn().mockResolvedValue(true),
}));

vi.mock('../../../hooks/useNotifications', () => ({
  useNotifications: () => ({
    showSuccess: vi.fn(),
  }),
}));

vi.mock('../../../services/flowsApi', () => ({
  listFlowExecutions: (...args: unknown[]) => mockListFlowExecutions(...args),
  listFlows: (...args: unknown[]) => mockListFlows(...args),
}));

vi.mock('../../../services/zkVerificationApi', () => ({
  startVerificationFlow: (...args: unknown[]) => mockStartVerificationFlow(...args),
  getVerificationFlowResult: (...args: unknown[]) => mockGetVerificationFlowResult(...args),
  getVerificationResult: (...args: unknown[]) => mockGetVerificationFlowResult(...args),
  getVerificationFlowInstance: (...args: unknown[]) => mockGetVerificationFlowInstance(...args),
}));

vi.mock('../../../services/issuerIdentitiesApi', () => ({
  listPublicIssuerIdentities: (...args: unknown[]) => mockListPublicIssuerIdentities(...args),
}));

vi.mock('../../../services/presentationPolicyApi', () => ({
  listPresentationPolicies: (...args: unknown[]) => mockListPresentationPolicies(...args),
}));

describe('VerificationSessionManager', () => {
  afterEach(() => vi.useRealTimers());
  beforeEach(() => {
    vi.clearAllMocks();
    mockListFlowExecutions.mockResolvedValue([]);
    mockListPublicIssuerIdentities.mockResolvedValue({
      identities: [{
        issuer_did: 'did:web:verifier.example:oid4vp',
        key_purpose: 'oid4vp_request_signing',
        algorithm: 'ES256',
        status: 'active',
      }],
    });
    mockListPresentationPolicies.mockResolvedValue([]);
    mockListFlows.mockResolvedValue([]);
    mockGetVerificationFlowResult.mockReset();
    mockGetVerificationFlowInstance.mockReset();
  });

  it('pending details reuse polling for rejection and recovery without creating another session', async () => {
    mockListFlowExecutions.mockResolvedValue([{ id: 'pending-detail', flow_type: 'oid4vp_presentation', status: 'AWAITING_WALLET',
      context_data: { presentation_policy_id: 'policy-1', request_uri: 'openid4vp://authorize' } }]);
    mockGetVerificationFlowInstance.mockResolvedValueOnce({ id: 'pending-detail', status: 'AWAITING_WALLET',
      last_presentation_attempt: { schema_version: 1, instance_id: 'pending-detail', policy_id: 'policy-1', native_credential_count: 1,
        nonce_sha256: 'a'.repeat(64), submission_digest: 'b'.repeat(64), vp_token_sha256: 'c'.repeat(64),
        outcome: 'rejected', retryable: true, observed_at: '2026-10-26T12:00:00Z',
        authentication: { format: 'mso_mdoc', document_count: 1, document_type: 'org.iso.18013.5.1.mDL', issuer_signature_valid: true,
          certificate_trust_passed: false, device_authentication_valid: true, certificate_trust_failures: ['CERTIFICATE_CHAIN_REJECTED'],
          issuer_certificate_sha256: 'd'.repeat(64) } } })
      .mockResolvedValueOnce({ id: 'pending-detail', status: 'COMPLETED' });
    mockGetVerificationFlowResult.mockResolvedValue({ instance_id: 'pending-detail', status: 'COMPLETED', result: 'passed', decision: 'allow', verified_claims: {}, credential_results: [] });
    render(<VerificationSessionManager organizationId="org-1" />);
    const open = await screen.findByRole('button', { name: 'Show QR code' });
    vi.useFakeTimers();
    await act(async () => { open.click(); });
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    expect(screen.getByTestId('presentation-attempt-rejected')).toHaveTextContent('issuer certificate was not accepted');
    expect(screen.getByTestId('verification-session-status')).toHaveAttribute('data-status', 'pending');
    expect(screen.queryByTestId('verification-result-summary')).not.toBeInTheDocument();
    expect(mockStartVerificationFlow).not.toHaveBeenCalled();
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    expect(screen.queryByTestId('presentation-attempt-rejected')).not.toBeInTheDocument();
    expect(screen.getByTestId('verification-result-summary')).toHaveAttribute('data-verification-decision', 'allow');
    expect(mockStartVerificationFlow).not.toHaveBeenCalled();
  });

  it('lists OID4VP sessions from MIP flow instances', async () => {
    mockListFlowExecutions.mockResolvedValue([
      {
        id: 'flow-session-1',
        flow_type: 'oid4vp_presentation',
        status: 'AWAITING_WALLET',
        context_data: {
          qr_code_data: 'openid4vp://authorize?request_uri=https://example.test/request',
          request_uri: 'https://example.test/request',
        },
        created_at: '2026-05-26T20:00:00Z',
        updated_at: '2026-05-26T20:00:00Z',
      },
      {
        id: 'issuance-session-1',
        flow_type: 'oid4vci_pre_authorized',
        status: 'IN_PROGRESS',
        created_at: '2026-05-26T20:00:00Z',
        updated_at: '2026-05-26T20:00:00Z',
      },
    ]);

    render(<VerificationSessionManager organizationId="org-1" />);

    expect(await screen.findByRole('tab', { name: /active \(1\)/i })).toBeInTheDocument();
    expect(screen.getByText('Credential verification')).toBeInTheDocument();
    expect(mockListFlowExecutions).toHaveBeenCalledWith(null, { organization_id: 'org-1' });
  });

  it('surfaces current flow API errors instead of falling back to legacy verification sessions', async () => {
    mockListFlowExecutions.mockRejectedValue(new Error('Flow service unavailable'));

    render(<VerificationSessionManager organizationId="org-1" />);

    await waitFor(() => {
      expect(mockListFlowExecutions).toHaveBeenCalledWith(null, { organization_id: 'org-1' });
    });

    expect(await screen.findByRole('tab', { name: /active \(0\)/i })).toBeInTheDocument();
    expect(screen.getByText('Flow service unavailable')).toBeInTheDocument();
  });

  it('keeps cancelled verification instances out of the active queue', async () => {
    mockListFlowExecutions.mockResolvedValue([
      {
        id: 'cancelled-session-1',
        flow_type: 'oid4vp_presentation',
        status: 'CANCELLED',
        created_at: '2026-07-12T12:00:00Z',
        updated_at: '2026-07-12T12:05:00Z',
      },
    ]);

    render(<VerificationSessionManager organizationId="org-1" />);

    expect(await screen.findByRole('tab', { name: /active \(0\)/i })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /history \(1\)/i })).toBeInTheDocument();
  });

  it('loads actual terminal evidence before showing a historical result', async () => {
    const user = userEvent.setup();
    mockListFlowExecutions.mockResolvedValue([{
      id: 'verified-session-1', flow_type: 'oid4vp_presentation', status: 'COMPLETED',
      created_at: '2026-07-12T12:00:00Z', updated_at: '2026-07-12T12:05:00Z',
    }]);
    mockGetVerificationFlowResult.mockResolvedValue({
      instance_id: 'verified-session-1', status: 'COMPLETED', result: 'passed', decision: 'allow',
      verified_claims: { age_over_21: true }, credential_results: [{
        trust_check_passed: true, signature_valid: true,
        authenticated_disclosures: { format: 'mso_mdoc', documents: [{
          doc_type: 'org.iso.18013.5.1.mDL', namespaces: { 'org.iso.18013.5.1': ['age_over_21'] },
        }] },
      }],
    });
    render(<VerificationSessionManager organizationId="org-1" />);
    await user.click(await screen.findByRole('tab', { name: /history \(1\)/i }));
    await user.click(await screen.findByRole('button', { name: 'View session details' }));
    expect(mockGetVerificationFlowResult).toHaveBeenCalledWith('verified-session-1');
    expect(await screen.findByTestId('verification-result-summary')).toHaveAttribute(
      'data-disclosed-claim-names', '["age_over_21"]',
    );
  });

  it('does not infer a successful result from history status when evidence fails to load', async () => {
    const user = userEvent.setup();
    mockListFlowExecutions.mockResolvedValue([{
      id: 'unavailable-session-1', flow_type: 'oid4vp_presentation', status: 'COMPLETED',
      created_at: '2026-07-12T12:00:00Z', updated_at: '2026-07-12T12:05:00Z',
    }]);
    mockGetVerificationFlowResult.mockRejectedValue(new Error('Result unavailable'));
    render(<VerificationSessionManager organizationId="org-1" />);
    await user.click(await screen.findByRole('tab', { name: /history \(1\)/i }));
    await user.click(await screen.findByRole('button', { name: 'View session details' }));
    expect(await screen.findByText('Result unavailable')).toBeInTheDocument();
    expect(screen.queryByTestId('verification-result-summary')).not.toBeInTheDocument();
  });

  it('reopens a pending POST request with its canonical authorization URI intact', async () => {
    const user = userEvent.setup();
    const requestUri = 'https://verifier.example/v1/flows/instances/post-resume/request';
    const authorizationUri = `openid4vp://authorize?client_id=did%3Aweb%3Averifier.example&request_uri=${encodeURIComponent(requestUri)}&request_uri_method=post`;
    mockListFlowExecutions.mockResolvedValue([{ id: 'post-resume', flow_type: 'oid4vp_presentation', status: 'AWAITING_WALLET',
      context_data: { presentation_policy_id: 'policy-1', request_uri: requestUri, qr_code_data: authorizationUri } }]);
    render(<VerificationSessionManager organizationId="org-1" />);
    await user.click(await screen.findByRole('button', { name: 'Show QR code' }));
    expect(screen.getByRole('img', { name: 'OID4VP QR Code' })).toHaveAttribute('data-qr-value', authorizationUri);
    await user.click(await screen.findByRole('button', { name: 'Open Wallet' }));
    expect(openDeepLink).toHaveBeenCalledWith(authorizationUri);
    const opened = new URL(vi.mocked(openDeepLink).mock.calls.at(-1)![0]);
    expect(opened.searchParams.get('request_uri')).toBe(requestUri);
    expect(opened.searchParams.get('request_uri_method')).toBe('post');
    expect(opened.searchParams.get('client_id')).toBe('did:web:verifier.example');
    expect(mockStartVerificationFlow).not.toHaveBeenCalled();
  });

  it('generates the details QR code when the flow exposes only request_uri', async () => {
    const user = userEvent.setup();
    const requestUri = 'openid4vp://authorize?request_uri=https%3A%2F%2Fexample.test%2Frequest';
    mockListFlowExecutions.mockResolvedValue([
      {
        id: 'flow-session-request-only',
        flow_type: 'oid4vp_presentation',
        status: 'AWAITING_WALLET',
        context_data: { request_uri: requestUri },
        created_at: '2026-07-13T12:00:00Z',
        updated_at: '2026-07-13T12:00:00Z',
      },
    ]);

    render(<VerificationSessionManager organizationId="org-1" />);

    await user.click(await screen.findByRole('button', { name: 'Show QR code' }));

    expect(await screen.findByRole('img', { name: 'OID4VP QR Code' })).toHaveAttribute(
      'data-qr-value',
      requestUri,
    );
  });

  function completedSession() {
    return {
      id: 'age-session-1', organization_id: 'org-1', flow_type: 'oid4vp_presentation',
      status: 'COMPLETED', created_at: '2026-10-20T12:00:00Z', updated_at: '2026-10-20T12:01:00Z',
    };
  }

  function measuredResult() {
    return {
      instance_id: 'age-session-1', status: 'COMPLETED', result: 'passed', decision: 'allow',
      verified_claims: { age_over_21: true }, credential_results: [{
        credential_template_id: 'mdl-template-1', signature_valid: true, trust_check_passed: true,
        authenticated_disclosures: { format: 'mso_mdoc', documents: [{
          doc_type: 'org.iso.18013.5.1.mDL', namespaces: { 'org.iso.18013.5.1': ['age_over_21'] },
        }] },
      }],
    };
  }

  async function openCompletedDetail() {
    const user = userEvent.setup();
    mockListFlowExecutions.mockResolvedValue([completedSession()]);
    render(<VerificationSessionManager organizationId="org-1" />);
    await user.click(await screen.findByRole('tab', { name: /history \(1\)/i }));
    await user.click(screen.getByRole('button', { name: 'View session details' }));
    return user;
  }

  it('loads the exact terminal result before showing authenticated disclosure evidence', async () => {
    mockGetVerificationFlowResult.mockResolvedValue(measuredResult());
    await openCompletedDetail();

    expect(mockGetVerificationFlowResult).toHaveBeenCalledWith('age-session-1');
    const summary = await screen.findByTestId('verification-result-summary');
    expect(summary).toHaveAttribute('data-disclosed-claim-names', '["age_over_21"]');
    expect(summary).toHaveAttribute('data-verification-instance-id', 'age-session-1');
    expect(summary).toHaveAttribute('data-credential-template-id', 'mdl-template-1');
    expect(summary).toHaveAttribute('data-issuer-trusted', 'true');
  });

  it.each(['foreign result', 'unavailable result'])('does not derive disclosure evidence from status after %s', async (failure) => {
    if (failure === 'foreign result') {
      mockGetVerificationFlowResult.mockResolvedValue({ ...measuredResult(), instance_id: 'other-session' });
    } else {
      mockGetVerificationFlowResult.mockRejectedValue(new Error('Result service unavailable'));
    }
    await openCompletedDetail();

    expect(await screen.findByRole('alert')).toHaveTextContent(
      failure === 'foreign result' ? 'different session' : 'Result service unavailable',
    );
    expect(screen.queryByTestId('verification-result-summary')).not.toBeInTheDocument();
  });

  it('does not reopen or repopulate details when a closed result request finishes', async () => {
    let resolveResult: (result: ReturnType<typeof measuredResult>) => void = () => {};
    mockGetVerificationFlowResult.mockReturnValue(new Promise((resolve) => { resolveResult = resolve; }));
    const user = await openCompletedDetail();
    expect(screen.getByLabelText('Loading verification result')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Close' }));
    await act(async () => { resolveResult(measuredResult()); });

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(screen.queryByTestId('verification-result-summary')).not.toBeInTheDocument();
  });

  it('starts verification with the organization issuer DID and no public profile ID', async () => {
    const user = userEvent.setup();
    mockListPresentationPolicies.mockResolvedValue([
      { id: 'policy-1', name: 'Employment proof', status: 'active' },
    ]);
    mockStartVerificationFlow.mockResolvedValue({
      instance_id: 'flow-1',
      request_uri: 'openid4vp://authorize?request_uri=https%3A%2F%2Fexample.test%2Frequest',
      status: 'AWAITING_WALLET',
    });

    render(<VerificationSessionManager organizationId="org-1" />);

    const newVerification = await screen.findByRole('button', { name: 'New Verification' });
    await waitFor(() => expect(newVerification).toBeEnabled());
    expect(mockListPublicIssuerIdentities).toHaveBeenCalledWith({
      organization_id: 'org-1',
      key_purpose: 'oid4vp_request_signing',
      algorithm: 'ES256',
    });
    await user.click(newVerification);
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
    expect(screen.queryByRole('switch', { name: /ad-hoc/i })).not.toBeInTheDocument();
    await user.click(await screen.findByLabelText('Presentation Policy'));
    await user.click(await screen.findByRole('option', { name: 'Employment proof' }));
    await user.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.queryByRole('switch', { name: /inspection/i })).not.toBeInTheDocument();
    expect(screen.queryByText(/InspectionSystem|deep document inspection/i)).not.toBeInTheDocument();
    await user.type(screen.getByLabelText('Verification Purpose'), 'Employment review');
    await user.click(screen.getByRole('button', { name: 'Start Session' }));

    await waitFor(() => {
      expect(mockStartVerificationFlow).toHaveBeenCalledWith({
        organization_id: 'org-1',
        issuer_did: 'did:web:verifier.example:oid4vp',
        presentation_policy_id: 'policy-1',
        trust_profile_id: undefined,
        deployment_profile_id: undefined,
        external_reference: 'Employment review',
      });
    });
    expect(mockStartVerificationFlow.mock.calls[0][0]).not.toHaveProperty('issuer_profile_id');
    expect(mockStartVerificationFlow.mock.calls[0][0]).not.toHaveProperty('inline_policy');
    expect(mockStartVerificationFlow.mock.calls[0][0]).not.toHaveProperty('request_inspection');
  });

  it('selects among multiple public issuer DIDs without exposing profile coordinates', async () => {
    const user = userEvent.setup();
    mockListPublicIssuerIdentities.mockResolvedValue({
      identities: [
        {
          issuer_did: 'did:web:verifier.example:standard',
          key_purpose: 'oid4vp_request_signing',
          algorithm: 'ES256',
          status: 'active',
        },
        {
          issuer_did: 'did:web:verifier.example:haip',
          key_purpose: 'oid4vp_request_signing',
          algorithm: 'ES256',
          status: 'active',
        },
      ],
    });
    mockListPresentationPolicies.mockResolvedValue([
      { id: 'policy-1', name: 'Employment proof', status: 'active' },
    ]);
    mockStartVerificationFlow.mockResolvedValue({
      instance_id: 'flow-1',
      request_uri: 'openid4vp://authorize?request_uri=https%3A%2F%2Fexample.test%2Frequest',
      status: 'AWAITING_WALLET',
    });

    render(<VerificationSessionManager organizationId="org-1" />);

    const newVerification = await screen.findByRole('button', { name: 'New Verification' });
    await waitFor(() => expect(newVerification).toBeEnabled());
    await user.click(newVerification);
    await user.click(await screen.findByLabelText('Presentation Policy'));
    await user.click(await screen.findByRole('option', { name: 'Employment proof' }));
    const next = screen.getByRole('button', { name: 'Next' });
    await waitFor(() => expect(next).toBeEnabled());
    await user.click(next);
    await screen.findByLabelText('Verification Purpose');
    await user.click(await screen.findByRole('combobox', { name: /Issuer DID/ }));
    await user.click(await screen.findByRole('option', { name: 'did:web:verifier.example:haip' }));
    await user.click(screen.getByRole('button', { name: 'Start Session' }));

    await waitFor(() => {
      expect(mockStartVerificationFlow).toHaveBeenCalledWith(expect.objectContaining({
        organization_id: 'org-1',
        issuer_did: 'did:web:verifier.example:haip',
      }));
    });
    const request = mockStartVerificationFlow.mock.calls[0][0];
    expect(request).not.toHaveProperty('issuer_profile_id');
    expect(request).not.toHaveProperty('signing_service_id');
    expect(request).not.toHaveProperty('signing_key_reference');
  });

  it('keeps Next disabled with a setup action when no active policy can start a session', async () => {
    const user = userEvent.setup();
    render(<VerificationSessionManager organizationId="org-1" />);
    const newVerification = await screen.findByRole('button', { name: 'New Verification' });
    await waitFor(() => expect(newVerification).toBeEnabled());
    await user.click(newVerification);

    expect(await screen.findByText('No active presentation policies')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Manage Presentation Policies' })).toHaveAttribute('href', '/console/org/policies/presentation');
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
    expect(screen.queryByRole('switch', { name: /ad-hoc/i })).not.toBeInTheDocument();
    expect(mockStartVerificationFlow).not.toHaveBeenCalled();
  });

  it('blocks a previously selected policy after a reload error and permits retry recovery', async () => {
    const user = userEvent.setup();
    mockListPresentationPolicies.mockResolvedValue([{ id: 'policy-1', name: 'Employment proof', status: 'active' }]);
    render(<VerificationSessionManager organizationId="org-1" />);
    const newVerification = await screen.findByRole('button', { name: 'New Verification' });
    await waitFor(() => expect(newVerification).toBeEnabled());
    await user.click(newVerification);
    await user.click(await screen.findByLabelText('Presentation Policy'));
    await user.click(await screen.findByRole('option', { name: 'Employment proof' }));
    await user.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByRole('button', { name: 'Start Session' })).toBeEnabled();

    mockListPresentationPolicies.mockRejectedValueOnce(new Error('Policy service unavailable'));
    await user.click(screen.getByRole('button', { name: 'Back' }));
    expect(await screen.findByText('Policy service unavailable')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
    expect(screen.queryByText('No active presentation policies')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(screen.getByRole('button', { name: 'Next' })).toBeEnabled());
    expect(mockStartVerificationFlow).not.toHaveBeenCalled();
  });

  it('closes and resets the configured wizard when the active organization changes', async () => {
    const user = userEvent.setup();
    mockListPresentationPolicies.mockResolvedValue([{ id: 'policy-1', name: 'Employment proof', status: 'active' }]);
    const { rerender } = render(<VerificationSessionManager organizationId="org-1" />);
    const newVerification = await screen.findByRole('button', { name: 'New Verification' });
    await waitFor(() => expect(newVerification).toBeEnabled());
    await user.click(newVerification);
    await user.click(await screen.findByLabelText('Presentation Policy'));
    await user.click(await screen.findByRole('option', { name: 'Employment proof' }));
    await user.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getByRole('button', { name: 'Start Session' })).toBeEnabled();

    mockListPresentationPolicies.mockResolvedValue([]);
    rerender(<VerificationSessionManager organizationId="org-2" />);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await waitFor(() => expect(screen.getByRole('button', { name: 'New Verification' })).toBeEnabled());
    await user.click(screen.getByRole('button', { name: 'New Verification' }));
    expect(await screen.findByText('No active presentation policies')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Next' })).toBeDisabled();
    expect(mockListPresentationPolicies).toHaveBeenLastCalledWith({ organization_id: 'org-2', limit: 100, offset: 0 });
    expect(mockStartVerificationFlow).not.toHaveBeenCalled();
  });

  it('ignores a session creation result from the previous organization', async () => {
    const user = userEvent.setup();
    let resolveSession!: (session: unknown) => void;
    mockStartVerificationFlow.mockReturnValueOnce(new Promise((resolve) => { resolveSession = resolve; }));
    mockListPresentationPolicies.mockResolvedValue([{ id: 'policy-1', name: 'Employment proof', status: 'active' }]);
    const { rerender } = render(<VerificationSessionManager organizationId="org-1" />);
    const newVerification = await screen.findByRole('button', { name: 'New Verification' });
    await waitFor(() => expect(newVerification).toBeEnabled());
    await user.click(newVerification);
    await user.click(await screen.findByLabelText('Presentation Policy'));
    await user.click(await screen.findByRole('option', { name: 'Employment proof' }));
    await user.click(screen.getByRole('button', { name: 'Next' }));
    await user.click(screen.getByRole('button', { name: 'Start Session' }));
    expect(mockStartVerificationFlow).toHaveBeenCalledOnce();

    rerender(<VerificationSessionManager organizationId="org-2" />);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    await act(async () => {
      resolveSession({ instance_id: 'old-org-session', request_uri: 'openid4vp://authorize', status: 'AWAITING_WALLET' });
    });
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.queryByRole('img', { name: 'OID4VP QR Code' })).not.toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('button', { name: 'New Verification' })).toBeEnabled());
    await user.click(screen.getByRole('button', { name: 'New Verification' }));
    expect(await screen.findByRole('button', { name: 'Next' })).toBeDisabled();
    expect(screen.queryByRole('button', { name: 'Done' })).not.toBeInTheDocument();
  });

  it('can reopen after closing during creation without a late result replacing the new wizard', async () => {
    const user = userEvent.setup();
    let resolveSession!: (session: unknown) => void;
    mockStartVerificationFlow.mockReturnValueOnce(new Promise((resolve) => { resolveSession = resolve; }));
    mockListPresentationPolicies.mockResolvedValue([{ id: 'policy-1', name: 'Employment proof', status: 'active' }]);
    render(<VerificationSessionManager organizationId="org-1" />);
    const newVerification = await screen.findByRole('button', { name: 'New Verification' });
    await waitFor(() => expect(newVerification).toBeEnabled());
    await user.click(newVerification);
    await user.click(await screen.findByLabelText('Presentation Policy'));
    await user.click(await screen.findByRole('option', { name: 'Employment proof' }));
    await waitFor(() => expect(screen.queryByRole('listbox', { hidden: true })).not.toBeInTheDocument());
    await user.click(screen.getByRole('button', { name: 'Next' }));
    await user.click(screen.getByRole('button', { name: 'Start Session' }));
    expect(mockStartVerificationFlow).toHaveBeenCalledOnce();
    await user.click(screen.getByLabelText('Verification Purpose'));
    await user.keyboard('{Escape}');
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());

    await user.click(screen.getByRole('button', { name: 'New Verification' }));
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeEnabled();
    await user.click(await screen.findByLabelText('Presentation Policy'));
    await user.click(await screen.findByRole('option', { name: 'Employment proof' }));
    expect(screen.getByRole('button', { name: 'Next' })).toBeEnabled();
    await act(async () => {
      resolveSession({ instance_id: 'old-wizard-session', request_uri: 'openid4vp://authorize', status: 'AWAITING_WALLET' });
    });
    expect(screen.getByRole('button', { name: 'Next' })).toBeEnabled();
    expect(screen.queryByRole('img', { name: 'OID4VP QR Code' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Done' })).not.toBeInTheDocument();
  });

  it('ignores old organization issuer identities before opening the new organization wizard', async () => {
    const user = userEvent.setup();
    let resolveOldIdentities!: (identities: unknown) => void;
    mockListPublicIssuerIdentities
      .mockReturnValueOnce(new Promise((resolve) => { resolveOldIdentities = resolve; }))
      .mockResolvedValueOnce({ identities: [{ issuer_did: 'did:web:org-2.example', status: 'active' }] });
    mockListPresentationPolicies.mockResolvedValue([{ id: 'policy-2', name: 'Org 2 Policy', status: 'active' }]);
    mockStartVerificationFlow.mockResolvedValue({ instance_id: 'org-2-session', request_uri: 'openid4vp://authorize', status: 'AWAITING_WALLET' });
    const { rerender } = render(<VerificationSessionManager organizationId="org-1" />);
    expect(screen.getByRole('button', { name: 'New Verification' })).toBeDisabled();
    rerender(<VerificationSessionManager organizationId="org-2" />);
    await waitFor(() => expect(screen.getByRole('button', { name: 'New Verification' })).toBeEnabled());
    await act(async () => {
      resolveOldIdentities({ identities: [{ issuer_did: 'did:web:org-1.example', status: 'active' }] });
    });

    await user.click(screen.getByRole('button', { name: 'New Verification' }));
    await user.click(await screen.findByLabelText('Presentation Policy'));
    await user.click(await screen.findByRole('option', { name: 'Org 2 Policy' }));
    await user.click(screen.getByRole('button', { name: 'Next' }));
    await user.click(screen.getByRole('button', { name: 'Start Session' }));
    expect(mockStartVerificationFlow).toHaveBeenCalledWith(expect.objectContaining({
      organization_id: 'org-2', issuer_did: 'did:web:org-2.example', presentation_policy_id: 'policy-2',
    }));
  });

  it.each(['success', 'failure'])('ignores a prior organization session-list %s while the current list is loading', async (outcome) => {
    let resolveOld!: (sessions: unknown[]) => void;
    let rejectOld!: (error: Error) => void;
    let resolveCurrent!: (sessions: unknown[]) => void;
    mockListFlowExecutions
      .mockReturnValueOnce(new Promise((resolve, reject) => { resolveOld = resolve; rejectOld = reject; }))
      .mockReturnValueOnce(new Promise((resolve) => { resolveCurrent = resolve; }));
    const { rerender } = render(<VerificationSessionManager organizationId="org-1" />);
    rerender(<VerificationSessionManager organizationId="org-2" />);
    await act(async () => {
      if (outcome === 'success') {
        resolveOld([{ id: 'old-session', flow_type: 'oid4vp', status: 'AWAITING_WALLET', purpose: 'Old organization session' }]);
      } else {
        rejectOld(new Error('Old organization unavailable'));
      }
    });
    expect(screen.getByRole('progressbar')).toBeInTheDocument();
    expect(screen.queryByText('Old organization session')).not.toBeInTheDocument();
    expect(screen.queryByText('Old organization unavailable')).not.toBeInTheDocument();

    await act(async () => {
      resolveCurrent([{ id: 'current-session', flow_type: 'oid4vp', status: 'AWAITING_WALLET', purpose: 'Current organization session' }]);
    });
    expect(await screen.findByText('Current organization session')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Active (1)' })).toBeInTheDocument();
    expect(mockListFlowExecutions).toHaveBeenLastCalledWith(null, { organization_id: 'org-2' });
  });

  it('clears the prior organization list and preserves manual refresh for the new organization', async () => {
    const user = userEvent.setup();
    let resolveCurrent!: (sessions: unknown[]) => void;
    mockListFlowExecutions
      .mockResolvedValueOnce([{ id: 'old-session', flow_type: 'oid4vp', status: 'AWAITING_WALLET', purpose: 'Old organization session' }])
      .mockReturnValueOnce(new Promise((resolve) => { resolveCurrent = resolve; }))
      .mockResolvedValueOnce([{ id: 'refreshed-session', flow_type: 'oid4vp', status: 'AWAITING_WALLET', purpose: 'Refreshed current session' }]);
    const { rerender } = render(<VerificationSessionManager organizationId="org-1" />);
    expect(await screen.findByText('Old organization session')).toBeInTheDocument();
    rerender(<VerificationSessionManager organizationId="org-2" />);
    expect(screen.queryByText('Old organization session')).not.toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Active (0)' })).toBeInTheDocument();
    await act(async () => { resolveCurrent([]); });
    await user.click(within(screen.getByLabelText('Refresh')).getByRole('button'));
    expect(await screen.findByText('Refreshed current session')).toBeInTheDocument();
    expect(mockListFlowExecutions).toHaveBeenCalledTimes(3);
    expect(mockListFlowExecutions).toHaveBeenLastCalledWith(null, { organization_id: 'org-2' });
    expect(screen.queryByText('Old organization session')).not.toBeInTheDocument();
  });
});
