import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen } from '@test/utils';

import { getVerificationFlowInstance, getVerificationResult } from '../../../../services/zkVerificationApi';
import QRDisplayStep, { isApprovedVerificationResult } from './QRDisplayStep';
import { runOpenId4VpDigitalCredentialFlow, supportsDigitalCredentials } from '../../../../services/digitalCredentialsApi';

vi.mock('../../../../services/zkVerificationApi', () => ({
  getVerificationFlowInstance: vi.fn(),
  getVerificationResult: vi.fn(),
}));

vi.mock('../../../../services/digitalCredentialsApi', () => ({
  DEFAULT_DC_API_PROTOCOL: 'openid4vp-v1-signed',
  formatDigitalCredentialError: (error: Error) => error.message,
  runOpenId4VpDigitalCredentialFlow: vi.fn(),
  supportsDigitalCredentials: vi.fn().mockResolvedValue(false),
}));

vi.mock('../../../../services/walletTransportService', () => ({
  createPresentationTransport: () => ({ openUri: 'openid4vp://authorize' }),
}));

vi.mock('../../../../utils/deviceDetection', () => ({
  openDeepLink: vi.fn(),
}));

describe('QRDisplayStep', () => {
  const rejectedAttempt = (instanceId = 'instance-retry') => ({
    schema_version: 1, instance_id: instanceId, policy_id: 'policy-1', native_credential_count: 1,
    nonce_sha256: 'a'.repeat(64), submission_digest: 'b'.repeat(64), vp_token_sha256: 'c'.repeat(64),
    outcome: 'rejected', retryable: true, observed_at: '2026-10-26T12:00:00Z',
    authentication: { format: 'mso_mdoc', document_count: 1, document_type: 'org.iso.18013.5.1.mDL',
      issuer_signature_valid: true, certificate_trust_passed: false, device_authentication_valid: true,
      certificate_trust_failures: ['CERTIFICATE_CHAIN_REJECTED'], issuer_certificate_sha256: 'd'.repeat(64) },
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  it('requires an explicit terminal allow and passed result', () => {
    expect(isApprovedVerificationResult({ status: 'COMPLETED', result: 'passed', decision: 'allow' })).toBe(true);
    expect(isApprovedVerificationResult({ status: 'COMPLETED', result: 'passed', decision: 'deny' })).toBe(false);
    expect(isApprovedVerificationResult({ status: 'COMPLETED' })).toBe(false);
  });

  it('reads the terminal result endpoint before claiming success', async () => {
    vi.useFakeTimers();
    vi.mocked(getVerificationFlowInstance).mockResolvedValue({ id: 'instance-verified', status: 'COMPLETED' });
    vi.mocked(getVerificationResult).mockResolvedValue({
      instance_id: 'instance-verified', status: 'COMPLETED', result: 'passed', decision: 'allow',
      verified_claims: { age_over_21: true }, credential_results: [{ trust_check_passed: true }],
    });
    render(<QRDisplayStep session={{ instance_id: 'instance-verified', status: 'AWAITING_WALLET' }} />);
    expect(screen.queryByText('Verification successful.')).not.toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    expect(getVerificationResult).toHaveBeenCalledWith('instance-verified');
    expect(screen.getByText('Verification successful.')).toBeInTheDocument();
  });

  it('does not call a completed session verified when the policy denied it', async () => {
    vi.useFakeTimers();
    vi.mocked(getVerificationFlowInstance).mockResolvedValue({ id: 'instance-denied', status: 'COMPLETED' });
    vi.mocked(getVerificationResult).mockResolvedValue({
      instance_id: 'instance-denied', status: 'FAILED', result: 'failed', decision: 'deny',
      decision_reason: 'Issuer not trusted', verified_claims: {}, credential_results: [],
    });
    render(<QRDisplayStep session={{ instance_id: 'instance-denied', status: 'AWAITING_WALLET' }} />);
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    expect(screen.getByText('Issuer not trusted')).toBeInTheDocument();
    expect(screen.queryByText('Verification successful.')).not.toBeInTheDocument();
  });

  it('fails closed when terminal evidence cannot be read', async () => {
    vi.useFakeTimers();
    vi.mocked(getVerificationFlowInstance).mockResolvedValue({ id: 'instance-unavailable', status: 'COMPLETED' });
    vi.mocked(getVerificationResult).mockRejectedValue(new Error('Result unavailable'));
    render(<QRDisplayStep session={{ instance_id: 'instance-unavailable', status: 'AWAITING_WALLET' }} />);
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    expect(screen.getAllByText('Result unavailable').length).toBeGreaterThan(0);
    expect(screen.queryByText('Verification successful.')).not.toBeInTheDocument();
  });
  it('renders the canonical QR payload as a generated SVG', () => {
    const qrValue = 'openid4vp://authorize?request_uri=https%3A%2F%2Fexample.test%2Frequest';

    render(
      <QRDisplayStep
        session={{ instance_id: 'instance-1', status: 'AWAITING_WALLET', qr_code_data: qrValue }}
      />,
    );

    const qrCode = screen.getByRole('img', { name: 'OID4VP QR Code' });
    expect(qrCode).toHaveAttribute('data-qr-value', qrValue);
    expect(qrCode.querySelector('svg')).toBeInTheDocument();
    expect(screen.queryByText(/did not return a wallet request/i)).not.toBeInTheDocument();
  });

  it('uses request_uri when qr_code_data is absent', () => {
    const requestUri = 'openid4vp://authorize?request_uri=https%3A%2F%2Fexample.test%2Frequest';

    render(
      <QRDisplayStep
        session={{ instance_id: 'instance-2', status: 'AWAITING_WALLET', request_uri: requestUri }}
      />,
    );

    expect(screen.getByRole('img', { name: 'OID4VP QR Code' })).toHaveAttribute(
      'data-qr-value',
      requestUri,
    );
  });

  it('shows a recoverable contract error when no wallet request is returned', () => {
    render(
      <QRDisplayStep session={{ instance_id: 'instance-3', status: 'AWAITING_WALLET' }} />,
    );

    expect(screen.getByText(/did not return a wallet request/i)).toBeInTheDocument();
    expect(screen.queryByRole('img', { name: 'OID4VP QR Code' })).not.toBeInTheDocument();
  });

  it('keeps a rejected attempt pending and polling, clears absent evidence, then recovers from measured allow', async () => {
    vi.useFakeTimers();
    const onComplete = vi.fn();
    vi.mocked(getVerificationFlowInstance)
      .mockResolvedValueOnce({ id: 'instance-retry', status: 'AWAITING_WALLET', last_presentation_attempt: rejectedAttempt(), error_codes: ['SignatureInvalid'] })
      .mockResolvedValueOnce({ id: 'instance-retry', status: 'AWAITING_WALLET', last_presentation_attempt: null })
      .mockResolvedValueOnce({ id: 'instance-retry', status: 'COMPLETED' });
    vi.mocked(getVerificationResult).mockResolvedValue({ instance_id: 'instance-retry', status: 'COMPLETED', result: 'passed', decision: 'allow', verified_claims: {} });
    render(<QRDisplayStep session={{ instance_id: 'instance-retry', presentation_policy_id: 'policy-1', status: 'AWAITING_WALLET', request_uri: 'openid4vp://authorize' }} onComplete={onComplete} />);
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    expect(screen.getByTestId('presentation-attempt-rejected')).toHaveTextContent('issuer certificate was not accepted');
    expect(screen.getByTestId('verification-session-status')).toHaveAttribute('data-status', 'pending');
    expect(screen.getByRole('button', { name: 'Open Wallet' })).toBeEnabled();
    expect(screen.getByRole('img', { name: 'OID4VP QR Code' })).toBeInTheDocument();
    expect(screen.queryByTestId('verification-result-summary')).not.toBeInTheDocument();
    expect(screen.queryByText('SignatureInvalid')).not.toBeInTheDocument();
    expect(onComplete).not.toHaveBeenCalled();
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    expect(screen.queryByTestId('presentation-attempt-rejected')).not.toBeInTheDocument();
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    expect(screen.getByText('Verification successful.')).toBeInTheDocument();
    expect(screen.queryByTestId('presentation-attempt-rejected')).not.toBeInTheDocument();
    expect(onComplete).toHaveBeenCalledTimes(1);
  });

  it('ignores wrong-session and malformed attempts and resets feedback on a new session', async () => {
    vi.useFakeTimers();
    const session = { instance_id: 'instance-retry', presentation_policy_id: 'policy-1', status: 'AWAITING_WALLET' };
    vi.mocked(getVerificationFlowInstance)
      .mockResolvedValueOnce({ id: 'other-session', status: 'AWAITING_WALLET', last_presentation_attempt: rejectedAttempt('other-session') })
      .mockResolvedValueOnce({ id: 'instance-retry', status: 'AWAITING_WALLET', last_presentation_attempt: { ...rejectedAttempt(), policy_id: 'other-policy' } })
      .mockResolvedValueOnce({ id: 'instance-retry', status: 'AWAITING_WALLET', last_presentation_attempt: rejectedAttempt() });
    const view = render(<QRDisplayStep session={session} />);
    for (let i = 0; i < 2; i += 1) {
      await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
      expect(screen.queryByTestId('presentation-attempt-rejected')).not.toBeInTheDocument();
    }
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    expect(screen.getByTestId('presentation-attempt-rejected')).toBeInTheDocument();
    view.rerender(<QRDisplayStep session={{ ...session, instance_id: 'new-session' }} />);
    expect(screen.queryByTestId('presentation-attempt-rejected')).not.toBeInTheDocument();
    expect(screen.getByTestId('verification-session-status')).toHaveAttribute('data-status', 'pending');
  });

  it('correlates legacy session_id and ignores deferred wallet completion after session replacement or unmount', async () => {
    vi.mocked(supportsDigitalCredentials).mockResolvedValue(true);
    let first: (value: unknown) => void = () => {};
    let second: (value: unknown) => void = () => {};
    vi.mocked(runOpenId4VpDigitalCredentialFlow)
      .mockReturnValueOnce(new Promise((resolve) => { first = resolve; }))
      .mockReturnValueOnce(new Promise((resolve) => { second = resolve; }));
    const onComplete = vi.fn();
    const session = { session_id: 'old-session', status: 'AWAITING_WALLET', request_uri: 'openid4vp://authorize', presentation_policy_id: 'policy-1' };
    const view = render(<QRDisplayStep session={session} onComplete={onComplete} />);
    await act(async () => { await Promise.resolve(); });
    await act(async () => { screen.getByRole('button', { name: 'Open Wallet Chooser' }).click(); });
    expect(runOpenId4VpDigitalCredentialFlow).toHaveBeenCalledWith(expect.objectContaining({ submitUrl: '/v1/flows/instances/old-session/submit/dc-api' }));
    view.rerender(<QRDisplayStep session={{ ...session, session_id: 'new-session' }} onComplete={onComplete} />);
    await act(async () => { first({ status: 'COMPLETED' }); });
    expect(onComplete).not.toHaveBeenCalled();
    expect(getVerificationResult).not.toHaveBeenCalled();
    await act(async () => { screen.getByRole('button', { name: 'Open Wallet Chooser' }).click(); });
    view.unmount();
    await act(async () => { second({ status: 'COMPLETED' }); });
    expect(onComplete).not.toHaveBeenCalled();
    expect(getVerificationResult).not.toHaveBeenCalled();
    vi.mocked(supportsDigitalCredentials).mockResolvedValue(false);
  });
});
