import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen } from '@test/utils';

import { getVerificationFlowInstance, getVerificationResult } from '../../../../services/zkVerificationApi';
import QRDisplayStep, { isApprovedVerificationResult } from './QRDisplayStep';

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
    vi.mocked(getVerificationFlowInstance).mockResolvedValue({ status: 'COMPLETED' });
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
    vi.mocked(getVerificationFlowInstance).mockResolvedValue({ status: 'COMPLETED' });
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
    vi.mocked(getVerificationFlowInstance).mockResolvedValue({ status: 'COMPLETED' });
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
});
