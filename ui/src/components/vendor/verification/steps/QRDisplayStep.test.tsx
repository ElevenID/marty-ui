import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@test/utils';

import QRDisplayStep from './QRDisplayStep';

vi.mock('../../../../services/zkVerificationApi', () => ({
  getVerificationFlowInstance: vi.fn(),
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
