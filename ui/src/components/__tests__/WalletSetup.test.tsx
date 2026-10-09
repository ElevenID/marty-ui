import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@test/utils';

import WalletSetup from '../WalletSetup';

const {
  mockIssueRemotePairingTicket,
  mockLoadRemotePairingStatus,
  mockRegisterWalletPushNotifications,
} = vi.hoisted(() => ({
  mockIssueRemotePairingTicket: vi.fn(),
  mockLoadRemotePairingStatus: vi.fn(),
  mockRegisterWalletPushNotifications: vi.fn(),
}));

// Stable references — prevent useCallback identity churn
const MOCK_AUTH = { user: { user_id: 'user-1' }, organizationId: 'org-1' };
const MOCK_BRANDING = { authenticatorName: 'Demo Authenticator', deepLinkProtocol: 'marty-auth:' };

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => MOCK_AUTH,
}));

vi.mock('../../hooks/useBranding', () => ({
  useBranding: () => MOCK_BRANDING,
}));

vi.mock('../../application/wallet', async () => {
  const actual = await vi.importActual<typeof import('../../application/wallet')>('../../application/wallet');
  return {
    ...actual,
    issueRemotePairingTicket: (...args: unknown[]) => mockIssueRemotePairingTicket(...args),
    loadRemotePairingStatus: (...args: unknown[]) => mockLoadRemotePairingStatus(...args),
    registerWalletPushNotifications: (...args: unknown[]) => mockRegisterWalletPushNotifications(...args),
  };
});

describe('WalletSetup', () => {
  beforeEach(() => {
    vi.stubEnv('VITE_API_URL', 'https://wallet.example');
    // Fake timers prevent the countdown (setTimeout ×300) and polling
    // (setInterval 3 s) from keeping the test alive.
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.clearAllMocks();

    mockIssueRemotePairingTicket.mockResolvedValue({
      pairing_code: 'A'.repeat(43),
      pairing_id: '11111111-2222-4333-8444-555555555555',
      expires_at: new Date(Date.now() + 300000).toISOString(),
    });
    mockLoadRemotePairingStatus.mockResolvedValue({ state: 'pending', registration_id: null });
    mockRegisterWalletPushNotifications.mockResolvedValue({
      deviceId: 'device-1',
      error: null,
    });

    Object.defineProperty(window, 'Notification', {
      configurable: true,
      value: {
        permission: 'default',
        requestPermission: vi.fn().mockResolvedValue('granted'),
      },
    });
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.useRealTimers();
  });

  it('issues an exact server ticket without claiming a previously registered device is paired', async () => {
    render(<WalletSetup />);

    await waitFor(() => {
      expect(mockIssueRemotePairingTicket).toHaveBeenCalledWith({ organizationId: 'org-1' });
    });

    expect(screen.queryByTestId('simulate-pairing-button')).not.toBeInTheDocument();
    expect(screen.queryByTestId('wallet-connected-alert')).not.toBeInTheDocument();
  });

  it('registers notifications through the application layer', async () => {
    mockLoadRemotePairingStatus.mockResolvedValue({ state: 'paired', registration_id: 'registration-1' });
    render(<WalletSetup />);

    await waitFor(() => expect(mockIssueRemotePairingTicket).toHaveBeenCalled());
    await vi.advanceTimersByTimeAsync(3000);
    await waitFor(() => expect(mockLoadRemotePairingStatus).toHaveBeenCalledWith({ pairingId: '11111111-2222-4333-8444-555555555555' }));

    // Wait for initial load to settle (activeStep → 1 = notifications step)
    const btn = await screen.findByTestId('enable-notifications-button');
    fireEvent.click(btn);

    await waitFor(() => {
      expect(mockRegisterWalletPushNotifications).toHaveBeenCalledWith({
        userId: 'user-1',
        organizationId: 'org-1',
        storage: window.localStorage,
      });
    });
  });
});
