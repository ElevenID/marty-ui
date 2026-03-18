import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@test/utils';

import WalletSetup from '../WalletSetup';

const {
  mockLoadWalletStatus,
  mockRegisterWalletPushNotifications,
} = vi.hoisted(() => ({
  mockLoadWalletStatus: vi.fn(),
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
    loadWalletStatus: (...args: unknown[]) => mockLoadWalletStatus(...args),
    registerWalletPushNotifications: (...args: unknown[]) => mockRegisterWalletPushNotifications(...args),
  };
});

describe('WalletSetup', () => {
  beforeEach(() => {
    // Fake timers prevent the countdown (setTimeout ×300) and polling
    // (setInterval 3 s) from keeping the test alive.
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.clearAllMocks();

    mockLoadWalletStatus.mockResolvedValue({
      walletConnected: true,
      walletDeviceId: 'device-1',
      nextStep: 1,
      successMessage: 'Wallet paired successfully!',
      error: null,
    });
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
    vi.useRealTimers();
  });

  it('loads wallet status through the application layer', async () => {
    render(<WalletSetup />);

    await waitFor(() => {
      expect(mockLoadWalletStatus).toHaveBeenCalledWith({
        userId: 'user-1',
        activeStep: 0,
      });
    });

    expect(await screen.findByTestId('wallet-setup-success')).toHaveTextContent('Wallet paired successfully!');
  });

  it('registers notifications through the application layer', async () => {
    render(<WalletSetup />);

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