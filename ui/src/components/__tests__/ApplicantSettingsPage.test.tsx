import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@test/utils';

import ApplicantSettingsPage from '../console/applicant/ApplicantSettingsPage.jsx';

const {
  mockGetApplicantByUser,
  mockCreateApplicant,
  mockUpdateApplicantProfile,
  mockListWallets,
  mockWalletPreferenceState,
  mockGetPlatform,
} = vi.hoisted(() => ({
  mockGetApplicantByUser: vi.fn(),
  mockCreateApplicant: vi.fn(),
  mockUpdateApplicantProfile: vi.fn(),
  mockListWallets: vi.fn(),
  mockWalletPreferenceState: { walletIds: [] as string[] },
  mockGetPlatform: vi.fn(),
}));

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({
    user: {
      user_id: 'user-1',
      email: 'applicant@example.com',
      name: 'Ada Lovelace',
    },
  }),
}));

vi.mock('../../services/applicantApi', () => ({
  getApplicantByUser: (...args: unknown[]) => mockGetApplicantByUser(...args),
  createApplicant: (...args: unknown[]) => mockCreateApplicant(...args),
  updateApplicantProfile: (...args: unknown[]) => mockUpdateApplicantProfile(...args),
}));

vi.mock('../../services/walletRegistryApi', () => ({
  listWallets: (...args: unknown[]) => mockListWallets(...args),
}));

vi.mock('../../utils/deviceDetection', () => ({
  getPlatform: (...args: unknown[]) => mockGetPlatform(...args),
}));

vi.mock('../../hooks/useWalletPreferences', () => ({
  default: () => ({
    walletIds: mockWalletPreferenceState.walletIds,
    addWallet: vi.fn(),
    removeWallet: vi.fn(),
  }),
}));

describe('ApplicantSettingsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockWalletPreferenceState.walletIds = [];
    mockGetPlatform.mockReturnValue('desktop');
    mockGetApplicantByUser.mockResolvedValue({
      id: 'app-1',
      given_name: 'Ada',
      family_name: 'Lovelace',
      email: 'applicant@example.com',
      phone_number: '',
    });
    mockCreateApplicant.mockResolvedValue({ id: 'app-created' });
    mockListWallets.mockResolvedValue([]);
  });

  it('removes the redundant wallet setup panel and keeps the wallet selection section anchored', async () => {
    render(<ApplicantSettingsPage />);

    expect(await screen.findByTestId('wallet-selection-section')).toHaveAttribute('id', 'wallet-selection');
    expect(screen.getByText('My Wallets')).toBeInTheDocument();
    expect(screen.getByText(/Choose the wallet apps you use/i)).toBeInTheDocument();
    expect(screen.queryByTestId('wallet-setup-section')).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Set Up Wallet' })).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Manage Wallet Setup' })).not.toBeInTheDocument();
    expect(screen.queryByTestId('organization-membership-section')).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'View My Organizations' })).not.toBeInTheDocument();
  });

  it('warns iOS users when a preferred wallet only supports protocol deep links', async () => {
    mockGetPlatform.mockReturnValue('ios');
    mockWalletPreferenceState.walletIds = ['wallet-protocol', 'wallet-safe'];
    mockListWallets.mockResolvedValue([
      {
        id: 'wallet-protocol',
        name: 'Protocol Wallet',
        description: 'Uses raw protocol links only',
        supported_platforms: ['ios'],
        ios_same_device_single_wallet_only: true,
      },
      {
        id: 'wallet-safe',
        name: 'Nested Wallet',
        description: 'Uses a wrapped wallet route',
        supported_platforms: ['ios'],
        ios_same_device_single_wallet_only: false,
      },
    ]);

    render(<ApplicantSettingsPage />);

    const warning = await screen.findByTestId('ios-same-device-wallet-warning');
    expect(warning).toHaveTextContent('Protocol Wallet');
    expect(warning).toHaveTextContent('single-wallet support');
    expect(warning).toHaveTextContent('openid-credential-offer://');
    expect(warning).not.toHaveTextContent('Nested Wallet');
  });

  it('does not show the iOS routing warning on non-iOS platforms', async () => {
    mockWalletPreferenceState.walletIds = ['wallet-protocol'];
    mockListWallets.mockResolvedValue([
      {
        id: 'wallet-protocol',
        name: 'Protocol Wallet',
        description: 'Uses raw protocol links only',
        supported_platforms: ['ios'],
        ios_same_device_single_wallet_only: true,
      },
    ]);

    render(<ApplicantSettingsPage />);

    await screen.findByText('Protocol Wallet');
    expect(screen.queryByTestId('ios-same-device-wallet-warning')).not.toBeInTheDocument();
  });

});