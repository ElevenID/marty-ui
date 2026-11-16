import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor } from '@test/utils';

import ApplicantSettingsPage from '../console/applicant/ApplicantSettingsPage.jsx';

const {
  mockGetMyApplicantProfile,
  mockUpsertMyApplicantProfile,
  mockListWallets,
  mockWalletPreferenceState,
  mockGetPlatform,
  mockAddWallet,
  mockRemoveWallet,
  authState,
} = vi.hoisted(() => ({
  mockGetMyApplicantProfile: vi.fn(),
  mockUpsertMyApplicantProfile: vi.fn(),
  mockListWallets: vi.fn(),
  mockWalletPreferenceState: { walletIds: [] as string[] },
  mockGetPlatform: vi.fn(),
  mockAddWallet: vi.fn(),
  mockRemoveWallet: vi.fn(),
  authState: {
    user: {
      user_id: 'user-1',
      email: 'applicant@example.com',
      name: 'Ada Lovelace',
      given_name: 'Ada',
      family_name: 'Lovelace',
    },
  },
}));

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({
    user: authState.user,
    organizationId: 'org-1',
  }),
}));

vi.mock('../../services/applicantApi', () => ({
  getMyApplicantProfile: (...args: unknown[]) => mockGetMyApplicantProfile(...args),
  upsertMyApplicantProfile: (...args: unknown[]) => mockUpsertMyApplicantProfile(...args),
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
    addWallet: mockAddWallet,
    removeWallet: mockRemoveWallet,
  }),
}));

describe('ApplicantSettingsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    authState.user = {
      user_id: 'user-1',
      email: 'applicant@example.com',
      name: 'Ada Lovelace',
      given_name: 'Ada',
      family_name: 'Lovelace',
    };
    mockWalletPreferenceState.walletIds = [];
    mockGetPlatform.mockReturnValue('desktop');
    mockGetMyApplicantProfile.mockResolvedValue({
      id: 'app-1',
      given_name: 'Ada',
      family_name: 'Lovelace',
      email: 'applicant@example.com',
      phone: '',
    });
    mockUpsertMyApplicantProfile.mockResolvedValue({ id: 'app-created' });
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

  it('creates a missing applicant profile without caller-controlled organization context', async () => {
    mockGetMyApplicantProfile.mockResolvedValue(null);
    mockUpsertMyApplicantProfile.mockResolvedValue({
      id: 'app-created',
      given_name: 'Ada',
      family_name: 'Lovelace',
      email: 'applicant@example.com',
      phone: '',
    });

    render(<ApplicantSettingsPage />);

    await waitFor(() => expect(screen.getByRole('button', { name: 'Save profile' })).toBeEnabled());
    expect(screen.getByDisplayValue('Ada Lovelace')).toBeInTheDocument();
    expect(mockUpsertMyApplicantProfile).toHaveBeenCalledWith({
      email: 'applicant@example.com',
      given_name: 'Ada',
      family_name: 'Lovelace',
    });
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

  it('keeps profile fields and Save disabled until the profile is loaded', async () => {
    let resolveProfile!: (value: unknown) => void;
    mockGetMyApplicantProfile.mockImplementationOnce(() => new Promise((resolve) => { resolveProfile = resolve; }));
    render(<ApplicantSettingsPage />);

    expect(screen.getByLabelText('Full Name')).toBeDisabled();
    expect(screen.getByLabelText('Phone Number')).toBeDisabled();
    const save = screen.getByRole('button', { name: 'Save profile' });
    expect(save).toBeDisabled();
    expect(mockUpsertMyApplicantProfile).not.toHaveBeenCalled();

    await act(async () => resolveProfile({ id: 'app-1', given_name: 'Ada', family_name: 'Lovelace', phone: '555-0100' }));

    expect(save).toBeEnabled();
    expect(screen.getByLabelText('Full Name')).toBeEnabled();
    expect(screen.getByLabelText('Phone Number')).toHaveValue('555-0100');
  });

  it('offers a profile retry after loading fails without allowing a save of fallback values', async () => {
    mockGetMyApplicantProfile.mockRejectedValueOnce(new Error('Profile unavailable'));
    const { user } = render(<ApplicantSettingsPage />);

    expect(await screen.findByText('Your profile could not be loaded. Please try again.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Save profile' })).toBeDisabled();
    expect(screen.getByLabelText('Full Name')).toBeDisabled();
    expect(mockUpsertMyApplicantProfile).not.toHaveBeenCalled();

    await user.click(screen.getByRole('button', { name: 'Retry' }));

    await waitFor(() => expect(screen.getByRole('button', { name: 'Save profile' })).toBeEnabled());
    expect(screen.queryByText('Your profile could not be loaded. Please try again.')).not.toBeInTheDocument();
    expect(mockGetMyApplicantProfile).toHaveBeenCalledTimes(2);
  });

  it('preserves a draft when the same user object is refreshed', async () => {
    const view = render(<ApplicantSettingsPage />);
    await waitFor(() => expect(screen.getByLabelText('Full Name')).toBeEnabled());
    await view.user.clear(screen.getByLabelText('Full Name'));
    await view.user.type(screen.getByLabelText('Full Name'), 'Draft Profile Name');

    authState.user = { ...authState.user };
    view.rerender(<ApplicantSettingsPage />);

    expect(screen.getByLabelText('Full Name')).toHaveValue('Draft Profile Name');
    expect(mockGetMyApplicantProfile).toHaveBeenCalledTimes(1);
  });

  it('does not expose notification switches that cannot be saved, while saving supported profile fields', async () => {
    const { user } = render(<ApplicantSettingsPage />);
    await waitFor(() => expect(screen.getByLabelText('Full Name')).toBeEnabled());

    expect(screen.getByText('Notification preferences are not available in this deployment.')).toBeInTheDocument();
    for (const label of ['Email Alerts', 'Application Updates', 'Expiration Reminders']) {
      expect(screen.queryByLabelText(label)).not.toBeInTheDocument();
    }
    await user.clear(screen.getByLabelText('Full Name'));
    await user.type(screen.getByLabelText('Full Name'), '  Ada   Byron Lovelace  ');
    await user.type(screen.getByLabelText('Phone Number'), '555-0100');
    await user.click(screen.getByRole('button', { name: 'Save profile' }));

    expect(mockUpsertMyApplicantProfile).toHaveBeenCalledExactlyOnceWith({
      given_name: 'Ada',
      family_name: 'Byron Lovelace',
      phone: '555-0100',
    });
    expect(await screen.findByText('Profile saved.')).toBeInTheDocument();
  });

  it('ignores a late profile response from the previous account', async () => {
    let resolvePrevious!: (value: unknown) => void;
    mockGetMyApplicantProfile.mockImplementationOnce(() => new Promise((resolve) => { resolvePrevious = resolve; }));
    const view = render(<ApplicantSettingsPage />);

    authState.user = { user_id: 'user-2', email: 'grace@example.com', name: 'Grace Hopper', given_name: 'Grace', family_name: 'Hopper' };
    mockGetMyApplicantProfile.mockResolvedValue({ id: 'app-2', given_name: 'Grace', family_name: 'Hopper', email: 'grace@example.com', phone: '555-0200' });
    view.rerender(<ApplicantSettingsPage />);
    await waitFor(() => expect(screen.getByLabelText('Phone Number')).toHaveValue('555-0200'));

    await act(async () => resolvePrevious({ id: 'app-1', full_name: 'Old Account', phone: '555-0100' }));

    expect(screen.getByLabelText('Full Name')).toHaveValue('Grace Hopper');
    expect(screen.getByLabelText('Email')).toHaveValue('grace@example.com');
    expect(screen.getByLabelText('Phone Number')).toHaveValue('555-0200');
  });

  it('ignores a late profile save after the account changes', async () => {
    let resolveSave!: (value: unknown) => void;
    mockUpsertMyApplicantProfile.mockImplementationOnce(() => new Promise((resolve) => { resolveSave = resolve; }));
    const view = render(<ApplicantSettingsPage />);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Save profile' })).toBeEnabled());
    await view.user.click(screen.getByRole('button', { name: 'Save profile' }));
    expect(screen.getByLabelText('Full Name')).toBeDisabled();

    authState.user = { user_id: 'user-2', email: 'grace@example.com', name: 'Grace Hopper', given_name: 'Grace', family_name: 'Hopper' };
    mockGetMyApplicantProfile.mockResolvedValue({ id: 'app-2', given_name: 'Grace', family_name: 'Hopper', phone: '555-0200' });
    view.rerender(<ApplicantSettingsPage />);
    await waitFor(() => expect(screen.getByLabelText('Phone Number')).toHaveValue('555-0200'));

    await act(async () => resolveSave({ id: 'app-1' }));

    expect(screen.queryByText('Profile saved.')).not.toBeInTheDocument();
    expect(screen.getByLabelText('Full Name')).toHaveValue('Grace Hopper');
    expect(screen.getByRole('button', { name: 'Save profile' })).toBeEnabled();
  });

  it('distinguishes a wallet registry failure from an empty registry and retries', async () => {
    mockListWallets.mockRejectedValueOnce(new Error('Wallet registry unavailable'))
      .mockResolvedValue([{ id: 'wallet-1', name: 'Example Wallet', supported_platforms: ['ios', 'android'] }]);
    const { user } = render(<ApplicantSettingsPage />);

    expect(await screen.findByText('Available wallets could not be loaded. Please try again.')).toBeInTheDocument();
    expect(screen.queryByText('No wallets are available in the registry yet.')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Retry' }));

    expect(await screen.findByRole('checkbox', { name: 'Example Wallet' })).toBeInTheDocument();
    expect(screen.queryByText('Available wallets could not be loaded. Please try again.')).not.toBeInTheDocument();
    expect(mockListWallets).toHaveBeenCalledTimes(2);
  });

  it.each([false, true])('provides an accessible keyboard wallet selection when checked=%s', async (checked) => {
    mockWalletPreferenceState.walletIds = checked ? ['wallet-1'] : [];
    mockListWallets.mockResolvedValue([{ id: 'wallet-1', name: 'Example Wallet', description: 'A wallet app' }]);
    const { user } = render(<ApplicantSettingsPage />);
    const checkbox = await screen.findByRole('checkbox', { name: 'Example Wallet' });

    checkbox.focus();
    await user.keyboard('[Space]');

    expect(checked ? mockRemoveWallet : mockAddWallet).toHaveBeenCalledExactlyOnceWith('wallet-1');
    expect(checked ? mockAddWallet : mockRemoveWallet).not.toHaveBeenCalled();
    expect(mockUpsertMyApplicantProfile).not.toHaveBeenCalled();
    expect(screen.getByText('Wallet choices are saved automatically in this browser.')).toBeInTheDocument();
  });

});
