import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';

import ClaimCredentialDialog from '../console/applicant/ClaimCredentialDialog';

const {
  mockGenerateIssuanceOffer,
  mockBuildWalletOpenLink,
  mockListWallets,
  mockWalletPreferenceState,
} = vi.hoisted(() => ({
  mockGenerateIssuanceOffer: vi.fn(),
  mockBuildWalletOpenLink: vi.fn(),
  mockListWallets: vi.fn(),
  mockWalletPreferenceState: { walletIds: [] as string[] },
}));

type InviteDisplayProps = {
  offerData?: { offer_url?: string | null };
  title?: string;
  instructions?: string;
};

vi.mock('../../services/credentialsApi', () => ({
  generateIssuanceOffer: (...args: unknown[]) => mockGenerateIssuanceOffer(...args),
}));

vi.mock('../../services/walletRegistryApi', () => ({
  buildWalletOpenLink: (...args: unknown[]) => mockBuildWalletOpenLink(...args),
  listWallets: (...args: unknown[]) => mockListWallets(...args),
}));

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({
    user: {
      user_id: 'user-1',
      email: 'applicant@example.com',
    },
  }),
}));

vi.mock('../../hooks/useWalletPreferences', () => ({
  default: () => ({
    walletIds: mockWalletPreferenceState.walletIds,
  }),
}));

vi.mock('../issuance/OID4VCIInviteDisplay', () => ({
  default: ({ offerData, title, instructions }: InviteDisplayProps) => (
    <div data-testid="claim-invite-display">
      <div data-testid="claim-invite-title">{title}</div>
      <div data-testid="claim-invite-instructions">{instructions || ''}</div>
      <div data-testid="claim-invite-url">{offerData?.offer_url || ''}</div>
    </div>
  ),
}));

describe('ClaimCredentialDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockWalletPreferenceState.walletIds = [];
    mockBuildWalletOpenLink.mockResolvedValue({ open_uri: 'marty-authenticator://open?inner=spruce-specific' });
    mockListWallets.mockResolvedValue([
      { id: 'wallet-1', name: 'Test Wallet' },
      { id: 'wr-spruce-001', name: 'SpruceKit' },
    ]);
    mockGenerateIssuanceOffer.mockResolvedValue({
      offer_url: 'openid://wallet-offer',
      status: 'active',
    });
  });

  it('blocks claiming until the applicant selects a wallet app', async () => {
    const onClose = vi.fn();
    const { user } = render(
      <ClaimCredentialDialog open onClose={onClose} applicationId="app-1" offerData={undefined} />,
    );

    expect(await screen.findByTestId('wallet-registration-guard')).toHaveTextContent(
      'Select a wallet app before you can receive this credential.',
    );
    expect(screen.queryByTestId('claim-invite-display')).not.toBeInTheDocument();
    expect(mockGenerateIssuanceOffer).not.toHaveBeenCalled();

    const setupLink = screen.getByRole('link', { name: 'Choose Wallet' });
    expect(setupLink).toHaveAttribute('href', '/console/applicant/settings#wallet-selection');

    await user.click(setupLink);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('loads a fresh wallet offer once a wallet app is selected', async () => {
    mockWalletPreferenceState.walletIds = ['wallet-1'];

    render(<ClaimCredentialDialog open onClose={vi.fn()} applicationId="app-1" offerData={undefined} />);

    await waitFor(() => {
      expect(mockGenerateIssuanceOffer).toHaveBeenCalledWith('app-1');
    });

    expect(await screen.findByTestId('claim-invite-display')).toBeInTheDocument();
    expect(screen.getByTestId('claim-invite-url')).toHaveTextContent('openid://wallet-offer');
    expect(screen.queryByTestId('wallet-registration-guard')).not.toBeInTheDocument();
  });

  it('uses the selected Spruce wallet-specific offer for the mobile open-wallet handoff', async () => {
    const originalLocation = window.location;
    const originalMatchMedia = window.matchMedia;
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { href: '' },
    });
    Object.defineProperty(window, 'matchMedia', {
      configurable: true,
      writable: true,
      value: vi.fn().mockImplementation((query: string) => ({
        matches: true,
        media: query,
        onchange: null,
        addListener: vi.fn(),
        removeListener: vi.fn(),
        addEventListener: vi.fn(),
        removeEventListener: vi.fn(),
        dispatchEvent: vi.fn(),
      })),
    });

    mockWalletPreferenceState.walletIds = ['wr-spruce-001'];
    mockGenerateIssuanceOffer.mockResolvedValue({
      offer_url: 'openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffers%2Fgeneric',
      credential_offer_uris: {
        'wr-spruce-001': 'openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Forg%2Forg-1%2Fspruce%2Foffers%2F123',
      },
      status: 'active',
    });

    render(<ClaimCredentialDialog open onClose={vi.fn()} applicationId="app-1" offerData={undefined} />);

    await waitFor(() => {
      expect(mockGenerateIssuanceOffer).toHaveBeenCalledWith('app-1');
    });

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Open in Wallet App' })).toBeInTheDocument();
    });

    screen.getByRole('button', { name: 'Open in Wallet App' }).click();

    await waitFor(() => {
      expect(mockBuildWalletOpenLink).toHaveBeenCalledWith(
        'wr-spruce-001',
        expect.objectContaining({
          innerUri: 'openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Forg%2Forg-1%2Fspruce%2Foffers%2F123',
        }),
      );
    });

    Object.defineProperty(window, 'location', {
      configurable: true,
      value: originalLocation,
    });
    Object.defineProperty(window, 'matchMedia', {
      configurable: true,
      writable: true,
      value: originalMatchMedia,
    });
  });
});