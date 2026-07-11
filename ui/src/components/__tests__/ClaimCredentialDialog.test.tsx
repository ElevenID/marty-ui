import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';

import ClaimCredentialDialog from '../console/applicant/ClaimCredentialDialog';

const {
  mockGenerateIssuanceOffer,
  mockBuildWalletOpenLink,
  mockListWallets,
  mockListDeliveryDestinations,
  mockWalletPreferenceState,
  mockSetWalletIds,
} = vi.hoisted(() => ({
  mockGenerateIssuanceOffer: vi.fn(),
  mockBuildWalletOpenLink: vi.fn(),
  mockListWallets: vi.fn(),
  mockListDeliveryDestinations: vi.fn(),
  mockWalletPreferenceState: { walletIds: [] as string[] },
  mockSetWalletIds: vi.fn(),
}));

type InviteDisplayProps = {
  offerData?: {
    offer_url?: string | null;
    credential_offer_uri?: string | null;
    credential_offer_uris?: Record<string, string>;
    credential_offer_labels?: Record<string, string>;
  };
  allowedWalletIds?: string[] | null;
  showDefaultWalletTab?: boolean;
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

vi.mock('../../services/deliveryDestinationsApi', () => ({
  listDeliveryDestinations: (...args: unknown[]) => mockListDeliveryDestinations(...args),
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
    setWalletIds: (...args: unknown[]) => mockSetWalletIds(...args),
  }),
}));

vi.mock('../issuance/OID4VCIInviteDisplay', () => ({
  default: ({ offerData, allowedWalletIds, showDefaultWalletTab, title, instructions }: InviteDisplayProps) => (
    <div data-testid="claim-invite-display">
      <div data-testid="claim-invite-title">{title}</div>
      <div data-testid="claim-invite-instructions">{instructions || ''}</div>
      <div data-testid="claim-invite-url">{offerData?.offer_url || ''}</div>
      <div data-testid="claim-invite-allowed-wallets">{allowedWalletIds?.join(',') || 'all'}</div>
      <div data-testid="claim-invite-default-tab">{String(showDefaultWalletTab)}</div>
      <div data-testid="claim-invite-wallet-uris">
        {Object.keys(offerData?.credential_offer_uris || {}).join(',')}
      </div>
      <div data-testid="claim-invite-walt-uri">
        {offerData?.credential_offer_uris?.['wr-waltid-001'] || ''}
      </div>
    </div>
  ),
}));

describe('ClaimCredentialDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockWalletPreferenceState.walletIds = [];
    mockBuildWalletOpenLink.mockResolvedValue({ open_uri: 'marty-authenticator://open?inner=spruce-specific' });
    mockListWallets.mockResolvedValue([
      {
        id: 'wr-default',
        name: 'Any OID4VCI Wallet',
        specifications: ['OID4VCI'],
        supported_platforms: ['web', 'ios', 'android'],
      },
      {
        id: 'wr-waltid-001',
        name: 'walt.id Wallet',
        specifications: ['OID4VCI'],
        supported_platforms: ['web', 'ios', 'android'],
      },
      {
        id: 'wr-spruce-001',
        name: 'SpruceKit',
        specifications: ['OID4VCI'],
        supported_platforms: ['ios', 'android'],
      },
    ]);
    mockListDeliveryDestinations.mockResolvedValue([
      {
        id: 'dd-elevenid-wallet',
        name: 'ElevenID Wallet',
        provider: 'elevenid_wallet',
        mode: 'holder_wallet',
        delivery_target: 'wallet',
        is_enabled: true,
      },
      {
        id: 'dd-oid4vci-compatible-wallet',
        name: 'Compatible Wallet',
        provider: 'oid4vci_wallet',
        mode: 'holder_wallet',
        delivery_target: 'wallet',
        is_enabled: true,
      },
      {
        id: 'dd-canvas-credentials-institutional',
        name: 'Canvas Credentials',
        provider: 'canvas_credentials',
        mode: 'organization_mirror',
        delivery_target: 'canvas_credentials',
        is_enabled: true,
      },
    ]);
    mockGenerateIssuanceOffer.mockResolvedValue({
      offer_url: 'openid://wallet-offer',
      status: 'active',
    });
  });

  it('uses the compatible wallet destination when no wallet app is selected', async () => {
    render(
      <ClaimCredentialDialog
        open
        onClose={vi.fn()}
        applicationId="app-1"
        organizationId="org-1"
        offerData={undefined}
      />,
    );

    expect(await screen.findByTestId('wallet-selector')).toBeInTheDocument();
    expect(screen.getByRole('radio', { name: /Any OID4VCI Wallet/i })).toHaveAttribute('aria-checked', 'true');
    await waitFor(() => {
      expect(mockListDeliveryDestinations).toHaveBeenCalledWith({
        activeOnly: true,
        organizationId: 'org-1',
      });
      expect(mockGenerateIssuanceOffer).toHaveBeenCalledWith(
        'app-1',
        expect.objectContaining({
          delivery_destination_ids: expect.arrayContaining([
            'dd-oid4vci-compatible-wallet',
            'dd-canvas-credentials-institutional',
          ]),
          canvas_credentials_consent: true,
        }),
      );
    });
    expect(await screen.findByTestId('claim-invite-display')).toBeInTheDocument();
    expect(screen.getByTestId('claim-invite-allowed-wallets')).toHaveTextContent('all');
    expect(screen.getByTestId('claim-invite-default-tab')).toHaveTextContent('true');
    expect(screen.getByText('Also show this badge in Canvas Credentials')).toBeInTheDocument();
    expect(screen.queryByTestId('wallet-registration-guard')).not.toBeInTheDocument();
  });

  it('explains when the issuer has not activated an OID4VCI issuance flow', async () => {
    mockGenerateIssuanceOffer.mockRejectedValue({
      response: {
        error_description: 'No active issuance flow produced an offer for this application. Configure and activate an OID4VCI flow for the credential template.',
      },
    });

    render(
      <ClaimCredentialDialog
        open
        onClose={vi.fn()}
        applicationId="app-1"
        organizationId="org-1"
        offerData={undefined}
      />,
    );

    expect(await screen.findByText(/issuer needs to activate an OID4VCI issuance flow/i)).toBeInTheDocument();
  });

  it('lets the applicant select a browser wallet in the claim flow', async () => {
    mockGenerateIssuanceOffer.mockResolvedValue({
      offer_url: 'https://issuer.example/offers/generic',
      credential_offer_uri: 'https://issuer.example/offers/generic',
      credential_offer_uris: {
        'wr-default': 'https://issuer.example/offers/default',
        'wr-spruce-001': 'https://issuer.example/offers/spruce',
      },
      credential_offer_labels: {
        'wr-spruce-001': 'SpruceKit',
      },
      status: 'active',
    });

    const { user } = render(
      <ClaimCredentialDialog open onClose={vi.fn()} applicationId="app-1" organizationId="org-1" offerData={undefined} />,
    );

    await user.click(await screen.findByTestId('wallet-option-wr-waltid-001'));

    expect(mockSetWalletIds).toHaveBeenCalledWith(['wr-waltid-001']);
    await waitFor(() => {
      expect(mockGenerateIssuanceOffer).toHaveBeenCalledWith(
        'app-1',
        expect.objectContaining({
          delivery_destination_ids: expect.arrayContaining(['dd-oid4vci-compatible-wallet']),
        }),
      );
    });
    expect(await screen.findByTestId('claim-invite-display')).toBeInTheDocument();
    expect(screen.getByTestId('claim-invite-allowed-wallets')).toHaveTextContent('wr-waltid-001');
    expect(screen.getByTestId('claim-invite-default-tab')).toHaveTextContent('false');
    expect(screen.getByTestId('claim-invite-wallet-uris')).toHaveTextContent('wr-waltid-001');
    expect(screen.getByTestId('claim-invite-walt-uri')).toHaveTextContent('https://issuer.example/offers/generic');
  });

  it('loads a fresh wallet offer once a wallet app is selected', async () => {
    mockWalletPreferenceState.walletIds = ['wr-waltid-001'];

    render(<ClaimCredentialDialog open onClose={vi.fn()} applicationId="app-1" organizationId="org-1" offerData={undefined} />);

    await waitFor(() => {
      expect(mockGenerateIssuanceOffer).toHaveBeenCalledWith(
        'app-1',
        expect.objectContaining({
          delivery_destination_ids: expect.arrayContaining(['dd-oid4vci-compatible-wallet']),
        }),
      );
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

    render(<ClaimCredentialDialog open onClose={vi.fn()} applicationId="app-1" organizationId="org-1" offerData={undefined} />);

    await waitFor(() => {
      expect(mockGenerateIssuanceOffer).toHaveBeenCalledWith(
        'app-1',
        expect.objectContaining({
          delivery_destination_ids: expect.arrayContaining(['dd-oid4vci-compatible-wallet']),
        }),
      );
    });

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Open SpruceKit' })).toBeInTheDocument();
    });

    screen.getByRole('button', { name: 'Open SpruceKit' }).click();

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

  it('keeps Canvas Credentials as an optional post-issuance mirror', async () => {
    render(
      <ClaimCredentialDialog open onClose={vi.fn()} applicationId="app-1" organizationId="org-1" offerData={undefined} />,
    );

    expect(await screen.findByText('Also show this badge in Canvas Credentials')).toBeInTheDocument();
    expect(screen.queryByTestId('canvas-credentials-destination-message')).not.toBeInTheDocument();
  });
});
