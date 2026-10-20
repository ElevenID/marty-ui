import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor } from '@test/utils';
import ClaimCredentialDialog from '../console/applicant/ClaimCredentialDialog';

const {
  mockGenerateIssuanceOffer, mockBuildWalletOpenLink, mockListWallets,
  mockListDeliveryDestinations, mockWalletPreferenceState, mockSetWalletIds, mockGetApplication,
} = vi.hoisted(() => ({
  mockGenerateIssuanceOffer: vi.fn(),
  mockBuildWalletOpenLink: vi.fn(),
  mockListWallets: vi.fn(),
  mockListDeliveryDestinations: vi.fn(),
  mockWalletPreferenceState: { walletIds: [] as string[] },
  mockSetWalletIds: vi.fn(),
  mockGetApplication: vi.fn(),
}));

vi.mock('../../services/credentialsApi', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../services/credentialsApi')>(),
  generateIssuanceOffer: (...args: unknown[]) => mockGenerateIssuanceOffer(...args),
}));
vi.mock('../../services/applicantApi', () => ({
  getApplication: (...args: unknown[]) => mockGetApplication(...args),
}));
vi.mock('../../services/walletRegistryApi', () => ({
  buildWalletOpenLink: (...args: unknown[]) => mockBuildWalletOpenLink(...args),
  listWallets: (...args: unknown[]) => mockListWallets(...args),
}));
vi.mock('../../services/deliveryDestinationsApi', () => ({
  listDeliveryDestinations: (...args: unknown[]) => mockListDeliveryDestinations(...args),
}));
vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({ user: { user_id: 'user-1', email: 'applicant@example.com' } }),
}));
vi.mock('../../hooks/useWalletPreferences', () => ({
  default: () => ({
    walletIds: mockWalletPreferenceState.walletIds,
    setWalletIds: (...args: unknown[]) => mockSetWalletIds(...args),
  }),
}));
vi.mock('../issuance/OID4VCIInviteDisplay', () => ({
  default: ({ offerData, allowedWalletIds, showDefaultWalletTab, onRegenerate }: {
    offerData?: { offer_url?: string; expires_at?: string; credential_offer_uris?: Record<string, string> };
    allowedWalletIds?: string[]; showDefaultWalletTab?: boolean; onRegenerate?: () => void;
  }) => (
    <div data-testid="claim-invite-display">
      <div data-testid="claim-invite-url">{offerData?.offer_url || ''}</div>
      <div data-testid="claim-invite-expires-at">{offerData?.expires_at || ''}</div>
      <div data-testid="claim-invite-allowed-wallets">{allowedWalletIds?.join(',') || 'all'}</div>
      <div data-testid="claim-invite-default-tab">{String(showDefaultWalletTab)}</div>
      <div data-testid="claim-invite-walt-uri">{offerData?.credential_offer_uris?.['wr-waltid-001'] || ''}</div>
      {onRegenerate && <button onClick={onRegenerate}>Refresh invite</button>}
    </div>
  ),
}));

const wallets = [
  { id: 'wr-default', name: 'Any OID4VCI Wallet', specifications: ['OID4VCI'], supported_platforms: ['web', 'ios', 'android'] },
  { id: 'wr-waltid-001', name: 'walt.id Wallet', specifications: ['OID4VCI'], supported_platforms: ['web', 'ios', 'android'] },
  { id: 'wr-spruce-001', name: 'SpruceKit', specifications: ['OID4VCI'], supported_platforms: ['ios', 'android'] },
];
const offer = {
  id: 'app-1',
  organization_id: 'org-1',
  offer_url: 'https://issuer.example/offers/current',
  status: 'OFFERED',
  claim_state: 'OFFER_READY',
  claim_capabilities: {
    oid4vci_wallet: true, delivery_destination_selection: false,
    canvas_credentials_mirror: false, offer_reuse: 'pending_until_consumed_or_expired',
  },
};
const rawApplication = {
  ...offer,
  credential_offer_uri: offer.offer_url,
  offer_expires_at: '2030-01-01T00:15:00Z',
  offer_url: undefined,
};
const props = { open: true, onClose: vi.fn(), applicationId: 'app-1', organizationId: 'org-1', offerData: undefined };

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

describe('ClaimCredentialDialog', () => {
  let opener: HTMLButtonElement;
  let locationDescriptor: PropertyDescriptor;
  let mediaDescriptor: PropertyDescriptor;

  beforeEach(() => {
    vi.clearAllMocks();
    locationDescriptor = Object.getOwnPropertyDescriptor(window, 'location')!;
    mediaDescriptor = Object.getOwnPropertyDescriptor(window, 'matchMedia')!;
    // Open from a real control and keep it alive through MUI's focus restoration.
    opener = document.createElement('button');
    opener.textContent = 'Claim credential';
    document.body.append(opener);
    opener.focus();
    mockWalletPreferenceState.walletIds = [];
    mockListWallets.mockResolvedValue(wallets);
    mockListDeliveryDestinations.mockResolvedValue([
      { id: 'dd-canvas-credentials-institutional', provider: 'canvas_credentials', mode: 'organization_mirror', is_enabled: true },
    ]);
    mockBuildWalletOpenLink.mockResolvedValue({ open_uri: 'marty-authenticator://open?inner=spruce-specific' });
    mockGenerateIssuanceOffer.mockResolvedValue(offer);
    mockGetApplication.mockImplementation((id) => Promise.resolve({
      ...rawApplication, id, organization_id: id === 'app-2' ? 'org-2' : 'org-1',
    }));
  });

  afterEach(() => {
    Object.defineProperty(window, 'location', locationDescriptor);
    Object.defineProperty(window, 'matchMedia', mediaDescriptor);
    opener.remove();
  });

  function mobileBrowser() {
    const location = { href: '' };
    Object.defineProperty(window, 'location', { configurable: true, value: location });
    Object.defineProperty(window, 'matchMedia', {
      configurable: true, writable: true,
      value: vi.fn().mockImplementation((query: string) => ({
        matches: true, media: query, onchange: null,
        addListener: vi.fn(), removeListener: vi.fn(),
        addEventListener: vi.fn(), removeEventListener: vi.fn(), dispatchEvent: vi.fn(),
      })),
    });
    return location;
  }

  it('acquires one server-governed offer and loads organization-scoped wallet links', async () => {
    render(<ClaimCredentialDialog {...props} />);
    expect(await screen.findByTestId('claim-invite-display')).toBeInTheDocument();
    expect(mockListWallets).toHaveBeenCalledWith(true, 'org-1');
    expect(mockGenerateIssuanceOffer).toHaveBeenCalledExactlyOnceWith('app-1');
    expect(screen.getByRole('radio', { name: /Any OID4VCI Wallet/i })).toHaveAttribute('aria-checked', 'true');
    expect(screen.getByTestId('claim-invite-allowed-wallets')).toHaveTextContent('all');
    expect(screen.getByTestId('claim-invite-default-tab')).toHaveTextContent('true');
  });

  it('does not offer Canvas consent or destination selection that the Rust claim path cannot execute', async () => {
    render(<ClaimCredentialDialog {...props} />);
    await screen.findByTestId('claim-invite-display');
    expect(screen.queryByRole('checkbox', { name: /Canvas Credentials/i })).not.toBeInTheDocument();
    expect(screen.queryByText('Also show this badge in Canvas Credentials')).not.toBeInTheDocument();
    expect(mockListDeliveryDestinations).not.toHaveBeenCalled();
    expect(mockGenerateIssuanceOffer).toHaveBeenCalledExactlyOnceWith('app-1');
  });

  it('explains when the issuer has not activated an OID4VCI issuance flow', async () => {
    mockGenerateIssuanceOffer.mockRejectedValue({
      response: { error_description: 'No active issuance flow produced an offer for this application. Configure and activate an OID4VCI flow for the credential template.' },
    });
    render(<ClaimCredentialDialog {...props} />);
    expect(await screen.findByText(/issuer needs to activate an OID4VCI issuance flow/i)).toBeInTheDocument();
  });

  it('changes browser wallet transport without starting another issuance', async () => {
    const { user } = render(<ClaimCredentialDialog {...props} />);
    await screen.findByTestId('claim-invite-display');
    await user.click(screen.getByTestId('wallet-option-wr-waltid-001'));
    expect(mockSetWalletIds).toHaveBeenCalledWith(['wr-waltid-001']);
    expect(screen.getByTestId('claim-invite-allowed-wallets')).toHaveTextContent('wr-waltid-001');
    expect(screen.getByTestId('claim-invite-default-tab')).toHaveTextContent('false');
    expect(screen.getByTestId('claim-invite-walt-uri')).toHaveTextContent(offer.offer_url);
    expect(mockGenerateIssuanceOffer).toHaveBeenCalledTimes(1);
  });

  it('waits for a delayed wallet catalogue and applies the preference without duplicate claims', async () => {
    const catalogue = deferred<unknown[]>();
    mockListWallets.mockReturnValue(catalogue.promise);
    mockWalletPreferenceState.walletIds = ['wr-spruce-001'];
    render(<ClaimCredentialDialog {...props} />);
    await waitFor(() => expect(mockListWallets).toHaveBeenCalledWith(true, 'org-1'));
    expect(mockGenerateIssuanceOffer).not.toHaveBeenCalled();
    await act(async () => catalogue.resolve(wallets));
    expect(await screen.findByTestId('claim-invite-allowed-wallets')).toHaveTextContent('wr-spruce-001');
    expect(mockGenerateIssuanceOffer).toHaveBeenCalledTimes(1);
  });

  it('ignores the previous application response after switching applications', async () => {
    const previous = deferred<typeof offer>();
    mockGenerateIssuanceOffer.mockImplementation((id) => id === 'app-1'
      ? previous.promise : Promise.resolve({ ...offer, offer_url: 'https://issuer.example/offers/app-2' }));
    const view = render(<ClaimCredentialDialog {...props} />);
    await waitFor(() => expect(mockGenerateIssuanceOffer).toHaveBeenCalledWith('app-1'));
    view.rerender(<ClaimCredentialDialog {...props} applicationId="app-2" organizationId="org-2" />);
    expect(await screen.findByTestId('claim-invite-url')).toHaveTextContent('/app-2');
    await act(async () => previous.resolve(offer));
    expect(screen.getByTestId('claim-invite-url')).toHaveTextContent('/app-2');
  });

  it('does not let a late organization registry replace the current wallet catalogue', async () => {
    const previous = deferred<unknown[]>();
    mockListWallets.mockImplementation((_active, org) => org === 'org-1' ? previous.promise : Promise.resolve([
      { id: 'wr-org-2', name: 'Current wallet', specifications: ['OID4VCI'], supported_platforms: ['android'] },
    ]));
    const view = render(<ClaimCredentialDialog {...props} />);
    await waitFor(() => expect(mockListWallets).toHaveBeenCalledWith(true, 'org-1'));
    view.rerender(<ClaimCredentialDialog {...props} applicationId="app-2" organizationId="org-2" />);
    await screen.findByTestId('wallet-option-wr-org-2');
    await act(async () => previous.resolve(wallets));
    expect(screen.getByTestId('wallet-option-wr-org-2')).toBeInTheDocument();
    expect(screen.queryByTestId('wallet-option-wr-spruce-001')).not.toBeInTheDocument();
    expect(mockGenerateIssuanceOffer).toHaveBeenCalledExactlyOnceWith('app-2');
  });

  it('shares a pending claim across close and reopen and restores focus to the opener', async () => {
    const pending = deferred<typeof offer>();
    mockGenerateIssuanceOffer.mockReturnValue(pending.promise);
    const view = render(<ClaimCredentialDialog {...props} />);
    await waitFor(() => expect(mockGenerateIssuanceOffer).toHaveBeenCalledTimes(1));
    view.rerender(<ClaimCredentialDialog {...props} open={false} />);
    expect(opener).toHaveFocus();
    view.rerender(<ClaimCredentialDialog {...props} />);
    await screen.findByTestId('wallet-option-wr-spruce-001');
    await act(async () => pending.resolve(offer));
    expect(await screen.findByTestId('claim-invite-url')).toHaveTextContent(offer.offer_url);
    expect(mockGenerateIssuanceOffer).toHaveBeenCalledTimes(1);
  });

  it('hides the previous invite while a refresh is pending and never restores it after failure', async () => {
    const pending = deferred<typeof offer>();
    const view = render(<ClaimCredentialDialog {...props} />);
    await screen.findByTestId('claim-invite-display');
    mockGenerateIssuanceOffer.mockReturnValue(pending.promise);
    await view.user.click(screen.getByRole('button', { name: 'Refresh invite' }));
    expect(screen.queryByTestId('claim-invite-display')).not.toBeInTheDocument();
    expect(screen.queryByText('Ready', { exact: true })).not.toBeInTheDocument();
    await act(async () => pending.reject(new Error('Request failed')));
    expect(await screen.findByRole('button', { name: 'Retry' })).toBeEnabled();
    expect(screen.queryByTestId('claim-invite-display')).not.toBeInTheDocument();
    mockGenerateIssuanceOffer.mockResolvedValue(offer);
    await view.user.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByTestId('claim-invite-display')).toBeInTheDocument();
    expect(mockGenerateIssuanceOffer).toHaveBeenCalledTimes(3);
  });

  it('uses the selected Spruce wallet-specific URI for the mobile handoff', async () => {
    const location = mobileBrowser();
    mockWalletPreferenceState.walletIds = ['wr-spruce-001'];
    const specific = 'openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Forg%2Forg-1%2Fspruce%2Foffers%2F123';
    mockGenerateIssuanceOffer.mockResolvedValue({ ...offer, credential_offer_uris: { 'wr-spruce-001': specific } });
    const view = render(<ClaimCredentialDialog {...props} />);
    await view.user.click(await screen.findByRole('button', { name: 'Open SpruceKit' }));
    await waitFor(() => expect(mockBuildWalletOpenLink).toHaveBeenCalledWith('wr-spruce-001', expect.objectContaining({ innerUri: specific })));
    await waitFor(() => expect(location.href).toBe('marty-authenticator://open?inner=spruce-specific'));
  });

  it('does not navigate when a delayed wallet link resolves after the dialog closes', async () => {
    const location = mobileBrowser();
    const openLink = deferred<{ open_uri: string }>();
    mockBuildWalletOpenLink.mockReturnValue(openLink.promise);
    mockWalletPreferenceState.walletIds = ['wr-spruce-001'];
    const view = render(<ClaimCredentialDialog {...props} />);
    await view.user.click(await screen.findByRole('button', { name: 'Open SpruceKit' }));
    expect(screen.getByRole('button', { name: 'Open SpruceKit' })).toBeDisabled();
    view.rerender(<ClaimCredentialDialog {...props} open={false} />);
    await act(async () => openLink.resolve({ open_uri: 'sprucekit://stale-offer' }));
    expect(location.href).toBe('');
  });

  it('uses the Rust expired claim state and offers a server retry', async () => {
    mockGenerateIssuanceOffer.mockResolvedValue({ ...offer, claim_state: 'EXPIRED' });
    render(<ClaimCredentialDialog {...props} />);
    expect(await screen.findByText('This wallet invite has expired.')).toBeInTheDocument();
    expect(screen.queryByTestId('claim-invite-display')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Get new offer' })).toBeEnabled();
  });

  it('replaces the invite with confirmed receipt through read-only polling', async () => {
    mockGetApplication.mockResolvedValue({ ...rawApplication, claim_state: 'CLAIMED', credential_offer_uri: null });
    const view = render(<ClaimCredentialDialog {...props} />);
    await screen.findByTestId('claim-invite-display');
    expect(await screen.findByText('Your credential has been claimed. You can close this dialog.', {}, { timeout: 3500 })).toBeInTheDocument();
    expect(screen.queryByTestId('claim-invite-display')).not.toBeInTheDocument();
    expect(screen.queryByText(/Your wallet invite has not been generated yet/)).not.toBeInTheDocument();
    expect(mockGetApplication).toHaveBeenCalledWith('app-1');
    expect(mockGenerateIssuanceOffer).toHaveBeenCalledTimes(1);
    view.unmount();
  });

  it('retains the raw Rust offer URL and expiration when the application is refreshed', async () => {
    mockGetApplication.mockResolvedValue({
      ...rawApplication, credential_offer_uri: 'https://issuer.example/offers/readback',
    });
    render(<ClaimCredentialDialog {...props} />);
    await screen.findByTestId('claim-invite-display');
    act(() => window.dispatchEvent(new Event('focus')));
    await waitFor(() => expect(screen.getByTestId('claim-invite-url')).toHaveTextContent('/readback'));
    expect(screen.getByTestId('claim-invite-expires-at')).toHaveTextContent(rawApplication.offer_expires_at);
    expect(mockGenerateIssuanceOffer).toHaveBeenCalledTimes(1);
  });

  it('invalidates a pending mobile wallet handoff when readback confirms the credential was claimed', async () => {
    const location = mobileBrowser();
    const openLink = deferred<{ open_uri: string }>();
    mockBuildWalletOpenLink.mockReturnValue(openLink.promise);
    mockWalletPreferenceState.walletIds = ['wr-spruce-001'];
    mockGetApplication.mockResolvedValue({ ...rawApplication, claim_state: 'CLAIMED' });
    const view = render(<ClaimCredentialDialog {...props} />);
    await view.user.click(await screen.findByRole('button', { name: 'Open SpruceKit' }));
    act(() => window.dispatchEvent(new Event('focus')));
    await screen.findByText('Your credential has been claimed. You can close this dialog.');
    await act(async () => openLink.resolve({ open_uri: 'sprucekit://consumed-offer' }));
    expect(location.href).toBe('');
    expect(screen.queryByTestId('wallet-open-link')).not.toBeInTheDocument();
    expect(mockGenerateIssuanceOffer).toHaveBeenCalledTimes(1);
  });

  it('coalesces browser return reads and keeps blocked claims from displaying an active QR', async () => {
    const status = deferred<Record<string, unknown>>();
    mockGetApplication.mockReturnValue(status.promise);
    render(<ClaimCredentialDialog {...props} />);
    await screen.findByTestId('claim-invite-display');
    act(() => { window.dispatchEvent(new Event('focus')); window.dispatchEvent(new Event('focus')); });
    expect(mockGetApplication).toHaveBeenCalledTimes(1);
    await act(async () => status.resolve({ ...offer, claim_state: 'BLOCKED', claim_blocker: { message: 'Issuer approval is required.' } }));
    expect(await screen.findByText('Issuer approval is required.')).toBeInTheDocument();
    expect(screen.queryByTestId('claim-invite-display')).not.toBeInTheDocument();
    expect(screen.queryByText('Ready', { exact: true })).not.toBeInTheDocument();
    expect(mockGenerateIssuanceOffer).toHaveBeenCalledTimes(1);
  });

  it('discards a late return read after switching applications and removes its listeners on unmount', async () => {
    const previous = deferred<Record<string, unknown>>();
    mockGetApplication.mockReturnValue(previous.promise);
    mockGenerateIssuanceOffer.mockImplementation((id) => Promise.resolve({ ...offer, id, offer_url: 'https://issuer.example/offers/' + id }));
    const view = render(<ClaimCredentialDialog {...props} />);
    await screen.findByTestId('claim-invite-display');
    act(() => window.dispatchEvent(new Event('focus')));
    expect(mockGetApplication).toHaveBeenCalledWith('app-1');
    view.rerender(<ClaimCredentialDialog {...props} applicationId="app-2" organizationId="org-2" />);
    expect(await screen.findByTestId('claim-invite-url')).toHaveTextContent('/app-2');
    await act(async () => previous.resolve({ ...offer, claim_state: 'CLAIMED' }));
    expect(screen.getByTestId('claim-invite-url')).toHaveTextContent('/app-2');
    view.unmount();
    act(() => window.dispatchEvent(new Event('focus')));
    expect(mockGetApplication).toHaveBeenCalledTimes(1);
  });

  it('does not preserve an actionable invite after failed or mismatched status readback', async () => {
    mockGetApplication.mockResolvedValue({ ...offer, id: 'different-application' });
    render(<ClaimCredentialDialog {...props} />);
    await screen.findByTestId('claim-invite-display');
    act(() => window.dispatchEvent(new Event('focus')));
    expect(await screen.findByText('Could not confirm the current claim status. Try again.')).toBeInTheDocument();
    expect(screen.queryByTestId('claim-invite-display')).not.toBeInTheDocument();
    expect(mockGenerateIssuanceOffer).toHaveBeenCalledTimes(1);
  });

  it('describes mailto as an email draft without claiming the message was sent', async () => {
    const windowOpen = vi.spyOn(window, 'open').mockImplementation(() => null);
    try {
      const { user } = render(<ClaimCredentialDialog {...props} />);
      await screen.findByTestId('claim-invite-display');
      await user.click(screen.getByRole('button', { name: 'Email link' }));
      await user.click(screen.getByRole('button', { name: 'Open email draft' }));
      expect(windowOpen).toHaveBeenCalledWith(expect.stringMatching(/^mailto:applicant@example.com\?/), '_blank');
      expect(await screen.findByText(/Complete and send the message in your email app/)).toBeInTheDocument();
      expect(screen.queryByText(/Email sent|Sent!/)).not.toBeInTheDocument();
    } finally {
      windowOpen.mockRestore();
    }
  });
});
