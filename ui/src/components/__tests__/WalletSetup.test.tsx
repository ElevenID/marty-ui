import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@test/utils';

import WalletSetup from '../WalletSetup';

const {
  mockIssueRemotePairingTicket,
  mockLoadRemotePairingStatus,
  mockRegisterWalletPushNotifications,
  mockListTrustProfiles,
} = vi.hoisted(() => ({
  mockIssueRemotePairingTicket: vi.fn(),
  mockLoadRemotePairingStatus: vi.fn(),
  mockRegisterWalletPushNotifications: vi.fn(),
  mockListTrustProfiles: vi.fn(),
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

vi.mock('../../services/presentationPolicyApi', () => ({
  listTrustProfiles: (...args: unknown[]) => mockListTrustProfiles(...args),
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
    MOCK_AUTH.organizationId = 'org-1';
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
    mockListTrustProfiles.mockResolvedValue([{ id: '11111111-2222-4333-8444-555555555555', name: 'Wallet trust', status: 'active' }]);
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
      expect(mockIssueRemotePairingTicket).toHaveBeenCalledWith({ organizationId: 'org-1', trustProfileId: '11111111-2222-4333-8444-555555555555' });
    });

    expect(screen.queryByTestId('simulate-pairing-button')).not.toBeInTheDocument();
    expect(screen.queryByTestId('wallet-connected-alert')).not.toBeInTheDocument();
  });

  it('registers notifications through the application layer', async () => {
    mockLoadRemotePairingStatus.mockResolvedValue({ state: 'paired', registration_id: 'registration-1' });
    render(<WalletSetup />);

    await screen.findByTestId('pairing-qr-code');
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

  it('discards a prior organization ticket that resolves after the new ticket', async () => {
    const pending = new Map<string, (ticket: unknown) => void>();
    mockListTrustProfiles.mockImplementation(({ organization_id }: { organization_id: string }) =>
      Promise.resolve([{ id: '11111111-2222-4333-8444-555555555555', name: organization_id, status: 'active' }]));
    mockIssueRemotePairingTicket.mockImplementation(({ organizationId }: { organizationId: string }) =>
      new Promise((resolve) => { pending.set(organizationId, resolve); }));

    const { rerender } = render(<WalletSetup />);
    await waitFor(() => expect(pending.has('org-1')).toBe(true));

    MOCK_AUTH.organizationId = 'org-2';
    rerender(<WalletSetup />);
    await waitFor(() => expect(pending.has('org-2')).toBe(true));

    const expires_at = new Date(Date.now() + 300000).toISOString();
    await act(async () => {
      pending.get('org-2')?.({ pairing_code: 'B'.repeat(43), pairing_id: '22222222-2222-4333-8444-555555555555', expires_at });
    });
    expect(screen.getByTestId('pairing-code')).toHaveTextContent('B'.repeat(43));

    await act(async () => {
      pending.get('org-1')?.({ pairing_code: 'A'.repeat(43), pairing_id: '11111111-2222-4333-8444-555555555555', expires_at });
    });
    expect(screen.getByTestId('pairing-code')).toHaveTextContent('B'.repeat(43));
  });

  it('discards a prior Trust Profile ticket after the selection changes', async () => {
    const pending = new Map<string, (ticket: unknown) => void>();
    const firstProfile = '11111111-2222-4333-8444-555555555555';
    const secondProfile = '22222222-2222-4333-8444-555555555555';
    mockListTrustProfiles.mockResolvedValue([
      { id: firstProfile, name: 'Profile A', status: 'active' },
      { id: secondProfile, name: 'Profile B', status: 'active' },
    ]);
    mockIssueRemotePairingTicket.mockImplementation(({ trustProfileId }: { trustProfileId: string }) =>
      new Promise((resolve) => { pending.set(trustProfileId, resolve); }));

    render(<WalletSetup />);
    await waitFor(() => expect(mockListTrustProfiles).toHaveBeenCalled());
    fireEvent.mouseDown(screen.getByRole('combobox', { name: 'Trust Profile' }));
    fireEvent.click(await screen.findByRole('option', { name: 'Profile A' }));
    await waitFor(() => expect(pending.has(firstProfile)).toBe(true));

    fireEvent.mouseDown(screen.getByRole('combobox', { name: 'Trust Profile' }));
    fireEvent.click(await screen.findByRole('option', { name: 'Profile B' }));
    await waitFor(() => expect(pending.has(secondProfile)).toBe(true));

    const expires_at = new Date(Date.now() + 300000).toISOString();
    await act(async () => {
      pending.get(secondProfile)?.({ pairing_code: 'B'.repeat(43), pairing_id: secondProfile, expires_at });
    });
    expect(screen.getByTestId('pairing-code')).toHaveTextContent('B'.repeat(43));

    await act(async () => {
      pending.get(firstProfile)?.({ pairing_code: 'A'.repeat(43), pairing_id: firstProfile, expires_at });
    });
    expect(screen.getByTestId('pairing-code')).toHaveTextContent('B'.repeat(43));
  });

  it('keeps verifier selection explicit and discards a late ticket for a previous verifier', async () => {
    const issuer = '11111111-2222-4333-8444-555555555555';
    const verifierA = '22222222-2222-4333-8444-555555555555';
    const verifierB = '33333333-2222-4333-8444-555555555555';
    const pending = new Map<string, (ticket: unknown) => void>();
    mockListTrustProfiles.mockResolvedValue([
      { id: issuer, name: 'Issuer profile', status: 'active', trust_purposes: ['CREDENTIAL_ISSUER'] },
      { id: verifierA, name: 'Verifier A', status: 'active', trust_purposes: ['PRESENTATION_VERIFIER'] },
      { id: verifierB, name: 'Verifier B', status: 'active', trust_purposes: ['PRESENTATION_VERIFIER'] },
    ]);
    mockIssueRemotePairingTicket.mockImplementation(({ verifierTrustProfileId }: { verifierTrustProfileId?: string }) =>
      new Promise((resolve) => { pending.set(verifierTrustProfileId || 'none', resolve); }));
    render(<WalletSetup />);
    await waitFor(() => expect(pending.has('none')).toBe(true));
    expect(mockIssueRemotePairingTicket).toHaveBeenCalledWith({ organizationId: 'org-1', trustProfileId: issuer });
    const selector = () => screen.getByRole('combobox', { name: 'Verifier Trust Profile (optional)' });
    fireEvent.mouseDown(selector());
    expect(screen.queryByRole('option', { name: 'Issuer profile' })).not.toBeInTheDocument();
    fireEvent.click(await screen.findByRole('option', { name: 'Verifier A' }));
    await waitFor(() => expect(pending.has(verifierA)).toBe(true));
    fireEvent.mouseDown(selector());
    fireEvent.click(await screen.findByRole('option', { name: 'Verifier B' }));
    await waitFor(() => expect(pending.has(verifierB)).toBe(true));
    const expires_at = new Date(Date.now() + 300000).toISOString();
    await act(async () => {
      pending.get(verifierB)?.({ pairing_code: 'B'.repeat(43), pairing_id: verifierB, expires_at });
    });
    expect(screen.getByTestId('pairing-code')).toHaveTextContent('B'.repeat(43));
    await act(async () => {
      pending.get(verifierA)?.({ pairing_code: 'A'.repeat(43), pairing_id: verifierA, expires_at });
      pending.get('none')?.({ pairing_code: 'C'.repeat(43), pairing_id: issuer, expires_at });
    });
    expect(screen.getByTestId('pairing-code')).toHaveTextContent('B'.repeat(43));
  });

  it('discards a prior pairing status after the verifier selection changes', async () => {
    let completePriorStatus: (status: unknown) => void = () => {};
    const issuer = '11111111-2222-4333-8444-555555555555';
    const verifier = '22222222-2222-4333-8444-555555555555';
    mockListTrustProfiles.mockResolvedValue([
      { id: issuer, name: 'Issuer profile', status: 'active', trust_purposes: ['CREDENTIAL_ISSUER'] },
      { id: verifier, name: 'Verifier profile', status: 'active', trust_purposes: ['PRESENTATION_VERIFIER'] },
    ]);
    mockLoadRemotePairingStatus.mockImplementationOnce(() => new Promise((resolve) => { completePriorStatus = resolve; }));
    render(<WalletSetup />);
    await screen.findByTestId('pairing-qr-code');
    await act(async () => { await vi.advanceTimersByTimeAsync(3000); });
    await waitFor(() => expect(mockLoadRemotePairingStatus).toHaveBeenCalledTimes(1));
    fireEvent.mouseDown(screen.getByRole('combobox', { name: 'Verifier Trust Profile (optional)' }));
    fireEvent.click(await screen.findByRole('option', { name: 'Verifier profile' }));
    await waitFor(() => expect(mockIssueRemotePairingTicket).toHaveBeenLastCalledWith({
      organizationId: 'org-1', trustProfileId: issuer, verifierTrustProfileId: verifier,
    }));
    await act(async () => { completePriorStatus({ state: 'paired', registration_id: 'previous-registration' }); });
    expect(screen.queryByTestId('wallet-connected-alert')).not.toBeInTheDocument();
    expect(screen.queryByTestId('enable-notifications-button')).not.toBeInTheDocument();
  });
});
