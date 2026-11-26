import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@test/utils';

import WalletSetup from '../WalletSetup';
import WebSurfaceBoundary from '../../apps/shared/WebSurfaceBoundary';
import { redirectBrowser } from '../../application/routing/appHandoff';

const {
  mockIssueRemotePairingTicket,
  mockLoadRemotePairingStatus,
  mockRegisterWalletPushNotifications,
  mockListTrustProfiles,
  mockUsePermissions,
  mockUseConsole,
} = vi.hoisted(() => ({
  mockIssueRemotePairingTicket: vi.fn(),
  mockLoadRemotePairingStatus: vi.fn(),
  mockRegisterWalletPushNotifications: vi.fn(),
  mockListTrustProfiles: vi.fn(),
  mockUsePermissions: vi.fn(),
  mockUseConsole: vi.fn(),
}));

// Stable references — prevent useCallback identity churn
const MOCK_AUTH = { user: { user_id: 'user-1' }, organizationId: 'org-1', isAuthenticated: true };
const MOCK_BRANDING = { authenticatorName: 'Demo Authenticator', deepLinkProtocol: 'marty-auth:' };
const MOCK_CONSOLE = { mode: 'org', activeOrgId: 'org-1' };
const PROFILE_PERMISSIONS = new Set<string>();
const MOCK_PERMISSIONS = {
  can: (resource: string, action: string) => PROFILE_PERMISSIONS.has(`${resource}:${action}`),
  isLoading: false,
  error: null as Error | null,
};

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => MOCK_AUTH,
}));

vi.mock('../../hooks/useBranding', () => ({
  useBranding: () => MOCK_BRANDING,
}));

vi.mock('../../hooks/usePermissions', () => ({
  usePermissions: () => mockUsePermissions(),
}));

vi.mock('../../contexts/ConsoleContext', () => ({
  useConsole: () => mockUseConsole(),
}));

vi.mock('../../application/routing/appHandoff', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../application/routing/appHandoff')>(),
  redirectBrowser: vi.fn(() => true),
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
    MOCK_AUTH.user.user_id = 'user-1';
    MOCK_CONSOLE.mode = 'org';
    MOCK_CONSOLE.activeOrgId = 'org-1';
    MOCK_PERMISSIONS.isLoading = false;
    MOCK_PERMISSIONS.error = null;
    PROFILE_PERMISSIONS.clear();
    PROFILE_PERMISSIONS.add('trust-profile:view');
    PROFILE_PERMISSIONS.add('trust-profile:create');
    vi.stubEnv('VITE_API_URL', 'https://wallet.example');
    // Fake timers prevent the countdown (setTimeout ×300) and polling
    // (setInterval 3 s) from keeping the test alive.
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.clearAllMocks();
    mockUsePermissions.mockReset().mockReturnValue(MOCK_PERMISSIONS);
    mockUseConsole.mockReset().mockReturnValue(MOCK_CONSOLE);
    window.history.replaceState({}, '', '/wallet/setup');

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
    window.history.replaceState({}, '', '/');
  });

  it('explains missing active issuers and reloads a newly activated profile without remounting', async () => {
    let resolveProfiles: (profiles: unknown[]) => void = () => {};
    mockListTrustProfiles.mockImplementationOnce(() => new Promise((resolve) => { resolveProfiles = resolve; }));
    const issuer = { id: '11111111-2222-4333-8444-555555555555', name: 'Issuer profile', status: 'draft', trust_purposes: ['CREDENTIAL_ISSUER'] };
    const verifier = { id: '22222222-2222-4333-8444-555555555555', name: 'Verifier profile', status: 'active', trust_purposes: ['PRESENTATION_VERIFIER'] };
    render(<WebSurfaceBoundary><WalletSetup /></WebSurfaceBoundary>);

    expect(screen.getByRole('status')).toHaveTextContent('Loading Trust Profiles');
    expect(screen.queryByTestId('wallet-profiles-empty')).not.toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Trust Profile' })).toHaveAttribute('aria-disabled', 'true');
    await act(async () => { resolveProfiles([issuer, verifier]); });

    expect(screen.getByTestId('wallet-profiles-empty')).toHaveTextContent('No active issuer Trust Profiles');
    expect(screen.getByRole('link', { name: 'Set up Trust Profiles' })).toHaveAttribute('href', '/console/org/trust/profiles');
    fireEvent.click(screen.getByRole('link', { name: 'Set up Trust Profiles' }), { button: 0 });
    expect(redirectBrowser).toHaveBeenCalledExactlyOnceWith('/console/org/trust/profiles', { replace: false });
    expect(screen.queryByTestId('pairing-qr-code')).not.toBeInTheDocument();
    expect(mockIssueRemotePairingTicket).not.toHaveBeenCalled();

    mockListTrustProfiles.mockResolvedValue([{ ...issuer, status: 'active' }, verifier]);
    fireEvent.click(screen.getByRole('button', { name: 'Reload profiles' }));

    await screen.findByTestId('pairing-qr-code');
    expect(mockListTrustProfiles).toHaveBeenCalledTimes(2);
    expect(mockListTrustProfiles).toHaveBeenLastCalledWith({ organization_id: 'org-1' });
    expect(mockIssueRemotePairingTicket).toHaveBeenCalledExactlyOnceWith({ organizationId: 'org-1', trustProfileId: issuer.id });
    expect(screen.queryByTestId('wallet-profiles-empty')).not.toBeInTheDocument();
    expect(screen.queryByTestId('wallet-setup-success')).not.toBeInTheDocument();
  });

  it('offers owner setup only for verified management permissions in the wallet organization', async () => {
    mockListTrustProfiles.mockResolvedValue([]);
    const { rerender } = render(<WalletSetup />);
    await screen.findByTestId('wallet-profiles-empty');
    expect(screen.getByRole('link', { name: 'Set up Trust Profiles' })).toBeInTheDocument();

    MOCK_PERMISSIONS.isLoading = true;
    rerender(<WalletSetup />);
    expect(screen.queryByRole('link', { name: 'Set up Trust Profiles' })).not.toBeInTheDocument();
    MOCK_PERMISSIONS.isLoading = false;
    MOCK_PERMISSIONS.error = new Error('Permission lookup failed');
    rerender(<WalletSetup />);
    expect(screen.queryByRole('link', { name: 'Set up Trust Profiles' })).not.toBeInTheDocument();
    MOCK_PERMISSIONS.error = null;
    MOCK_CONSOLE.activeOrgId = 'org-2';
    rerender(<WalletSetup />);
    expect(screen.queryByRole('link', { name: 'Set up Trust Profiles' })).not.toBeInTheDocument();
    MOCK_CONSOLE.activeOrgId = 'org-1';
    PROFILE_PERMISSIONS.delete('trust-profile:view');
    rerender(<WalletSetup />);
    expect(screen.queryByRole('link', { name: 'Set up Trust Profiles' })).not.toBeInTheDocument();
    PROFILE_PERMISSIONS.add('trust-profile:view');
    PROFILE_PERMISSIONS.delete('trust-profile:create');
    rerender(<WalletSetup />);
    expect(screen.queryByRole('link', { name: 'Set up Trust Profiles' })).not.toBeInTheDocument();
    expect(screen.getByTestId('wallet-profiles-empty')).toHaveTextContent('check your access');
    expect(screen.getByRole('link', { name: 'Open my organizations' })).toHaveAttribute('href', '/console/organizations');
    PROFILE_PERMISSIONS.add('trust-profile:activate');
    rerender(<WalletSetup />);
    expect(screen.getByRole('link', { name: 'Set up Trust Profiles' })).toBeInTheDocument();
    expect(mockIssueRemotePairingTicket).not.toHaveBeenCalled();
  });

  it('offers organization selection in the actual initial public context without claiming owner permissions', async () => {
    const actualConsole = await vi.importActual<typeof import('../../contexts/ConsoleContext')>('../../contexts/ConsoleContext');
    const actualPermissions = await vi.importActual<typeof import('../../hooks/usePermissions')>('../../hooks/usePermissions');
    // The real context starts in applicant mode with no selected membership.
    // Even an owner must select its organization before the real hook grants access.
    mockUseConsole.mockImplementation(actualConsole.useConsole);
    mockUsePermissions.mockImplementation(actualPermissions.usePermissions);
    mockListTrustProfiles.mockResolvedValue([]);
    MOCK_AUTH.organizationId = '';
    const { rerender } = render(<WebSurfaceBoundary><WalletSetup /></WebSurfaceBoundary>);

    expect(screen.getByText('Select an organization to load wallet Trust Profiles.')).toBeInTheDocument();
    expect(mockListTrustProfiles).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('link', { name: 'Open my organizations' }), { button: 0 });
    expect(redirectBrowser).toHaveBeenCalledExactlyOnceWith('/console/organizations', { replace: false });

    MOCK_AUTH.organizationId = 'org-1';
    rerender(<WebSurfaceBoundary><WalletSetup /></WebSurfaceBoundary>);

    await screen.findByTestId('wallet-profiles-empty');
    expect(screen.queryByRole('link', { name: 'Set up Trust Profiles' })).not.toBeInTheDocument();
    const organizations = screen.getByRole('link', { name: 'Open my organizations' });
    expect(organizations).toHaveAttribute('href', '/console/organizations');
    expect(screen.getByTestId('wallet-profiles-empty')).toHaveTextContent('check your access');
    fireEvent.click(organizations, { button: 0 });
    expect(redirectBrowser).toHaveBeenCalledTimes(2);
    expect(redirectBrowser).toHaveBeenLastCalledWith('/console/organizations', { replace: false });
    expect(window.location.pathname).toBe('/wallet/setup');
    expect(mockIssueRemotePairingTicket).not.toHaveBeenCalled();
  });

  it('distinguishes a failed profile lookup from an empty list and supports retry', async () => {
    mockListTrustProfiles.mockRejectedValueOnce(new Error('Unavailable'));
    render(<WalletSetup />);
    await screen.findByTestId('wallet-profiles-error');
    expect(screen.queryByTestId('wallet-profiles-empty')).not.toBeInTheDocument();
    expect(screen.queryByTestId('pairing-qr-code')).not.toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Set up Trust Profiles' })).not.toBeInTheDocument();
    expect(mockIssueRemotePairingTicket).not.toHaveBeenCalled();

    mockListTrustProfiles.mockResolvedValue([]);
    fireEvent.click(screen.getByRole('button', { name: 'Reload profiles' }));
    await screen.findByTestId('wallet-profiles-empty');
    expect(screen.queryByTestId('wallet-profiles-error')).not.toBeInTheDocument();
    expect(mockListTrustProfiles).toHaveBeenCalledTimes(2);
  });

  it.each(['organization', 'actor'])('discards a late profile list after the %s changes', async (changedScope) => {
    const pending: Array<(profiles: unknown[]) => void> = [];
    mockListTrustProfiles.mockImplementation(() => new Promise((resolve) => { pending.push(resolve); }));
    const { rerender } = render(<WalletSetup />);
    await waitFor(() => expect(pending).toHaveLength(1));
    if (changedScope === 'organization') MOCK_AUTH.organizationId = 'org-2';
    else MOCK_AUTH.user.user_id = 'user-2';
    rerender(<WalletSetup />);
    await waitFor(() => expect(pending).toHaveLength(2));
    const issuer = { id: '22222222-2222-4333-8444-555555555555', name: 'Current issuer', status: 'active', trust_purposes: ['CREDENTIAL_ISSUER'] };
    await act(async () => { pending[1]([issuer]); });
    await screen.findByTestId('pairing-qr-code');
    await act(async () => { pending[0]([]); });

    expect(screen.queryByTestId('wallet-profiles-empty')).not.toBeInTheDocument();
    expect(screen.getByRole('combobox', { name: 'Trust Profile' })).toHaveTextContent('Current issuer');
    expect(mockIssueRemotePairingTicket).toHaveBeenCalledExactlyOnceWith({ organizationId: MOCK_AUTH.organizationId, trustProfileId: issuer.id });
  });

  it('invalidates an outstanding pairing ticket when profiles are reloaded', async () => {
    let resolveTicket: (ticket: unknown) => void = () => {};
    mockIssueRemotePairingTicket.mockImplementationOnce(() => new Promise((resolve) => { resolveTicket = resolve; }));
    render(<WalletSetup />);
    await waitFor(() => expect(mockIssueRemotePairingTicket).toHaveBeenCalledTimes(1));
    mockListTrustProfiles.mockResolvedValue([]);
    fireEvent.click(screen.getByRole('button', { name: 'Reload profiles' }));
    await screen.findByTestId('wallet-profiles-empty');
    await act(async () => {
      resolveTicket({ pairing_code: 'A'.repeat(43), pairing_id: '11111111-2222-4333-8444-555555555555', expires_at: new Date(Date.now() + 300000).toISOString() });
    });
    expect(screen.queryByTestId('pairing-qr-code')).not.toBeInTheDocument();
    expect(screen.queryByTestId('wallet-setup-success')).not.toBeInTheDocument();
    expect(screen.queryByTestId('wallet-connected-alert')).not.toBeInTheDocument();
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
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Trust Profile' })).not.toHaveAttribute('aria-disabled', 'true'));
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
