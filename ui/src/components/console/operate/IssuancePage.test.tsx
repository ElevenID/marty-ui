import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MemoryRouter, Route, Routes } from 'react-router';
import { screen, waitFor } from '@testing-library/react';
import { renderWithoutRouter } from '../../../test/utils';
import IssuancePage from './IssuancePage';
import { formatOfficialReference } from '../../../utils/officialReferences';

const {
  mockFetchIssuedCredentials,
  mockSuspendCredential,
  mockReinstateCredential,
  mockRevokeCredential,
  mockRenewCredential,
  mockListCredentialTemplates,
  mockShowSuccess,
  mockShowInfo,
  mockShowError,
} = vi.hoisted(() => ({
  mockFetchIssuedCredentials: vi.fn(),
  mockSuspendCredential: vi.fn(),
  mockReinstateCredential: vi.fn(),
  mockRevokeCredential: vi.fn(),
  mockRenewCredential: vi.fn(),
  mockListCredentialTemplates: vi.fn(),
  mockShowSuccess: vi.fn(),
  mockShowInfo: vi.fn(),
  mockShowError: vi.fn(),
}));

vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-123' }),
}));

vi.mock('../../../application/vendor', () => ({
  fetchIssuedCredentials: (...args: unknown[]) => mockFetchIssuedCredentials(...args),
  suspendCredential: (...args: unknown[]) => mockSuspendCredential(...args),
  reinstateCredential: (...args: unknown[]) => mockReinstateCredential(...args),
  revokeCredential: (...args: unknown[]) => mockRevokeCredential(...args),
  renewCredential: (...args: unknown[]) => mockRenewCredential(...args),
}));

vi.mock('../../../hooks/useNotifications', () => ({
  useNotifications: () => ({
    showSuccess: mockShowSuccess,
    showInfo: mockShowInfo,
    showError: mockShowError,
  }),
}));

vi.mock('../../../services/presentationPolicyApi', () => ({
  listCredentialTemplates: (...args: unknown[]) => mockListCredentialTemplates(...args),
}));

describe('IssuancePage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockFetchIssuedCredentials.mockResolvedValue({
      credentials: [
        {
          id: 'issued-rec-1',
          credential_id: 'cred-open-badge-1',
          credential_type: 'open_badge',
          type: 'open_badge',
          subject_id: 'holder@example.com',
          holder_label: 'Demo Employee 01',
          holder_email: 'holder@example.com',
          issued_date: '2026-05-07T12:00:00Z',
          expiry_date: '2026-06-07T12:00:00Z',
          status: 'ACTIVE',
          flow_execution_id: 'flow-execution-1',
          renewed_from_credential_id: 'cred-open-badge-0',
          application_id: 'application-1',
          credential_template_id: 'template-open-badge',
          issuer_did: 'did:web:issuer.example.com',
          renewable: true,
          can_renew: true,
          renewal_eligible_at: '2026-05-01T12:00:00Z',
        },
      ],
      total: 1,
    });
    mockRenewCredential.mockResolvedValue({
      credential_offer_uri: 'openid-credential-offer://offer/test',
      expires_at: '2026-05-07T12:15:00Z',
      status: 'active',
    });
    mockSuspendCredential.mockResolvedValue({ id: 'issued-rec-1', status: 'SUSPENDED' });
    mockReinstateCredential.mockResolvedValue({ id: 'issued-rec-1', status: 'ACTIVE' });
    mockRevokeCredential.mockResolvedValue({ id: 'issued-rec-1', status: 'REVOKED' });
    mockListCredentialTemplates.mockResolvedValue([
      {
        id: 'template-open-badge',
        name: 'Open Badge Login Template',
      },
    ]);
  });

  it('renders issued credentials instead of the legacy issuance tabs', async () => {
    renderWithoutRouter(
      <MemoryRouter initialEntries={['/console/org/operate/issuance']}>
        <Routes>
          <Route path="/console/org/operate/issuance" element={<IssuancePage />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByTestId('issued-credentials-page')).toBeInTheDocument();
    });

    expect(screen.getByRole('heading', { name: 'Issued Credentials' })).toBeInTheDocument();
    expect(screen.getByText(formatOfficialReference('cred-open-badge-1', 'credential'))).toBeInTheDocument();
    expect(screen.getByText('Open Badge Login Template')).toBeInTheDocument();
    expect(screen.getByText('Demo Employee 01')).toBeInTheDocument();
    expect(screen.getByText(formatOfficialReference('flow-execution-1', 'flow'))).toBeInTheDocument();
    expect(screen.getByText(`Renewed from ${formatOfficialReference('cred-open-badge-0', 'credential')}`)).toBeInTheDocument();
    expect(screen.getByText('Active')).toBeInTheDocument();
    expect(screen.getByRole('row', { name: /open badge login template/i })).toHaveAttribute(
      'data-credential-record-id',
      'issued-rec-1',
    );
    expect(screen.queryByText('Unknown')).not.toBeInTheDocument();
    expect(screen.queryByText('Active Offers')).not.toBeInTheDocument();
  });

  it('keeps the current inventory visible while a refresh is pending', async () => {
    let resolveRefresh: ((value: unknown) => void) | undefined;
    const pendingRefresh = new Promise((resolve) => { resolveRefresh = resolve; });
    const { user } = renderWithoutRouter(
      <MemoryRouter initialEntries={['/console/org/operate/issuance']}>
        <Routes>
          <Route path="/console/org/operate/issuance" element={<IssuancePage />} />
        </Routes>
      </MemoryRouter>
    );

    const reference = formatOfficialReference('cred-open-badge-1', 'credential');
    expect(await screen.findByText(reference)).toBeInTheDocument();
    mockFetchIssuedCredentials.mockReturnValueOnce(pendingRefresh);
    await user.click(screen.getByRole('button', { name: /^refresh$/i }));

    expect(screen.getByRole('progressbar', { name: /refreshing issued credentials/i })).toBeInTheDocument();
    expect(screen.getAllByText(reference).length).toBeGreaterThan(0);
    resolveRefresh?.({ credentials: [], total: 0 });
    await waitFor(() => expect(screen.queryByText(reference)).not.toBeInTheDocument());
  });

  it('opens the detail view and creates a renewal offer', async () => {
    const { user } = renderWithoutRouter(
      <MemoryRouter initialEntries={['/console/org/operate/issuance']}>
        <Routes>
          <Route path="/console/org/operate/issuance" element={<IssuancePage />} />
          <Route path="/console/org/operate/issuance/:credentialId" element={<IssuancePage />} />
        </Routes>
      </MemoryRouter>
    );

    await waitFor(() => {
      expect(screen.getByText(formatOfficialReference('cred-open-badge-1', 'credential'))).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: /view credential details/i }));

    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
    });
    expect(screen.getByRole('button', { name: /view lifecycle audit/i })).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /^renew$/i }));

    await waitFor(() => {
      expect(mockRenewCredential).toHaveBeenCalledWith({ credentialId: 'issued-rec-1' });
    });

    expect(screen.getByText(/renewal offer ready.*replacement not issued yet/i)).toBeInTheDocument();
    expect(screen.getByText('openid-credential-offer://offer/test')).toBeInTheDocument();
  });

  it('generates a row renewal without remounting or losing the filtered inventory', async () => {
    const { user } = renderWithoutRouter(
      <MemoryRouter initialEntries={['/console/org/operate/issuance']}>
        <Routes>
          <Route path="/console/org/operate/issuance" element={<IssuancePage />} />
          <Route path="/console/org/operate/issuance/:credentialId" element={<IssuancePage />} />
        </Routes>
      </MemoryRouter>
    );

    const reference = formatOfficialReference('cred-open-badge-1', 'credential');
    const search = await screen.findByPlaceholderText(/search issued credentials/i);
    await user.type(search, reference);
    await user.click(screen.getByRole('button', { name: /renew credential/i }));

    expect(await screen.findByRole('dialog')).toBeInTheDocument();
    expect(search).toHaveValue(reference);
    expect(screen.getAllByText(reference).length).toBeGreaterThan(0);
    await user.click(screen.getByRole('button', { name: /^close$/i }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
    expect(search).toHaveValue(reference);
  });

  it('requires a reason and suspends an active credential', async () => {
    const { user } = renderWithoutRouter(
      <MemoryRouter initialEntries={['/console/org/operate/issuance']}>
        <Routes>
          <Route path="/console/org/operate/issuance" element={<IssuancePage />} />
        </Routes>
      </MemoryRouter>
    );

    const suspendButton = await screen.findByRole('button', { name: /suspend credential/i });
    await user.click(suspendButton);

    const confirm = screen.getByRole('button', { name: /^suspend$/i });
    expect(confirm).toBeDisabled();
    await user.type(screen.getByRole('textbox', { name: /reason/i }), 'Membership under review');
    await user.click(confirm);

    await waitFor(() => {
      expect(mockSuspendCredential).toHaveBeenCalledWith({
        credentialId: 'issued-rec-1',
        reason: 'Membership under review',
      });
    });
    expect(mockShowInfo).toHaveBeenCalledWith(
      'Lifecycle state: Suspended. Verification policies may now deny this credential.',
      expect.objectContaining({ replaceKey: 'credential-lifecycle' }),
    );
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('reinstates a suspended credential and does not offer suspension', async () => {
    mockFetchIssuedCredentials.mockResolvedValue({
      credentials: [
        {
          id: 'issued-rec-1',
          credential_id: 'cred-open-badge-1',
          credential_type: 'open_badge',
          subject_id: 'did:key:zDemoLifecycleHolder',
          holder_email: 'did:key:zDemoLifecycleHolder',
          status: 'SUSPENDED',
        },
      ],
      total: 1,
    });

    const { user } = renderWithoutRouter(
      <MemoryRouter initialEntries={['/console/org/operate/issuance']}>
        <Routes>
          <Route path="/console/org/operate/issuance" element={<IssuancePage />} />
        </Routes>
      </MemoryRouter>
    );

    expect(await screen.findByRole('button', { name: /reinstate credential/i })).toBeInTheDocument();
    expect(screen.getByText(`Lifecycle holder • ${formatOfficialReference('did:key:zDemoLifecycleHolder', 'account')}`)).toBeInTheDocument();
    expect(screen.queryByText('did:key:zDemoLifecycleHolder')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /suspend credential/i })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /reinstate credential/i }));
    await user.type(screen.getByRole('textbox', { name: /reason/i }), 'Review complete');
    await user.click(screen.getByRole('button', { name: /^reinstate$/i }));

    await waitFor(() => {
      expect(mockReinstateCredential).toHaveBeenCalledWith({
        credentialId: 'issued-rec-1',
        reason: 'Review complete',
      });
    });
  });

  it('requires explicit confirmation before revoking', async () => {
    const { user } = renderWithoutRouter(
      <MemoryRouter initialEntries={['/console/org/operate/issuance']}>
        <Routes>
          <Route path="/console/org/operate/issuance" element={<IssuancePage />} />
        </Routes>
      </MemoryRouter>
    );

    await user.click(await screen.findByRole('button', { name: /revoke credential/i }));
    expect(screen.getByText(/revocation is permanent/i)).toBeInTheDocument();
    await user.type(screen.getByRole('textbox', { name: /reason/i }), 'Membership ended');
    await user.click(screen.getByRole('button', { name: /^revoke$/i }));

    await waitFor(() => {
      expect(mockRevokeCredential).toHaveBeenCalledWith({
        credentialId: 'issued-rec-1',
        reason: 'Membership ended',
      });
    });
  });
});
