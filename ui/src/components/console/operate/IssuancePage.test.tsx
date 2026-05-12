import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { screen, waitFor } from '@testing-library/react';
import { renderWithoutRouter } from '../../../test/utils';
import IssuancePage from './IssuancePage';
import { formatOfficialReference } from '../../../utils/officialReferences';

const {
  mockFetchIssuedCredentials,
  mockGenerateIssuanceOffer,
  mockListCredentialTemplates,
  mockShowSuccess,
  mockShowError,
} = vi.hoisted(() => ({
  mockFetchIssuedCredentials: vi.fn(),
  mockGenerateIssuanceOffer: vi.fn(),
  mockListCredentialTemplates: vi.fn(),
  mockShowSuccess: vi.fn(),
  mockShowError: vi.fn(),
}));

vi.mock('../../../hooks/useAuth', () => ({
  useAuth: () => ({
    organizationId: 'org-123',
  }),
}));

vi.mock('../../../application/vendor', () => ({
  fetchIssuedCredentials: (...args: unknown[]) => mockFetchIssuedCredentials(...args),
}));

vi.mock('../../../hooks/useNotifications', () => ({
  useNotifications: () => ({
    showSuccess: mockShowSuccess,
    showError: mockShowError,
  }),
}));

vi.mock('../../../services/presentationPolicyApi', () => ({
  listCredentialTemplates: (...args: unknown[]) => mockListCredentialTemplates(...args),
}));

vi.mock('../../../services/credentialsApi', () => ({
  generateIssuanceOffer: (...args: unknown[]) => mockGenerateIssuanceOffer(...args),
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
          holder_email: 'holder@example.com',
          issued_date: '2026-05-07T12:00:00Z',
          expiry_date: '2026-06-07T12:00:00Z',
          status: 'active',
          application_id: 'application-1',
          credential_template_id: 'template-open-badge',
          issuer_did: 'did:web:issuer.example.com',
        },
      ],
      total: 1,
    });
    mockGenerateIssuanceOffer.mockResolvedValue({
      offer_url: 'openid-credential-offer://offer/test',
      expires_at: '2026-05-07T12:15:00Z',
      status: 'active',
    });
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
    expect(screen.getByText(formatOfficialReference('template-open-badge', 'template'))).toBeInTheDocument();
    expect(screen.queryByText('Active Offers')).not.toBeInTheDocument();
  });

  it('opens the detail view and reissues a fresh wallet offer', async () => {
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

    await user.click(screen.getByRole('button', { name: /^reissue$/i }));

    await waitFor(() => {
      expect(mockGenerateIssuanceOffer).toHaveBeenCalledWith('application-1');
    });

    expect(screen.getByText('Fresh wallet offer ready')).toBeInTheDocument();
    expect(screen.getByText('openid-credential-offer://offer/test')).toBeInTheDocument();
  });
});