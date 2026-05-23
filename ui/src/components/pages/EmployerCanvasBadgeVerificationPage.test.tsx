import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, renderWithRouter } from '@test/utils';

import EmployerCanvasBadgeVerificationPage from './EmployerCanvasBadgeVerificationPage';

const { mockGetCanvasMirrorProvenance } = vi.hoisted(() => ({
  mockGetCanvasMirrorProvenance: vi.fn(),
}));

vi.mock('../../services/canvasIntegrationsApi', () => ({
  getCanvasMirrorProvenance: mockGetCanvasMirrorProvenance,
}));

const provenanceResponse = {
  delivery_record_id: 'delivery-1',
  organization_id: 'org-1',
  canvas_account_id: 'canvas-real-account-1',
  mirror: {
    provider: 'canvas',
    delivery_target: 'canvas_credentials',
    delivery_status: 'delivered',
    delivery_mode: 'wallet_plus_canvas_mirror',
    external_credential_id: 'canvas-sandbox-credential-1',
    external_issuer_id: 'canvas-issuer-1',
    metadata: {
      published_at: '2026-05-19T12:00:00+00:00',
      publish_response: {
        credential_url: 'https://canvas-sandbox.elevenidllc.com/credentials/canvas-sandbox-credential-1',
      },
    },
  },
  canonical_credential: {
    credential_id: 'credential-1',
    credential_template_id: 'template-1',
    credential_format: 'SD_JWT_VC',
    credential_status: 'ACTIVE',
    subject_id_hash: 'subject-hash-1',
    issued_at: '2026-05-19T11:00:00+00:00',
  },
  canonical_issuance: {
    transaction_id: 'tx-1',
    application_id: 'app-1',
  },
  issuer: {
    issuer_did: 'did:web:beta.elevenidllc.com:orgs:marty',
    issuer_profile_id: 'ip-marty-vc-jwt-issuer',
    issuer_mode: 'org_managed',
    credential_issuer_url: 'https://beta.elevenidllc.com/org/org-1',
  },
  trust_basis: {
    canonical_issuance_backed: true,
    mirror_backed_by_delivery_record: true,
    organization_consistent: true,
    distribution_channel: 'canvas_credentials',
    credential_status: 'ACTIVE',
  },
};

describe('EmployerCanvasBadgeVerificationPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetCanvasMirrorProvenance.mockResolvedValue(provenanceResponse);
  });

  it('loads an employer verification result from a Canvas credential URL', async () => {
    renderWithRouter(<EmployerCanvasBadgeVerificationPage />, {
      initialEntries: [
        '/verify/canvas-credentials?external_credential_id=canvas-sandbox-credential-1&canvas_account_id=canvas-real-account-1&organization_id=org-1',
      ],
    });

    await screen.findByTestId('employer-canvas-verification-result');

    expect(mockGetCanvasMirrorProvenance).toHaveBeenCalledWith({
      externalCredentialId: 'canvas-sandbox-credential-1',
      canvasAccountId: 'canvas-real-account-1',
      organizationId: 'org-1',
    });
    expect(screen.getByText('Verified for employer review')).toBeInTheDocument();
    expect(screen.getByText('Canvas Credential')).toBeInTheDocument();
    expect(screen.getAllByText('did:web:beta.elevenidllc.com:orgs:marty').length).toBeGreaterThan(0);
    expect(screen.getByText('subject-hash-1')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /view canvas credential mirror/i })).toHaveAttribute(
      'href',
      'https://canvas-sandbox.elevenidllc.com/credentials/canvas-sandbox-credential-1',
    );
  });

  it('submits a manual Canvas credential lookup', async () => {
    const { user } = renderWithRouter(<EmployerCanvasBadgeVerificationPage />, {
      initialEntries: ['/verify/canvas-credentials'],
    });

    await user.type(screen.getByTestId('employer-canvas-lookup'), 'canvas-sandbox-credential-1');
    await user.type(screen.getByLabelText('Canvas Account'), 'canvas-real-account-1');
    await user.click(screen.getByRole('button', { name: /verify badge/i }));

    await waitFor(() => {
      expect(mockGetCanvasMirrorProvenance).toHaveBeenCalledWith({
        externalCredentialId: 'canvas-sandbox-credential-1',
        canvasAccountId: 'canvas-real-account-1',
        organizationId: undefined,
      });
    });
    expect(await screen.findByTestId('employer-canvas-verification-result')).toBeInTheDocument();
  });
});
