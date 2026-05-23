import { beforeEach, describe, expect, it, vi } from 'vitest';
import { screen, waitFor, renderWithRouter } from '@test/utils';

import CanvasMirrorProvenanceLookup from './CanvasMirrorProvenanceLookup';

const { mockGetCanvasMirrorProvenance } = vi.hoisted(() => ({
  mockGetCanvasMirrorProvenance: vi.fn(),
}));

vi.mock('../../services/canvasIntegrationsApi', () => ({
  getCanvasMirrorProvenance: mockGetCanvasMirrorProvenance,
}));

const provenanceResponse = {
  delivery_record_id: 'delivery-1',
  organization_id: 'org-1',
  canvas_account_id: 'canvas-account-1',
  mirror: {
    provider: 'canvas',
    delivery_target: 'canvas_credentials',
    delivery_status: 'delivered',
    delivery_mode: 'wallet_plus_canvas_mirror',
    external_credential_id: 'canvas-cred-1',
    external_issuer_id: 'canvas-issuer-1',
    metadata: { published_at: '2026-03-01T12:00:00+00:00' },
  },
  canonical_credential: {
    credential_id: 'cred-1',
    credential_template_id: 'template-1',
    credential_format: 'SD_JWT_VC',
    credential_status: 'ACTIVE',
    subject_id_hash: 'hash-123',
    issued_at: '2026-03-01T10:00:00+00:00',
  },
  canonical_issuance: {
    transaction_id: 'tx-1',
    application_id: 'app-1',
  },
  issuer: {
    issuer_did: 'did:web:issuer.example',
    issuer_profile_id: 'issuer-profile-1',
    issuer_mode: 'org_managed',
    credential_issuer_url: 'https://issuer.example/org/org-1',
  },
  trust_basis: {
    canonical_issuance_backed: true,
    mirror_backed_by_delivery_record: true,
    organization_consistent: true,
    distribution_channel: 'canvas_credentials',
    credential_status: 'ACTIVE',
  },
};

describe('CanvasMirrorProvenanceLookup', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGetCanvasMirrorProvenance.mockResolvedValue(provenanceResponse);
  });

  it('loads provenance from initial params and shows canonical issuer context', async () => {
    renderWithRouter(
      <CanvasMirrorProvenanceLookup
        initialParams={{
          externalCredentialId: 'canvas-cred-1',
          canvasAccountId: 'canvas-account-1',
        }}
      />,
    );

    await screen.findByTestId('canvas-provenance-result');

    expect(mockGetCanvasMirrorProvenance).toHaveBeenCalledWith({
      externalCredentialId: 'canvas-cred-1',
      canvasAccountId: 'canvas-account-1',
      organizationId: undefined,
    });
    expect(screen.getByText('Canonical issuance found')).toBeInTheDocument();
    expect(screen.getAllByText('did:web:issuer.example').length).toBeGreaterThan(0);
    expect(screen.getByText('canvas-cred-1')).toBeInTheDocument();
    expect(screen.getByText('hash-123')).toBeInTheDocument();
  });

  it('submits a manual lookup by delivery record ID', async () => {
    const { user } = renderWithRouter(<CanvasMirrorProvenanceLookup />);

    await user.click(screen.getByRole('button', { name: 'Delivery ID' }));
    await user.type(screen.getByTestId('canvas-provenance-lookup'), 'delivery-1');
    await user.type(screen.getByLabelText('Organization'), 'org-1');
    await user.click(screen.getByRole('button', { name: /resolve/i }));

    await waitFor(() => {
      expect(mockGetCanvasMirrorProvenance).toHaveBeenCalledWith({
        deliveryRecordId: 'delivery-1',
        canvasAccountId: undefined,
        organizationId: 'org-1',
      });
    });
    expect(await screen.findByTestId('canvas-provenance-result')).toBeInTheDocument();
  });
});
