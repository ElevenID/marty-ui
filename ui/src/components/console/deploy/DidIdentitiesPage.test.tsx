import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderWithRouter, screen, waitFor } from '@test/utils';

import DidIdentitiesPage from './DidIdentitiesPage';

const { listPublicIssuerIdentities, rebindIssuerIdentity, deleteIssuerIdentity, storeIssuerIdentityCertificate, enrollCscaCertificate, showNotification } = vi.hoisted(() => ({
  listPublicIssuerIdentities: vi.fn(),
  rebindIssuerIdentity: vi.fn(),
  deleteIssuerIdentity: vi.fn(),
  storeIssuerIdentityCertificate: vi.fn(),
  enrollCscaCertificate: vi.fn(),
  showNotification: vi.fn(),
}));

vi.mock('../../../services/signingKeysApi', () => ({
  default: {
    listPublicIssuerIdentities: (...args: unknown[]) => listPublicIssuerIdentities(...args),
    rebindIssuerIdentity: (...args: unknown[]) => rebindIssuerIdentity(...args),
    deleteIssuerIdentity: (...args: unknown[]) => deleteIssuerIdentity(...args),
    storeIssuerIdentityCertificate: (...args: unknown[]) => storeIssuerIdentityCertificate(...args),
    enrollCscaCertificate: (...args: unknown[]) => enrollCscaCertificate(...args),
  },
}));

vi.mock('../../../hooks/useNotifications', () => ({
  useNotifications: () => ({ showNotification }),
}));

vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: 'org-test-1' }),
}));

describe('DidIdentitiesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listPublicIssuerIdentities.mockImplementation(async ({ credential_format: credentialFormat }) => ({
      identities: credentialFormat === 'SD_JWT_VC'
        ? [{
          issuer_did: 'did:web:issuer.example:orgs:test',
          key_purpose: 'vc_jwt_issuer',
          algorithm: 'ES256',
          status: 'active',
        }]
        : [],
    }));
    deleteIssuerIdentity.mockResolvedValue({ deleted: { issuer_did: 'did:web:issuer.example:orgs:test' } });
    rebindIssuerIdentity.mockResolvedValue({ changed: true });
    storeIssuerIdentityCertificate.mockResolvedValue({ ok: true });
    enrollCscaCertificate.mockResolvedValue({ status: 'VALID' });
  });

  it('loads identities through format-scoped public DID queries', async () => {
    renderWithRouter(<DidIdentitiesPage />);

    expect(await screen.findByText('did:web:issuer.example:orgs:test')).toBeInTheDocument();
    expect(screen.getByText('vc_jwt_issuer')).toBeInTheDocument();
    expect(screen.getByText('SD_JWT_VC')).toBeInTheDocument();
    expect(listPublicIssuerIdentities).toHaveBeenCalledTimes(6);
    expect(listPublicIssuerIdentities).toHaveBeenCalledWith({
      organization_id: 'org-test-1',
      credential_format: 'SD_JWT_VC',
    });
  });

  it('retires an identity with the complete public tuple', async () => {
    const { user } = renderWithRouter(<DidIdentitiesPage />);
    await screen.findByText('did:web:issuer.example:orgs:test');
    await user.click(screen.getByRole('button', { name: 'Retire identity' }));
    await user.click(screen.getByRole('button', { name: 'Retire identity' }));

    await waitFor(() => {
      expect(deleteIssuerIdentity).toHaveBeenCalledWith({
        organization_id: 'org-test-1',
        issuer_did: 'did:web:issuer.example:orgs:test',
        key_purpose: 'vc_jwt_issuer',
        credential_format: 'SD_JWT_VC',
        algorithm: 'ES256',
      });
    });
    expect(showNotification).toHaveBeenCalledWith('Issuer identity retired.', 'success');
  });

  it('moves an identity to the configured default without exposing custody coordinates', async () => {
    const { user } = renderWithRouter(<DidIdentitiesPage />);
    await screen.findByText('did:web:issuer.example:orgs:test');
    await user.click(screen.getByRole('button', { name: 'Move identity to default signing service' }));
    await user.click(screen.getByRole('button', { name: 'Move identity' }));

    await waitFor(() => {
      expect(rebindIssuerIdentity).toHaveBeenCalledWith({
        organization_id: 'org-test-1',
        issuer_did: 'did:web:issuer.example:orgs:test',
        key_purpose: 'vc_jwt_issuer',
        credential_format: 'SD_JWT_VC',
        algorithm: 'ES256',
      });
    });
    expect(showNotification).toHaveBeenCalledWith(
      'Issuer identity moved to the default signing service.',
      'success',
    );
  });

  it('attaches a passport DSC through the public issuer selector without key material', async () => {
    listPublicIssuerIdentities.mockImplementation(async ({ credential_format: credentialFormat }) => ({
      identities: credentialFormat === 'ICAO_EMRTD'
        ? [{
          issuer_did: 'did:web:issuer.example:orgs:passport',
          key_purpose: 'x509_doc_signer',
          algorithm: 'ES256',
          status: 'active',
        }]
        : [],
    }));
    const { user } = renderWithRouter(<DidIdentitiesPage />);
    await screen.findByText('did:web:issuer.example:orgs:passport');
    await user.click(screen.getByRole('button', { name: 'Attach document signer certificate' }));
    await user.type(screen.getByRole('textbox', { name: /Document signer certificate PEM/i }), 'certificate');
    await user.click(screen.getByRole('button', { name: 'Attach certificate' }));
    await waitFor(() => {
      expect(storeIssuerIdentityCertificate).toHaveBeenCalledWith({
        organization_id: 'org-test-1',
        issuer_did: 'did:web:issuer.example:orgs:passport',
        key_purpose: 'x509_doc_signer',
        credential_format: 'ICAO_EMRTD',
        algorithm: 'ES256',
        cert_pem: 'certificate',
        cert_chain_pem: '',
      });
    });
  });

  it('enrolls a public CSCA anchor for the managed identity without custody inputs', async () => {
    listPublicIssuerIdentities.mockImplementation(async ({ credential_format: credentialFormat }) => ({
      identities: credentialFormat === 'MDOC'
        ? [{
          issuer_did: 'did:web:issuer.example:orgs:csca',
          key_purpose: 'csca',
          algorithm: 'ES256',
          status: 'active',
        }]
        : [],
    }));
    const { user } = renderWithRouter(<DidIdentitiesPage />);
    await screen.findByText('did:web:issuer.example:orgs:csca');
    await user.click(screen.getByRole('button', { name: 'Enroll public CSCA trust anchor' }));
    await user.type(screen.getByRole('textbox', { name: 'CSCA certificate ID' }), 'pilot-csca');
    await user.type(screen.getByRole('textbox', { name: 'CSCA certificate PEM' }), 'public-certificate');
    await user.click(screen.getByRole('button', { name: 'Enroll trust anchor' }));
    await waitFor(() => {
      expect(enrollCscaCertificate).toHaveBeenCalledWith({
        organization_id: 'org-test-1',
        issuer_did: 'did:web:issuer.example:orgs:csca',
        credential_format: 'MDOC',
        algorithm: 'ES256',
        certificate_id: 'pilot-csca',
        cert_pem: 'public-certificate',
        cert_chain_pem: '',
      });
    });
    expect(storeIssuerIdentityCertificate).not.toHaveBeenCalled();
    expect(showNotification).toHaveBeenCalledWith('Public CSCA trust anchor enrolled.', 'success');
  });

  it('never loads issuer profiles, services, or raw keys', async () => {
    renderWithRouter(<DidIdentitiesPage />);
    await waitFor(() => expect(listPublicIssuerIdentities).toHaveBeenCalled());
    expect(screen.queryByRole('textbox', { name: /signing service/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('textbox', { name: /key reference/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('textbox', { name: /issuer profile/i })).not.toBeInTheDocument();
  });
});
