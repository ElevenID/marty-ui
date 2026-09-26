import { beforeEach, describe, expect, it, vi } from 'vitest';
import { renderWithRouter, screen, waitFor } from '@test/utils';

import DidIdentitiesPage from './DidIdentitiesPage';

const { listPublicIssuerIdentities, rebindIssuerIdentity, deleteIssuerIdentity, storeIssuerIdentityCertificate, enrollCscaCertificate, generateIssuerIdentityCsr, showNotification } = vi.hoisted(() => ({
  listPublicIssuerIdentities: vi.fn(),
  rebindIssuerIdentity: vi.fn(),
  deleteIssuerIdentity: vi.fn(),
  storeIssuerIdentityCertificate: vi.fn(),
  enrollCscaCertificate: vi.fn(),
  generateIssuerIdentityCsr: vi.fn(),
  showNotification: vi.fn(),
}));

vi.mock('../../../services/signingKeysApi', () => ({
  default: {
    listPublicIssuerIdentities: (...args: unknown[]) => listPublicIssuerIdentities(...args),
    rebindIssuerIdentity: (...args: unknown[]) => rebindIssuerIdentity(...args),
    deleteIssuerIdentity: (...args: unknown[]) => deleteIssuerIdentity(...args),
    storeIssuerIdentityCertificate: (...args: unknown[]) => storeIssuerIdentityCertificate(...args),
    enrollCscaCertificate: (...args: unknown[]) => enrollCscaCertificate(...args),
    generateIssuerIdentityCsr: (...args: unknown[]) => generateIssuerIdentityCsr(...args),
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
    generateIssuerIdentityCsr.mockResolvedValue({ csr_pem: '-----BEGIN CERTIFICATE REQUEST-----\npublic-csr\n-----END CERTIFICATE REQUEST-----' });
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

  it('generates a public PKCS#10 request through the selected KMS-held CSCA identity', async () => {
    listPublicIssuerIdentities.mockImplementation(async ({ credential_format: credentialFormat }) => ({
      identities: credentialFormat === 'MDOC'
        ? [{ issuer_did: 'did:web:issuer.example:orgs:csca', key_purpose: 'csca', algorithm: 'ES256', status: 'active' }]
        : [],
    }));
    const { user } = renderWithRouter(<DidIdentitiesPage />);
    await screen.findByText('did:web:issuer.example:orgs:csca');
    await user.click(screen.getByRole('button', { name: 'Enroll public CSCA trust anchor' }));
    await user.type(screen.getByRole('textbox', { name: 'Country code (C)' }), 'US');
    await user.type(screen.getByRole('textbox', { name: 'Organization (O)' }), 'ElevenID Beta');
    await user.type(screen.getByRole('textbox', { name: 'Common name (CN)' }), 'Pilot CSCA');
    await user.click(screen.getByRole('button', { name: 'Generate KMS-backed CSR' }));
    await waitFor(() => expect(generateIssuerIdentityCsr).toHaveBeenCalledWith({
      organization_id: 'org-test-1',
      issuer_did: 'did:web:issuer.example:orgs:csca',
      key_purpose: 'csca',
      credential_format: 'MDOC',
      algorithm: 'ES256',
      country: 'US',
      organization: 'ElevenID Beta',
      common_name: 'Pilot CSCA',
    }));
    expect((screen.getByRole('textbox', { name: 'Certificate Signing Request (PEM)' }) as HTMLInputElement).value)
      .toContain('BEGIN CERTIFICATE REQUEST');
    expect(storeIssuerIdentityCertificate).not.toHaveBeenCalled();
    expect(enrollCscaCertificate).not.toHaveBeenCalled();
  });

  it('uses the document-signer identity rather than the shared signing service for its CSR', async () => {
    listPublicIssuerIdentities.mockImplementation(async ({ credential_format: credentialFormat }) => ({
      identities: credentialFormat === 'ICAO_EMRTD'
        ? [{ issuer_did: 'did:web:issuer.example:orgs:dsc', key_purpose: 'x509_doc_signer', algorithm: 'ES384', status: 'active' }]
        : [],
    }));
    const { user } = renderWithRouter(<DidIdentitiesPage />);
    await screen.findByText('did:web:issuer.example:orgs:dsc');
    await user.click(screen.getByRole('button', { name: 'Attach document signer certificate' }));
    await user.type(screen.getByRole('textbox', { name: 'Country code (C)' }), 'US');
    await user.type(screen.getByRole('textbox', { name: 'Organization (O)' }), 'ElevenID Beta');
    await user.type(screen.getByRole('textbox', { name: 'Common name (CN)' }), 'Pilot DSC');
    await user.click(screen.getByRole('button', { name: 'Generate KMS-backed CSR' }));
    await waitFor(() => expect(generateIssuerIdentityCsr).toHaveBeenCalledWith(expect.objectContaining({
      issuer_did: 'did:web:issuer.example:orgs:dsc',
      key_purpose: 'x509_doc_signer',
      credential_format: 'ICAO_EMRTD',
      algorithm: 'ES384',
      common_name: 'Pilot DSC',
    })));
    expect(storeIssuerIdentityCertificate).not.toHaveBeenCalled();
  });

  it('never loads issuer profiles, services, or raw keys', async () => {
    renderWithRouter(<DidIdentitiesPage />);
    await waitFor(() => expect(listPublicIssuerIdentities).toHaveBeenCalled());
    expect(screen.queryByRole('textbox', { name: /signing service/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('textbox', { name: /key reference/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('textbox', { name: /issuer profile/i })).not.toBeInTheDocument();
  });
});
