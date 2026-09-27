import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act } from '@testing-library/react';
import { renderWithRouter, screen, waitFor } from '@test/utils';

import DidIdentitiesPage from './DidIdentitiesPage';

const { listPublicIssuerIdentities, rebindIssuerIdentity, deleteIssuerIdentity, storeIssuerIdentityCertificate, enrollCscaCertificate, generateIssuerIdentityCsr, issueCscaSelfSignedCertificate, issueDscCertificate, can, permissionState, orgState, showNotification } = vi.hoisted(() => ({
  listPublicIssuerIdentities: vi.fn(),
  rebindIssuerIdentity: vi.fn(),
  deleteIssuerIdentity: vi.fn(),
  storeIssuerIdentityCertificate: vi.fn(),
  enrollCscaCertificate: vi.fn(),
  generateIssuerIdentityCsr: vi.fn(),
  issueCscaSelfSignedCertificate: vi.fn(),
  issueDscCertificate: vi.fn(),
  can: vi.fn(),
  permissionState: { isLoading: false },
  orgState: { activeOrgId: 'org-test-1' },
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
    issueCscaSelfSignedCertificate: (...args: unknown[]) => issueCscaSelfSignedCertificate(...args),
    issueDscCertificate: (...args: unknown[]) => issueDscCertificate(...args),
  },
}));

vi.mock('../../../hooks/useNotifications', () => ({
  useNotifications: () => ({ showNotification }),
}));

vi.mock('../../../contexts/ConsoleContext', () => ({
  useConsole: () => ({ activeOrgId: orgState.activeOrgId }),
}));

vi.mock('../../../hooks/usePermissions', () => ({
  usePermissions: () => ({ can, isLoading: permissionState.isLoading }),
}));

describe('DidIdentitiesPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    window.sessionStorage.clear();
    permissionState.isLoading = false;
    orgState.activeOrgId = 'org-test-1';
    can.mockReturnValue(false);
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
    issueCscaSelfSignedCertificate.mockResolvedValue({ certificate_pem: 'public-csca-pem', chain_pem: '', serial: '123', not_before: '2026-01-01', not_after: '2027-01-01' });
    issueDscCertificate.mockResolvedValue({ certificate_pem: 'public-dsc-pem', chain_pem: 'public-csca-pem', serial: '456', not_before: '2026-01-01', not_after: '2026-02-01' });
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

  it.each(['RS256', 'EdDSA'])('keeps public certificate enrollment available without offering a %s CSR', async (algorithm) => {
    listPublicIssuerIdentities.mockImplementation(async ({ credential_format: credentialFormat }) => ({
      identities: credentialFormat === 'ICAO_EMRTD'
        ? [{ issuer_did: 'did:web:issuer.example:orgs:dsc', key_purpose: 'x509_doc_signer', algorithm, status: 'active' }]
        : [],
    }));
    const { user } = renderWithRouter(<DidIdentitiesPage />);
    await screen.findByText('did:web:issuer.example:orgs:dsc');
    await user.click(screen.getByRole('button', { name: 'Attach document signer certificate' }));
    expect(screen.getByRole('button', { name: 'Generate KMS-backed CSR' })).toBeDisabled();
    expect(screen.getByText(/certificate requests support ES256, ES384, and ES512/i)).toBeInTheDocument();
    await user.type(screen.getByRole('textbox', { name: /Document signer certificate PEM/i }), 'certificate');
    expect(screen.getByRole('button', { name: 'Attach certificate' })).toBeEnabled();
    expect(generateIssuerIdentityCsr).not.toHaveBeenCalled();
  });

  it('never loads issuer profiles, services, or raw keys', async () => {
    renderWithRouter(<DidIdentitiesPage />);
    await waitFor(() => expect(listPublicIssuerIdentities).toHaveBeenCalled());
    expect(screen.queryByRole('textbox', { name: /signing service/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('textbox', { name: /key reference/i })).not.toBeInTheDocument();
    expect(screen.queryByRole('textbox', { name: /issuer profile/i })).not.toBeInTheDocument();
  });

  it('issues a self-signed CSCA only for an operator with the dedicated grant', async () => {
    can.mockImplementation((resource: string, action: string) => resource === 'passport-certificate' && action === 'issue-csca');
    listPublicIssuerIdentities.mockImplementation(async ({ credential_format: format }) => ({
      identities: format === 'ICAO_EMRTD'
        ? [{ issuer_did: 'did:web:issuer.example:csca', key_purpose: 'csca', algorithm: 'ES256', status: 'active' }]
        : [],
    }));
    const { user } = renderWithRouter(<DidIdentitiesPage />);
    await screen.findByText('did:web:issuer.example:csca');
    expect(screen.queryByRole('button', { name: 'Issue DSC' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Issue CSCA' }));
    await user.type(screen.getByRole('textbox', { name: 'CSCA certificate ID' }), 'beta-csca-1');
    await user.type(screen.getByRole('textbox', { name: 'Country code (C)' }), 'US');
    await user.type(screen.getByRole('textbox', { name: 'Organization (O)' }), 'Beta Issuer');
    await user.type(screen.getByRole('textbox', { name: 'Common name (CN)' }), 'Beta CSCA');
    await user.click(screen.getByRole('button', { name: 'Issue CSCA certificate' }));
    await waitFor(() => expect(issueCscaSelfSignedCertificate).toHaveBeenCalledWith({
      organization_id: 'org-test-1', issuer_did: 'did:web:issuer.example:csca',
      certificate_id: 'beta-csca-1', country: 'US', organization: 'Beta Issuer',
      common_name: 'Beta CSCA', validity_days: 365,
    }));
    expect(screen.getByRole('textbox', { name: 'Issued certificate PEM' })).toHaveValue('public-csca-pem');
    expect(issueDscCertificate).not.toHaveBeenCalled();
    expect(screen.queryByRole('textbox', { name: /KMS locator|private key|token/i })).not.toBeInTheDocument();
  });

  it('issues a DSC through the selected DSC and public CSCA identity with a stable retry key', async () => {
    can.mockImplementation((resource: string, action: string) => resource === 'passport-certificate' && action === 'issue');
    issueDscCertificate.mockRejectedValueOnce(new Error('response lost'));
    listPublicIssuerIdentities.mockImplementation(async ({ credential_format: format }) => ({
      identities: format === 'ICAO_EMRTD'
        ? [{ issuer_did: 'did:web:issuer.example:dsc', key_purpose: 'x509_doc_signer', algorithm: 'ES256', status: 'active' }]
        : [],
    }));
    const { user } = renderWithRouter(<DidIdentitiesPage />);
    await screen.findByText('did:web:issuer.example:dsc');
    await user.click(screen.getByRole('button', { name: 'Issue DSC' }));
    await user.type(screen.getByRole('textbox', { name: 'CSCA issuer DID' }), 'did:web:issuer.example:csca');
    await user.type(screen.getByRole('textbox', { name: 'CSCA certificate ID' }), 'beta-csca-1');
    await user.type(screen.getByRole('textbox', { name: 'Country code (C)' }), 'US');
    await user.type(screen.getByRole('textbox', { name: 'Organization (O)' }), 'Beta Issuer');
    await user.type(screen.getByRole('textbox', { name: 'Common name (CN)' }), 'Beta DSC');
    const retryReference = screen.getByRole('textbox', { name: 'DSC request reference' });
    const reference = (retryReference as HTMLInputElement).value;
    expect(reference).toMatch(/^passport-dsc-[A-Za-z0-9._-]+$/);
    await user.click(screen.getByRole('button', { name: 'Issue DSC certificate' }));
    await screen.findByText(/could not be issued/i);
    expect(retryReference).toHaveValue(reference);
    await user.click(screen.getByRole('button', { name: 'Issue DSC certificate' }));
    await waitFor(() => expect(issueDscCertificate).toHaveBeenCalledWith(expect.objectContaining({
      organization_id: 'org-test-1', dsc_issuer_did: 'did:web:issuer.example:dsc',
      csca_issuer_did: 'did:web:issuer.example:csca', csca_certificate_id: 'beta-csca-1',
      country: 'US', organization: 'Beta Issuer', common_name: 'Beta DSC', validity_days: 30,
      idempotency_key: reference,
    })));
    expect(issueDscCertificate).toHaveBeenCalledTimes(2);
    expect(issueDscCertificate.mock.calls[0][0].idempotency_key).toBe(reference);
    expect(issueDscCertificate.mock.calls[1][0].idempotency_key).toBe(reference);
    expect(screen.getByRole('textbox', { name: 'Issued certificate PEM' })).toHaveValue('public-dsc-pem');
    expect(screen.getByRole('textbox', { name: 'Issued certificate chain PEM' })).toHaveValue('public-csca-pem');
    expect(issueCscaSelfSignedCertificate).not.toHaveBeenCalled();
  });

  it('restores an uncertain DSC request after refresh and retries its exact payload', async () => {
    can.mockImplementation((resource: string, action: string) => resource === 'passport-certificate' && action === 'issue');
    issueDscCertificate.mockRejectedValueOnce(new Error('response lost'));
    listPublicIssuerIdentities.mockImplementation(async ({ credential_format: format }) => ({
      identities: format === 'ICAO_EMRTD'
        ? [{ issuer_did: 'did:web:issuer.example:dsc', key_purpose: 'x509_doc_signer', algorithm: 'ES256', status: 'active' }]
        : [],
    }));
    const first = renderWithRouter(<DidIdentitiesPage />);
    await screen.findByText('did:web:issuer.example:dsc');
    await first.user.click(screen.getByRole('button', { name: 'Issue DSC' }));
    await first.user.type(screen.getByRole('textbox', { name: 'CSCA issuer DID' }), 'did:web:issuer.example:csca');
    await first.user.type(screen.getByRole('textbox', { name: 'CSCA certificate ID' }), 'beta-csca-1');
    await first.user.type(screen.getByRole('textbox', { name: 'Country code (C)' }), 'US');
    await first.user.type(screen.getByRole('textbox', { name: 'Organization (O)' }), 'Beta Issuer');
    await first.user.type(screen.getByRole('textbox', { name: 'Common name (CN)' }), 'Beta DSC');
    await first.user.click(screen.getByRole('button', { name: 'Issue DSC certificate' }));
    await screen.findByText(/could not be issued/i);
    const firstRequest = issueDscCertificate.mock.calls[0][0];
    expect(window.sessionStorage.length).toBe(1);
    first.unmount();

    const second = renderWithRouter(<DidIdentitiesPage />);
    await screen.findByText('did:web:issuer.example:dsc');
    await second.user.click(screen.getByRole('button', { name: 'Issue DSC' }));
    expect(screen.getByRole('textbox', { name: 'DSC request reference' })).toHaveValue(firstRequest.idempotency_key);
    expect(screen.getByRole('textbox', { name: 'DSC request reference' })).toBeDisabled();
    expect(screen.getByRole('textbox', { name: 'Common name (CN)' })).toHaveValue('Beta DSC');
    expect(screen.getByText(/request is pending or its response was lost/i)).toBeInTheDocument();
    await second.user.click(screen.getByRole('button', { name: 'Issue DSC certificate' }));
    await waitFor(() => expect(issueDscCertificate).toHaveBeenCalledTimes(2));
    expect(issueDscCertificate.mock.calls[1][0]).toEqual(firstRequest);
    await screen.findByRole('textbox', { name: 'Issued certificate PEM' });
    expect(window.sessionStorage.length).toBe(0);
  });

  it('hides both issuance actions while permissions are loading or missing', async () => {
    permissionState.isLoading = true;
    can.mockReturnValue(true);
    listPublicIssuerIdentities.mockImplementation(async ({ credential_format: format }) => ({
      identities: format === 'ICAO_EMRTD'
        ? [
          { issuer_did: 'did:web:issuer.example:csca', key_purpose: 'csca', algorithm: 'ES256', status: 'active' },
          { issuer_did: 'did:web:issuer.example:dsc', key_purpose: 'x509_doc_signer', algorithm: 'ES256', status: 'active' },
        ] : [],
    }));
    renderWithRouter(<DidIdentitiesPage />);
    await screen.findByText('did:web:issuer.example:csca');
    expect(screen.queryByRole('button', { name: 'Issue CSCA' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Issue DSC' })).not.toBeInTheDocument();
  });

  it('offers issuance only for active ES256 passport profiles', async () => {
    can.mockReturnValue(true);
    listPublicIssuerIdentities.mockImplementation(async ({ credential_format: format }) => ({
      identities: format === 'ICAO_EMRTD'
        ? [
          { issuer_did: 'did:web:issuer.example:inactive-csca', key_purpose: 'csca', algorithm: 'ES256', status: 'retired' },
          { issuer_did: 'did:web:issuer.example:wrong-algorithm', key_purpose: 'x509_doc_signer', algorithm: 'ES384', status: 'active' },
        ] : [],
    }));
    renderWithRouter(<DidIdentitiesPage />);
    await screen.findByText('did:web:issuer.example:inactive-csca');
    expect(screen.queryByRole('button', { name: 'Issue CSCA' })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Issue DSC' })).not.toBeInTheDocument();
  });

  it('closes issuance and discards an in-flight certificate result after organization switch', async () => {
    can.mockReturnValue(true);
    listPublicIssuerIdentities.mockImplementation(async ({ organization_id: organizationId, credential_format: format }) => ({
      identities: organizationId === 'org-test-1' && format === 'ICAO_EMRTD'
        ? [{ issuer_did: 'did:web:issuer.example:csca', key_purpose: 'csca', algorithm: 'ES256', status: 'active' }]
        : [],
    }));
    let resolveIssue: (value: unknown) => void = () => {};
    issueCscaSelfSignedCertificate.mockImplementation(() => new Promise((resolve) => { resolveIssue = resolve; }));
    const { user, rerender } = renderWithRouter(<DidIdentitiesPage />);
    await screen.findByText('did:web:issuer.example:csca');
    await user.click(screen.getByRole('button', { name: 'Issue CSCA' }));
    await user.type(screen.getByRole('textbox', { name: 'CSCA certificate ID' }), 'beta-csca-1');
    await user.type(screen.getByRole('textbox', { name: 'Country code (C)' }), 'US');
    await user.type(screen.getByRole('textbox', { name: 'Organization (O)' }), 'Beta Issuer');
    await user.type(screen.getByRole('textbox', { name: 'Common name (CN)' }), 'Beta CSCA');
    await user.click(screen.getByRole('button', { name: 'Issue CSCA certificate' }));
    await waitFor(() => expect(issueCscaSelfSignedCertificate).toHaveBeenCalledTimes(1));
    orgState.activeOrgId = 'org-test-2';
    rerender(<DidIdentitiesPage />);
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Issue CSCA' })).not.toBeInTheDocument());
    await act(async () => resolveIssue({ certificate_pem: 'old-tenant-public-certificate' }));
    expect(screen.queryByRole('textbox', { name: 'Issued certificate PEM' })).not.toBeInTheDocument();
    expect(showNotification).not.toHaveBeenCalledWith('CSCA certificate issued.', 'success');
  });

  it('discards an old organization identity list that finishes after a switch', async () => {
    can.mockReturnValue(true);
    let resolveOld: (value: unknown) => void = () => {};
    listPublicIssuerIdentities.mockImplementation(({ organization_id: organizationId, credential_format: format }) => {
      if (organizationId === 'org-test-1' && format === 'ICAO_EMRTD') {
        return new Promise((resolve) => { resolveOld = resolve; });
      }
      return Promise.resolve({ identities: [] });
    });
    const { rerender } = renderWithRouter(<DidIdentitiesPage />);
    await waitFor(() => expect(listPublicIssuerIdentities).toHaveBeenCalledWith({
      organization_id: 'org-test-1', credential_format: 'ICAO_EMRTD',
    }));
    orgState.activeOrgId = 'org-test-2';
    rerender(<DidIdentitiesPage />);
    await screen.findByText(/No active issuer identities/);
    await act(async () => resolveOld({ identities: [
      { issuer_did: 'did:web:issuer.example:old-csca', key_purpose: 'csca', algorithm: 'ES256', status: 'active' },
    ] }));
    expect(screen.queryByText('did:web:issuer.example:old-csca')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Issue CSCA' })).not.toBeInTheDocument();
  });
});
