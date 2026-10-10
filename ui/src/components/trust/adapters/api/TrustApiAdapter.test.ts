import { beforeEach, describe, expect, it, vi } from 'vitest';
import TrustApiAdapter from './TrustApiAdapter';
import MockTrustAdapter from '../mock/MockTrustAdapter';

const { storeIssuerIdentityCertificate } = vi.hoisted(() => ({
  storeIssuerIdentityCertificate: vi.fn(),
}));

vi.mock('../../../../services/signingKeysApi', () => ({ storeIssuerIdentityCertificate }));

const attachment = {
  issuerDid: 'did:web:issuer.example:org',
  keyPurpose: 'vc_jwt_issuer',
  credentialFormat: 'SD_JWT_VC',
  algorithm: 'ES256',
  issuerCertificate: '-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----',
  intermediateCertificates: '-----BEGIN CERTIFICATE-----\nintermediate\n-----END CERTIFICATE-----',
  rootCaCertificate: '-----BEGIN CERTIFICATE-----\nroot\n-----END CERTIFICATE-----',
};

describe('TrustApiAdapter managed issuer certificate attachment', () => {
  beforeEach(() => {
    storeIssuerIdentityCertificate.mockReset().mockResolvedValue({ ok: true });
  });

  it('sends only public certificates and the DID identity selector to the supported signing route', async () => {
    const adapter = new TrustApiAdapter();
    await expect(adapter.uploadBYOKCertificates('org-a', attachment)).resolves.toEqual({ ok: true });
    expect(storeIssuerIdentityCertificate).toHaveBeenCalledWith({
      organization_id: 'org-a',
      issuer_did: attachment.issuerDid,
      key_purpose: attachment.keyPurpose,
      credential_format: attachment.credentialFormat,
      algorithm: attachment.algorithm,
      cert_pem: attachment.issuerCertificate,
      cert_chain_pem: `${attachment.intermediateCertificates}\n${attachment.rootCaCertificate}`,
    });
  });

  it.each([
    { privateKeyPem: '-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----' },
    { private_key_pem: 'secret' },
    { issuerCertificate: '-----BEGIN EC PRIVATE KEY-----\nsecret\n-----END EC PRIVATE KEY-----' },
    { rootCaCertificate: '-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----' },
  ])('rejects private material before the signing API is called', async override => {
    const adapter = new TrustApiAdapter();
    await expect(adapter.uploadBYOKCertificates('org-a', { ...attachment, ...override })).rejects.toThrow();
    expect(storeIssuerIdentityCertificate).not.toHaveBeenCalled();
  });

  it('requires a complete managed identity selector', async () => {
    const adapter = new TrustApiAdapter();
    await expect(adapter.uploadBYOKCertificates('org-a', { ...attachment, issuerDid: '' })).rejects.toThrow();
    expect(storeIssuerIdentityCertificate).not.toHaveBeenCalled();
  });

  it('does not let the mock adapter fabricate a key from a certificate upload', async () => {
    const mock = new MockTrustAdapter({ latencyMs: 0 });
    const orgId = 'mock-public-certificate-org';
    await expect(mock.uploadBYOKCertificates(orgId, attachment)).rejects.toThrow();
    const created = await mock.generateKey(orgId);
    const before = await mock.getTrustConfig(orgId);
    await mock.uploadBYOKCertificates(orgId, {
      ...attachment,
      issuerDid: created.key.did,
      algorithm: created.key.algorithm,
    });
    const after = await mock.getTrustConfig(orgId);
    expect(after.issuerKeys).toHaveLength(before.issuerKeys.length);
    expect(after.issuerKeys[0].hasCertificate).toBe(true);
  });
});
