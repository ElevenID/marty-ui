/** Build the public-only signing-service request for an existing managed identity. */
export function managedIssuerCertificateRequest(orgId, certificates) {
  if (!certificates || typeof certificates !== 'object'
    || 'privateKeyPem' in certificates || 'private_key_pem' in certificates) {
    throw new Error('Private key upload is not supported. Select an existing managed issuer identity.');
  }
  const required = ['issuerDid', 'keyPurpose', 'credentialFormat', 'algorithm', 'issuerCertificate'];
  if (typeof orgId !== 'string' || !orgId.trim()
    || required.some(field => typeof certificates[field] !== 'string' || !certificates[field].trim())) {
    throw new Error('An organization, managed issuer identity, and issuer certificate are required.');
  }
  for (const field of ['intermediateCertificates', 'rootCaCertificate']) {
    if (certificates[field] != null && typeof certificates[field] !== 'string') {
      throw new Error('Certificate chain fields must contain public PEM strings.');
    }
  }
  const chain = [certificates.intermediateCertificates, certificates.rootCaCertificate]
    .filter(value => typeof value === 'string' && value.trim())
    .map(value => value.trim());
  if ([certificates.issuerCertificate, ...chain].some(value => /-----BEGIN [^-]*PRIVATE KEY-----/.test(value))) {
    throw new Error('Only public certificates may be attached to a managed issuer identity.');
  }
  return {
    organization_id: orgId.trim(),
    issuer_did: certificates.issuerDid.trim(),
    key_purpose: certificates.keyPurpose.trim(),
    credential_format: certificates.credentialFormat.trim(),
    algorithm: certificates.algorithm.trim(),
    cert_pem: certificates.issuerCertificate.trim(),
    cert_chain_pem: chain.join('\n'),
  };
}
