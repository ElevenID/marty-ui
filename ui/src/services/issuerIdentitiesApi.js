/** Public DID identity operations. Provider configuration belongs to signingKeysApi. */
import { get, post, put, patch, del } from './api';
import { postWithIdempotency } from './idempotency';
import { buildDefinedQueryString, requireOrganizationId, withQuery } from './queryUtils';

const BASE_PATH = '/v1/signing-keys/issuer-identities';
const organization = (params, action) => requireOrganizationId(
  typeof params === 'string' ? params : params?.organization_id || params?.organizationId,
  action,
);

export async function createIssuerIdentity(body) {
  return postWithIdempotency(BASE_PATH, {
    organization_id: organization(body, 'creating issuer identities'),
    issuer_did: body?.issuer_did,
    key_purpose: body?.key_purpose,
    credential_format: body?.credential_format,
    algorithm: body?.algorithm,
    key_attestation_policy: body?.key_attestation_policy,
  });
}

export async function listPublicIssuerIdentities(params = {}) {
  const organizationId = organization(params, 'loading issuer identities');
  const result = await get(withQuery(BASE_PATH, buildDefinedQueryString({
    organization_id: organizationId,
    key_purpose: params?.key_purpose,
    credential_format: params?.credential_format,
    algorithm: params?.algorithm,
  })));
  const seen = new Set();
  if (!Array.isArray(result?.identities) || !result.identities.every((identity) => {
    const valid = typeof identity?.issuer_did === 'string' && identity.issuer_did.startsWith('did:')
      && ['key_purpose', 'credential_format', 'algorithm', 'status'].every((field) => typeof identity[field] === 'string' && identity[field].trim())
      && (identity.organization_id == null || identity.organization_id === organizationId);
    const key = JSON.stringify(['issuer_did', 'key_purpose', 'credential_format', 'algorithm'].map((field) => identity?.[field]));
    if (!valid || seen.has(key)) return false;
    seen.add(key); return true;
  })) throw new Error('Issuer inventory returned invalid or ambiguous identity data.');
  return { identities: result.identities.map(({ issuer_did, key_purpose, credential_format, algorithm, status }) => ({
    issuer_did, key_purpose, credential_format, algorithm, status,
  })) };
}

const PRIVATE_INSPECTION_FIELDS = new Set(['rsa_d', 'd', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k', 'privatekeyjwk', 'privatekeymultibase',
  'privatekeybase58', 'private_key', 'key_reference', 'auth_reference', 'auth_token', 'access_token', 'api_key', 'secret', 'secret_key',
  'seed', 'password', 'credentials', 'credential_reference', 'signing_service_id', 'signing_key_reference', 'issuer_profile_id',
  'kms_provider', 'kms_arn', 'kms_region', 'provider_config', 'service_id', 'client_secret', 'key_binding']);
function assertPublicInspection(value, depth = 0) {
  if (depth > 48) throw new Error('Identity inspection returned an invalid public document.');
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    if (PRIVATE_INSPECTION_FIELDS.has(key.toLowerCase())) throw new Error('Identity inspection returned private custody data.');
    assertPublicInspection(child, depth + 1);
  }
}

/** Inspect a public tuple from the current organization inventory; no private selector is accepted. */
export async function inspectIssuerIdentity(params = {}) {
  const organizationId = organization(params, 'inspecting issuer identities');
  const fields = ['issuer_did', 'key_purpose', 'credential_format', 'algorithm'];
  if (!fields.every((field) => typeof params[field] === 'string' && params[field].trim())) {
    throw new Error('Select a complete issuer identity from the organization inventory.');
  }
  const result = await get(withQuery(`${BASE_PATH}/inspection`, buildDefinedQueryString({
    organization_id: organizationId, ...Object.fromEntries(fields.map((field) => [field, params[field]])),
  })));
  assertPublicInspection(result);
  const methodsValid = (methods) => Array.isArray(methods) && methods.every((method) =>
    ['id', 'type', 'controller'].every((field) => typeof method?.[field] === 'string' && method[field])
    && typeof method.assertion_authorized === 'boolean' && Array.isArray(method.x5c)
    && method.x5c.every((certificate) => typeof certificate === 'string'));
  const documentValid = (document) => document && document.id === params.issuer_did;
  const timestampValid = (value) => value == null || (typeof value === 'string'
    && /^\d{4}-\d\d-\d\dT/.test(value) && Number.isFinite(Date.parse(value)));
  if (result?.organization_id !== organizationId || result?.identity?.status !== 'active'
    || !fields.every((field) => result?.identity?.[field] === params[field])
    || !['available', 'not_published'].includes(result?.registry?.status) || !documentValid(result.registry.document)
    || !['scoped_document', 'legacy_projection', 'empty_fallback'].includes(result.registry.source)
    || !methodsValid(result.registry.verification_methods)
    || !['matched', 'mismatch', 'unavailable'].includes(result?.managed_signer?.status)
    || typeof result.managed_signer.assertion_authorized !== 'boolean'
    || !['matched', 'stale', 'unverified', 'unavailable', 'invalid', 'unsupported'].includes(result?.public_resolution?.status)
    || (result.public_resolution.document != null && !documentValid(result.public_resolution.document))
    || !methodsValid(result.public_resolution.verification_methods)
    || typeof result.public_resolution.assertion_authorized !== 'boolean'
    || !['not_expired', 'expired', 'invalid', 'absent'].includes(result?.certificate?.status)
    || !Array.isArray(result.certificate.x5c) || !result.certificate.x5c.every((certificate) => typeof certificate === 'string')
    || typeof result.assertion_ready !== 'boolean'
    || typeof result.inspected_at !== 'string' || typeof result.managed_signer.checked_at !== 'string'
    || ![result.inspected_at, result.identity_created_at, result.identity_updated_at, result.registry.updated_at,
      result.managed_signer.checked_at, result.public_resolution.checked_at, result.public_resolution.retrieved_at, result.certificate.expires_at].every(timestampValid)
    || (result.public_resolution.status === 'matched' && (!result.public_resolution.document || typeof result.public_resolution.retrieved_at !== 'string'))
    || (result.assertion_ready && !(result.registry.status === 'available' && result.managed_signer.status === 'matched' && result.public_resolution.status === 'matched'
      && result.managed_signer.assertion_authorized && result.public_resolution.assertion_authorized))) {
    throw new Error('Identity inspection returned invalid organization or observation data.');
  }
  if (result.canonical_document_url != null) {
    const url = new URL(result.canonical_document_url);
    if (url.protocol !== 'https:' || url.username || url.password) throw new Error('Identity inspection returned an invalid publication URL.');
  }
  return result;
}

export async function getIssuerIdentityCapabilities(params = {}) {
  const organizationId = organization(params, 'loading issuer capabilities');
  const result = await get(withQuery(`${BASE_PATH}/capabilities`, buildDefinedQueryString({
    organization_id: organizationId,
  })));
  if (result?.organization_id !== organizationId
    || result?.basis !== 'configuration'
    || !Array.isArray(result?.creation_options)
    || !result.creation_options.every((option) => ['key_purpose', 'credential_format', 'algorithm']
      .every((field) => typeof option?.[field] === 'string' && option[field].trim()))
    || (result.managed_issuer_did_prefix !== null
      && (typeof result.managed_issuer_did_prefix !== 'string'
        || !result.managed_issuer_did_prefix.startsWith('did:')))) {
    throw new Error('Issuer capabilities returned invalid organization or identity data.');
  }
  return {
    organization_id: result.organization_id,
    managed_issuer_did_prefix: result.managed_issuer_did_prefix,
    basis: result.basis,
    creation_options: result.creation_options.map(({ key_purpose, credential_format, algorithm }) => ({
      key_purpose, credential_format, algorithm,
    })),
  };
}

export async function getTemplateIssuerOptions(params = {}) {
  const organizationId = organization(params, 'loading template issuer options');
  const result = await post('/v1/credential-templates/issuer-options', {
    organization_id: organizationId,
    compliance_profile_id: params.compliance_profile_id,
    ...(params.credential_payload_format ? { credential_payload_format: params.credential_payload_format } : {}),
    ...(Array.isArray(params.supported_formats) ? { supported_formats: params.supported_formats } : {}),
  });
  if (result?.organization_id !== organizationId
    || result?.compliance_profile_id !== params.compliance_profile_id
    || typeof result?.credential_payload_format !== 'string'
    || typeof result?.issuance_protocol !== 'string'
    || !Array.isArray(result?.supported_formats) || result.supported_formats.length === 0
    || !result.supported_formats.every((format) => typeof format === 'string' && format)
    || !['vct', 'doctype', 'revocation_profile', 'x509_certificate'].every((field) => typeof result?.requirements?.[field] === 'boolean')
    || !Array.isArray(result?.identities) || !result.identities.every((identity) => typeof identity?.issuer_did === 'string'
      && identity.issuer_did.startsWith('did:') && Array.isArray(identity.bindings) && identity.bindings.length > 0
      && identity.bindings.every((binding) => ['credential_format', 'key_purpose', 'algorithm'].every((field) => typeof binding?.[field] === 'string' && binding[field])))
    || !Array.isArray(result?.rejected_issuers)
    || !result.rejected_issuers.every((identity) => typeof identity?.issuer_did === 'string'
      && identity.issuer_did.startsWith('did:')
      && ['ambiguous_identity', 'incompatible_identity'].includes(identity.reason))) {
    throw new Error('Template issuer options returned invalid organization or compatibility data.');
  }
  return {
    organization_id: result.organization_id, compliance_profile_id: result.compliance_profile_id,
    credential_payload_format: result.credential_payload_format, supported_formats: result.supported_formats,
    issuance_protocol: result.issuance_protocol,
    requirements: Object.fromEntries(['vct', 'doctype', 'revocation_profile', 'x509_certificate'].map((field) => [field, result.requirements[field]])),
    identities: result.identities.map(({ issuer_did, bindings }) => ({ issuer_did,
      bindings: bindings.map(({ credential_format, key_purpose, algorithm }) => ({ credential_format, key_purpose, algorithm })) })),
    rejected_issuers: result.rejected_issuers.map(({ issuer_did, reason }) => ({ issuer_did, reason })),
  };
}

function withIdentityOrganizationQuery(path, params = {}) {
  return withQuery(path, buildDefinedQueryString({ organization_id: organization(params, 'using public identity material') }));
}

/**
 * Get the org JWKS document (published public keys).
 * @param {string} [organizationId]
 * @returns {Promise<Object>} JWKS document
 */
export async function getOrgJwks(organizationId) {
  return get(withIdentityOrganizationQuery('/v1/signing-keys/jwks', organizationId));
}

/**
 * Get the org DID document.
 * @param {string} [organizationId]
 * @returns {Promise<Object>} DID document
 */
export async function getOrgDidDocument(organizationId) {
  return get(withIdentityOrganizationQuery('/v1/signing-keys/did-document', organizationId));
}

// ---------------------------------------------------------------------------
// Provider-neutral issuer identities
// ---------------------------------------------------------------------------

/**
 * Rebind one DID-selected identity to Marty's compatible default signing
 * service. Provider and key coordinates remain private to the service.
 */
export async function rebindIssuerIdentity(body) {
  const organizationId = organization(body, 'rebinding issuer identities');
  return patch(`${BASE_PATH}`, {
    organization_id: organizationId,
    issuer_did: body?.issuer_did,
    key_purpose: body?.key_purpose,
    credential_format: body?.credential_format,
    algorithm: body?.algorithm,
  });
}

/**
 * Attach a public certificate chain to one DID-selected managed identity.
 */
export async function storeIssuerIdentityCertificate(body) {
  const organizationId = organization(body, 'attaching issuer certificates');
  return put(`${BASE_PATH}/certificate`, {
    organization_id: organizationId,
    issuer_did: body?.issuer_did,
    key_purpose: body?.key_purpose,
    credential_format: body?.credential_format,
    algorithm: body?.algorithm,
    cert_pem: body?.cert_pem,
    cert_chain_pem: body?.cert_chain_pem,
  });
}

/** Enroll only public CSCA material; Rust resolves the managed key internally. */
export async function enrollCscaCertificate(body) {
  const organizationId = organization(body, 'enrolling CSCA certificates');
  return put(`${BASE_PATH}/csca-certificate`, {
    organization_id: organizationId,
    issuer_did: body?.issuer_did,
    credential_format: body?.credential_format,
    algorithm: body?.algorithm,
    certificate_id: body?.certificate_id,
    cert_pem: body?.cert_pem,
    cert_chain_pem: body?.cert_chain_pem,
  });
}

/** Issue a beta CSCA certificate using the selected managed issuer profile. */
export async function issueCscaSelfSignedCertificate(body) {
  return post(withIdentityOrganizationQuery(`${BASE_PATH}/csca-self-signed-certificate`, body), {
    issuer_did: body?.issuer_did,
    certificate_id: body?.certificate_id,
    credential_format: 'ICAO_EMRTD',
    country: body?.country,
    organization: body?.organization,
    common_name: body?.common_name,
    validity_days: body?.validity_days,
  });
}

/** Issue a beta DSC certificate through managed DSC and CSCA profiles. */
export async function issueDscCertificate(body) {
  return post(withIdentityOrganizationQuery(`${BASE_PATH}/dsc-certificate`, body), {
    dsc_issuer_did: body?.dsc_issuer_did,
    csca_issuer_did: body?.csca_issuer_did,
    csca_certificate_id: body?.csca_certificate_id,
    credential_format: 'ICAO_EMRTD',
    country: body?.country,
    organization: body?.organization,
    common_name: body?.common_name,
    validity_days: body?.validity_days,
    idempotency_key: body?.idempotency_key,
  });
}

/** Build a public PKCS#10 request using the selected issuer identity's KMS key. */
export async function generateIssuerIdentityCsr(body) {
  const organizationId = organization(body, 'generating an issuer CSR');
  return put(`${BASE_PATH}/certificate-csr`, {
    organization_id: organizationId,
    issuer_did: body?.issuer_did,
    key_purpose: body?.key_purpose,
    credential_format: body?.credential_format,
    algorithm: body?.algorithm,
    country: body?.country,
    organization: body?.organization,
    common_name: body?.common_name,
  });
}

/**
 * Retire exactly one DID-selected managed identity.
 */
export async function deleteIssuerIdentity(body) {
  const organizationId = organization(body, 'retiring issuer identities');
  return del(`${BASE_PATH}`, {
    body: JSON.stringify({
      organization_id: organizationId,
      issuer_did: body?.issuer_did,
      key_purpose: body?.key_purpose,
      credential_format: body?.credential_format,
      algorithm: body?.algorithm,
    }),
  });
}

export default { createIssuerIdentity, listPublicIssuerIdentities, getIssuerIdentityCapabilities, getTemplateIssuerOptions, inspectIssuerIdentity, getOrgJwks, getOrgDidDocument, rebindIssuerIdentity, storeIssuerIdentityCertificate, enrollCscaCertificate, issueCscaSelfSignedCertificate, issueDscCertificate, generateIssuerIdentityCsr, deleteIssuerIdentity };
