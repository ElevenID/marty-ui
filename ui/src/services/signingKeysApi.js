/**
 * Signing Keys API Service
 * 
 * Manages cryptographic signing keys for credential issuance and verification.
 * Keys can be rotated, and HSM/Vault integration can be configured.
 */

import { get, post, put, patch, del } from './api';
import { postWithIdempotency } from './idempotency';
import { buildDefinedQueryString, buildTruthyQueryString, withQuery } from './queryUtils';

const BASE_PATH = '/v1/signing-keys';

function resolveOrganizationId(params = {}) {
  if (typeof params === 'string') {
    return params;
  }
  return params?.organization_id || params?.organizationId || null;
}

function requireOrganizationId(params = {}, action = 'using signing keys') {
  const organizationId = resolveOrganizationId(params);
  if (
    organizationId == null
    || String(organizationId).trim() === ''
    || String(organizationId).trim().toLowerCase() === 'null'
    || String(organizationId).trim().toLowerCase() === 'undefined'
  ) {
    const error = new Error(`An active organization is required before ${action}.`);
    error.code = 'ORG_REQUIRED';
    error.status = 400;
    throw error;
  }
  return String(organizationId).trim();
}

function withOrganizationQuery(path, params = {}, extra = {}, action) {
  const organizationId = requireOrganizationId(params, action);
  return withQuery(path, buildDefinedQueryString({
    organization_id: organizationId,
    ...extra,
  }));
}

function withoutOrganizationFields(value = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return value;
  }
  const rest = { ...value };
  delete rest.organization_id;
  delete rest.organizationId;
  return rest;
}

/**
 * List signing keys for the organization
 * @param {Object} filters - Query filters
 * @param {string} filters.status - Filter by status: 'valid', 'expired', 'invalid'
 * @param {number} filters.limit - Page size
 * @param {number} filters.offset - Offset for pagination
 * @returns {Promise<Array>} List of signing keys
 */
export async function listSigningKeys(filters = {}) {
  const queryString = buildDefinedQueryString({
    organization_id: requireOrganizationId(filters, 'loading signing keys'),
    status: filters.status,
    limit: filters.limit,
    offset: filters.offset,
  });
  return get(withQuery(BASE_PATH, queryString));
}

/**
 * Get signing key by ID
 * @param {string} keyId - Key ID
 * @returns {Promise<Object>} Signing key details
 */
export async function getSigningKey(keyId, params = {}) {
  return get(withOrganizationQuery(`${BASE_PATH}/${keyId}`, params, {}, 'loading signing keys'));
}

/**
 * Upload/create a new signing key
 * @param {Object} keyData - Key configuration
 * @param {string} keyData.name - Key name
 * @param {string} keyData.algorithm - Algorithm (e.g., 'ES256', 'RS256')
 * @param {string} keyData.public_key - Public key in PEM format
 * @param {string} keyData.key_type - Key type: 'local', 'hsm', 'vault'
 * @param {Object} keyData.hsm_config - HSM configuration (if key_type === 'hsm')
 * @param {Object} keyData.vault_config - Vault configuration (if key_type === 'vault')
 * @returns {Promise<Object>} Created signing key
 */
export async function createSigningKey(keyData) {
  const body = withoutOrganizationFields(keyData);
  return postWithIdempotency(
    withOrganizationQuery(BASE_PATH, keyData, {}, 'creating signing keys'),
    body
  );
}

/**
 * Rotate a signing key (generates new key, marks old as deprecated)
 * @param {string} keyId - Key ID to rotate
 * @param {Object} options - Rotation options
 * @param {boolean} options.immediate - Whether to immediately invalidate old key
 * @returns {Promise<Object>} New signing key
 */
export async function rotateSigningKey(keyId, options = {}) {
  return post(withOrganizationQuery(`${BASE_PATH}/${keyId}/rotate`, options), withoutOrganizationFields(options));
}

/**
 * Update signing key metadata
 * @param {string} keyId - Key ID
 * @param {Object} updates - Fields to update
 * @param {string} updates.name - New name
 * @param {string} updates.status - New status: 'active', 'deprecated', 'revoked'
 * @returns {Promise<Object>} Updated signing key
 */
export async function updateSigningKey(keyId, updates = {}) {
  return patch(withOrganizationQuery(`${BASE_PATH}/${keyId}`, updates), withoutOrganizationFields(updates));
}

/**
 * Delete a signing key
 * @param {string} keyId - Key ID
 * @returns {Promise<void>}
 */
export async function deleteSigningKey(keyId, params = {}) {
  return del(withOrganizationQuery(`${BASE_PATH}/${keyId}`, params));
}

/**
 * Get HSM/Vault configuration
 * @returns {Promise<Object>} HSM/Vault settings
 */
export async function getKeyManagementConfig(params = {}) {
  return get(withOrganizationQuery(`${BASE_PATH}/config`, params, {}, 'loading key management configuration'));
}

/**
 * Update HSM/Vault configuration
 * @param {Object} config - HSM/Vault configuration
 * @param {boolean} config.hsm_enabled - Whether HSM is enabled
 * @param {Object} config.hsm_settings - HSM connection settings
 * @param {boolean} config.vault_enabled - Whether Vault is enabled
 * @param {Object} config.vault_settings - Vault connection settings
 * @returns {Promise<Object>} Updated configuration
 */
export async function updateKeyManagementConfig(config) {
  return patch(
    withOrganizationQuery(`${BASE_PATH}/config`, config, {}, 'saving key management configuration'),
    withoutOrganizationFields(config)
  );
}

/**
 * Validate a key management service registration before saving.
 * @param {Object} payload - Service registration draft
 * @returns {Promise<Object>} Validation checks and overall status
 */
export async function validateKeyManagementService(payload) {
  return post(withOrganizationQuery(`${BASE_PATH}/config/validate`, payload, {}, 'validating key management services'), withoutOrganizationFields(payload));
}

/**
 * Resolve the best signing service for a given credential format and key purpose.
 * @param {Object} params
 * @param {string} params.credential_format - e.g. 'jwt_vc_json', 'mso_mdoc'
 * @param {string} [params.key_purpose] - e.g. 'mdoc_dsc', 'vc_jwt_issuer'
 * @param {string} [params.algorithm] - e.g. 'ES256'
 * @returns {Promise<Object>} Resolved service or null
 */
export async function resolveSigningService(params) {
  return post(withOrganizationQuery(`${BASE_PATH}/config/resolve`, params), withoutOrganizationFields(params));
}

/**
 * List all valid key purposes defined in the gateway.
 * @returns {Promise<Object>} { purposes: string[] }
 */
export async function listKeyPurposes() {
  return get(`${BASE_PATH}/config/purposes`);
}

/**
 * List provider capability metadata for all supported service types.
 * @returns {Promise<Object>} Capability map keyed by service type
 */
export async function listServiceCapabilities() {
  return get(`${BASE_PATH}/config/service-capabilities`);
}

/**
 * List services with certificates expiring within a threshold.
 * @param {number} [thresholdDays=30] - Days ahead to look for expiring certs
 * @returns {Promise<Object>} { alerts: Array }
 */
export async function getCertificateExpiryAlerts(thresholdDays, params = {}) {
  return get(withOrganizationQuery(
    `${BASE_PATH}/config/certificate-expiry-alerts`,
    params,
    { days_until_expiry: thresholdDays },
    'loading certificate expiry alerts'
  ));
}

/**
 * Publish a service's public key to the org JWKS document.
 * @param {string} serviceId
 * @param {string} [organizationId]
 * @returns {Promise<Object>}
 */
export async function publishServiceToJwks(serviceId, organizationId, body = {}) {
  return post(
    withOrganizationQuery(`${BASE_PATH}/services/${serviceId}/publish-jwks`, organizationId),
    withoutOrganizationFields(body || {})
  );
}

/**
 * Publish a service's public key as a DID verification method.
 * @param {string} serviceId
 * @param {string} [organizationId]
 * @param {Object} [body] - Optional body with did_id, org_slug, fragment
 * @returns {Promise<Object>}
 */
export async function publishServiceToDidVm(serviceId, organizationId, body) {
  return post(
    withOrganizationQuery(`${BASE_PATH}/services/${serviceId}/publish-did-vm`, organizationId),
    withoutOrganizationFields(body || {})
  );
}

/**
 * Generate a PKCS#10 CSR for a service's key.
 * @param {string} serviceId
 * @param {Object} subjectFields - CSR subject fields (common_name, organization, country, etc.)
 * @returns {Promise<Object>} { csr_pem: string }
 */
export async function generateServiceCsr(serviceId, subjectFields = {}) {
  return post(
    withOrganizationQuery(`${BASE_PATH}/services/${serviceId}/certificate-csr`, subjectFields),
    withoutOrganizationFields(subjectFields)
  );
}

/**
 * Store a signed certificate response against a service.
 * @param {string} serviceId
 * @param {Object} certData - { cert_pem: string, cert_chain_pem?: string, cert_expires_at?: string }
 * @returns {Promise<Object>}
 */
export async function setServiceCertificate(serviceId, certData) {
  return put(
    withOrganizationQuery(`${BASE_PATH}/services/${serviceId}/certificate`, certData),
    withoutOrganizationFields(certData)
  );
}

/**
 * Retrieve the stored certificate and chain for a service.
 * @param {string} serviceId
 * @returns {Promise<Object>} { cert_pem, cert_chain_pem, cert_expires_at, ... }
 */
export async function getServiceCertificate(serviceId, params = {}) {
  return get(withOrganizationQuery(`${BASE_PATH}/services/${serviceId}/certificate`, params));
}

/**
 * Rotate the signing key for a service (OpenBao Transit).
 * @param {string} serviceId
 * @param {Object} [options]
 * @returns {Promise<Object>}
 */
export async function rotateServiceKey(serviceId, options = {}) {
  return post(withOrganizationQuery(`${BASE_PATH}/services/${serviceId}/rotate`, options), withoutOrganizationFields(options));
}

/**
 * Get mDoc X.509 header material (x5c chain) for a service.
 * @param {string} serviceId
 * @returns {Promise<Object>} { x5c: string[], ... }
 */
export async function getMdocX5cMaterial(serviceId, params = {}) {
  return get(withOrganizationQuery(`${BASE_PATH}/services/${serviceId}/mdoc-x5c`, params));
}

/**
 * Sign a payload using a service's KMS key.
 * @param {string} serviceId
 * @param {Object} payload - { payload_b64?: string, payload_hex?: string, algorithm?: string }
 * @returns {Promise<Object>} { signature_b64, signature_hex, algorithm, ... }
 */
export async function signPayload(serviceId, payload) {
  return post(withOrganizationQuery(`${BASE_PATH}/services/${serviceId}/sign`, payload), withoutOrganizationFields(payload));
}

/**
 * Register a holder/presentation binding key.
 * @param {Object} keyData
 * @returns {Promise<Object>}
 */
export async function registerHolderKey(keyData) {
  return post(withOrganizationQuery(`${BASE_PATH}/holder-keys`, keyData), withoutOrganizationFields(keyData));
}

/**
 * List registered holder/presentation keys.
 * @param {Object} [filters]
 * @returns {Promise<Object>}
 */
export async function listHolderKeys(filters = {}) {
  const queryString = buildTruthyQueryString({
    ...filters,
    organization_id: requireOrganizationId(filters, 'loading holder keys'),
  });
  return get(withQuery(`${BASE_PATH}/holder-keys`, queryString));
}

/**
 * Get the org JWKS document (published public keys).
 * @param {string} [organizationId]
 * @returns {Promise<Object>} JWKS document
 */
export async function getOrgJwks(organizationId) {
  return get(withOrganizationQuery(`${BASE_PATH}/jwks`, organizationId));
}

/**
 * Get the org DID document.
 * @param {string} [organizationId]
 * @returns {Promise<Object>} DID document
 */
export async function getOrgDidDocument(organizationId) {
  return get(withOrganizationQuery(`${BASE_PATH}/did-document`, organizationId));
}

// ---------------------------------------------------------------------------
// Provider-neutral issuer identities
// ---------------------------------------------------------------------------

/**
 * Provision or adopt a DID identity. Custody selection remains inside Marty.
 * @param {Object} body - { organization_id, issuer_did, key_purpose, credential_format, algorithm }
 * @returns {Promise<Object>} { identity, created }
 */
export async function createIssuerIdentity(body) {
  const organizationId = requireOrganizationId(body, 'creating issuer identities');
  return postWithIdempotency(`${BASE_PATH}/issuer-identities`, {
    organization_id: organizationId,
    issuer_did: body?.issuer_did,
    key_purpose: body?.key_purpose,
    credential_format: body?.credential_format,
    algorithm: body?.algorithm,
    key_attestation_policy: body?.key_attestation_policy,
  });
}

/**
 * List DID-first runtime identities without issuer-profile or KMS coordinates.
 * @returns {Promise<Object>} { identities: [{ issuer_did, key_purpose, algorithm, status }] }
 */
export async function listPublicIssuerIdentities(params = {}) {
  const organizationId = requireOrganizationId(params, 'loading issuer identities');
  return get(withQuery(`${BASE_PATH}/issuer-identities`, buildDefinedQueryString({
    organization_id: organizationId,
    key_purpose: params?.key_purpose,
    credential_format: params?.credential_format,
    algorithm: params?.algorithm,
  })));
}

/**
 * Rebind one DID-selected identity to Marty's compatible default signing
 * service. Provider and key coordinates remain private to the service.
 */
export async function rebindIssuerIdentity(body) {
  const organizationId = requireOrganizationId(body, 'rebinding issuer identities');
  return patch(`${BASE_PATH}/issuer-identities`, {
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
  const organizationId = requireOrganizationId(body, 'attaching issuer certificates');
  return put(`${BASE_PATH}/issuer-identities/certificate`, {
    organization_id: organizationId,
    issuer_did: body?.issuer_did,
    key_purpose: body?.key_purpose,
    credential_format: body?.credential_format,
    algorithm: body?.algorithm,
    cert_pem: body?.cert_pem,
    cert_chain_pem: body?.cert_chain_pem,
  });
}

/**
 * Retire exactly one DID-selected managed identity.
 */
export async function deleteIssuerIdentity(body) {
  const organizationId = requireOrganizationId(body, 'retiring issuer identities');
  return del(`${BASE_PATH}/issuer-identities`, {
    body: JSON.stringify({
      organization_id: organizationId,
      issuer_did: body?.issuer_did,
      key_purpose: body?.key_purpose,
      credential_format: body?.credential_format,
      algorithm: body?.algorithm,
    }),
  });
}

export default {
  listSigningKeys,
  getSigningKey,
  createSigningKey,
  rotateSigningKey,
  updateSigningKey,
  deleteSigningKey,
  getKeyManagementConfig,
  updateKeyManagementConfig,
  validateKeyManagementService,
  resolveSigningService,
  listKeyPurposes,
  listServiceCapabilities,
  getCertificateExpiryAlerts,
  publishServiceToJwks,
  publishServiceToDidVm,
  generateServiceCsr,
  setServiceCertificate,
  getServiceCertificate,
  rotateServiceKey,
  getMdocX5cMaterial,
  signPayload,
  registerHolderKey,
  listHolderKeys,
  getOrgJwks,
  getOrgDidDocument,
  createIssuerIdentity,
  listPublicIssuerIdentities,
  rebindIssuerIdentity,
  storeIssuerIdentityCertificate,
  deleteIssuerIdentity,
};
