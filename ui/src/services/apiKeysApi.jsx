/**
 * API Keys Service
 *
 * API client functions for API key management.
 * Uses the centralized api.js service for consistent error handling and retry logic.
 */
import { get, post, patch, del, getErrorMessage } from './api';
import { postWithIdempotency } from './idempotency';
import { buildDefinedQueryString, withQuery } from './queryUtils';

const ORGANIZATION_BASE_PATH = '/v1/organizations';
const API_KEYS_BASE_PATH = '/v1/api-keys';

function requireOrganizationId(organizationId) {
  const normalized = String(organizationId ?? '').trim();
  if (
    normalized === ''
    || normalized.toLowerCase() === 'null'
    || normalized.toLowerCase() === 'undefined'
  ) {
    const error = new Error('An active organization is required before managing API keys.');
    error.code = 'ORG_REQUIRED';
    error.status = 400;
    throw error;
  }
  return normalized;
}

/**
 * Get available API key scopes
 * @returns {Promise<{scopes: Array<{id: string, label: string, description: string}>}>}
 */
export async function getAvailableScopes() {
  return get(`${ORGANIZATION_BASE_PATH}/api-key-scopes`);
}

/**
 * List API keys for an organization
 * @param {string} organizationId - Organization ID
 * @param {Object} options - Filter options
 * @param {boolean} options.includeRevoked - Include revoked keys (default: false)
 * @param {boolean} options.includeExpired - Include expired keys (default: false)
 * @returns {Promise<Array>} - Array of API key objects
 */
export async function listApiKeys(organizationId, { includeRevoked = false, includeExpired = false } = {}) {
  const activeOrganizationId = requireOrganizationId(organizationId);
  const queryString = buildDefinedQueryString({
    organization_id: activeOrganizationId,
    include_revoked: includeRevoked ? 'true' : undefined,
    include_expired: includeExpired ? 'true' : undefined,
  });
  const url = withQuery(API_KEYS_BASE_PATH, queryString);
  const response = await get(url);
  return Array.isArray(response) ? response : (response?.keys || []);
}

/**
 * Create a new API key
 * @param {string} organizationId - Organization ID
 * @param {Object} keyData - Key creation data
 * @param {string} keyData.name - Key name (1-100 chars)
 * @param {Array<string>} keyData.scopes - Array of scope IDs (min 1)
 * @param {string|null} keyData.expiresAt - Optional expiration date ISO string
 * @returns {Promise<Object>} - Created API key with plain text 'key' field
 */
export async function createApiKey(organizationId, { name, scopes, expiresAt }) {
  const activeOrganizationId = requireOrganizationId(organizationId);
  const url = withQuery(API_KEYS_BASE_PATH, buildDefinedQueryString({ organization_id: activeOrganizationId }));
  return postWithIdempotency(url, {
    name,
    scopes,
    expires_at: expiresAt || null,
  });
}

/**
 * Get a single API key
 * @param {string} organizationId - Organization ID
 * @param {string} keyId - API key ID
 * @returns {Promise<Object>} - API key object
 */
export async function getApiKey(organizationId, keyId) {
  return get(withQuery(`${API_KEYS_BASE_PATH}/${keyId}`, buildDefinedQueryString({ organization_id: requireOrganizationId(organizationId) })));
}

/**
 * Update an API key
 * @param {string} organizationId - Organization ID
 * @param {string} keyId - API key ID
 * @param {Object} updates - Fields to update
 * @param {string} updates.name - New key name
 * @param {Array<string>} updates.scopes - New scopes
 * @returns {Promise<Object>} - Updated API key object
 */
export async function updateApiKey(organizationId, keyId, { name, scopes }) {
  const body = {};
  if (name !== undefined) body.name = name;
  if (scopes !== undefined) body.scopes = scopes;
  return patch(
    withQuery(`${API_KEYS_BASE_PATH}/${keyId}`, buildDefinedQueryString({ organization_id: requireOrganizationId(organizationId) })),
    body
  );
}

/**
 * Revoke an API key (soft delete - key becomes inactive)
 * @param {string} organizationId - Organization ID
 * @param {string} keyId - API key ID
 * @returns {Promise<Object>} - Updated API key object with is_active=false
 */
export async function revokeApiKey(organizationId, keyId) {
  return del(withQuery(`${API_KEYS_BASE_PATH}/${keyId}`, buildDefinedQueryString({ organization_id: requireOrganizationId(organizationId) })));
}

/**
 * Delete an API key permanently
 * @param {string} organizationId - Organization ID
 * @param {string} keyId - API key ID
 * @returns {Promise<null>} - Empty response on success
 */
export async function deleteApiKey(organizationId, keyId) {
  return del(withQuery(`${API_KEYS_BASE_PATH}/${keyId}`, buildDefinedQueryString({ organization_id: requireOrganizationId(organizationId) })));
}

/**
 * Validate an API key (used for testing keys)
 * @param {string} apiKey - The full API key to validate
 * @returns {Promise<{valid: boolean, organization_id?: string, scopes?: Array, message?: string}>}
 */
export async function validateApiKey(apiKey) {
  return post(`${ORGANIZATION_BASE_PATH}/api-keys/validate`, {}, {
    headers: {
      'X-API-Key': apiKey,
    },
  });
}

// Re-export getErrorMessage for convenience
export { getErrorMessage };

export default {
  getAvailableScopes,
  listApiKeys,
  createApiKey,
  getApiKey,
  updateApiKey,
  revokeApiKey,
  deleteApiKey,
  validateApiKey,
  getErrorMessage,
};
