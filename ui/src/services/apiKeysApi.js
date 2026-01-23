/**
 * API Keys Service
 *
 * API client functions for API key management.
 * Uses the centralized api.js service for consistent error handling and retry logic.
 */
import { get, post, patch, del, getErrorMessage } from './api';

const BASE_PATH = '/api/organizations';

/**
 * Get available API key scopes
 * @returns {Promise<{scopes: Array<{id: string, label: string, description: string}>}>}
 */
export async function getAvailableScopes() {
  return get(`${BASE_PATH}/api-key-scopes`);
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
  const params = new URLSearchParams();
  if (includeRevoked) params.append('include_revoked', 'true');
  if (includeExpired) params.append('include_expired', 'true');
  const queryString = params.toString();
  const url = `${BASE_PATH}/${organizationId}/api-keys${queryString ? `?${queryString}` : ''}`;
  const response = await get(url);
  return response?.keys || [];
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
  return post(`${BASE_PATH}/${organizationId}/api-keys`, {
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
  return get(`${BASE_PATH}/${organizationId}/api-keys/${keyId}`);
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
  return patch(`${BASE_PATH}/${organizationId}/api-keys/${keyId}`, body);
}

/**
 * Revoke an API key (soft delete - key becomes inactive)
 * @param {string} organizationId - Organization ID
 * @param {string} keyId - API key ID
 * @returns {Promise<Object>} - Updated API key object with is_active=false
 */
export async function revokeApiKey(organizationId, keyId) {
  return post(`${BASE_PATH}/${organizationId}/api-keys/${keyId}/revoke`, {});
}

/**
 * Delete an API key permanently
 * @param {string} organizationId - Organization ID
 * @param {string} keyId - API key ID
 * @returns {Promise<null>} - Empty response on success
 */
export async function deleteApiKey(organizationId, keyId) {
  return del(`${BASE_PATH}/${organizationId}/api-keys/${keyId}`);
}

/**
 * Validate an API key (used for testing keys)
 * @param {string} apiKey - The full API key to validate
 * @returns {Promise<{valid: boolean, organization_id?: string, scopes?: Array, message?: string}>}
 */
export async function validateApiKey(apiKey) {
  return post(`${BASE_PATH}/api-keys/validate`, {}, {
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
