/**
 * Signing Keys API Service
 * 
 * Manages cryptographic signing keys for credential issuance and verification.
 * Keys can be rotated, and HSM/Vault integration can be configured.
 */

import { get, post, patch, del } from './api';
import { buildTruthyQueryString, withQuery } from './queryUtils';

const BASE_PATH = '/v1/signing-keys';

/**
 * List signing keys for the organization
 * @param {Object} filters - Query filters
 * @param {string} filters.status - Filter by status: 'valid', 'expired', 'invalid'
 * @param {number} filters.limit - Page size
 * @param {number} filters.offset - Offset for pagination
 * @returns {Promise<Array>} List of signing keys
 */
export async function listSigningKeys(filters = {}) {
  const queryString = buildTruthyQueryString({
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
export async function getSigningKey(keyId) {
  return get(`${BASE_PATH}/${keyId}`);
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
  return post(BASE_PATH, keyData);
}

/**
 * Rotate a signing key (generates new key, marks old as deprecated)
 * @param {string} keyId - Key ID to rotate
 * @param {Object} options - Rotation options
 * @param {boolean} options.immediate - Whether to immediately invalidate old key
 * @returns {Promise<Object>} New signing key
 */
export async function rotateSigningKey(keyId, options = {}) {
  return post(`${BASE_PATH}/${keyId}/rotate`, options);
}

/**
 * Update signing key metadata
 * @param {string} keyId - Key ID
 * @param {Object} updates - Fields to update
 * @param {string} updates.name - New name
 * @param {string} updates.status - New status: 'active', 'deprecated', 'revoked'
 * @returns {Promise<Object>} Updated signing key
 */
export async function updateSigningKey(keyId, updates) {
  return patch(`${BASE_PATH}/${keyId}`, updates);
}

/**
 * Delete a signing key
 * @param {string} keyId - Key ID
 * @returns {Promise<void>}
 */
export async function deleteSigningKey(keyId) {
  return del(`${BASE_PATH}/${keyId}`);
}

/**
 * Get HSM/Vault configuration
 * @returns {Promise<Object>} HSM/Vault settings
 */
export async function getKeyManagementConfig() {
  return get(`${BASE_PATH}/config`);
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
  return patch(`${BASE_PATH}/config`, config);
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
};
