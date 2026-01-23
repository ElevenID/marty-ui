/**
 * Trust Service Port (Interface)
 * 
 * Defines the contract for trust configuration operations.
 * Implementations: TrustApiAdapter, MockTrustAdapter
 */

/**
 * @interface ITrustService
 * 
 * Trust service interface following hexagonal architecture.
 * All methods should be async and return promises.
 */

/**
 * @typedef {Object} ITrustService
 * @property {function(string): Promise<import('./types').TrustProfile>} getTrustConfig
 *   Get trust configuration for an organization
 * @property {function(string, Partial<import('./types').TrustProfile>): Promise<import('./types').TrustProfile>} updateTrustConfig
 *   Update trust configuration
 * @property {function(string, import('./types').BYOKCertificateUpload): Promise<Object>} uploadBYOKCertificates
 *   Upload BYOK certificates
 * @property {function(string, Object): Promise<Object>} generateKey
 *   Generate a new Marty-hosted signing key
 * @property {function(string): Promise<Object>} deactivateKey
 *   Deactivate an issuer key
 * @property {function(string, import('./types').KeyLocationConfig): Promise<{success: boolean, message: string}>} testKeyConnection
 *   Test connection to external key storage (KMS/Signing Agent)
 * @property {function(string): Promise<import('./types').TrustHealthStatus>} getTrustHealth
 *   Get trust health status for an organization
 */

/**
 * Validates that an object implements ITrustService interface.
 * @param {Object} service - Service to validate
 * @returns {boolean} - True if valid implementation
 */
export function isValidTrustService(service) {
  const requiredMethods = [
    'getTrustConfig',
    'updateTrustConfig',
    'uploadBYOKCertificates',
    'generateKey',
    'testKeyConnection',
    'getTrustHealth',
  ];

  return requiredMethods.every(
    method => typeof service[method] === 'function'
  );
}

/**
 * Trust service method signatures for documentation.
 * This is a reference - adapters should implement these methods.
 */
export const TrustServiceMethods = {
  /**
   * Get trust configuration for an organization.
   * @param {string} orgId - Organization ID
   * @returns {Promise<import('./types').TrustProfile>}
   */
  getTrustConfig: async (orgId) => {},

  /**
   * Update trust configuration.
   * @param {string} orgId - Organization ID
   * @param {Partial<import('./types').TrustProfile>} config - Config updates
   * @returns {Promise<import('./types').TrustProfile>}
   */
  updateTrustConfig: async (orgId, config) => {},

  /**
   * Upload BYOK (Bring Your Own Key) certificates.
   * @param {string} orgId - Organization ID
   * @param {import('./types').BYOKCertificateUpload} certificates - Certificate data
   * @returns {Promise<Object>} - Upload result with key info
   */
  uploadBYOKCertificates: async (orgId, certificates) => {},

  /**
   * Generate a new Marty-hosted signing key.
   * @param {string} orgId - Organization ID
   * @param {Object} options - Key generation options
   * @param {string} [options.algorithm='ES256'] - Signing algorithm
   * @param {string} [options.didMethod='key'] - DID method
   * @param {boolean} [options.setAsDefault=true] - Set as default key
   * @param {number} [options.validityDays=365] - Key validity period
   * @returns {Promise<Object>} - Generated key info (public only)
   */
  generateKey: async (orgId, options) => {},

  /**
   * Test connection to external key storage.
   * @param {string} orgId - Organization ID
   * @param {import('./types').KeyLocationConfig} keyConfig - Key location config
   * @returns {Promise<{success: boolean, message: string, latencyMs?: number}>}
   */
  testKeyConnection: async (orgId, keyConfig) => {},

  /**
   * Get trust health status for an organization.
   * @param {string} orgId - Organization ID
   * @returns {Promise<import('./types').TrustHealthStatus>}
   */
  getTrustHealth: async (orgId) => {},
};
