/**
 * Trust Adapters Index
 * 
 * Exports all adapters and factory function for creating trust services.
 */

import TrustApiAdapter from './api/TrustApiAdapter';
import MockTrustAdapter from './mock/MockTrustAdapter';
import NodeForgeCertParser from './parsing/NodeForgeCertParser';

export { TrustApiAdapter, MockTrustAdapter, NodeForgeCertParser };

/**
 * Create a trust service adapter based on configuration.
 * 
 * Factory function following hexagonal architecture pattern.
 * Returns MockTrustAdapter in development or when explicitly configured,
 * otherwise returns TrustApiAdapter for real backend integration.
 * 
 * @param {Object} [config] - Configuration options
 * @param {boolean} [config.useMock] - Force mock adapter
 * @param {string} [config.baseUrl] - API base URL override
 * @param {Object} [config.fetchOptions] - Custom fetch options
 * @param {number} [config.mockLatencyMs] - Mock latency for realistic UX
 * @returns {TrustApiAdapter|MockTrustAdapter}
 */
export function createTrustService(config = {}) {
  const useMock = 
    config.useMock ?? 
    (process.env.REACT_APP_USE_MOCK_TRUST_LIST === 'true' ||
    process.env.NODE_ENV === 'test');

  if (useMock) {
    return new MockTrustAdapter({
      latencyMs: config.mockLatencyMs,
    });
  }

  return new TrustApiAdapter({
    baseUrl: config.baseUrl,
    fetchOptions: config.fetchOptions,
  });
}

/**
 * Create a certificate parser instance.
 * 
 * Currently only NodeForgeCertParser is available.
 * Future: could support WebCrypto-based parser.
 * 
 * @returns {NodeForgeCertParser}
 */
export function createCertParser() {
  return new NodeForgeCertParser();
}

/**
 * Default adapter instances for direct import.
 * Prefer using createTrustService() for proper configuration.
 */
export const defaultTrustService = createTrustService();
export const defaultCertParser = createCertParser();
