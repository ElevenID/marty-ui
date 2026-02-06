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
 * Returns TrustApiAdapter by default for real backend integration.
 * MockTrustAdapter only used when explicitly configured (for isolated UI development).
 * 
 * @param {Object} [config] - Configuration options
 * @param {boolean} [config.useMock] - Force mock adapter (for isolated UI dev only)
 * @param {string} [config.baseUrl] - API base URL override
 * @param {Object} [config.fetchOptions] - Custom fetch options
 * @param {number} [config.mockLatencyMs] - Mock latency for realistic UX (mock only)
 * @returns {TrustApiAdapter|MockTrustAdapter}
 */
export function createTrustService(config = {}) {
  // Only use mock if explicitly requested - not by default
  const useMock = config.useMock === true;

  if (useMock) {
    console.warn('[TrustService] Using MockTrustAdapter - for development only');
    return new MockTrustAdapter({
      latencyMs: config.mockLatencyMs,
    });
  }

  // Default: use real API adapter
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
