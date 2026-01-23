/**
 * Mock Trust Adapter
 * 
 * Implements ITrustService with static/mock data for development.
 * Used when REACT_APP_USE_MOCK_TRUST_LIST is true.
 */

import {
  TrustFramework,
  IssuerKeySource,
  RevocationPolicy,
  createDefaultHealthStatus,
} from '../../ports/types';

// Simulated latency for realistic UX
const MOCK_LATENCY_MS = 500;

/**
 * Simulate async operation with delay.
 * @private
 */
const delay = (ms = MOCK_LATENCY_MS) => 
  new Promise(resolve => setTimeout(resolve, ms));

/**
 * Mock trust profiles storage (in-memory).
 * @private
 */
const mockProfiles = new Map();

/**
 * Mock Trust Adapter - implements ITrustService interface.
 */
class MockTrustAdapter {
  constructor(options = {}) {
    this.latencyMs = options.latencyMs ?? MOCK_LATENCY_MS;
    this.shouldFail = options.shouldFail ?? false;
  }

  /**
   * Get trust configuration for an organization.
   * @param {string} orgId - Organization ID
   * @returns {Promise<import('../ports/types').TrustProfile>}
   */
  async getTrustConfig(orgId) {
    await delay(this.latencyMs);

    if (this.shouldFail) {
      throw new Error('Mock: Failed to fetch trust config');
    }

    if (mockProfiles.has(orgId)) {
      return mockProfiles.get(orgId);
    }

    // Return a sample configured profile for demo
    const profile = {
      id: `trust-${orgId}`,
      organizationId: orgId,
      trustFramework: TrustFramework.EUDI,
      keySource: IssuerKeySource.MARTY_GENERATED,
      isConfigured: false,
      trustAnchorUrl: null,
      trustAnchorDid: null,
      policyUri: null,
      termsOfUseUri: null,
      settings: {
        trustedCountries: [],
        acceptedDocTypes: ['pid', 'mdl', 'passport'],
        revocationPolicy: RevocationPolicy.HARD_FAIL,
      },
      issuerKeys: [],
      createdAt: new Date(),
      updatedAt: null,
    };

    mockProfiles.set(orgId, profile);
    return profile;
  }

  /**
   * Update trust configuration.
   * @param {string} orgId - Organization ID
   * @param {Partial<import('../ports/types').TrustProfile>} config - Config updates
   * @returns {Promise<import('../ports/types').TrustProfile>}
   */
  async updateTrustConfig(orgId, config) {
    await delay(this.latencyMs);

    if (this.shouldFail) {
      throw new Error('Mock: Failed to update trust config');
    }

    const existing = await this.getTrustConfig(orgId);
    const updated = {
      ...existing,
      ...config,
      settings: {
        ...existing.settings,
        ...(config.settings || {}),
      },
      updatedAt: new Date(),
      isConfigured: true,
    };

    mockProfiles.set(orgId, updated);
    return updated;
  }

  /**
   * Upload BYOK (Bring Your Own Key) certificates.
   * @param {string} orgId - Organization ID
   * @param {import('../ports/types').BYOKCertificateUpload} certificates - Certificate data
   * @returns {Promise<Object>}
   */
  async uploadBYOKCertificates(orgId, certificates) {
    await delay(this.latencyMs);

    if (this.shouldFail) {
      throw new Error('Mock: Failed to upload certificates');
    }

    // Simulate processing and return mock key info
    const keyId = `key-${Date.now()}`;
    const mockKey = {
      id: keyId,
      keyId: keyId,
      algorithm: 'ES256',
      keyType: 'EC',
      did: `did:key:z${keyId}`,
      didMethod: 'key',
      isActive: true,
      isDefault: true,
      validFrom: new Date(),
      validUntil: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
      hasCertificate: true,
    };

    // Update profile with new key
    const profile = await this.getTrustConfig(orgId);
    profile.issuerKeys = [...profile.issuerKeys, mockKey];
    profile.keySource = IssuerKeySource.IMPORTED;
    profile.isConfigured = true;
    profile.updatedAt = new Date();
    mockProfiles.set(orgId, profile);

    return {
      success: true,
      key: mockKey,
      message: 'Certificates uploaded successfully',
    };
  }

  /**
   * Generate a new Marty-hosted signing key.
   * @param {string} orgId - Organization ID
   * @param {Object} options - Key generation options
   * @returns {Promise<Object>}
   */
  async generateKey(orgId, options = {}) {
    await delay(this.latencyMs);

    if (this.shouldFail) {
      throw new Error('Mock: Failed to generate key');
    }

    const algorithm = options.algorithm || 'ES256';
    const didMethod = options.didMethod || 'key';
    const keyId = `key-${Date.now()}`;

    const mockKey = {
      id: keyId,
      keyId: keyId,
      algorithm,
      keyType: algorithm === 'EdDSA' ? 'OKP' : 'EC',
      did: `did:${didMethod}:z${keyId.substring(0, 32)}`,
      didMethod,
      isActive: true,
      isDefault: options.setAsDefault ?? true,
      validFrom: new Date(),
      validUntil: new Date(Date.now() + (options.validityDays || 365) * 24 * 60 * 60 * 1000),
      hasCertificate: false,
    };

    // Update profile with new key
    const profile = await this.getTrustConfig(orgId);
    
    // If setting as default, mark others as non-default
    if (mockKey.isDefault) {
      profile.issuerKeys = profile.issuerKeys.map(k => ({
        ...k,
        isDefault: false,
      }));
    }
    
    profile.issuerKeys = [...profile.issuerKeys, mockKey];
    profile.keySource = IssuerKeySource.MARTY_GENERATED;
    profile.isConfigured = true;
    profile.updatedAt = new Date();
    mockProfiles.set(orgId, profile);

    return {
      success: true,
      key: mockKey,
      message: 'Key generated successfully',
    };
  }

  /**
   * Test connection to external key storage.
   * @param {string} orgId - Organization ID
   * @param {import('../ports/types').KeyLocationConfig} keyConfig - Key location config
   * @returns {Promise<{success: boolean, message: string, latencyMs?: number}>}
   */
  async testKeyConnection(orgId, keyConfig) {
    await delay(this.latencyMs);

    if (this.shouldFail) {
      return {
        success: false,
        message: 'Mock: Connection test failed',
      };
    }

    // Simulate successful connection for valid-looking configs
    if (keyConfig.source === IssuerKeySource.KMS && keyConfig.kmsArn) {
      return {
        success: true,
        message: 'KMS connection successful (mock)',
        latencyMs: this.latencyMs,
      };
    }

    if (keyConfig.source === IssuerKeySource.SIGNING_AGENT && keyConfig.signingAgentUrl) {
      return {
        success: true,
        message: 'Signing agent is reachable (mock)',
        latencyMs: this.latencyMs,
      };
    }

    return {
      success: false,
      message: 'No external key source configured',
    };
  }

  /**
   * Get trust health status for an organization.
   * @param {string} orgId - Organization ID
   * @returns {Promise<import('../ports/types').TrustHealthStatus>}
   */
  async getTrustHealth(orgId) {
    await delay(this.latencyMs);

    if (this.shouldFail) {
      return createDefaultHealthStatus();
    }

    const profile = await this.getTrustConfig(orgId);
    const hasKeys = profile.issuerKeys.length > 0;
    const hasActiveKey = profile.issuerKeys.some(k => k.isActive);
    const isConfigured = profile.isConfigured;

    return {
      verifier: {
        accessCertLoaded: isConfigured,
        signingConfigured: hasActiveKey,
        permissionsConfirmed: isConfigured,
      },
      issuer: {
        accessCertLoaded: hasKeys,
        signingKeyReachable: hasActiveKey,
        signingCertAttached: profile.issuerKeys.some(k => k.hasCertificate),
      },
      trust: {
        listConfigured: profile.trustFramework !== TrustFramework.CUSTOM,
        revocationEnabled: profile.settings?.revocationPolicy !== 'disabled',
      },
      chainStatus: isConfigured ? {
        rootCA: { status: 'valid', expires: '2035' },
        intermediateCA: { status: 'valid', expires: '2030' },
        crlStatus: 'up_to_date',
        healthy: true,
      } : null,
      allPassed: isConfigured && hasActiveKey,
      warnings: isConfigured ? [] : ['Trust profile not fully configured'],
      errors: [],
    };
  }

  /**
   * Clear all mock data (for testing).
   */
  clearMockData() {
    mockProfiles.clear();
  }
}

export default MockTrustAdapter;
