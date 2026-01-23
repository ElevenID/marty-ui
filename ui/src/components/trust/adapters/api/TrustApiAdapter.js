/**
 * Trust API Adapter
 * 
 * Implements ITrustService by wrapping the backend REST API.
 * Endpoints from trust/router.py
 */

import {
  TrustFramework,
  IssuerKeySource,
  createDefaultTrustProfile,
  createDefaultHealthStatus,
} from '../../ports/types';

const API_BASE_URL = process.env.REACT_APP_API_URL || '';

/**
 * Trust API Adapter - implements ITrustService interface.
 */
class TrustApiAdapter {
  constructor(options = {}) {
    this.baseUrl = options.baseUrl || API_BASE_URL;
    this.fetchOptions = {
      credentials: 'include',
      ...options.fetchOptions,
    };
  }

  /**
   * Make an API request with error handling.
   * @private
   */
  async _request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    const response = await fetch(url, {
      ...this.fetchOptions,
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...this.fetchOptions.headers,
        ...options.headers,
      },
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      const error = new Error(errorData.detail || `API error: ${response.status}`);
      error.status = response.status;
      error.data = errorData;
      throw error;
    }

    return response.json();
  }

  /**
   * Get trust configuration for an organization.
   * @param {string} orgId - Organization ID
   * @returns {Promise<import('../ports/types').TrustProfile>}
   */
  async getTrustConfig(orgId) {
    try {
      const data = await this._request(`/api/organizations/${orgId}/trust-config`);
      return this._mapResponseToProfile(data);
    } catch (error) {
      if (error.status === 404) {
        // Return default unconfigured profile
        return createDefaultTrustProfile(orgId);
      }
      throw error;
    }
  }

  /**
   * Update trust configuration.
   * @param {string} orgId - Organization ID
   * @param {Partial<import('../ports/types').TrustProfile>} config - Config updates
   * @returns {Promise<import('../ports/types').TrustProfile>}
   */
  async updateTrustConfig(orgId, config) {
    const payload = this._mapProfileToRequest(config);
    const data = await this._request(`/api/organizations/${orgId}/trust-config`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
    return this._mapResponseToProfile(data);
  }

  /**
   * Upload BYOK (Bring Your Own Key) certificates.
   * @param {string} orgId - Organization ID
   * @param {import('../ports/types').BYOKCertificateUpload} certificates - Certificate data
   * @returns {Promise<Object>}
   */
  async uploadBYOKCertificates(orgId, certificates) {
    const payload = {
      root_ca_certificate: certificates.rootCaCertificate,
      intermediate_certificates: certificates.intermediateCertificates || null,
      issuer_certificate: certificates.issuerCertificate,
      private_key_pem: certificates.privateKeyPem,
    };

    return this._request(`/api/organizations/${orgId}/trust-config/byok`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  /**
   * Generate a new Marty-hosted signing key.
   * @param {string} orgId - Organization ID
   * @param {Object} options - Key generation options
   * @returns {Promise<Object>}
   */
  async generateKey(orgId, options = {}) {
    const payload = {
      algorithm: options.algorithm || 'ES256',
      did_method: options.didMethod || 'key',
      set_as_default: options.setAsDefault ?? true,
      validity_days: options.validityDays || 365,
    };

    return this._request(`/api/organizations/${orgId}/trust-config/generate-key`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  /**
   * Test connection to external key storage.
   * @param {string} orgId - Organization ID
   * @param {import('../ports/types').KeyLocationConfig} keyConfig - Key location config
   * @returns {Promise<{success: boolean, message: string, latencyMs?: number}>}
   */
  async testKeyConnection(orgId, keyConfig) {
    try {
      const startTime = Date.now();
      
      // For KMS, we'd call a test endpoint
      // For Signing Agent, we'd ping the URL
      if (keyConfig.source === IssuerKeySource.SIGNING_AGENT && keyConfig.signingAgentUrl) {
        // Try to reach the signing agent health endpoint
        const response = await fetch(`${keyConfig.signingAgentUrl}/health`, {
          method: 'GET',
          signal: AbortSignal.timeout(10000), // 10 second timeout
        });
        
        const latencyMs = Date.now() - startTime;
        
        if (response.ok) {
          return {
            success: true,
            message: 'Signing agent is reachable',
            latencyMs,
          };
        } else {
          return {
            success: false,
            message: `Signing agent returned status ${response.status}`,
            latencyMs,
          };
        }
      }

      if (keyConfig.source === IssuerKeySource.KMS && keyConfig.kmsArn) {
        // For KMS, we'd need a backend endpoint to test
        // This is a placeholder - backend should implement test-kms endpoint
        return this._request(`/api/organizations/${orgId}/trust-config/test-kms`, {
          method: 'POST',
          body: JSON.stringify({
            kms_arn: keyConfig.kmsArn,
            kms_region: keyConfig.kmsRegion,
          }),
        });
      }

      return {
        success: false,
        message: 'No external key source configured',
      };
    } catch (error) {
      return {
        success: false,
        message: error.message || 'Connection test failed',
      };
    }
  }

  /**
   * Get trust health status for an organization.
   * @param {string} orgId - Organization ID
   * @returns {Promise<import('../ports/types').TrustHealthStatus>}
   */
  async getTrustHealth(orgId) {
    try {
      // Try to get config and derive health from it
      const config = await this.getTrustConfig(orgId);
      return this._deriveHealthFromConfig(config);
    } catch (error) {
      // Return default unchecked health
      return createDefaultHealthStatus();
    }
  }

  /**
   * Map API response to TrustProfile type.
   * @private
   */
  _mapResponseToProfile(data) {
    return {
      id: data.id || '',
      organizationId: data.organization_id,
      trustFramework: data.trust_framework || TrustFramework.MARTY_HOSTED,
      keySource: data.key_source || IssuerKeySource.MARTY_GENERATED,
      isConfigured: data.is_configured || false,
      trustAnchorUrl: data.trust_anchor_url,
      trustAnchorDid: data.trust_anchor_did,
      policyUri: data.policy_uri,
      termsOfUseUri: data.terms_of_use_uri,
      settings: data.settings || {},
      issuerKeys: (data.issuer_keys || []).map(key => ({
        id: key.id,
        keyId: key.key_id,
        algorithm: key.algorithm,
        keyType: key.key_type,
        did: key.did,
        didMethod: key.did_method,
        isActive: key.is_active,
        isDefault: key.is_default,
        validFrom: new Date(key.valid_from),
        validUntil: key.valid_until ? new Date(key.valid_until) : null,
        hasCertificate: key.has_certificate,
      })),
      createdAt: new Date(data.created_at),
      updatedAt: data.updated_at ? new Date(data.updated_at) : null,
    };
  }

  /**
   * Map TrustProfile to API request format.
   * @private
   */
  _mapProfileToRequest(config) {
    const payload = {};
    
    if (config.trustFramework !== undefined) {
      payload.trust_framework = config.trustFramework;
    }
    if (config.keySource !== undefined) {
      payload.key_source = config.keySource;
    }
    if (config.trustAnchorUrl !== undefined) {
      payload.trust_anchor_url = config.trustAnchorUrl;
    }
    if (config.trustAnchorDid !== undefined) {
      payload.trust_anchor_did = config.trustAnchorDid;
    }
    if (config.policyUri !== undefined) {
      payload.policy_uri = config.policyUri;
    }
    if (config.termsOfUseUri !== undefined) {
      payload.terms_of_use_uri = config.termsOfUseUri;
    }
    if (config.settings !== undefined) {
      payload.settings = config.settings;
    }

    return payload;
  }

  /**
   * Derive health status from config.
   * @private
   */
  _deriveHealthFromConfig(config) {
    const hasIssuerKeys = config.issuerKeys && config.issuerKeys.length > 0;
    const hasActiveKey = config.issuerKeys?.some(k => k.isActive);
    const isConfigured = config.isConfigured;

    return {
      verifier: {
        accessCertLoaded: isConfigured,
        signingConfigured: hasActiveKey,
        permissionsConfirmed: isConfigured,
      },
      issuer: {
        accessCertLoaded: hasIssuerKeys,
        signingKeyReachable: hasActiveKey,
        signingCertAttached: config.issuerKeys?.some(k => k.hasCertificate),
      },
      trust: {
        listConfigured: !!config.trustFramework && config.trustFramework !== TrustFramework.CUSTOM,
        revocationEnabled: config.settings?.revocationPolicy !== 'disabled',
      },
      chainStatus: null, // Would need separate endpoint
      allPassed: isConfigured && hasActiveKey,
      warnings: this._getConfigWarnings(config),
      errors: [],
    };
  }

  /**
   * Get warnings for config issues.
   * @private
   */
  _getConfigWarnings(config) {
    const warnings = [];
    
    if (!config.isConfigured) {
      warnings.push('Trust profile not fully configured');
    }
    
    const expiringKeys = config.issuerKeys?.filter(k => {
      if (!k.validUntil) return false;
      const daysUntilExpiry = (k.validUntil - new Date()) / (1000 * 60 * 60 * 24);
      return daysUntilExpiry <= 30;
    });
    
    if (expiringKeys?.length > 0) {
      warnings.push(`${expiringKeys.length} key(s) expiring soon`);
    }

    return warnings;
  }
}

export default TrustApiAdapter;
