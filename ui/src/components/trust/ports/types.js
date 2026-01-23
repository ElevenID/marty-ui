/**
 * Trust Module Types (DTOs)
 * 
 * Data transfer objects and enums for trust configuration.
 * These mirror the backend models from trust/router.py
 */

/**
 * Trust list source options.
 * Matches TrustListSource enum from backend.
 */
export const TrustListSource = Object.freeze({
  AAMVA: 'aamva',
  ICAO_PKD: 'icao_pkd',
  VICAL: 'vical',
  EUDI: 'eudi',
  CUSTOM: 'custom',
});

/**
 * Issuer key source options.
 * Matches IssuerKeySource enum from backend.
 */
export const IssuerKeySource = Object.freeze({
  MARTY_GENERATED: 'marty_generated',
  IMPORTED: 'imported',
  KMS: 'kms',
  SIGNING_AGENT: 'signing_agent',
});

/**
 * Trust framework options.
 * Matches TrustFramework enum from backend.
 */
export const TrustFramework = Object.freeze({
  MARTY_HOSTED: 'marty_hosted',
  EUDI: 'eudi',
  ICAO: 'icao',
  AAMVA: 'aamva',
  CUSTOM: 'custom',
});

/**
 * Certificate type options.
 */
export const CertificateType = Object.freeze({
  RP_ACCESS: 'rp_access',
  RP_REGISTRATION: 'rp_registration',
  ISSUER_ACCESS: 'issuer_access',
  ISSUER_SIGNING: 'issuer_signing',
  ROOT_CA: 'root_ca',
  INTERMEDIATE: 'intermediate',
});

/**
 * Revocation policy options.
 */
export const RevocationPolicy = Object.freeze({
  HARD_FAIL: 'hard_fail',
  SOFT_FAIL: 'soft_fail',
  OFFLINE_GRACE: 'offline_grace',
});

/**
 * Health check status.
 */
export const HealthStatus = Object.freeze({
  VALID: 'valid',
  WARNING: 'warning',
  ERROR: 'error',
  UNKNOWN: 'unknown',
});

/**
 * @typedef {Object} CertificateData
 * @property {string} subject - Certificate subject (CN, O, etc.)
 * @property {string} issuer - Certificate issuer
 * @property {Date} validFrom - Not before date
 * @property {Date} validUntil - Not after date
 * @property {string} serialNumber - Certificate serial number
 * @property {string} algorithm - Signature algorithm
 * @property {string} fingerprint - SHA-256 fingerprint
 * @property {boolean} isValid - Whether currently valid
 * @property {boolean} isExpiringSoon - Expires within 30 days
 * @property {CertificateData[]} [chain] - Intermediate certificates (advanced view)
 * @property {string} pemData - Original PEM data
 */

/**
 * @typedef {Object} KeyLocationConfig
 * @property {string} source - One of IssuerKeySource values
 * @property {string} [kmsArn] - KMS key ARN (if source is KMS)
 * @property {string} [kmsRegion] - KMS region
 * @property {string} [signingAgentUrl] - Signing agent URL (if source is SIGNING_AGENT)
 * @property {string} [signingAgentAuth] - Auth method: 'mtls' | 'api_token'
 * @property {string} [algorithm] - Signing algorithm: 'ES256' | 'EdDSA'
 */

/**
 * @typedef {Object} TrustChainStatus
 * @property {Object} rootCA - Root CA status
 * @property {string} rootCA.status - 'valid' | 'invalid' | 'expired' | 'expiring_soon'
 * @property {string} rootCA.expires - Expiry year/date
 * @property {string} [rootCA.subject] - CA subject
 * @property {Object} [intermediateCA] - Intermediate CA status (optional)
 * @property {string} intermediateCA.status
 * @property {string} intermediateCA.expires
 * @property {string} crlStatus - 'up_to_date' | 'stale' | 'unavailable'
 * @property {boolean} healthy - Overall health
 */

/**
 * @typedef {Object} TrustHealthStatus
 * @property {Object} verifier - Verifier health checks
 * @property {boolean} verifier.accessCertLoaded
 * @property {boolean} verifier.signingConfigured
 * @property {boolean} verifier.permissionsConfirmed
 * @property {Object} issuer - Issuer health checks
 * @property {boolean} issuer.accessCertLoaded
 * @property {boolean} issuer.signingKeyReachable
 * @property {boolean} issuer.signingCertAttached
 * @property {Object} trust - Trust source health checks
 * @property {boolean} trust.listConfigured
 * @property {boolean} trust.revocationEnabled
 * @property {TrustChainStatus} [chainStatus] - Chain validation status
 * @property {boolean} allPassed - All checks passed
 * @property {string[]} warnings - Warning messages
 * @property {string[]} errors - Error messages
 */

/**
 * @typedef {Object} TrustProfile
 * @property {string} id
 * @property {string} organizationId
 * @property {string} trustFramework - One of TrustFramework values
 * @property {string} keySource - One of IssuerKeySource values
 * @property {boolean} isConfigured
 * @property {string} [trustAnchorUrl]
 * @property {string} [trustAnchorDid]
 * @property {string} [policyUri]
 * @property {string} [termsOfUseUri]
 * @property {Object} settings - Additional settings
 * @property {string[]} [settings.trustedCountries] - Country filter
 * @property {string[]} [settings.acceptedDocTypes] - Document type filter
 * @property {string} [settings.revocationPolicy] - Revocation policy
 * @property {Object[]} issuerKeys - Configured issuer keys
 * @property {Date} createdAt
 * @property {Date} [updatedAt]
 */

/**
 * @typedef {Object} BYOKCertificateUpload
 * @property {string} rootCaCertificate - PEM-encoded root CA certificate
 * @property {string} [intermediateCertificates] - PEM-encoded intermediate certs
 * @property {string} issuerCertificate - PEM-encoded issuer signing certificate
 * @property {string} privateKeyPem - PEM-encoded private key (only for direct upload)
 */

/**
 * Create default trust profile for a new organization.
 * @param {string} organizationId 
 * @returns {TrustProfile}
 */
export function createDefaultTrustProfile(organizationId) {
  return {
    id: '',
    organizationId,
    trustFramework: TrustFramework.MARTY_HOSTED,
    keySource: IssuerKeySource.MARTY_GENERATED,
    isConfigured: false,
    settings: {
      trustedCountries: [],
      acceptedDocTypes: ['pid', 'mdl', 'passport'],
      revocationPolicy: RevocationPolicy.HARD_FAIL,
    },
    issuerKeys: [],
    createdAt: new Date(),
  };
}

/**
 * Create default health status (all unchecked).
 * @returns {TrustHealthStatus}
 */
export function createDefaultHealthStatus() {
  return {
    verifier: {
      accessCertLoaded: false,
      signingConfigured: false,
      permissionsConfirmed: false,
    },
    issuer: {
      accessCertLoaded: false,
      signingKeyReachable: false,
      signingCertAttached: false,
    },
    trust: {
      listConfigured: false,
      revocationEnabled: false,
    },
    allPassed: false,
    warnings: [],
    errors: [],
  };
}
