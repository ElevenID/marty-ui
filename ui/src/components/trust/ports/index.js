/**
 * Trust Ports Index
 * 
 * Re-exports all port interfaces and types for the trust module.
 */

// Types and DTOs
export {
  TrustListSource,
  IssuerKeySource,
  TrustFramework,
  CertificateType,
  RevocationPolicy,
  HealthStatus,
  createDefaultTrustProfile,
  createDefaultHealthStatus,
} from './types';

// Service interface
export {
  isValidTrustService,
  TrustServiceMethods,
} from './ITrustService';

// Parser interface
export {
  isValidCertParser,
  CertParserMethods,
  SUPPORTED_CERT_EXTENSIONS,
  CERT_MIME_TYPES,
} from './ICertParser';
