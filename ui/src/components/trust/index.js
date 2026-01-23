/**
 * Trust Module Index
 * 
 * Main entry point for trust configuration components.
 * Provides hexagonal architecture with ports, adapters, and components.
 */

// Ports (interfaces and types)
export * from './ports';

// Adapters (implementations)
export {
  TrustApiAdapter,
  MockTrustAdapter,
  NodeForgeCertParser,
  createTrustService,
  createCertParser,
} from './adapters';

// Components
export {
  TrustChainStatus,
  CertificateUploader,
  KeyLocationSelector,
  TrustHealthChecklist,
} from './components';

// Context and hooks
export {
  TrustProvider,
  useTrustService,
  useCertParser,
  useTrust,
} from './TrustProvider';
