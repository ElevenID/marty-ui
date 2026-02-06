/**
 * Trust-related hooks
 *
 * These hooks provide access to trust services and context.
 * Separated from TrustProvider component to comply with fast refresh rules.
 */

import { useContext } from 'react';
import { TrustContext } from './TrustProvider';

/**
 * Hook to access trust service.
 * @returns {import('./adapters/api/TrustApiAdapter').default|import('./adapters/mock/MockTrustAdapter').default}
 */
export const useTrustService = () => {
  const context = useContext(TrustContext);
  if (!context) {
    throw new Error('useTrustService must be used within a TrustProvider');
  }
  return context.trustService;
};

/**
 * Hook to access certificate parser.
 * @returns {import('./adapters/parsing/NodeForgeCertParser').default}
 */
export const useCertParser = () => {
  const context = useContext(TrustContext);
  if (!context) {
    throw new Error('useCertParser must be used within a TrustProvider');
  }
  return context.certParser;
};

/**
 * Hook to access full trust context.
 * @returns {TrustContextValue}
 */
export const useTrust = () => {
  const context = useContext(TrustContext);
  if (!context) {
    throw new Error('useTrust must be used within a TrustProvider');
  }
  return context;
};