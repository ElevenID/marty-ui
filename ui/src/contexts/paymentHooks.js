/**
 * Payment-related hooks
 *
 * These hooks provide access to payment services and context.
 * Separated from PaymentProvider component to comply with fast refresh rules.
 */

import { useContext } from 'react';
import { PaymentContext } from './PaymentContext';

/**
 * Hook to access payment context.
 * @returns {PaymentContextValue}
 */
export function usePayment() {
  const context = useContext(PaymentContext);
  if (!context) {
    throw new Error('usePayment must be used within a PaymentProvider');
  }
  return context;
}