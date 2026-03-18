/**
 * Payment API service layer.
 */
import { post } from '../../services/api';

export async function processPayment({ amountCents, currency, sourceId, metadata = {} }) {
  return post('/api/payments/process', {
    amount_cents: amountCents,
    currency,
    source_id: sourceId,
    ...metadata,
  });
}
