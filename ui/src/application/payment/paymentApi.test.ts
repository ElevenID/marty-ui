import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../../services/api', () => ({
  post: vi.fn(),
}));

import { processPayment } from './paymentApi';
import { post } from '../../services/api';

describe('paymentApi', () => {
  beforeEach(() => vi.clearAllMocks());

  it('processPayment posts to /api/payments/process', async () => {
    post.mockResolvedValue({ payment_id: 'pay_123' });

    const result = await processPayment({
      amountCents: 2500,
      currency: 'USD',
      sourceId: 'tok_abc',
    });

    expect(post).toHaveBeenCalledWith('/api/payments/process', {
      amount_cents: 2500,
      currency: 'USD',
      source_id: 'tok_abc',
    });
    expect(result.payment_id).toBe('pay_123');
  });

  it('processPayment spreads metadata into body', async () => {
    post.mockResolvedValue({ payment_id: 'pay_456' });

    await processPayment({
      amountCents: 1000,
      currency: 'EUR',
      sourceId: 'tok_def',
      metadata: { invoice_id: 'inv_1' },
    });

    expect(post).toHaveBeenCalledWith('/api/payments/process', {
      amount_cents: 1000,
      currency: 'EUR',
      source_id: 'tok_def',
      invoice_id: 'inv_1',
    });
  });
});
