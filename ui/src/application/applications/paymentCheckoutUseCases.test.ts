import { describe, expect, it, vi } from 'vitest';

import {
  buildPaymentCheckoutInitialBillingInfo,
  buildPaymentCheckoutMetadata,
  buildPaymentCheckoutReceipt,
  buildPaymentCheckoutSubmissionPayload,
  initializePaymentCheckout,
  processPaymentCheckout,
  submitPaymentCheckoutApplication,
  updatePaymentCheckoutBillingInfo,
  validatePaymentCheckoutBilling,
} from './paymentCheckoutUseCases';

describe('paymentCheckout use cases', () => {
  it('builds and updates billing info', () => {
    expect(buildPaymentCheckoutInitialBillingInfo({ name: 'Ada', email: 'ada@example.com' })).toEqual({
      name: 'Ada',
      email: 'ada@example.com',
      address: '',
      city: '',
      state: '',
      zip: '',
      country: 'US',
    });

    expect(updatePaymentCheckoutBillingInfo({ city: 'London' }, 'zip', '12345')).toEqual({
      city: 'London',
      zip: '12345',
    });
  });

  it('validates billing completeness', () => {
    expect(validatePaymentCheckoutBilling({
      name: 'Ada',
      email: 'ada@example.com',
      address: '1 Main St',
      city: 'Paris',
      state: 'TX',
      zip: '75001',
    })).toBe(true);

    expect(validatePaymentCheckoutBilling({ name: 'Ada' })).toBe(false);
  });

  it('initializes checkout and redirects when credential is missing', async () => {
    const navigate = vi.fn();

    await expect(initializePaymentCheckout({
      credential: null,
      processingFee: 25,
      navigate,
      initializePayment: vi.fn(),
    })).resolves.toEqual({
      redirected: true,
      error: null,
    });

    expect(navigate).toHaveBeenCalledWith('/credentials');

    await expect(initializePaymentCheckout({
      credential: { id: 'cred-1' },
      processingFee: 25,
      navigate: vi.fn(),
      initializePayment: vi.fn().mockResolvedValue({ success: false, error: 'boom' }),
    })).resolves.toEqual({
      redirected: false,
      error: 'boom',
    });
  });

  it('builds checkout metadata, payloads, and receipts', () => {
    expect(buildPaymentCheckoutMetadata({
      credential: { id: 'cred-1', name: 'Passport' },
      user: { email: 'ada@example.com' },
      billingInfo: { city: 'Paris' },
    })).toEqual({
      billingContact: { city: 'Paris' },
      metadata: {
        credentialId: 'cred-1',
        credentialName: 'Passport',
        applicantEmail: 'ada@example.com',
      },
    });

    expect(buildPaymentCheckoutSubmissionPayload({
      credential: { id: 'cred-1' },
      processingFee: 25,
      billingInfo: { city: 'Paris' },
      paymentResult: { paymentId: 'pay-1' },
    })).toEqual({
      credentialId: 'cred-1',
      credentialType: 'cred-1',
      paymentId: 'pay-1',
      processingFee: 25,
      billingInfo: { city: 'Paris' },
    });

    expect(buildPaymentCheckoutReceipt({
      applicationId: 'app-1',
      paymentResult: { paymentId: 'pay-1' },
      processingFee: 25,
      credentialName: 'Passport',
      nowIso: '2026-03-16T00:00:00.000Z',
    })).toEqual({
      applicationId: 'app-1',
      paymentId: 'pay-1',
      amount: 25,
      date: '2026-03-16T00:00:00.000Z',
      credentialName: 'Passport',
      warning: null,
    });
  });

  it('submits checkout applications and falls back to pending receipts on submission failure', async () => {
    await expect(submitPaymentCheckoutApplication({
      submitCheckoutApplication: vi.fn().mockResolvedValue({ applicationId: 'app-1' }),
      credential: { name: 'Passport', id: 'cred-1' },
      processingFee: 25,
      billingInfo: { city: 'Paris' },
      paymentResult: { paymentId: 'pay-1' },
      nowIso: '2026-03-16T00:00:00.000Z',
    })).resolves.toEqual({
      receiptData: {
        applicationId: 'app-1',
        paymentId: 'pay-1',
        amount: 25,
        date: '2026-03-16T00:00:00.000Z',
        credentialName: 'Passport',
        warning: null,
      },
      activeStep: 2,
      error: null,
    });

    const fallback = await submitPaymentCheckoutApplication({
      submitCheckoutApplication: vi.fn().mockRejectedValue(new Error('nope')),
      credential: { name: 'Passport', id: 'cred-1' },
      processingFee: 25,
      billingInfo: { city: 'Paris' },
      paymentResult: { paymentId: 'pay-1' },
      nowIso: '2026-03-16T00:00:00.000Z',
    });

    expect(fallback.receiptData.warning).toContain('Application submission pending');
    expect(fallback.activeStep).toBe(2);
  });

  it('processes payments using the payment context contract and supports free submissions', async () => {
    const submitCheckoutApplication = vi.fn().mockResolvedValue({ applicationId: 'app-1' });

    await expect(processPaymentCheckout({
      processingFee: 25,
      billingInfo: { city: 'Paris' },
      credential: { id: 'cred-1', name: 'Passport' },
      user: { email: 'ada@example.com' },
      processPayment: vi.fn().mockResolvedValue({ success: true, paymentId: 'pay-1' }),
      submitCheckoutApplication,
      nowIso: '2026-03-16T00:00:00.000Z',
    })).resolves.toMatchObject({
      activeStep: 2,
      receiptData: expect.objectContaining({ paymentId: 'pay-1' }),
    });

    await expect(processPaymentCheckout({
      processingFee: 0,
      billingInfo: { city: 'Paris' },
      credential: { id: 'cred-1', name: 'Passport' },
      user: { email: 'ada@example.com' },
      processPayment: vi.fn(),
      submitCheckoutApplication,
      nowIso: '2026-03-16T00:00:00.000Z',
    })).resolves.toMatchObject({
      activeStep: 2,
      receiptData: expect.objectContaining({ amount: 0 }),
    });

    await expect(processPaymentCheckout({
      processingFee: 25,
      billingInfo: { city: 'Paris' },
      credential: { id: 'cred-1', name: 'Passport' },
      user: { email: 'ada@example.com' },
      processPayment: vi.fn().mockResolvedValue({ success: false, error: 'Declined' }),
      submitCheckoutApplication,
    })).rejects.toThrow('Declined');
  });
});
