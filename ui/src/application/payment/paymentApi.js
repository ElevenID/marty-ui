/**
 * Billing API service layer.
 *
 * Calls the billing service via the gateway proxy (/v1/billing/*).
 */
import { get, post } from '../../services/api';

export async function subscribe({ organizationId, planTier, paymentNonce }) {
  return post('/v1/billing/subscribe', {
    organization_id: organizationId,
    plan_tier: planTier,
    payment_nonce: paymentNonce,
  });
}

export async function changePlan({ organizationId, newPlanTier }) {
  return post('/v1/billing/change-plan', {
    organization_id: organizationId,
    new_plan_tier: newPlanTier,
  });
}

export async function cancelSubscription({ organizationId, atPeriodEnd = true }) {
  return post('/v1/billing/cancel', {
    organization_id: organizationId,
    at_period_end: atPeriodEnd,
  });
}

export async function getSubscription(organizationId) {
  return get(`/v1/billing/subscription?organization_id=${encodeURIComponent(organizationId)}`);
}

export async function getInvoices(organizationId, { limit = 50, offset = 0 } = {}) {
  const params = new URLSearchParams({
    organization_id: organizationId,
    limit: String(limit),
    offset: String(offset),
  });
  return get(`/v1/billing/invoices?${params}`);
}

export async function addPaymentMethod({ organizationId, paymentNonce }) {
  return post('/v1/billing/payment-methods', {
    organization_id: organizationId,
    payment_nonce: paymentNonce,
  });
}

export async function getPaymentMethods(organizationId) {
  return get(`/v1/billing/payment-methods?organization_id=${encodeURIComponent(organizationId)}`);
}
