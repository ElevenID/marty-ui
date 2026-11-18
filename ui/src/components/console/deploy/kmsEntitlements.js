import { IS_SELFHOST_UI } from '@ui-public-config';

const PREMIUM_PLAN_TIERS = new Set([
  'institution',
  'system',
  'enterprise',
  'professional',
  'self_hosted_production',
  'self-hosted-production',
  'production',
]);

export const normalizePlanTier = (value) => (
  typeof value === 'string' ? value.trim().toLowerCase() : ''
);

export const isPremiumPlanTier = (value) => PREMIUM_PLAN_TIERS.has(normalizePlanTier(value));

export const isDidWebX509ChainEligible = (planTier) => (
  IS_SELFHOST_UI || isPremiumPlanTier(planTier)
);

export const getDidWebX509ChainGateMessage = (isEligible) => (
  isEligible
    ? 'did:web X.509 chaining is enabled for this organization.'
    : 'did:web X.509 chaining requires a premium plan tier or a self-hosted deployment.'
);