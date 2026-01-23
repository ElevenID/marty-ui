/**
 * Onboarding Components Index
 * 
 * Re-exports all onboarding-related components
 */

export { default as RoleCard } from './RoleCard';
export { default as MembershipModeChip } from './MembershipModeChip';
export { default as ConfirmOrgDialog } from './ConfirmOrgDialog';
export { default as RoleSelectionStep } from './steps/RoleSelectionStep';
export { default as ApplicantJoinStep } from './steps/ApplicantJoinStep';
export { default as VendorCreateOrgStep } from './steps/VendorCreateOrgStep';
export { default as CompletionStep } from './steps/CompletionStep';
export { default as WalletPairingStep } from './steps/WalletPairingStep';

// Trust setup steps
export { default as TrustProfileStep } from './steps/TrustProfileStep';
export { default as VerifierIdentityStep } from './steps/VerifierIdentityStep';
export { default as IssuerIdentityStep } from './steps/IssuerIdentityStep';
export { default as TrustSourcesStep } from './steps/TrustSourcesStep';
export { default as TrustHealthCheckStep } from './steps/TrustHealthCheckStep';

// Consolidated trust setup steps
export { default as BusinessContextStep } from './steps/BusinessContextStep';
export { default as TechnicalIdentityStep } from './steps/TechnicalIdentityStep';
