/**
 * Compatibility shell for applicant vetting components.
 *
 * Re-exports the split component modules so existing imports remain stable.
 */

export {
  ApplicantRegistration,
  ApplicationWizard,
  ApprovedApplicantSelector,
  BiometricCapture,
  VettingDashboard,
  default,
} from './applicantVetting';