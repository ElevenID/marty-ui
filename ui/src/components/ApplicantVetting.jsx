/**
 * Compatibility shell for applicant vetting components.
 *
 * Re-exports the split component modules so existing imports remain stable.
 */

export {
  ApplicantRegistration,
} from './applicantVetting/ApplicantRegistration';

export {
  ApplicationWizard,
} from './applicantVetting/ApplicationWizard';

export {
  ApprovedApplicantSelector,
} from './applicantVetting/ApprovedApplicantSelector';

export {
  BiometricCapture,
} from './applicantVetting/BiometricCapture';

export {
  VettingDashboard,
  default,
} from './applicantVetting/VettingDashboard';