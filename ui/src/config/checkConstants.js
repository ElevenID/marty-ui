/**
 * Shared constants for vetting check types and statuses.
 *
 * Extracted from ApplicantVetting so they can be reused across
 * the Application Review page, the vetting dashboard, and
 * any future check-related components.
 */

import BadgeIcon from '@mui/icons-material/Badge';
import WorkIcon from '@mui/icons-material/Work';
import FingerprintIcon from '@mui/icons-material/Fingerprint';
import SecurityIcon from '@mui/icons-material/Security';
import FlightIcon from '@mui/icons-material/Flight';
import GavelIcon from '@mui/icons-material/Gavel';
import ListIcon from '@mui/icons-material/List';
import PeopleIcon from '@mui/icons-material/People';
import SchoolIcon from '@mui/icons-material/School';
import HomeIcon from '@mui/icons-material/Home';
import AccountBalanceIcon from '@mui/icons-material/AccountBalance';
import DocumentScannerIcon from '@mui/icons-material/DocumentScanner';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import BuildIcon from '@mui/icons-material/Build';

/**
 * Icon component keyed by VettingCheckType value.
 */
export const CHECK_TYPE_ICONS = {
  identity_verification: BadgeIcon,
  document_verification: DocumentScannerIcon,
  biometric_enrollment: FingerprintIcon,
  employment_verification: WorkIcon,
  education_verification: SchoolIcon,
  address_verification: HomeIcon,
  criminal_history: GavelIcon,
  sanctions_screening: SecurityIcon,
  watchlist_check: ListIcon,
  reference_check: PeopleIcon,
  security_clearance: VerifiedUserIcon,
  aviation_experience: FlightIcon,
  financial_check: AccountBalanceIcon,
  custom: BuildIcon,
};

/**
 * MUI color keyed by VettingCheckStatus value.
 * Maps to Chip color prop.
 */
export const CHECK_STATUS_COLORS = {
  not_started: 'default',
  pending: 'warning',
  in_progress: 'info',
  passed: 'success',
  failed: 'error',
  requires_manual_review: 'warning',
  completed_passed: 'success',
  completed_failed: 'error',
  completed_conditional: 'warning',
  expired: 'error',
  waived: 'default',
  skipped: 'default',
};

/**
 * Human-readable label keyed by VettingCheckType value.
 */
export const CHECK_TYPE_LABELS = {
  identity_verification: 'Identity Verification',
  document_verification: 'Document Verification',
  biometric_enrollment: 'Biometric Enrollment',
  employment_verification: 'Employment Verification',
  education_verification: 'Education Verification',
  address_verification: 'Address Verification',
  criminal_history: 'Criminal History',
  sanctions_screening: 'Sanctions Screening',
  watchlist_check: 'Watchlist Check',
  reference_check: 'Reference Check',
  security_clearance: 'Security Clearance',
  aviation_experience: 'Aviation Experience',
  financial_check: 'Financial Check',
  custom: 'Custom Check',
};

/**
 * Human-readable label keyed by VettingCheckStatus value.
 */
export const CHECK_STATUS_LABELS = {
  not_started: 'Not Started',
  pending: 'Pending',
  in_progress: 'In Progress',
  passed: 'Passed',
  failed: 'Failed',
  requires_manual_review: 'Manual Review Required',
  completed_passed: 'Passed',
  completed_failed: 'Failed',
  completed_conditional: 'Conditional Pass',
  expired: 'Expired',
  waived: 'Waived',
  skipped: 'Skipped',
};

/**
 * Statuses that indicate a check is still in an actionable / unresolved state.
 */
export const PENDING_CHECK_STATUSES = new Set([
  'not_started',
  'pending',
  'in_progress',
  'requires_manual_review',
]);

/**
 * Statuses that indicate a check has been conclusively resolved.
 */
export const TERMINAL_CHECK_STATUSES = new Set([
  'passed',
  'failed',
  'completed_passed',
  'completed_failed',
  'completed_conditional',
  'expired',
  'waived',
  'skipped',
]);

/**
 * All 14 built-in check types available for template configuration.
 */
export const ALL_CHECK_TYPES = Object.keys(CHECK_TYPE_LABELS);
