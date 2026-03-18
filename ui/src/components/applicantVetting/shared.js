import {
  Person as PersonIcon,
  Assignment as ApplicationIcon,
  Fingerprint as FingerprintIcon,
  Security as SecurityIcon,
  Description as DocumentIcon,
} from '@mui/icons-material';

export const STATUS_COLORS = {
  DRAFT: 'default',
  SUBMITTED: 'info',
  UNDER_REVIEW: 'warning',
  PENDING_BIOMETRICS: 'secondary',
  PENDING_KYC: 'secondary',
  PENDING_APPROVAL: 'warning',
  APPROVED: 'success',
  REJECTED: 'error',
  ISSUED: 'success',
};

export const CHECK_STATUS_COLORS = {
  PENDING: 'default',
  IN_PROGRESS: 'info',
  PASSED: 'success',
  FAILED: 'error',
  REQUIRES_MANUAL_REVIEW: 'warning',
  SKIPPED: 'default',
};

export const CHECK_TYPE_ICONS = {
  IDENTITY_VERIFICATION: PersonIcon,
  BIOMETRIC_ENROLLMENT: FingerprintIcon,
  CRIMINAL_HISTORY: SecurityIcon,
  DOCUMENT_VERIFICATION: DocumentIcon,
  SECURITY_CLEARANCE: SecurityIcon,
  EMPLOYMENT_VERIFICATION: ApplicationIcon,
  ADDRESS_VERIFICATION: ApplicationIcon,
  FINANCIAL_CHECK: ApplicationIcon,
};

export const DOCUMENT_TYPES = [
  { value: 'PASSPORT', label: 'Passport', description: 'Standard passport' },
  { value: 'PASSPORT_RENEWAL', label: 'Passport Renewal', description: 'Renew existing passport' },
  { value: 'VISA', label: 'Visa', description: 'Travel visa' },
  { value: 'TRAVEL_PERMIT', label: 'Travel Permit', description: 'Temporary travel permit' },
  { value: 'DIPLOMATIC_CREDENTIAL', label: 'Diplomatic Credential', description: 'Diplomatic passport' },
  { value: 'EMERGENCY_TRAVEL_DOCUMENT', label: 'Emergency Travel Document', description: 'Emergency issuance' },
];

export const NATIONALITIES = [
  { code: 'USA', name: 'United States' },
  { code: 'GBR', name: 'United Kingdom' },
  { code: 'CAN', name: 'Canada' },
  { code: 'AUS', name: 'Australia' },
  { code: 'DEU', name: 'Germany' },
  { code: 'FRA', name: 'France' },
  { code: 'JPN', name: 'Japan' },
];

export function formatDate(dateStr) {
  if (!dateStr) return 'N/A';
  return new Date(dateStr).toLocaleDateString();
}
