/**
 * Pure helpers for applicant registration, application workflows, and vetting dashboards.
 */

export const APPLICATION_WIZARD_STEPS = [
  { label: 'Document Type', description: 'Select document and options' },
  { label: 'Review', description: 'Review and submit application' },
  { label: 'Submitted', description: 'Application submitted for vetting' },
];

export const APPLICANT_REGISTRATION_STEPS = [
  { label: 'Personal Information', description: 'Enter your details' },
  { label: 'Biometric Enrollment', description: 'Capture facial biometric' },
  { label: 'Complete', description: 'Registration complete' },
];

export function createApplicantRegistrationFormData() {
  return {
    given_name: '',
    family_name: '',
    email: '',
    phone_number: '',
    date_of_birth: '',
    nationality: 'USA',
    address: {
      street_line1: '',
      street_line2: '',
      city: '',
      state_province: '',
      postal_code: '',
      country: 'USA',
    },
  };
}

export function updateApplicantRegistrationFormData(formData, field, value) {
  if (field.startsWith('address.')) {
    const addressField = field.replace('address.', '');
    return {
      ...formData,
      address: {
        ...formData.address,
        [addressField]: value,
      },
    };
  }

  return {
    ...formData,
    [field]: value,
  };
}

export function normalizeEnumValue(value) {
  return value ? value.toString().replace(/-/g, '_').toUpperCase() : '';
}

export function normalizeCheckStatus(value) {
  const normalized = normalizeEnumValue(value);
  if (normalized === 'COMPLETED_PASSED') return 'PASSED';
  if (normalized === 'COMPLETED_FAILED') return 'FAILED';
  if (normalized === 'COMPLETED_CONDITIONAL') return 'REQUIRES_MANUAL_REVIEW';
  return normalized;
}

export function formatStatusLabel(value) {
  return value
    ? value
        .toLowerCase()
        .split('_')
        .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ')
    : 'Unknown';
}

export function buildApplicantRegistrationPayload({ userId, formData }) {
  return {
    user_id: userId,
    ...formData,
  };
}

export function canContinueApplicantRegistration(formData) {
  return Boolean(formData?.given_name && formData?.family_name && formData?.email);
}

export function canCompleteBiometricEnrollment({ createdApplicant, biometricData }) {
  return Boolean(createdApplicant && biometricData);
}

export function resolveApplicantCreated(applicant) {
  return {
    createdApplicant: applicant,
    activeStep: 1,
  };
}

export function resolveBiometricCaptured(biometricData) {
  return {
    biometricData,
  };
}

export function resolveApplicantRegistrationCompleted(createdApplicant) {
  return {
    activeStep: 2,
    completedApplicant: createdApplicant,
  };
}

export function createApplicationWizardFormData(issuingAuthority = '') {
  return {
    document_type: 'PASSPORT',
    issuing_authority: issuingAuthority,
    requested_validity_years: 10,
    travel_purpose: '',
    destination_countries: [],
    is_expedited: false,
  };
}

export function updateApplicationWizardFormData(formData, field, value) {
  return {
    ...formData,
    [field]: value,
  };
}

export function buildApplicationCreationPayload({ applicantId, formData }) {
  return {
    applicant_id: applicantId,
    ...formData,
  };
}

export function canSubmitApplicationWizard(formData) {
  return Boolean(formData?.document_type);
}

export function resolveDocumentTypeDetails(documentTypes = [], documentType) {
  return documentTypes.find((entry) => entry.document_type === documentType) || null;
}

export function resolveDocumentTypesLoadResult(documentTypes = []) {
  return {
    documentTypes,
  };
}

export function resolveApplicationCreated(application) {
  return {
    createdApplication: application,
    activeStep: 1,
  };
}

export function resolveApplicationSubmitted(application) {
  return {
    createdApplication: application,
    activeStep: 2,
    completedApplication: application,
  };
}

export function buildApprovalPayload({ notes, approvedBy = 'admin' }) {
  return {
    approved_by: approvedBy,
    notes: notes || '',
  };
}

export function buildRejectionPayload({ reason, rejectedBy = 'admin' }) {
  return {
    rejected_by: rejectedBy,
    reason,
  };
}

export function canRejectApplication(rejectionReason) {
  return Boolean(rejectionReason);
}

export function buildCompleteCheckPayload({ passed, performedBy = 'admin' }) {
  return {
    passed,
    performed_by: performedBy,
    notes: passed ? 'Manually verified' : 'Failed verification',
  };
}

export function filterApplicationsByTab(applications = [], tabValue) {
  if (tabValue === 1) {
    return applications.filter((app) => normalizeEnumValue(app.status) === 'PENDING_APPROVAL');
  }

  return applications;
}

export function resolveDashboardTabChange(tabValue) {
  return {
    tabValue,
  };
}

export function getDashboardStats(applications = [], pendingChecks = [], today = new Date()) {
  const todayLabel = today.toDateString();

  return {
    pendingApprovalCount: applications.filter((app) => normalizeEnumValue(app.status) === 'PENDING_APPROVAL').length,
    underReviewCount: applications.filter((app) => normalizeEnumValue(app.status) === 'UNDER_REVIEW').length,
    pendingChecksCount: pendingChecks.length,
    approvedTodayCount: applications.filter((app) => (
      normalizeEnumValue(app.status) === 'APPROVED' &&
      app.approved_at &&
      new Date(app.approved_at).toDateString() === todayLabel
    )).length,
  };
}

export function mapApprovedApplicantOptions(approvedApps = []) {
  return approvedApps.map((app) => ({
    value: app.application_id,
    primaryLabel: app.applicant_name,
    secondaryLabel: `${app.reference_number} - ${app.document_type}`,
  }));
}

export function resolveDashboardLoadResult({ applicationsResponse, pendingChecksResponse }) {
  return {
    applications: applicationsResponse?.applications || [],
    pendingChecks: pendingChecksResponse || [],
  };
}

export function resolveViewDetailsResult({ application, details }) {
  return {
    selectedApplication: application,
    applicationDetails: details,
    detailDialogOpen: true,
  };
}

export function resolveDetailDialogClose() {
  return {
    detailDialogOpen: false,
  };
}

export function resolveApproveDialogOpen(application) {
  return {
    selectedApplication: application,
    approveDialogOpen: true,
  };
}

export function resolveApproveDialogClose() {
  return {
    approveDialogOpen: false,
    approvalNotes: '',
  };
}

export function resolveRejectDialogOpen(application) {
  return {
    selectedApplication: application,
    rejectDialogOpen: true,
  };
}

export function resolveRejectDialogClose() {
  return {
    rejectDialogOpen: false,
    rejectionReason: '',
  };
}

export function resolveApprovalNotesInput(approvalNotes) {
  return {
    approvalNotes,
  };
}

export function resolveRejectionReasonInput(rejectionReason) {
  return {
    rejectionReason,
  };
}

export function resolveApproveSuccess() {
  return {
    successMessage: 'Application approved successfully',
    approveDialogOpen: false,
    approvalNotes: '',
    shouldReload: true,
  };
}

export function resolveRejectSuccess() {
  return {
    successMessage: 'Application rejected',
    rejectDialogOpen: false,
    rejectionReason: '',
    shouldReload: true,
  };
}

export function resolveCheckCompletionSuccess(passed) {
  return {
    successMessage: `Check ${passed ? 'passed' : 'failed'}`,
    shouldReload: true,
    shouldRefreshDetails: true,
  };
}

export function resolveApprovedApplicationsLoadResult(approvedApps = []) {
  return {
    approvedApps,
    options: mapApprovedApplicantOptions(approvedApps),
  };
}

export function resolveApprovedApplicantSelection(approvedApps = [], applicationId) {
  return approvedApps.find((app) => app.application_id === applicationId) || null;
}

export function resolveApprovedApplicantSelected(approvedApps = [], applicationId) {
  return {
    selectedApp: resolveApprovedApplicantSelection(approvedApps, applicationId),
  };
}
