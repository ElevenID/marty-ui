import {
  buildApplicantRegistrationPayload,
  buildApplicationCreationPayload,
  buildApprovalPayload,
  buildCompleteCheckPayload,
  buildRejectionPayload,
  canCompleteBiometricEnrollment,
  resolveApplicantCreated,
  resolveApplicantRegistrationCompleted,
  resolveApproveSuccess,
  resolveApprovedApplicationsLoadResult,
  resolveApplicationCreated,
  resolveApplicationSubmitted,
  resolveCheckCompletionSuccess,
  resolveDashboardLoadResult,
  resolveDocumentTypesLoadResult,
  resolveRejectSuccess,
  resolveViewDetailsResult,
} from './applicantVettingFlow';

export async function registerApplicant({ createApplicant, userId, formData }) {
  const applicant = await createApplicant(buildApplicantRegistrationPayload({ userId, formData }));
  return resolveApplicantCreated(applicant);
}

export async function completeApplicantBiometricEnrollment({ enrollBiometric, createdApplicant, biometricData }) {
  if (!canCompleteBiometricEnrollment({ createdApplicant, biometricData })) {
    return null;
  }

  await enrollBiometric(createdApplicant.id, biometricData);
  return resolveApplicantRegistrationCompleted(createdApplicant);
}

export async function loadApplicationDocumentTypes({ getDocumentTypes }) {
  const documentTypes = await getDocumentTypes();
  return resolveDocumentTypesLoadResult(documentTypes);
}

export async function createApplicantDocumentApplication({ createApplication, applicantId, formData }) {
  const application = await createApplication(buildApplicationCreationPayload({ applicantId, formData }));
  return resolveApplicationCreated(application);
}

export async function submitApplicantDocumentApplication({ submitApplication, createdApplication }) {
  const application = await submitApplication(createdApplication.id);
  return resolveApplicationSubmitted(application);
}

export async function loadVettingDashboard({ listApplications, getPendingChecks, limit = 50 }) {
  const [applicationsResponse, pendingChecksResponse] = await Promise.all([
    listApplications({ limit }),
    getPendingChecks(),
  ]);

  return resolveDashboardLoadResult({
    applicationsResponse,
    pendingChecksResponse,
  });
}

export async function loadVettingApplicationDetails({ getApplication, application }) {
  const details = await getApplication(application.id);
  return resolveViewDetailsResult({ application, details });
}

export async function approveVettingApplication({ approveApplication, applicationId, approvalNotes }) {
  await approveApplication(applicationId, buildApprovalPayload({ notes: approvalNotes }));
  return resolveApproveSuccess();
}

export async function rejectVettingApplication({ rejectApplication, applicationId, rejectionReason }) {
  await rejectApplication(applicationId, buildRejectionPayload({ reason: rejectionReason }));
  return resolveRejectSuccess();
}

export async function completeVettingDashboardCheck({
  completeCheck,
  getApplication,
  checkId,
  passed,
  applicationDetails,
  selectedApplication,
}) {
  await completeCheck(checkId, buildCompleteCheckPayload({ passed }));

  const result = resolveCheckCompletionSuccess(passed);
  let refreshedApplicationDetails = null;

  if (result.shouldRefreshDetails && applicationDetails && selectedApplication?.id) {
    refreshedApplicationDetails = await getApplication(selectedApplication.id);
  }

  return {
    ...result,
    applicationDetails: refreshedApplicationDetails,
  };
}

export async function loadApprovedApplicantOptions({ getApprovedApplications }) {
  const approvedApps = await getApprovedApplications();
  return resolveApprovedApplicationsLoadResult(approvedApps);
}