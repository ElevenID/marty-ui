export const MY_APPLICATION_STATUS_COLORS = {
  pending: 'warning',
  submitted: 'info',
  pending_approval: 'warning',
  under_review: 'info',
  approved: 'success',
  offered: 'primary',
  rejected: 'error',
  credentialed: 'success',
  issued: 'success',
  completed: 'success',
  needs_revision: 'warning',
};

export const MY_APPLICATION_STATUS_LABELS = {
  pending: 'Pending',
  submitted: 'Submitted',
  pending_approval: 'Pending Approval',
  under_review: 'Under Review',
  approved: 'Approved',
  offered: 'Wallet Invite Ready',
  rejected: 'Rejected',
  credentialed: 'Credential Issued',
  issued: 'Issued',
  completed: 'Completed',
  needs_revision: 'Needs Revision',
};

export function normalizeMyApplicationStatus(status) {
  return `${status || ''}`.toLowerCase();
}

export function getMyApplicationStatusPresentation(status) {
  const normalizedStatus = normalizeMyApplicationStatus(status);

  return {
    status: normalizedStatus,
    label: MY_APPLICATION_STATUS_LABELS[normalizedStatus] || status || 'Unknown',
    color: MY_APPLICATION_STATUS_COLORS[normalizedStatus] || 'default',
  };
}

export function formatMyApplicationDate(dateString, locale = 'en-US') {
  if (!dateString) return 'N/A';

  return new Date(dateString).toLocaleDateString(locale, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

export function formatMyApplicationId(applicationId) {
  if (!applicationId) {
    return 'N/A';
  }

  return applicationId.length > 8 ? `${applicationId.slice(0, 8)}...` : applicationId;
}

export function canEditMyApplication(application) {
  return normalizeMyApplicationStatus(application?.status) === 'needs_revision';
}

export function canAddMyApplicationToWallet(application) {
  const normalizedStatus = normalizeMyApplicationStatus(application?.status);
  return ['approved', 'offered'].includes(normalizedStatus);
}

export function buildMyApplicationEditNavigation(application) {
  return {
    path: `/application/${application?.credential_configuration_id}`,
    state: {
      applicationId: application?.id,
      revisionData: application,
    },
  };
}

export async function loadMyApplications({ listApplications, limit = 50 }) {
  const result = await listApplications({ limit });
  const applications = Array.isArray(result) ? result : (result?.applications || []);

  return {
    applications,
    total: result?.total || applications.length,
  };
}
