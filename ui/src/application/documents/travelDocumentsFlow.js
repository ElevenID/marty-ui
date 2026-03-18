/**
 * Pure helpers for travel document administration.
 */

export const TRAVEL_DOCUMENTS_DEFAULT_STATS = {
  total_documents: 0,
  by_status: {
    active: 0,
    suspended: 0,
    revoked: 0,
    expired: 0,
    draft: 0,
  },
  issued_today: 0,
  expiring_soon: 0,
  by_type: {},
};

export function createTravelDocumentIssueForm({ issuingAuthority = '' } = {}) {
  return {
    document_type: 'eMRTD',
    document_number: '',
    holder_name: '',
    holder_given_name: '',
    holder_family_name: '',
    holder_dob: '',
    nationality: 'USA',
    issuing_country: 'USA',
    issuing_authority: issuingAuthority,
    validity_years: 10,
  };
}

export function resolveTravelDocumentsList(data) {
  if (Array.isArray(data)) {
    return {
      documents: data,
      total: data.length,
    };
  }

  return {
    documents: Array.isArray(data?.documents) ? data.documents : [],
    total: typeof data?.total === 'number' ? data.total : 0,
  };
}

export function resolveTravelDocumentStats(data, fallback = TRAVEL_DOCUMENTS_DEFAULT_STATS) {
  if (!data || typeof data !== 'object') {
    return fallback;
  }

  return {
    ...fallback,
    ...data,
    by_status: {
      ...fallback.by_status,
      ...(data.by_status || {}),
    },
    by_type: {
      ...fallback.by_type,
      ...(data.by_type || {}),
    },
  };
}

export function resolveApprovedTravelDocumentApplicants(data) {
  if (Array.isArray(data)) {
    return data;
  }

  if (Array.isArray(data?.applications)) {
    return data.applications;
  }

  return [];
}

export function prefillTravelDocumentIssueForm(issueForm, applicant) {
  if (!applicant) {
    return issueForm;
  }

  return {
    ...issueForm,
    document_type: applicant.document_type || issueForm.document_type,
    holder_name: applicant.applicant_name || issueForm.holder_name,
    holder_given_name: applicant.applicant_given_name || '',
    holder_family_name: applicant.applicant_family_name || '',
    holder_dob: applicant.applicant_dob || '',
    nationality: applicant.applicant_nationality || 'USA',
    issuing_country: applicant.applicant_nationality || 'USA',
  };
}

export function formatTravelDocumentDate(dateStr) {
  if (!dateStr) {
    return 'N/A';
  }

  return new Date(dateStr).toLocaleDateString();
}

export function formatTravelDocumentDateTime(dateStr) {
  if (!dateStr) {
    return 'N/A';
  }

  return new Date(dateStr).toLocaleString();
}

export function canSubmitTravelDocumentIssue({
  loading = false,
  issueMode = 'applicant',
  selectedApplicant = null,
  issueForm = {},
} = {}) {
  if (loading) {
    return false;
  }

  if (issueMode === 'applicant') {
    return Boolean(selectedApplicant);
  }

  return Boolean(issueForm.document_number && issueForm.holder_name && issueForm.holder_dob);
}
