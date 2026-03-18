import { del, get, getErrorMessage, patch, post } from '../../services/api';
import {
  TRAVEL_DOCUMENTS_DEFAULT_STATS,
  resolveApprovedTravelDocumentApplicants,
  resolveTravelDocumentsList,
  resolveTravelDocumentStats,
} from './travelDocumentsFlow';

const API_BASE = '/api/documents';

async function defaultGetDocuments({ documentType, status, limit, offset } = {}) {
  const params = new URLSearchParams();

  if (documentType) params.append('document_type', documentType);
  if (status) params.append('status', status);
  if (typeof limit === 'number') params.append('limit', String(limit));
  if (typeof offset === 'number') params.append('offset', String(offset));

  return get(`${API_BASE}?${params.toString()}`);
}

async function defaultGetDocumentStats() {
  return get(`${API_BASE}/stats`);
}

async function defaultGetApprovedApplicants({ documentType } = {}) {
  const params = new URLSearchParams();
  if (documentType) {
    params.append('document_type', documentType);
  }

  return get(`${API_BASE}/approved-applicants?${params.toString()}`);
}

async function defaultIssueDocument(issueForm) {
  return post(API_BASE, issueForm);
}

async function defaultIssueDocumentForApplicant({ applicationId, documentNumber, now = Date.now }) {
  const params = new URLSearchParams({
    application_id: applicationId,
    document_number: documentNumber || `DOC-${now()}`,
  });

  return post(`${API_BASE}/issue-from-application?${params.toString()}`, {});
}

async function defaultUpdateDocumentStatus({ documentId, status, reason }) {
  return patch(`${API_BASE}/${documentId}/status`, { status, reason });
}

async function defaultDeleteDocument({ documentId, reason }) {
  return del(`${API_BASE}/${documentId}?reason=${encodeURIComponent(reason)}`);
}

async function defaultGetDocumentAudit({ documentId }) {
  return get(`${API_BASE}/${documentId}/audit`);
}

export async function loadTravelDocumentsDashboard({
  filters = {},
  getDocuments = defaultGetDocuments,
  getDocumentStats = defaultGetDocumentStats,
} = {}) {
  const [documentsResult, statsResult] = await Promise.allSettled([
    getDocuments({
      documentType: filters.document_type,
      status: filters.status,
      limit: filters.limit,
      offset: filters.offset,
    }),
    getDocumentStats(),
  ]);

  if (documentsResult.status !== 'fulfilled') {
    throw new Error(getErrorMessage(documentsResult.reason) || 'Failed to fetch documents');
  }

  return {
    ...resolveTravelDocumentsList(documentsResult.value),
    stats: statsResult.status === 'fulfilled'
      ? resolveTravelDocumentStats(statsResult.value, TRAVEL_DOCUMENTS_DEFAULT_STATS)
      : TRAVEL_DOCUMENTS_DEFAULT_STATS,
    statsError: statsResult.status === 'rejected'
      ? getErrorMessage(statsResult.reason)
      : null,
  };
}

export async function loadApprovedTravelDocumentApplicants({
  documentType,
  getApprovedApplicants = defaultGetApprovedApplicants,
} = {}) {
  const result = await getApprovedApplicants({ documentType });
  return resolveApprovedTravelDocumentApplicants(result);
}

export async function issueTravelDocument({
  issueMode,
  selectedApplicant,
  issueForm,
  issueDocument = defaultIssueDocument,
  issueDocumentForApplicant = defaultIssueDocumentForApplicant,
  now = Date.now,
} = {}) {
  if (issueMode === 'applicant') {
    if (!selectedApplicant?.application_id) {
      throw new Error('Select an approved applicant before issuing a document');
    }

    await issueDocumentForApplicant({
      applicationId: selectedApplicant.application_id,
      documentNumber: issueForm?.document_number || undefined,
      now,
    });

    return {
      successMessage: 'Document issued successfully for approved applicant',
    };
  }

  await issueDocument(issueForm);

  return {
    successMessage: 'Document issued successfully',
  };
}

export async function updateTravelDocumentStatus({
  documentId,
  status,
  reason,
  updateDocumentStatus = defaultUpdateDocumentStatus,
} = {}) {
  await updateDocumentStatus({ documentId, status, reason });
  return {
    successMessage: `Document status updated to ${status}`,
  };
}

export async function deleteTravelDocument({
  documentId,
  reason,
  deleteDocument = defaultDeleteDocument,
} = {}) {
  await deleteDocument({ documentId, reason });
  return {
    successMessage: 'Document deleted successfully',
  };
}

export async function loadTravelDocumentAudit({
  documentId,
  getDocumentAudit = defaultGetDocumentAudit,
} = {}) {
  const result = await getDocumentAudit({ documentId });

  return {
    entries: Array.isArray(result?.entries) ? result.entries : [],
  };
}
