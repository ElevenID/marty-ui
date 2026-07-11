/**
 * Applicant API Service
 *
 * API functions for applicant registration, biometric enrollment,
 * application workflow, and vetting operations.
 */

import { get, post, patch, del } from './api';
import { buildTruthyQueryString, requireOrganizationId, withQuery } from './queryUtils';

const API_BASE = '/v1/applicants';

// ── Applicant Profile ─────────────────────────────────────────────────────────

export async function listApplicants(organizationId) {
  const orgId = requireOrganizationId(organizationId, 'loading applicants');
  const queryString = buildTruthyQueryString({ organization_id: orgId });
  const data = await get(withQuery(API_BASE, queryString));
  return Array.isArray(data) ? data : [];
}

export async function createApplicant(data) {
  return post(API_BASE, data);
}

export async function getApplicant(applicantId) {
  return get(`${API_BASE}/profiles/${applicantId}`);
}

export async function getApplicantByUser(userId) {
  try {
    return await get(`${API_BASE}/by-user/${userId}`);
  } catch (error) {
    if (error?.status === 404 || error?.message?.includes('404')) return null;
    throw error;
  }
}

export async function updateApplicantProfile(applicantId, updates) {
  return patch(`${API_BASE}/profiles/${applicantId}`, updates);
}

// ── Biometrics ────────────────────────────────────────────────────────────────

export async function enrollBiometric(applicantId, data) {
  return post(`${API_BASE}/profiles/${applicantId}/biometrics`, data);
}

export async function getApplicantBiometrics(applicantId) {
  return get(`${API_BASE}/profiles/${applicantId}/biometrics`);
}

// ── Applications ──────────────────────────────────────────────────────────────

export async function createApplication(data) {
  return post(`${API_BASE}/applications`, data);
}

export async function submitApplication(applicationId) {
  return post(`${API_BASE}/applications/${applicationId}/submit`, {});
}

export async function supersedeApplication(applicationId, data = {}) {
  return post(`${API_BASE}/applications/${applicationId}/supersede`, data);
}

export async function getApplication(applicationId) {
  return get(`${API_BASE}/applications/${applicationId}`);
}

export async function getApplicationEvidenceSummary(applicationId) {
  return get(`${API_BASE}/applications/${applicationId}/evidence-summary`);
}

export async function runApplicationExternalEvidenceApiCheck(applicationId, checkId, payload = {}) {
  return post(`${API_BASE}/applications/${applicationId}/evidence/api-checks/${checkId}/run`, payload);
}

export async function getApprovedApplications(limit = 50) {
  return get(withQuery(`${API_BASE}/applications/approved`, `limit=${limit}`));
}

export async function listOrganizationApplications(organizationId, params = {}) {
  const orgId = requireOrganizationId(organizationId, 'loading organization applications');
  const queryString = buildTruthyQueryString({
    organization_id: orgId,
    status: params.status && params.status !== 'all' ? params.status : undefined,
  });
  const data = await get(withQuery(`${API_BASE}/org-applications`, queryString));
  const normalized = Array.isArray(data) ? data : (data?.applications || []);
  return {
    applications: normalized,
    total: normalized.length,
    limit: params.limit || normalized.length,
    offset: params.offset || 0,
  };
}

export async function listApplicantApplicationsForProfile(applicantId) {
  const data = await get(`${API_BASE}/profiles/${applicantId}/applications`);
  return Array.isArray(data) ? data : (data?.applications || []);
}

export async function reviewOrganizationApplication(applicationId, decision, payload = {}) {
  return post(`${API_BASE}/applications/${applicationId}/review`, { decision, ...payload });
}

export async function issueOrganizationApplication(applicationId) {
  return post(`${API_BASE}/applications/${applicationId}/issue`, {});
}

export async function autoIssueApplication(applicationId) {
  return post(`${API_BASE}/applications/${applicationId}/auto-issue`, {});
}

// ── Vetting Checks ────────────────────────────────────────────────────────────

export async function getVettingChecks(applicationId) {
  return get(`${API_BASE}/applications/${applicationId}/checks`);
}

export async function startCheck(checkId) {
  return post(`${API_BASE}/checks/${checkId}/start`, {});
}

export async function completeCheck(checkId, data) {
  return post(`${API_BASE}/checks/${checkId}/complete`, data);
}

export async function getPendingChecks(checkType = null) {
  const queryString = buildTruthyQueryString({ check_type: checkType });
  return get(withQuery(`${API_BASE}/checks/pending`, queryString));
}

// ── Request Info ──────────────────────────────────────────────────────────────

export async function requestApplicationInfo(applicationId, data) {
  return post(`${API_BASE}/applications/${applicationId}/request-info`, data);
}

// ── Reviewer Lock ─────────────────────────────────────────────────────────────

export async function acquireReviewerLock(applicationId, reviewerId, reviewerName) {
  return post(`${API_BASE}/applications/${applicationId}/lock`, {
    reviewer_id: reviewerId,
    reviewer_name: reviewerName,
  });
}

export async function releaseReviewerLock(applicationId, reviewerId) {
  try {
    return await del(
      withQuery(`${API_BASE}/applications/${applicationId}/lock`,
        `reviewer_id=${encodeURIComponent(reviewerId)}`),
    );
  } catch {
    return { released: false };
  }
}

export async function getLockStatus(applicationId) {
  try {
    return await get(`${API_BASE}/applications/${applicationId}/lock`);
  } catch {
    return { locked: false };
  }
}

// ── Approval ──────────────────────────────────────────────────────────────────

export async function approveApplication(applicationId, data) {
  return post(`${API_BASE}/applications/${applicationId}/approve`, data);
}

export async function rejectApplication(applicationId, data) {
  return post(`${API_BASE}/applications/${applicationId}/reject`, data);
}

// ── KYC ───────────────────────────────────────────────────────────────────────

export async function submitKYC(applicationId, data) {
  return post(`${API_BASE}/applications/${applicationId}/kyc`, data);
}

export async function getDocumentTypes() {
  return get(`${API_BASE}/document-types`);
}

// ── Applicant Dashboard & Profile ─────────────────────────────────────────────

/**
 * List applications for the currently authenticated user.
 *
 * Performs a multi-step lookup: auth/me → applicant-by-user → applications.
 * Falls back gracefully at each step, returning an empty list rather than
 * throwing so callers do not need to handle the initial "no applicant" state.
 */
export async function listApplications(params = {}) {
  const empty = {
    applications: [],
    total: 0,
    limit: params.limit || 50,
    offset: params.offset || 0,
  };

  try {
    // Step 1: get authenticated user
    const me = await get('/v1/auth/me').catch(() => null);
    if (!me) return empty;

    const userId = me?.user?.user_id || me?.user_id || me?.sub;
    const applicantIdFromAuth = me?.user?.applicant_id || me?.applicant_id || null;
    if (!userId) return empty;

    // Step 2: resolve applicant ID
    let applicantId = null;
    const applicant = await get(`${API_BASE}/by-user/${userId}`).catch(() => null);
    if (applicant) applicantId = applicant?.id || null;
    if (!applicantId) applicantId = applicantIdFromAuth;
    if (!applicantId) return empty;

    // Step 3: fetch applications. Prefer the profile-scoped route used by the
    // current API, but keep the legacy route as a fallback for older stacks.
    let data = await get(`${API_BASE}/profiles/${applicantId}/applications`).catch(() => null);
    if (!data) {
      data = await get(`${API_BASE}/${applicantId}/applications`).catch(() => null);
    }
    if (!data) return empty;

    const normalized = Array.isArray(data) ? data : (data?.applications || []);
    return {
      applications: normalized,
      total: normalized.length,
      limit: params.limit || normalized.length,
      offset: params.offset || 0,
    };
  } catch (error) {
    console.error('Error in listApplications:', error);
    return empty;
  }
}

/** Alias for listApplications — backend filters by authenticated user automatically. */
export async function getMyApplications(params = {}) {
  return listApplications(params);
}

/** Get credentials issued to the current user. */
export async function getMyCredentials() {
  try {
    return await get('/v1/documents');
  } catch (error) {
    if (error?.status === 404 || error?.message?.includes('404')) {
      return { credentials: [] };
    }
    throw error;
  }
}

/**
 * Compute dashboard statistics for the current applicant by aggregating
 * existing endpoints. Returns safe defaults on failure.
 */
export async function getApplicantStats() {
  try {
    const [applications, credentials] = await Promise.all([
      listApplications({ limit: 100 }),
      getMyCredentials().catch(() => ({ credentials: [] })),
    ]);

    const pendingStatuses = ['SUBMITTED', 'UNDER_REVIEW', 'VETTING_IN_PROGRESS'];
    const pendingApplications = applications.applications?.filter(
      app => pendingStatuses.includes(app.status),
    ).length || 0;

    const activeCredentials = credentials.credentials?.filter(
      cred => cred.status === 'ACTIVE',
    ).length || 0;

    const now = new Date();
    const ninetyDaysFromNow = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);
    const expiringSoon = credentials.credentials?.filter(cred => {
      if (!cred.expiry_date) return false;
      const expiryDate = new Date(cred.expiry_date);
      return expiryDate > now && expiryDate <= ninetyDaysFromNow;
    }).length || 0;

    return {
      activeCredentials,
      pendingApplications,
      expiringSoon,
      totalApplications: applications.total || 0,
      totalCredentials: credentials.credentials?.length || 0,
    };
  } catch (error) {
    console.error('Error fetching applicant stats:', error);
    return {
      activeCredentials: 0,
      pendingApplications: 0,
      expiringSoon: 0,
      totalApplications: 0,
      totalCredentials: 0,
    };
  }
}
