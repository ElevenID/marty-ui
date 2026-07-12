/** MIP 0.3 applicant and reviewer API client. */
import { get, post, patch, del } from './api';
import { buildTruthyQueryString, requireOrganizationId, withQuery } from './queryUtils';

const ME_PROFILE = '/v1/me/applicant-profile';
const ME_APPLICATIONS = '/v1/me/applications';

const orgApplicantsPath = (organizationId) => (
  `/v1/organizations/${encodeURIComponent(requireOrganizationId(organizationId, 'accessing applications'))}/applicants`
);

function normalizePage(data, params = {}) {
  const items = Array.isArray(data) ? data : (data?.items || []);
  return {
    applications: items,
    items,
    total: data?.total ?? items.length,
    limit: data?.limit ?? params.limit ?? items.length,
    offset: data?.offset ?? params.offset ?? 0,
  };
}

export async function getMyApplicantProfile(organizationId) {
  const orgId = requireOrganizationId(organizationId, 'loading your applicant profile');
  try {
    return await get(withQuery(ME_PROFILE, `organization_id=${encodeURIComponent(orgId)}`));
  } catch (error) {
    if (error?.status === 404) return null;
    throw error;
  }
}

export async function upsertMyApplicantProfile(data) {
  requireOrganizationId(data?.organization_id, 'saving your applicant profile');
  return patch(ME_PROFILE, data);
}

export async function enrollMyBiometric(organizationId, data) {
  const orgId = requireOrganizationId(organizationId, 'enrolling a biometric');
  return post(withQuery(`${ME_PROFILE}/biometrics`, `organization_id=${encodeURIComponent(orgId)}`), data);
}

export async function listApplicants(organizationId, params = {}) {
  return (await listOrganizationApplications(organizationId, params)).applications;
}

export async function listApplications(params = {}) {
  const query = buildTruthyQueryString({ limit: params.limit, offset: params.offset });
  return normalizePage(await get(withQuery(ME_APPLICATIONS, query)), params);
}

export const getMyApplications = listApplications;

export async function createApplication(data) {
  return post(ME_APPLICATIONS, data);
}

export async function submitApplication(applicationId) {
  return post(`${ME_APPLICATIONS}/${encodeURIComponent(applicationId)}/submit`, {});
}

export async function withdrawApplication(applicationId, data = {}) {
  return post(`${ME_APPLICATIONS}/${encodeURIComponent(applicationId)}/withdraw`, data);
}

export async function claimApplication(applicationId, data = {}) {
  return post(`${ME_APPLICATIONS}/${encodeURIComponent(applicationId)}/claim`, data);
}

export async function getApplication(applicationId) {
  return get(`${ME_APPLICATIONS}/${encodeURIComponent(applicationId)}`);
}

export async function listOrganizationApplications(organizationId, params = {}) {
  const query = buildTruthyQueryString({
    status: params.status && params.status !== 'all' ? params.status : undefined,
    limit: params.limit,
    offset: params.offset,
  });
  return normalizePage(await get(withQuery(orgApplicantsPath(organizationId), query)), params);
}

export async function getOrganizationApplication(organizationId, applicationId) {
  return get(`${orgApplicantsPath(organizationId)}/${encodeURIComponent(applicationId)}`);
}

export async function reviewOrganizationApplication(organizationId, applicationId, decision, payload = {}) {
  if (!['approve', 'reject'].includes(decision)) throw new Error('decision must be approve or reject');
  return post(`${orgApplicantsPath(organizationId)}/${encodeURIComponent(applicationId)}/${decision}`, payload);
}

export async function issueOrganizationApplication(organizationId, applicationId, data = {}) {
  return post(`${orgApplicantsPath(organizationId)}/${encodeURIComponent(applicationId)}/issue`, data);
}

export async function getVettingChecks(organizationId, applicationId) {
  return get(`${orgApplicantsPath(organizationId)}/${encodeURIComponent(applicationId)}/checks`);
}

export async function startCheck(organizationId, applicationId, checkId) {
  return post(`${orgApplicantsPath(organizationId)}/${encodeURIComponent(applicationId)}/checks/${encodeURIComponent(checkId)}/start`, {});
}

export async function completeCheck(organizationId, applicationId, checkId, data) {
  return post(`${orgApplicantsPath(organizationId)}/${encodeURIComponent(applicationId)}/checks/${encodeURIComponent(checkId)}/complete`, data);
}

export async function requestApplicationInfo(organizationId, applicationId, data) {
  return post(`${orgApplicantsPath(organizationId)}/${encodeURIComponent(applicationId)}/request-information`, data);
}

export async function acquireReviewerLock(organizationId, applicationId) {
  return post(`${orgApplicantsPath(organizationId)}/${encodeURIComponent(applicationId)}/lock`, {});
}

export async function releaseReviewerLock(organizationId, applicationId) {
  return del(`${orgApplicantsPath(organizationId)}/${encodeURIComponent(applicationId)}/lock`);
}

export async function getLockStatus(organizationId, applicationId) {
  return get(`${orgApplicantsPath(organizationId)}/${encodeURIComponent(applicationId)}/lock`);
}

export async function getApplicationEvidenceSummary(organizationId, applicationId) {
  return get(`${orgApplicantsPath(organizationId)}/${encodeURIComponent(applicationId)}/evidence-summary`);
}

export async function runApplicationExternalEvidenceApiCheck(organizationId, applicationId, checkId, payload = {}) {
  return post(`${orgApplicantsPath(organizationId)}/${encodeURIComponent(applicationId)}/evidence/api-checks/${encodeURIComponent(checkId)}/run`, payload);
}

export async function getMyCredentials(params = {}) {
  const query = buildTruthyQueryString({ status: params.status, limit: params.limit, offset: params.offset });
  return get(withQuery('/v1/issued-credentials/mine', query));
}

export async function getApplicantStats() {
  const [applications, credentials] = await Promise.all([
    listApplications({ limit: 100 }),
    getMyCredentials({ limit: 100 }),
  ]);
  const credentialItems = credentials?.items || [];
  const pendingStatuses = new Set(['SUBMITTED', 'UNDER_REVIEW', 'VETTING_IN_PROGRESS']);
  const now = new Date();
  const ninetyDays = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);
  return {
    activeCredentials: credentialItems.filter((item) => String(item.status).toUpperCase() === 'ACTIVE').length,
    pendingApplications: applications.applications.filter((item) => pendingStatuses.has(String(item.status).toUpperCase())).length,
    expiringSoon: credentialItems.filter((item) => {
      const expiry = item.valid_until ? new Date(item.valid_until) : null;
      return expiry && expiry > now && expiry <= ninetyDays;
    }).length,
    totalApplications: applications.total,
    totalCredentials: credentials?.total ?? credentialItems.length,
  };
}

export async function submitKYC(applicationId, data) {
  return post(`${ME_APPLICATIONS}/${encodeURIComponent(applicationId)}/kyc`, data);
}

export async function getDocumentTypes() {
  return get('/v1/application-document-types');
}
