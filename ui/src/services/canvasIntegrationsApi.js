import { get, post, put, del } from './api';
import { postWithIdempotency } from './idempotency';
import { buildDefinedQueryString, requireOrganizationId, withQuery } from './queryUtils';

const API_BASE = '/v1/integrations/canvas';

const PLATFORM_WRITE_FIELDS = [
  'display_name',
  'canvas_base_url',
  'lti_client_id',
  'lti_deployment_id',
  'enabled',
];

const PROGRAM_BINDING_WRITE_FIELDS = [
  'application_template_id',
  'credential_template_id',
  'display_name',
  'auto_approve_on_evidence',
  'evidence_requirements',
  'canvas_scope',
  'delivery_mode',
  'approval_policy_set_id',
  'deployment_profile_id',
  'feature_flags',
  'canvas_credentials',
];

const LTI_INSTALLATION_WRITE_FIELDS = [
  'lti_client_id',
  'lti_deployment_id',
];

const OAUTH_AUTHORIZATION_WRITE_FIELDS = [
  'client_id',
  'client_secret_secret_id',
  'capabilities',
];

function pickDefined(data = {}, fields = []) {
  return Object.fromEntries(
    fields
      .filter((field) => data[field] !== undefined)
      .map((field) => [field, data[field]])
  );
}

export async function listCanvasPlatforms(organizationId) {
  const queryString = buildDefinedQueryString({
    organization_id: requireOrganizationId(organizationId, 'loading Canvas platforms'),
  });
  const data = await get(withQuery(`${API_BASE}/platforms`, queryString));
  return Array.isArray(data) ? data : [];
}

export async function createCanvasPlatform(data, params = {}) {
  const organizationId = requireOrganizationId(
    params.organizationId || data?.organization_id || data?.organizationId,
    'creating Canvas platforms'
  );
  const queryString = buildDefinedQueryString({ organization_id: organizationId });
  return postWithIdempotency(
    withQuery(`${API_BASE}/platforms`, queryString),
    pickDefined(data, PLATFORM_WRITE_FIELDS)
  );
}

export async function updateCanvasPlatform(platformId, data) {
  return put(
    `${API_BASE}/platforms/${encodeURIComponent(platformId)}`,
    pickDefined(data, PLATFORM_WRITE_FIELDS)
  );
}

export async function finalizeCanvasLtiInstallation(platformId, data) {
  return put(
    `${API_BASE}/platforms/${encodeURIComponent(platformId)}/lti-installation`,
    pickDefined(data, LTI_INSTALLATION_WRITE_FIELDS)
  );
}

export const configureCanvasLtiInstallation = finalizeCanvasLtiInstallation;

export async function deleteCanvasPlatform(platformId) {
  return del(`${API_BASE}/platforms/${encodeURIComponent(platformId)}`);
}

export async function getCanvasLtiRegistrationConfig(platformId) {
  return get(`${API_BASE}/platforms/${encodeURIComponent(platformId)}/registration-config`);
}

export async function getCanvasPlatformReadiness(platformId) {
  return get(`${API_BASE}/platforms/${encodeURIComponent(platformId)}/readiness`);
}

export async function startCanvasOAuthConnection(platformId, data) {
  return post(
    `${API_BASE}/platforms/${encodeURIComponent(platformId)}/oauth/authorizations`,
    pickDefined(data, OAUTH_AUTHORIZATION_WRITE_FIELDS)
  );
}

export async function disconnectCanvasOAuthConnection(platformId) {
  return del(`${API_BASE}/platforms/${encodeURIComponent(platformId)}/oauth`);
}

export async function listCanvasProgramBindings(params = {}) {
  const organizationId = requireOrganizationId(params.organizationId, 'loading Canvas program bindings');
  const queryString = buildDefinedQueryString({
    organization_id: organizationId,
    platform_id: params.platformId,
    application_template_id: params.applicationTemplateId,
  });
  const data = await get(withQuery(`${API_BASE}/program-bindings`, queryString));
  return Array.isArray(data) ? data : [];
}

export async function createCanvasProgramBinding(platformId, data, params = {}) {
  const organizationId = requireOrganizationId(
    params.organizationId || data?.organization_id || data?.organizationId,
    'creating Canvas program bindings'
  );
  const queryString = buildDefinedQueryString({ organization_id: organizationId });
  return postWithIdempotency(
    withQuery(`${API_BASE}/platforms/${encodeURIComponent(platformId)}/program-bindings`, queryString),
    pickDefined(data, PROGRAM_BINDING_WRITE_FIELDS)
  );
}

export async function updateCanvasProgramBinding(bindingId, data) {
  return put(
    `${API_BASE}/program-bindings/${encodeURIComponent(bindingId)}`,
    pickDefined(data, PROGRAM_BINDING_WRITE_FIELDS)
  );
}

export async function deleteCanvasProgramBinding(bindingId) {
  return del(`${API_BASE}/program-bindings/${encodeURIComponent(bindingId)}`);
}

export async function validateCanvasProgramBinding(bindingId) {
  return post(`${API_BASE}/program-bindings/${encodeURIComponent(bindingId)}/validate`, {});
}

export async function activateCanvasProgramBinding(bindingId) {
  return post(`${API_BASE}/program-bindings/${encodeURIComponent(bindingId)}/activate`, {});
}

export async function deactivateCanvasProgramBinding(bindingId) {
  return post(`${API_BASE}/program-bindings/${encodeURIComponent(bindingId)}/deactivate`, {});
}

export async function validateCanvasCredentialsProvider(canvasCredentials = {}, params = {}) {
  return post(`${API_BASE}/canvas-credentials/validate`, {
    organization_id: requireOrganizationId(params.organizationId, 'validating Canvas credentials'),
    canvas_credentials: canvasCredentials,
  });
}

export async function listCanvasIntegrationSecrets(params = {}) {
  const organizationId = requireOrganizationId(params.organizationId, 'loading Canvas integration secrets');
  const queryString = buildDefinedQueryString({
    organization_id: organizationId,
    provider: params.provider || 'canvas_credentials',
  });
  const data = await get(withQuery(`${API_BASE}/integration-secrets`, queryString));
  return Array.isArray(data) ? data : [];
}

export async function createCanvasIntegrationSecret(data) {
  return postWithIdempotency(`${API_BASE}/integration-secrets`, {
    ...data,
    organization_id: requireOrganizationId(data?.organization_id || data?.organizationId, 'creating Canvas integration secrets'),
  });
}

export async function updateCanvasIntegrationSecret(secretId, data) {
  return put(`${API_BASE}/integration-secrets/${encodeURIComponent(secretId)}`, data);
}

export async function deleteCanvasIntegrationSecret(secretId) {
  return del(`${API_BASE}/integration-secrets/${encodeURIComponent(secretId)}`);
}

export async function discoverCanvasScope(platformId, params = {}) {
  return post(`${API_BASE}/platforms/${encodeURIComponent(platformId)}/scope-discovery`, {
    course_id: params.courseId,
    include_courses: params.includeCourses !== false,
    include_assignments: params.includeAssignments !== false,
    include_quizzes: params.includeQuizzes !== false,
    include_modules: params.includeModules !== false,
    limit: params.limit || 50,
  });
}

export async function enqueueCanvasEvidenceSync(applicationId) {
  return post(`${API_BASE}/applications/${encodeURIComponent(applicationId)}/canvas-sync`, {});
}

export async function getCanvasSyncJob(jobId) {
  return get(`${API_BASE}/canvas-sync-jobs/${encodeURIComponent(jobId)}`);
}

export async function retryCanvasSyncJob(jobId) {
  return post(`${API_BASE}/canvas-sync-jobs/${encodeURIComponent(jobId)}/retry`, {});
}

export async function resolveCanvasSyncJob(jobId) {
  return post(`${API_BASE}/canvas-sync-jobs/${encodeURIComponent(jobId)}/resolve`, {});
}

export async function listCanvasSyncJobs(params = {}) {
  const queryString = buildDefinedQueryString({
    organization_id: requireOrganizationId(params.organizationId, 'loading Canvas synchronization jobs'),
    status: params.status,
    platform_id: params.platformId,
    binding_id: params.bindingId,
  });
  const data = await get(withQuery(`${API_BASE}/canvas-sync-jobs`, queryString));
  return Array.isArray(data) ? data : (data?.items || []);
}

export async function listCanvasAwardCandidates(params = {}) {
  const queryString = buildDefinedQueryString({
    organization_id: requireOrganizationId(params.organizationId, 'loading Canvas award candidates'),
    status: params.status,
    platform_id: params.platformId,
    binding_id: params.bindingId,
  });
  const data = await get(withQuery(`${API_BASE}/canvas-award-candidates`, queryString));
  return Array.isArray(data) ? data : (data?.items || []);
}

export async function listCanvasEvidencePolicyReviews(params = {}) {
  const queryString = buildDefinedQueryString({
    organization_id: requireOrganizationId(params.organizationId, 'loading Canvas correction reviews'),
    status: params.status,
    binding_id: params.bindingId,
  });
  const data = await get(withQuery(`${API_BASE}/evidence-policy-reviews`, queryString));
  return Array.isArray(data) ? data : (data?.items || []);
}

export async function resolveCanvasEvidencePolicyReview(reviewId, action, note = '') {
  return post(`${API_BASE}/evidence-policy-reviews/${encodeURIComponent(reviewId)}/resolve`, {
    action,
    note,
  });
}

export async function getCanvasMirrorProvenance(params = {}) {
  const organizationId = requireOrganizationId(params.organizationId, 'loading Canvas mirror provenance');
  const queryString = buildDefinedQueryString({
    delivery_record_id: params.deliveryRecordId,
    external_credential_id: params.externalCredentialId,
    credential_id: params.credentialId,
    canvas_account_id: params.canvasAccountId,
    organization_id: organizationId,
  });
  return get(withQuery('/v1/issuance/delivery-records/canvas-credentials/provenance', queryString));
}

export async function getCanvasMirrorHealth(organizationId) {
  const orgId = requireOrganizationId(organizationId, 'loading Canvas mirror health');
  return get(`/v1/issuance/organizations/${encodeURIComponent(orgId)}/canvas-mirror-health`);
}

export async function processPendingCanvasMirrorDeliveries(params = {}) {
  const organizationId = requireOrganizationId(params.organizationId, 'processing Canvas mirror deliveries');
  const queryString = buildDefinedQueryString({
    organization_id: organizationId,
    limit: params.limit,
    retry_failed: params.retryFailed,
  });
  return post(withQuery('/v1/issuance/delivery-records/canvas-credentials/process-pending', queryString), {});
}

export async function processCanvasMirrorStatusSyncFailures(params = {}) {
  const organizationId = requireOrganizationId(params.organizationId, 'processing Canvas mirror status sync failures');
  const queryString = buildDefinedQueryString({
    organization_id: organizationId,
    limit: params.limit,
  });
  return post(withQuery('/v1/issuance/delivery-records/canvas-credentials/process-status-sync-failures', queryString), {});
}

export async function runCanvasMirrorAutomationCycle(params = {}) {
  const organizationId = requireOrganizationId(params.organizationId, 'running Canvas mirror automation');
  const queryString = buildDefinedQueryString({
    organization_id: organizationId,
    limit: params.limit,
    retry_failed: params.retryFailed,
  });
  return post(withQuery('/v1/issuance/delivery-records/canvas-credentials/run-automation-cycle', queryString), {});
}
