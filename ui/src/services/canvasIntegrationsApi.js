import { get, post, put, del } from './api';
import { buildDefinedQueryString, withQuery } from './queryUtils';

const API_BASE = '/v1/integrations/canvas';

export async function listCanvasPlatforms(organizationId) {
  const queryString = buildDefinedQueryString({ organization_id: organizationId });
  const data = await get(withQuery(`${API_BASE}/platforms`, queryString));
  return Array.isArray(data) ? data : [];
}

export async function createCanvasPlatform(data) {
  return post(`${API_BASE}/platforms`, data);
}

export async function updateCanvasPlatform(platformId, data) {
  return put(`${API_BASE}/platforms/${encodeURIComponent(platformId)}`, data);
}

export async function deleteCanvasPlatform(platformId) {
  return del(`${API_BASE}/platforms/${encodeURIComponent(platformId)}`);
}

export async function listCanvasProgramBindings(params = {}) {
  const queryString = buildDefinedQueryString({
    organization_id: params.organizationId,
    platform_id: params.platformId,
    application_template_id: params.applicationTemplateId,
  });
  const data = await get(withQuery(`${API_BASE}/program-bindings`, queryString));
  return Array.isArray(data) ? data : [];
}

export async function createCanvasProgramBinding(platformId, data) {
  return post(`${API_BASE}/platforms/${encodeURIComponent(platformId)}/program-bindings`, data);
}

export async function updateCanvasProgramBinding(bindingId, data) {
  return put(`${API_BASE}/program-bindings/${encodeURIComponent(bindingId)}`, data);
}

export async function deleteCanvasProgramBinding(bindingId) {
  return del(`${API_BASE}/program-bindings/${encodeURIComponent(bindingId)}`);
}

export async function validateCanvasCredentialsProvider(canvasCredentials = {}, params = {}) {
  return post(`${API_BASE}/canvas-credentials/validate`, {
    organization_id: params.organizationId,
    canvas_credentials: canvasCredentials,
  });
}

export async function listCanvasIntegrationSecrets(params = {}) {
  const queryString = buildDefinedQueryString({
    organization_id: params.organizationId,
    provider: params.provider || 'canvas_credentials',
  });
  const data = await get(withQuery(`${API_BASE}/integration-secrets`, queryString));
  return Array.isArray(data) ? data : [];
}

export async function createCanvasIntegrationSecret(data) {
  return post(`${API_BASE}/integration-secrets`, data);
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
    api_token_env: params.apiTokenEnv,
    api_token_file: params.apiTokenFile,
    include_courses: params.includeCourses !== false,
    include_assignments: params.includeAssignments !== false,
    include_quizzes: params.includeQuizzes !== false,
    include_modules: params.includeModules !== false,
    limit: params.limit || 50,
  });
}

export async function getCanvasMirrorProvenance(params = {}) {
  const queryString = buildDefinedQueryString({
    delivery_record_id: params.deliveryRecordId,
    external_credential_id: params.externalCredentialId,
    credential_id: params.credentialId,
    canvas_account_id: params.canvasAccountId,
    organization_id: params.organizationId,
  });
  return get(withQuery('/v1/issuance/delivery-records/canvas-credentials/provenance', queryString));
}

export async function getCanvasMirrorHealth(organizationId) {
  return get(`/v1/issuance/organizations/${encodeURIComponent(organizationId)}/canvas-mirror-health`);
}

export async function processPendingCanvasMirrorDeliveries(params = {}) {
  const queryString = buildDefinedQueryString({
    organization_id: params.organizationId,
    limit: params.limit,
    retry_failed: params.retryFailed,
  });
  return post(withQuery('/v1/issuance/delivery-records/canvas-credentials/process-pending', queryString), {});
}

export async function processCanvasMirrorStatusSyncFailures(params = {}) {
  const queryString = buildDefinedQueryString({
    organization_id: params.organizationId,
    limit: params.limit,
  });
  return post(withQuery('/v1/issuance/delivery-records/canvas-credentials/process-status-sync-failures', queryString), {});
}

export async function runCanvasMirrorAutomationCycle(params = {}) {
  const queryString = buildDefinedQueryString({
    organization_id: params.organizationId,
    limit: params.limit,
    retry_failed: params.retryFailed,
  });
  return post(withQuery('/v1/issuance/delivery-records/canvas-credentials/run-automation-cycle', queryString), {});
}
