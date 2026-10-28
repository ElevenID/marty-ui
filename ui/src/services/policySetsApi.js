import { get, patch, post, withApiErrorHandling } from './api';
import { postWithIdempotency } from './idempotency';
import { requireOrganizationId } from './queryUtils';

const BASE = '/v1/policy-sets';

function orgParams(organizationId) {
  return { organization_id: requireOrganizationId(organizationId, 'managing policy sets') };
}

export async function listPolicySets(organizationId, status) {
  return withApiErrorHandling(() => get(BASE, { params: { ...orgParams(organizationId), ...(status ? { status } : {}) } }));
}

export async function listPolicySetTemplates(organizationId) {
  return withApiErrorHandling(() => get(`${BASE}/templates`, { params: orgParams(organizationId) }));
}

export async function getPolicySet(organizationId, policySetId) {
  return withApiErrorHandling(() => get(`${BASE}/${encodeURIComponent(policySetId)}`, { params: orgParams(organizationId) }));
}

export async function createPolicySet(organizationId, payload) {
  return withApiErrorHandling(async () => {
    const query = new URLSearchParams(orgParams(organizationId)).toString();
    return await postWithIdempotency(`${BASE}?${query}`, payload);
  });
}

export async function validatePolicySet(organizationId, cedarPolicies) {
  return withApiErrorHandling(() => post(`${BASE}/validate`, { cedar_policies: cedarPolicies }, { params: orgParams(organizationId) }));
}

export async function updatePolicySetMetadata(organizationId, policySetId, updates) {
  return withApiErrorHandling(async () => {
    if (!updates || !Object.keys(updates).length || Object.keys(updates).some((key) => !['name', 'description'].includes(key))) {
      throw new Error('Policy Set metadata changes must contain only changed name or description fields.');
    }
    return patch(`${BASE}/${encodeURIComponent(policySetId)}`, updates, { params: orgParams(organizationId) });
  });
}

export async function activatePolicySet(organizationId, policySetId) {
  return post(`${BASE}/${encodeURIComponent(policySetId)}/activate`, null, { params: orgParams(organizationId) });
}

export async function archivePolicySet(organizationId, policySetId) {
  return post(`${BASE}/${encodeURIComponent(policySetId)}/archive`, null, { params: orgParams(organizationId) });
}
