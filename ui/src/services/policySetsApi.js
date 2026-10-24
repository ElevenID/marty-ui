import { apiClient, handleApiError } from './api';
import { postWithIdempotency } from './idempotency';
import { requireOrganizationId } from './queryUtils';

const BASE = '/v1/policy-sets';

function orgParams(organizationId) {
  return { organization_id: requireOrganizationId(organizationId, 'managing policy sets') };
}

export async function listPolicySets(organizationId, status) {
  try {
    const response = await apiClient.get(BASE, { params: { ...orgParams(organizationId), ...(status ? { status } : {}) } });
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
}

export async function listPolicySetTemplates(organizationId) {
  try {
    const response = await apiClient.get(`${BASE}/templates`, { params: orgParams(organizationId) });
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
}

export async function getPolicySet(organizationId, policySetId) {
  try {
    const response = await apiClient.get(`${BASE}/${encodeURIComponent(policySetId)}`, { params: orgParams(organizationId) });
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
}

export async function createPolicySet(organizationId, payload) {
  try {
    const query = new URLSearchParams(orgParams(organizationId)).toString();
    return await postWithIdempotency(`${BASE}?${query}`, payload);
  } catch (error) {
    throw handleApiError(error);
  }
}

export async function validatePolicySet(organizationId, cedarPolicies) {
  try {
    const response = await apiClient.post(`${BASE}/validate`, { cedar_policies: cedarPolicies }, { params: orgParams(organizationId) });
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
}

export async function updatePolicySetMetadata(organizationId, policySetId, patch) {
  try {
    if (!patch || !Object.keys(patch).length || Object.keys(patch).some((key) => !['name', 'description'].includes(key))) {
      throw new Error('Policy Set metadata changes must contain only changed name or description fields.');
    }
    const response = await apiClient.patch(`${BASE}/${encodeURIComponent(policySetId)}`, patch, { params: orgParams(organizationId) });
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
}

export async function activatePolicySet(organizationId, policySetId) {
  const response = await apiClient.post(`${BASE}/${encodeURIComponent(policySetId)}/activate`, null, { params: orgParams(organizationId) });
  return response.data;
}

export async function archivePolicySet(organizationId, policySetId) {
  const response = await apiClient.post(`${BASE}/${encodeURIComponent(policySetId)}/archive`, null, { params: orgParams(organizationId) });
  return response.data;
}
