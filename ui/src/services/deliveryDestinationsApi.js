import { apiClient } from './api';
import { postWithIdempotency } from './idempotency';
import { requireOrganizationId } from './queryUtils';

const BASE = '/v1/delivery-destinations';

export const listDeliveryDestinations = async ({
  activeOnly = true,
  organizationId,
  provider,
  mode,
} = {}) => {
  const orgId = requireOrganizationId(organizationId, 'loading delivery destinations');
  const response = await apiClient.get(BASE, {
    params: {
      active_only: activeOnly,
      organization_id: orgId,
      ...(provider ? { provider } : {}),
      ...(mode ? { mode } : {}),
    },
  });
  return response.data;
};

export const getDeliveryDestination = async (destinationId) => {
  const response = await apiClient.get(`${BASE}/${destinationId}`);
  return response.data;
};

export const createDeliveryDestination = async (payload) => {
  return postWithIdempotency(BASE, {
    ...payload,
    organization_id: requireOrganizationId(
      payload?.organization_id || payload?.organizationId,
      'creating delivery destinations',
    ),
  });
};

export const updateDeliveryDestination = async (destinationId, payload) => {
  const response = await apiClient.patch(`${BASE}/${destinationId}`, payload);
  return response.data;
};

export const deleteDeliveryDestination = async (destinationId) => {
  const response = await apiClient.delete(`${BASE}/${destinationId}`);
  return response.data;
};
