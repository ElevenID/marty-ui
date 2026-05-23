import { apiClient } from './api';

const BASE = '/v1/delivery-destinations';

export const listDeliveryDestinations = async ({
  activeOnly = true,
  organizationId,
  provider,
  mode,
} = {}) => {
  const response = await apiClient.get(BASE, {
    params: {
      active_only: activeOnly,
      ...(organizationId ? { organization_id: organizationId } : {}),
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
  const response = await apiClient.post(BASE, payload);
  return response.data;
};

export const updateDeliveryDestination = async (destinationId, payload) => {
  const response = await apiClient.patch(`${BASE}/${destinationId}`, payload);
  return response.data;
};

export const deleteDeliveryDestination = async (destinationId) => {
  const response = await apiClient.delete(`${BASE}/${destinationId}`);
  return response.data;
};
