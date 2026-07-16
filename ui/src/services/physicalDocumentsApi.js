import { apiClient, handleApiError } from './api';

export async function getPhysicalDocumentCapabilities() {
  try {
    const response = await apiClient.get('/v1/passport/capabilities');
    return response.data;
  } catch (error) {
    throw handleApiError(error);
  }
}
