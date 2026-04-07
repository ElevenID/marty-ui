/**
 * API Service — Browser entry point.
 *
 * Thin wrapper over @elevenid/marty-api-core that injects browser-specific config:
 *   • Base URL from Vite env (import.meta.env.VITE_API_URL)
 *   • Cookie-based auth (credentials: 'include')
 *
 * All retry logic, error parsing, and request helpers live in the shared
 * @elevenid/marty-api-core package so they can be shared with the CLI
 * and test harnesses.
 */
import {
  createApiClient,
  getErrorMessage,
  getErrorCode,
  isAuthError,
  isRetryableError,
  handleApiError,
} from '@elevenid/marty-api-core';

const client = createApiClient({
  baseUrl: import.meta.env.VITE_API_URL || '',
  requestOptions: () => ({ credentials: 'include' }),
});

export const {
  fetchWithRetry,
  apiRequest,
  get,
  post,
  put,
  patch,
  del,
  reportClientError,
  apiClient,
} = client;

export { getErrorMessage, getErrorCode, isAuthError, isRetryableError, handleApiError };

export default {
  fetchWithRetry,
  apiRequest,
  get,
  post,
  put,
  patch,
  del,
  reportClientError,
  getErrorMessage,
  getErrorCode,
  isAuthError,
  isRetryableError,
  apiClient,
  handleApiError,
};
