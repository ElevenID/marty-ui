/**
 * API Service
 * 
 * Unified API client with:
 * - Automatic retry with exponential backoff for GET requests
 * - Unified error response parsing
 * - Client error reporting
 * - Request ID tracking
 */

// API base URL
const API_BASE_URL = process.env.REACT_APP_API_URL || '';

/**
 * Default retry configuration for GET requests.
 */
const DEFAULT_RETRY_CONFIG = {
  maxRetries: 3,
  baseDelay: 1000, // 1 second
  maxDelay: 10000, // 10 seconds
  backoffMultiplier: 2,
  // HTTP status codes that should trigger retry
  retryableStatuses: [408, 429, 500, 502, 503, 504],
  // Error types that should trigger retry
  retryableErrors: ['TypeError', 'NetworkError'],
};


/**
 * Sleep for a given number of milliseconds.
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}


/**
 * Calculate delay with exponential backoff and jitter.
 */
function calculateDelay(attempt, config) {
  const exponentialDelay = config.baseDelay * Math.pow(config.backoffMultiplier, attempt);
  const cappedDelay = Math.min(exponentialDelay, config.maxDelay);
  // Add random jitter (±25%)
  const jitter = cappedDelay * 0.25 * (Math.random() * 2 - 1);
  return Math.round(cappedDelay + jitter);
}


/**
 * Check if an error is retryable.
 */
function isRetryable(error, response, config) {
  // Check if error type is retryable
  if (error && config.retryableErrors.includes(error.name)) {
    return true;
  }
  
  // Check if HTTP status is retryable
  if (response && config.retryableStatuses.includes(response.status)) {
    return true;
  }
  
  // Check for specific error codes that indicate transient failures
  if (error?.code === 'ECONNRESET' || error?.code === 'ETIMEDOUT') {
    return true;
  }
  
  return false;
}


/**
 * Parse error response into unified format.
 */
async function parseErrorResponse(response) {
  try {
    const data = await response.json();
    
    // Check for unified error response format
    if (data.error) {
      return {
        error: data.error,
        request_id: data.request_id,
        timestamp: data.timestamp,
      };
    }
    
    // Check for validation errors format
    if (data.errors) {
      return {
        errors: data.errors,
        request_id: data.request_id,
        timestamp: data.timestamp,
      };
    }
    
    // Fall back to generic error
    return {
      error: {
        code: `HTTP_${response.status}`,
        message: data.detail || data.message || response.statusText,
        user_message: data.detail || 'An error occurred',
        severity: response.status >= 500 ? 'high' : 'low',
        recovery_action: response.status >= 500 ? 'retry' : 'fail_fast',
      },
      request_id: response.headers.get('X-Request-ID'),
    };
  } catch (parseError) {
    // If response isn't JSON, create a generic error
    return {
      error: {
        code: `HTTP_${response.status}`,
        message: response.statusText,
        user_message: 'An unexpected error occurred',
        severity: 'high',
        recovery_action: 'retry',
      },
      request_id: response.headers.get('X-Request-ID'),
    };
  }
}


/**
 * Enhanced fetch with retry logic for GET requests.
 * 
 * @param {string} url - The URL to fetch
 * @param {Object} options - Fetch options
 * @param {Object} retryConfig - Retry configuration (optional, for GET requests)
 * @returns {Promise<Response>}
 */
export async function fetchWithRetry(url, options = {}, retryConfig = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const shouldRetry = method === 'GET'; // Only auto-retry GET requests
  
  const config = shouldRetry ? {
    ...DEFAULT_RETRY_CONFIG,
    ...retryConfig,
  } : { maxRetries: 0 };
  
  let lastError = null;
  let lastResponse = null;
  
  for (let attempt = 0; attempt <= config.maxRetries; attempt++) {
    try {
      // Add default headers
      const headers = {
        'Accept': 'application/json',
        ...options.headers,
      };
      
      // Add request ID for tracing
      const requestId = crypto.randomUUID?.() || 
        `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      headers['X-Request-ID'] = requestId;
      
      const response = await fetch(url, {
        ...options,
        headers,
        credentials: options.credentials || 'include',
      });
      
      // Success case
      if (response.ok) {
        return response;
      }
      
      // Store for retry decision
      lastResponse = response;
      
      // Check if we should retry
      if (shouldRetry && attempt < config.maxRetries && isRetryable(null, response, config)) {
        const delay = calculateDelay(attempt, config);
        console.warn(
          `Request failed with status ${response.status}, retrying in ${delay}ms ` +
          `(attempt ${attempt + 1}/${config.maxRetries})`
        );
        await sleep(delay);
        continue;
      }
      
      // Parse error response
      const errorData = await parseErrorResponse(response);
      const error = new Error(errorData.error?.message || response.statusText);
      error.status = response.status;
      error.response = errorData;
      error.requestId = errorData.request_id;
      throw error;
      
    } catch (error) {
      lastError = error;
      
      // Don't retry if it's already a parsed error with response data
      if (error.response) {
        throw error;
      }
      
      // Check if we should retry network errors
      if (shouldRetry && attempt < config.maxRetries && isRetryable(error, null, config)) {
        const delay = calculateDelay(attempt, config);
        console.warn(
          `Request failed with ${error.name}: ${error.message}, retrying in ${delay}ms ` +
          `(attempt ${attempt + 1}/${config.maxRetries})`
        );
        await sleep(delay);
        continue;
      }
      
      throw error;
    }
  }
  
  // If we get here, all retries failed
  throw lastError || new Error('Request failed after retries');
}


/**
 * Make an API request with retry support.
 * 
 * @param {string} endpoint - API endpoint (relative to API_BASE_URL)
 * @param {Object} options - Fetch options
 * @returns {Promise<any>} - Parsed JSON response
 */
export async function apiRequest(endpoint, options = {}) {
  const url = endpoint.startsWith('http') ? endpoint : `${API_BASE_URL}${endpoint}`;
  
  const response = await fetchWithRetry(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });
  
  // Handle empty responses
  const contentType = response.headers.get('Content-Type');
  if (!contentType || !contentType.includes('application/json')) {
    return null;
  }
  
  return response.json();
}


/**
 * GET request with automatic retry.
 */
export async function get(endpoint, options = {}) {
  return apiRequest(endpoint, { ...options, method: 'GET' });
}


/**
 * POST request (no automatic retry).
 */
export async function post(endpoint, data, options = {}) {
  return apiRequest(endpoint, {
    ...options,
    method: 'POST',
    body: JSON.stringify(data),
  });
}


/**
 * PUT request (no automatic retry).
 */
export async function put(endpoint, data, options = {}) {
  return apiRequest(endpoint, {
    ...options,
    method: 'PUT',
    body: JSON.stringify(data),
  });
}


/**
 * PATCH request (no automatic retry).
 */
export async function patch(endpoint, data, options = {}) {
  return apiRequest(endpoint, {
    ...options,
    method: 'PATCH',
    body: JSON.stringify(data),
  });
}


/**
 * DELETE request (no automatic retry).
 */
export async function del(endpoint, options = {}) {
  return apiRequest(endpoint, { ...options, method: 'DELETE' });
}


/**
 * Report a client-side error to the backend.
 * 
 * This function is fire-and-forget - it won't throw on failure
 * and won't retry excessively to avoid infinite loops.
 * 
 * @param {Object} errorReport - Error report data
 * @returns {Promise<{error_id: string}|null>}
 */
export async function reportClientError(errorReport) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/client-errors`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      credentials: 'include',
      body: JSON.stringify(errorReport),
    });
    
    if (!response.ok) {
      // Don't retry or throw - just log and return null
      console.warn('Failed to report client error:', response.status);
      return null;
    }
    
    return response.json();
  } catch (error) {
    // Silently fail - we don't want error reporting to cause more errors
    console.warn('Failed to report client error:', error.message);
    return null;
  }
}


/**
 * Extract user-friendly message from an error.
 * 
 * @param {Error|Object} error - Error object or API error response
 * @returns {string} - User-friendly error message
 */
export function getErrorMessage(error) {
  // Handle API error responses
  if (error?.response?.error?.user_message) {
    return error.response.error.user_message;
  }
  
  // Handle validation error responses
  if (error?.response?.errors?.[0]?.user_message) {
    return error.response.errors[0].user_message;
  }
  
  // Handle error with message property
  if (error?.message) {
    // Don't show technical messages to users
    if (error.message.includes('Failed to fetch') || 
        error.message.includes('NetworkError')) {
      return 'Unable to connect to the server. Please check your internet connection.';
    }
    return error.message;
  }
  
  return 'An unexpected error occurred. Please try again.';
}


/**
 * Extract error code from an error.
 */
export function getErrorCode(error) {
  return error?.response?.error?.code || null;
}


/**
 * Check if error indicates authentication is required.
 */
export function isAuthError(error) {
  const code = getErrorCode(error);
  if (code?.startsWith('AUTH.')) {
    return true;
  }
  return error?.status === 401;
}


/**
 * Check if error is retryable.
 */
export function isRetryableError(error) {
  const recoveryAction = error?.response?.error?.recovery_action;
  return recoveryAction === 'retry' || recoveryAction === 'retry_with_backoff';
}


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
};
