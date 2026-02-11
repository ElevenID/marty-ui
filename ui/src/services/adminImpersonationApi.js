/**
 * Admin Impersonation API Service
 * 
 * Provides functions for platform admin impersonation of organizations.
 */

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

/**
 * Start impersonating an organization
 * @param {string} organizationId - Organization ID to impersonate
 * @param {string} reason - Reason for impersonation (for audit)
 * @returns {Promise<Object>} Impersonation session details
 */
export async function startImpersonation(organizationId, reason) {
  const response = await fetch(`${API_BASE_URL}/api/admin/impersonate/start`, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      organization_id: organizationId,
      reason,
    }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to start impersonation');
  }

  return response.json();
}

/**
 * Stop current impersonation session
 * @returns {Promise<Object>} Stop impersonation result
 */
export async function stopImpersonation() {
  const response = await fetch(`${API_BASE_URL}/api/admin/impersonate/stop`, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to stop impersonation');
  }

  return response.json();
}

/**
 * Get current impersonation status
 * @returns {Promise<Object>} Current impersonation status
 */
export async function getImpersonationStatus() {
  const response = await fetch(`${API_BASE_URL}/api/admin/impersonate/status`, {
    method: 'GET',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to get impersonation status');
  }

  return response.json();
}
