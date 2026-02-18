/**
 * Admin Impersonation API Service
 * 
 * Provides functions for platform admin impersonation of organizations.
 */

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || '';

function buildApiUrl(path) {
  return `${API_BASE_URL}${path}`;
}

async function parseError(response, fallbackMessage) {
  try {
    const error = await response.json();
    return error?.detail || error?.message || fallbackMessage;
  } catch {
    return fallbackMessage;
  }
}

/**
 * Start impersonating an organization
 * @param {string} organizationId - Organization ID to impersonate
 * @param {string} reason - Reason for impersonation (for audit)
 * @returns {Promise<Object>} Impersonation session details
 */
export async function startImpersonation(organizationId, reason) {
  const response = await fetch(buildApiUrl('/api/admin/impersonate/start'), {
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
    throw new Error(await parseError(response, 'Failed to start impersonation'));
  }

  return response.json();
}

/**
 * Stop current impersonation session
 * @returns {Promise<Object>} Stop impersonation result
 */
export async function stopImpersonation() {
  const response = await fetch(buildApiUrl('/api/admin/impersonate/stop'), {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(await parseError(response, 'Failed to stop impersonation'));
  }

  return response.json();
}

/**
 * Get current impersonation status
 * @returns {Promise<Object>} Current impersonation status
 */
export async function getImpersonationStatus() {
  const response = await fetch(buildApiUrl('/api/admin/impersonate/status'), {
    method: 'GET',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(await parseError(response, 'Failed to get impersonation status'));
  }

  return response.json();
}
