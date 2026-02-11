/**
 * Role Escalation API Service
 * 
 * Provides functions for managing role escalation requests.
 */

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

/**
 * Get pending role escalation requests for the organization
 * @returns {Promise<Array>} List of pending role escalation requests
 */
export async function getPendingRoleRequests() {
  const response = await fetch(`${API_BASE_URL}/api/roles/pending-requests`, {
    method: 'GET',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to fetch pending role requests');
  }

  return response.json();
}

/**
 * Request a role change for the current user
 * @param {string} requestedRole - The role being requested (member, operator, admin)
 * @param {string} message - Reason for the role change request
 * @returns {Promise<Object>} Request submission result
 */
export async function requestRoleChange(requestedRole, message) {
  const response = await fetch(`${API_BASE_URL}/api/roles/request-change`, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      requested_role: requestedRole,
      message,
    }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to submit role change request');
  }

  return response.json();
}

/**
 * Approve a role escalation request
 * @param {string} requestId - The role escalation request ID
 * @returns {Promise<Object>} Approval result
 */
export async function approveRoleRequest(requestId) {
  const response = await fetch(`${API_BASE_URL}/api/roles/review-request`, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      request_id: requestId,
      action: 'approve',
    }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to approve role request');
  }

  return response.json();
}

/**
 * Reject a role escalation request
 * @param {string} requestId - The role escalation request ID
 * @param {string} rejectionReason - Reason for rejection
 * @returns {Promise<Object>} Rejection result
 */
export async function rejectRoleRequest(requestId, rejectionReason) {
  const response = await fetch(`${API_BASE_URL}/api/roles/review-request`, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      request_id: requestId,
      action: 'reject',
      rejection_reason: rejectionReason,
    }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to reject role request');
  }

  return response.json();
}
