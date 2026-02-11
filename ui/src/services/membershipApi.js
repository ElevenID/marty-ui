/**
 * Membership Request API Client
 * 
 * Handles membership request operations for organization administrators.
 */

const API_BASE = '/api/onboarding';

/**
 * Get pending membership requests for the current organization
 * @returns {Promise<{requests: Array}>} List of pending requests
 */
export async function getPendingRequests() {
  const response = await fetch(`${API_BASE}/pending-requests`, {
    method: 'GET',
    credentials: 'include',
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Failed to fetch requests' }));
    throw new Error(error.detail || 'Failed to fetch pending membership requests');
  }

  return response.json();
}

/**
 * Approve a membership request
 * @param {string} requestId - The request ID to approve
 * @returns {Promise<{success: boolean, message: string}>} Approval response
 */
export async function approveMembershipRequest(requestId) {
  const response = await fetch(`${API_BASE}/review-request`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    credentials: 'include',
    body: JSON.stringify({
      request_id: requestId,
      action: 'approve',
    }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Failed to approve request' }));
    throw new Error(error.detail || 'Failed to approve membership request');
  }

  return response.json();
}

/**
 * Reject a membership request
 * @param {string} requestId - The request ID to reject
 * @param {string} [reason] - Optional rejection reason
 * @returns {Promise<{success: boolean, message: string}>} Rejection response
 */
export async function rejectMembershipRequest(requestId, reason = null) {
  const response = await fetch(`${API_BASE}/review-request`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    credentials: 'include',
    body: JSON.stringify({
      request_id: requestId,
      action: 'reject',
      rejection_reason: reason,
    }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Failed to reject request' }));
    throw new Error(error.detail || 'Failed to reject membership request');
  }

  return response.json();
}
