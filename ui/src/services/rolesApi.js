/**
 * Role Escalation API Service
 *
 * Provides functions for managing role escalation requests.
 */

import { get, post } from './api';

/**
 * Get pending role escalation requests for the organization
 * @returns {Promise<Array>} List of pending role escalation requests
 */
export async function getPendingRoleRequests() {
  return get('/api/roles/pending-requests');
}

/**
 * Request a role change for the current user
 * @param {string} requestedRole - The role being requested (member, operator, admin)
 * @param {string} message - Reason for the role change request
 * @returns {Promise<Object>} Request submission result
 */
export async function requestRoleChange(requestedRole, message) {
  return post('/api/roles/request-change', { requested_role: requestedRole, message });
}

/**
 * Approve a role escalation request
 * @param {string} requestId - The role escalation request ID
 * @returns {Promise<Object>} Approval result
 */
export async function approveRoleRequest(requestId) {
  return post('/api/roles/review-request', { request_id: requestId, action: 'approve' });
}

/**
 * Reject a role escalation request
 * @param {string} requestId - The role escalation request ID
 * @param {string} rejectionReason - Reason for rejection
 * @returns {Promise<Object>} Rejection result
 */
export async function rejectRoleRequest(requestId, rejectionReason) {
  return post('/api/roles/review-request', {
    request_id: requestId,
    action: 'reject',
    rejection_reason: rejectionReason,
  });
}
