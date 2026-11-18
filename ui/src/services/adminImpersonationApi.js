/**
 * Admin Impersonation API Service
 *
 * Provides functions for platform admin impersonation of organizations.
 */

import { get, post } from './api';

/**
 * Start impersonating an organization
 * @param {string} organizationId - Organization ID to impersonate
 * @param {string} reason - Reason for impersonation (for audit)
 * @returns {Promise<Object>} Impersonation session details
 */
export async function startImpersonation(organizationId, reason) {
  return post('/api/admin/impersonate/start', { organization_id: organizationId, reason });
}

/**
 * Stop current impersonation session
 * @returns {Promise<Object>} Stop impersonation result
 */
export async function stopImpersonation() {
  return post('/api/admin/impersonate/stop', {});
}

/**
 * Get current impersonation status
 * @returns {Promise<Object>} Current impersonation status
 */
export async function getImpersonationStatus() {
  return get('/api/admin/impersonate/status');
}
