/**
 * Audit Logs API Service
 * 
 * Fetches audit logs for security-relevant events.
 * Supports filtering, pagination, and export.
 */

import { get, post } from './api';
import { buildTruthyQueryString, withQuery } from './queryUtils';

const BASE_PATH = '/v1/audit/events';

/**
 * List audit events
 * @param {Object} filters - Query filters
 * @param {string} filters.actor - Filter by user ID or email
 * @param {string} filters.resource_type - Filter by resource type
 * @param {string} filters.resource_id - Filter by resource ID
 * @param {string} filters.action - Filter by action type
 * @param {string} filters.severity - Filter by severity (info, warning, error)
 * @param {string} filters.ip_address - Filter by IP address
 * @param {string} filters.start_date - Start date (ISO format)
 * @param {string} filters.end_date - End date (ISO format)
 * @param {number} filters.limit - Page size (default: 50)
 * @param {number} filters.offset - Offset for pagination
 * @returns {Promise<Object>} Paginated audit events
 */
export async function listAuditEvents(filters = {}) {
  const queryString = buildTruthyQueryString({
    actor: filters.actor,
    resource_type: filters.resource_type,
    resource_id: filters.resource_id,
    action: filters.action,
    severity: filters.severity,
    ip_address: filters.ip_address,
    start_date: filters.start_date,
    end_date: filters.end_date,
    limit: filters.limit,
    offset: filters.offset,
  });

  return get(withQuery(BASE_PATH, queryString));
}

/**
 * Get audit event by ID
 * @param {string} eventId - Event ID
 * @returns {Promise<Object>} Audit event details
 */
export async function getAuditEvent(eventId) {
  return get(`${BASE_PATH}/${eventId}`);
}

/**
 * Export audit events (server-side)
 * @param {Object} filters - Same filters as listAuditEvents
 * @param {string} format - Export format: 'csv' or 'json'
 * @returns {Promise<Object>} Export job details with download URL
 */
export async function exportAuditEvents(filters = {}, format = 'csv') {
  return post(`${BASE_PATH}/export`, {
    filters,
    format,
  });
}

/**
 * Get critical events (last 24 hours)
 * @returns {Promise<Array>} List of critical audit events
 */
export async function getCriticalEvents() {
  return get('/v1/audit/critical');
}

/**
 * Save filter view
 * @param {Object} view - Filter view configuration
 * @param {string} view.name - View name
 * @param {Object} view.filters - Filter configuration
 * @returns {Promise<Object>} Created filter view
 */
export async function saveFilterView(view) {
  return post(`${BASE_PATH}/views`, view);
}

/**
 * List saved filter views
 * @returns {Promise<Array>} List of saved views
 */
export async function listFilterViews() {
  return get(`${BASE_PATH}/views`);
}

export default {
  listAuditEvents,
  getAuditEvent,
  exportAuditEvents,
  getCriticalEvents,
  saveFilterView,
  listFilterViews,
};
