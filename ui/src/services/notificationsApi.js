/**
 * Notifications API Service
 * 
 * Manages in-app notifications, alerting rules, and notification preferences.
 */

import { get, post, patch, del } from './api';

const BASE_PATH = '/v1/notifications';

/**
 * List notifications for current user
 * @param {Object} filters - Query filters
 * @param {boolean} filters.unread_only - Show only unread notifications
 * @param {string} filters.severity - Filter by severity
 * @param {number} filters.limit - Page size
 * @param {number} filters.offset - Offset for pagination
 * @returns {Promise<Object>} Paginated notifications
 */
export async function listNotifications(filters = {}) {
  const params = new URLSearchParams();
  
  if (filters.unread_only) params.append('unread_only', 'true');
  if (filters.severity) params.append('severity', filters.severity);
  if (filters.limit) params.append('limit', filters.limit);
  if (filters.offset) params.append('offset', filters.offset);
  
  const queryString = params.toString();
  return get(queryString ? `${BASE_PATH}?${queryString}` : BASE_PATH);
}

/**
 * Get unread notification count
 * @returns {Promise<Object>} Count of unread notifications
 */
export async function getUnreadCount() {
  return get(`${BASE_PATH}/unread/count`);
}

/**
 * Mark notification as read
 * @param {string} notificationId - Notification ID
 * @returns {Promise<void>}
 */
export async function markAsRead(notificationId) {
  return patch(`${BASE_PATH}/${notificationId}/read`, {});
}

/**
 * Mark all notifications as read
 * @returns {Promise<void>}
 */
export async function markAllAsRead() {
  return post(`${BASE_PATH}/read-all`, {});
}

/**
 * Delete notification
 * @param {string} notificationId - Notification ID
 * @returns {Promise<void>}
 */
export async function deleteNotification(notificationId) {
  return del(`${BASE_PATH}/${notificationId}`);
}

/**
 * Get notification preferences for current user
 * @returns {Promise<Object>} Notification preferences
 */
export async function getNotificationPreferences() {
  return get(`${BASE_PATH}/preferences`);
}

/**
 * Update notification preferences
 * @param {Object} preferences - Preferences to update
 * @param {boolean} preferences.email_on_errors - Email on errors
 * @param {boolean} preferences.email_on_warnings - Email on warnings
 * @param {boolean} preferences.daily_summary - Daily summary email
 * @param {string} preferences.webhook_url - Webhook URL for external notifications
 * @returns {Promise<Object>} Updated preferences
 */
export async function updateNotificationPreferences(preferences) {
  return patch(`${BASE_PATH}/preferences`, preferences);
}

/**
 * List alert rules
 * @returns {Promise<Array>} List of alert rules
 */
export async function listAlertRules() {
  return get(`${BASE_PATH}/rules`);
}

/**
 * Create alert rule
 * @param {Object} rule - Alert rule configuration
 * @param {string} rule.name - Rule name
 * @param {string} rule.metric - Metric to monitor (e.g., 'login.failed')
 * @param {string} rule.condition - Condition type ('threshold', 'rate')
 * @param {number} rule.threshold - Threshold value
 * @param {number} rule.time_window - Time window in minutes
 * @param {Array<string>} rule.actions - Actions to take (e.g., ['email', 'webhook'])
 * @param {boolean} rule.enabled - Whether rule is enabled
 * @returns {Promise<Object>} Created alert rule
 */
export async function createAlertRule(rule) {
  return post(`${BASE_PATH}/rules`, rule);
}

/**
 * Update alert rule
 * @param {string} ruleId - Rule ID
 * @param {Object} updates - Fields to update
 * @returns {Promise<Object>} Updated alert rule
 */
export async function updateAlertRule(ruleId, updates) {
  return patch(`${BASE_PATH}/rules/${ruleId}`, updates);
}

/**
 * Delete alert rule
 * @param {string} ruleId - Rule ID
 * @returns {Promise<void>}
 */
export async function deleteAlertRule(ruleId) {
  return del(`${BASE_PATH}/rules/${ruleId}`);
}

/**
 * Toggle alert rule enabled state
 * @param {string} ruleId - Rule ID
 * @param {boolean} enabled - Whether to enable or disable
 * @returns {Promise<Object>} Updated alert rule
 */
export async function toggleAlertRule(ruleId, enabled) {
  return patch(`${BASE_PATH}/rules/${ruleId}`, { enabled });
}

export default {
  listNotifications,
  getUnreadCount,
  markAsRead,
  markAllAsRead,
  deleteNotification,
  getNotificationPreferences,
  updateNotificationPreferences,
  listAlertRules,
  createAlertRule,
  updateAlertRule,
  deleteAlertRule,
  toggleAlertRule,
};
