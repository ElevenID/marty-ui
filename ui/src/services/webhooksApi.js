/**
 * Webhooks Service
 *
 * API client functions for webhook management.
 * Uses the centralized api.js service for consistent error handling and retry logic.
 */
import { get, post, patch, del, getErrorMessage } from './api';

const BASE_PATH = '/api/v1/webhooks';

/**
 * List webhooks for an organization
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Array>} - Array of webhook objects
 */
export async function listWebhooks(organizationId) {
  const response = await get(`${BASE_PATH}?organization_id=${organizationId}`);
  return response?.webhooks || [];
}

/**
 * Create a new webhook endpoint
 * @param {string} organizationId - Organization ID
 * @param {Object} webhookData - Webhook creation data
 * @param {string} webhookData.url - Webhook URL (must be HTTPS)
 * @param {Array<string>} webhookData.eventTypes - Array of event type strings
 * @param {string} webhookData.description - Optional description
 * @returns {Promise<Object>} - Created webhook with secret for HMAC verification
 */
export async function createWebhook(organizationId, { url, eventTypes, description }) {
  return post(BASE_PATH, {
    organization_id: organizationId,
    url,
    event_types: eventTypes,
    description: description || '',
  });
}

/**
 * Get a single webhook
 * @param {string} webhookId - Webhook ID
 * @returns {Promise<Object>} - Webhook object
 */
export async function getWebhook(webhookId) {
  return get(`${BASE_PATH}/${webhookId}`);
}

/**
 * Update a webhook endpoint
 * @param {string} webhookId - Webhook ID
 * @param {Object} updates - Fields to update
 * @param {string} updates.url - New webhook URL
 * @param {Array<string>} updates.eventTypes - New event types
 * @param {string} updates.description - New description
 * @param {boolean} updates.enabled - Enable/disable webhook
 * @returns {Promise<Object>} - Updated webhook object
 */
export async function updateWebhook(webhookId, { url, eventTypes, description, enabled }) {
  const body = {};
  if (url !== undefined) body.url = url;
  if (eventTypes !== undefined) body.event_types = eventTypes;
  if (description !== undefined) body.description = description;
  if (enabled !== undefined) body.enabled = enabled;
  return patch(`${BASE_PATH}/${webhookId}`, body);
}

/**
 * Delete a webhook endpoint
 * @param {string} webhookId - Webhook ID
 * @returns {Promise<null>} - Empty response on success
 */
export async function deleteWebhook(webhookId) {
  return del(`${BASE_PATH}/${webhookId}`);
}

/**
 * Send a test event to a webhook
 * @param {string} webhookId - Webhook ID
 * @returns {Promise<Object>} - Test delivery result with status code and response
 */
export async function testWebhook(webhookId) {
  return post(`${BASE_PATH}/${webhookId}/test`, {});
}

/**
 * Get delivery attempts for a webhook
 * @param {string} webhookId - Webhook ID
 * @param {Object} options - Filter options
 * @param {number} options.limit - Max number of records (default: 100)
 * @param {number} options.offset - Pagination offset (default: 0)
 * @returns {Promise<Array>} - Array of delivery attempt objects
 */
export async function getWebhookDeliveryAttempts(webhookId, { limit = 100, offset = 0 } = {}) {
  const params = new URLSearchParams();
  params.append('limit', limit.toString());
  params.append('offset', offset.toString());
  const response = await get(`${BASE_PATH}/${webhookId}/deliveries?${params.toString()}`);
  return response?.deliveries || [];
}

/**
 * Regenerate webhook secret
 * @param {string} webhookId - Webhook ID
 * @returns {Promise<Object>} - Updated webhook with new secret
 */
export async function regenerateWebhookSecret(webhookId) {
  return post(`${BASE_PATH}/${webhookId}/regenerate-secret`, {});
}

/**
 * Get available webhook event types
 * @returns {Promise<Array>} - Array of event type objects with categories
 */
export async function getAvailableEventTypes() {
  // This could be a backend endpoint or we can define it here
  // For now, return the standardized event types
  return Promise.resolve({
    categories: [
      {
        name: 'Credential',
        events: [
          { type: 'credential.issued', description: 'A new credential was issued' },
          { type: 'credential.revoked', description: 'A credential was revoked' },
          { type: 'credential.suspended', description: 'A credential was suspended' },
          { type: 'credential.reactivated', description: 'A suspended credential was reactivated' },
        ],
      },
      {
        name: 'Verification',
        events: [
          { type: 'verification.completed', description: 'A verification was completed successfully' },
          { type: 'verification.failed', description: 'A verification attempt failed' },
          { type: 'verification.initiated', description: 'A verification was initiated' },
        ],
      },
      {
        name: 'Application',
        events: [
          { type: 'application.submitted', description: 'An application was submitted' },
          { type: 'application.approved', description: 'An application was approved' },
          { type: 'application.rejected', description: 'An application was rejected' },
          { type: 'application.pending_review', description: 'An application is pending review' },
          { type: 'application.documents_requested', description: 'Additional documents were requested' },
          { type: 'application.documents_received', description: 'Requested documents were received' },
        ],
      },
      {
        name: 'Audit',
        events: [
          { type: 'audit.access_logged', description: 'Access to a resource was logged' },
          { type: 'audit.configuration_changed', description: 'System configuration was changed' },
          { type: 'audit.credential_accessed', description: 'A credential was accessed' },
        ],
      },
      {
        name: 'Trust',
        events: [
          { type: 'trust.certificate_issued', description: 'A trust certificate was issued' },
          { type: 'trust.certificate_expiring', description: 'A trust certificate is expiring soon' },
          { type: 'trust.chain_validation_failed', description: 'Trust chain validation failed' },
        ],
      },
    ],
  });
}

// Re-export getErrorMessage for convenience
export { getErrorMessage };

export default {
  listWebhooks,
  createWebhook,
  getWebhook,
  updateWebhook,
  deleteWebhook,
  testWebhook,
  getWebhookDeliveryAttempts,
  regenerateWebhookSecret,
  getAvailableEventTypes,
  getErrorMessage,
};
