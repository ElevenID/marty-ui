/**
 * Webhooks Service
 *
 * API client functions for webhook management.
 * Uses the centralized api.js service for consistent error handling and retry logic.
 */
import { get, post, patch, del, getErrorMessage } from './api';
import { postWithIdempotency } from './idempotency';
import { buildDefinedQueryString, requireOrganizationId, withQuery } from './queryUtils';
import {
  createSubscription,
  deleteSubscription,
  listSubscriptions,
  updateSubscription,
} from './subscriptionsApi';

const BASE_PATH = '/v1/webhooks';

function scopedWebhookPath(organizationId, webhookId, suffix = '') {
  const queryString = buildDefinedQueryString({
    organization_id: requireOrganizationId(organizationId, 'accessing a webhook'),
  });
  return withQuery(`${BASE_PATH}/${webhookId}${suffix}`, queryString);
}

function normalizeWebhookResponse(value) {
  if (!value || typeof value !== 'object') return value;
  return {
    ...value,
    url: value.endpoint_url ?? value.url ?? '',
    event_types: Array.isArray(value.events) ? value.events : (value.event_types ?? []),
    secret: value.signing_secret ?? value.secret,
  };
}

function defaultWebhookName(url, description) {
  if (description?.trim()) return description.trim().slice(0, 255);
  try {
    return `Webhook for ${new URL(url).hostname}`;
  } catch {
    return 'External webhook';
  }
}

function subscriptionTargetsWebhook(subscription, webhookId) {
  return subscription?.delivery_target_id === webhookId
    || subscription?.delivery?.target_id === webhookId;
}

function pairedSubscriptionName(webhook) {
  return `${webhook.name || defaultWebhookName(webhook.url, webhook.description)} deliveries`;
}

/**
 * List webhooks for an organization
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Array>} - Array of webhook objects
 */
export async function listWebhooks(organizationId) {
  const queryString = buildDefinedQueryString({
    organization_id: requireOrganizationId(organizationId, 'loading webhooks'),
  });
  const response = await get(withQuery(BASE_PATH, queryString));
  const values = Array.isArray(response) ? response : (response?.webhooks || []);
  return values.map(normalizeWebhookResponse);
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
export async function createWebhook(organizationId, { name, url, eventTypes, description }) {
  const orgId = requireOrganizationId(organizationId, 'creating webhooks');
  const response = await postWithIdempotency(BASE_PATH, {
    organization_id: orgId,
    name: name?.trim() || defaultWebhookName(url, description),
    url,
    event_types: eventTypes,
    description: description || '',
  });
  return normalizeWebhookResponse(response);
}

/**
 * Create the endpoint and its delivery subscription as one UI operation.
 * If subscription creation fails, compensate by removing the inert endpoint.
 */
export async function createWebhookConfiguration(organizationId, webhookData) {
  const webhook = await createWebhook(organizationId, webhookData);
  try {
    const subscription = await createSubscription(organizationId, {
      name: pairedSubscriptionName(webhook),
      description: webhookData.description || '',
      eventTypes: webhookData.eventTypes,
      deliveryTargetId: webhook.id,
    });
    return { ...webhook, subscription_id: subscription.id };
  } catch (error) {
    try {
      await deleteWebhook(organizationId, webhook.id);
    } catch (cleanupError) {
      throw new Error(
        `${getErrorMessage(error)} The inactive webhook endpoint also requires manual cleanup: ${getErrorMessage(cleanupError)}`,
        { cause: error },
      );
    }
    throw error;
  }
}

/**
 * Get a single webhook
 * @param {string} webhookId - Webhook ID
 * @returns {Promise<Object>} - Webhook object
 */
export async function getWebhook(organizationId, webhookId) {
  return normalizeWebhookResponse(await get(scopedWebhookPath(organizationId, webhookId)));
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
export async function updateWebhook(organizationId, webhookId, { name, url, eventTypes, description, enabled }) {
  const body = {};
  if (name !== undefined) body.name = name;
  if (url !== undefined) body.url = url;
  if (eventTypes !== undefined) body.event_types = eventTypes;
  if (description !== undefined) body.description = description;
  if (enabled !== undefined) body.enabled = enabled;
  return normalizeWebhookResponse(await patch(scopedWebhookPath(organizationId, webhookId), body));
}

/** Keep the endpoint filter and its single delivery subscription in sync. */
export async function updateWebhookConfiguration(organizationId, webhookId, updates) {
  const [previousWebhook, allSubscriptions] = await Promise.all([
    getWebhook(organizationId, webhookId),
    listSubscriptions(organizationId),
  ]);
  const subscriptions = allSubscriptions
    .filter((subscription) => subscriptionTargetsWebhook(subscription, webhookId));
  if (subscriptions.length > 1) {
    throw new Error('This webhook has multiple advanced subscriptions and must be edited through subscription management.');
  }
  const webhook = await updateWebhook(organizationId, webhookId, updates);
  const subscriptionUpdates = {
    name: pairedSubscriptionName(webhook),
    description: updates.description ?? webhook.description ?? '',
    eventTypes: updates.eventTypes ?? webhook.event_types,
    enabled: updates.enabled ?? webhook.enabled,
  };
  try {
    const subscription = subscriptions[0]
      ? await updateSubscription(organizationId, subscriptions[0].id, subscriptionUpdates)
      : await createSubscription(organizationId, {
        ...subscriptionUpdates,
        deliveryTargetId: webhookId,
      });
    return { ...webhook, subscription_id: subscription.id };
  } catch (error) {
    try {
      await updateWebhook(organizationId, webhookId, {
        name: previousWebhook.name,
        url: previousWebhook.url,
        eventTypes: previousWebhook.event_types,
        description: previousWebhook.description,
        enabled: previousWebhook.enabled,
      });
    } catch (rollbackError) {
      throw new Error(
        `${getErrorMessage(error)} The endpoint update also requires manual rollback: ${getErrorMessage(rollbackError)}`,
        { cause: error },
      );
    }
    throw error;
  }
}

/**
 * Delete a webhook endpoint
 * @param {string} webhookId - Webhook ID
 * @returns {Promise<null>} - Empty response on success
 */
export async function deleteWebhook(organizationId, webhookId) {
  return del(scopedWebhookPath(organizationId, webhookId));
}

/** Remove the endpoint and any subscriptions that exclusively target it. */
export async function deleteWebhookConfiguration(organizationId, webhookId) {
  const subscriptions = (await listSubscriptions(organizationId))
    .filter((subscription) => subscriptionTargetsWebhook(subscription, webhookId));
  const result = await deleteWebhook(organizationId, webhookId);
  const cleanup = await Promise.allSettled(
    subscriptions.map((subscription) => deleteSubscription(organizationId, subscription.id)),
  );
  if (cleanup.some((item) => item.status === 'rejected')) {
    throw new Error('The webhook was deleted, but one or more orphaned subscriptions require manual cleanup.');
  }
  return result;
}

/**
 * Send a test event to a webhook
 * @param {string} webhookId - Webhook ID
 * @returns {Promise<Object>} - Test delivery result with status code and response
 */
export async function testWebhook(organizationId, webhookId) {
  return post(scopedWebhookPath(organizationId, webhookId, '/test'), {});
}

/**
 * Get delivery attempts for a webhook
 * @param {string} webhookId - Webhook ID
 * @param {Object} options - Filter options
 * @param {number} options.limit - Max number of records (default: 100)
 * @param {number} options.offset - Pagination offset (default: 0)
 * @returns {Promise<Array>} - Array of delivery attempt objects
 */
export async function getWebhookDeliveryAttempts(organizationId, webhookId, { limit = 100, offset = 0 } = {}) {
  const queryString = buildDefinedQueryString({
    organization_id: requireOrganizationId(organizationId, 'loading webhook deliveries'),
    limit,
    offset,
  });
  const response = await get(withQuery(`${BASE_PATH}/${webhookId}/deliveries`, queryString));
  return Array.isArray(response) ? response : (response?.deliveries || []);
}

/**
 * Regenerate webhook secret
 * @param {string} webhookId - Webhook ID
 * @returns {Promise<Object>} - Updated webhook with new secret
 */
export async function regenerateWebhookSecret(organizationId, webhookId) {
  return normalizeWebhookResponse(await post(scopedWebhookPath(organizationId, webhookId, '/regenerate-secret'), {}));
}

/**
 * Get available webhook event types
 * @returns {Promise<Array>} - Array of event type objects with categories
 */
export async function getAvailableEventTypes() {
  const response = await get(`${BASE_PATH}/event-types`);
  const eventTypes = Array.isArray(response?.event_types) ? response.event_types : [];
  const grouped = new Map();
  for (const type of eventTypes) {
    const category = String(type).split('.')[0] || 'other';
    if (!grouped.has(category)) grouped.set(category, []);
    grouped.get(category).push({
      type,
      description: String(type).replaceAll('.', ' ').replaceAll('_', ' '),
    });
  }
  return {
    categories: Array.from(grouped, ([category, events]) => ({
      name: category.charAt(0).toUpperCase() + category.slice(1),
      events,
    })),
  };
}

// Re-export getErrorMessage for convenience
export { getErrorMessage };

export default {
  listWebhooks,
  createWebhook,
  createWebhookConfiguration,
  getWebhook,
  updateWebhook,
  updateWebhookConfiguration,
  deleteWebhook,
  deleteWebhookConfiguration,
  testWebhook,
  getWebhookDeliveryAttempts,
  regenerateWebhookSecret,
  getAvailableEventTypes,
  getErrorMessage,
};
