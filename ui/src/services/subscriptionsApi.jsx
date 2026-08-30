/** Public gateway client for webhook subscriptions. */
import { get, patch, del } from './api';
import { postWithIdempotency } from './idempotency';
import { buildDefinedQueryString, requireOrganizationId, withQuery } from './queryUtils';

const BASE_PATH = '/v1/subscriptions';

function scopedPath(organizationId, subscriptionId = '') {
  const query = buildDefinedQueryString({
    organization_id: requireOrganizationId(organizationId, 'accessing webhook subscriptions'),
  });
  return withQuery(subscriptionId ? `${BASE_PATH}/${subscriptionId}` : BASE_PATH, query);
}

export async function listSubscriptions(organizationId) {
  const response = await get(scopedPath(organizationId));
  return Array.isArray(response) ? response : (response?.subscriptions || []);
}

export async function createSubscription(organizationId, {
  name,
  description = '',
  eventTypes,
  deliveryTargetId,
  filter = {},
  retryPolicy,
  enabled = true,
}) {
  const organization_id = requireOrganizationId(organizationId, 'creating webhook subscriptions');
  return postWithIdempotency(BASE_PATH, {
    organization_id,
    name,
    description,
    event_types: eventTypes,
    delivery_channel: 'WEBHOOK',
    delivery_target_id: deliveryTargetId,
    filter,
    ...(retryPolicy ? { retry_policy: retryPolicy } : {}),
    enabled,
  });
}

export async function updateSubscription(organizationId, subscriptionId, updates) {
  return patch(scopedPath(organizationId, subscriptionId), updates);
}

export async function deleteSubscription(organizationId, subscriptionId) {
  return del(scopedPath(organizationId, subscriptionId));
}

export default {
  listSubscriptions,
  createSubscription,
  updateSubscription,
  deleteSubscription,
};
