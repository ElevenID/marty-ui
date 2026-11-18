/** Native organization-scoped notification inbox and embedded delivery targets. */
import { get, post, patch, del } from './api';
import { buildDefinedQueryString, requireOrganizationId, withQuery } from './queryUtils';

const BASE_PATH = '/v1/notifications';
function scopedPath(path, organizationId, params = {}) {
  return withQuery(path, buildDefinedQueryString({ ...params, organization_id: requireOrganizationId(organizationId, 'using notifications') }));
}
function notification(value, organizationId) {
  if (!value || value.organization_id !== organizationId || typeof value.id !== 'string'
    || typeof value.body !== 'string' || typeof value.read !== 'boolean') {
    throw new Error('Notification response is invalid or outside the selected organization.');
  }
  return value;
}
export async function listNotifications({ organization_id, recipient_id, unread_only, status, limit, offset } = {}) {
  const org = requireOrganizationId(organization_id, 'loading notifications');
  const result = await get(scopedPath(BASE_PATH, org, { recipient_id, unread_only, status, limit, offset }));
  if (!Array.isArray(result)) throw new Error('Notification inventory must be an array.');
  return result.map((value) => notification(value, org));
}
export async function getUnreadCount(organizationId, recipientId) {
  return get(scopedPath(`${BASE_PATH}/unread/count`, organizationId, { recipient_id: recipientId }));
}
export async function getNotification(notificationId, organizationId) {
  const org = requireOrganizationId(organizationId);
  return notification(await get(scopedPath(`${BASE_PATH}/${encodeURIComponent(notificationId)}`, org)), org);
}
export async function markAsRead(notificationId, organizationId) {
  const org = requireOrganizationId(organizationId);
  return notification(await patch(scopedPath(`${BASE_PATH}/${encodeURIComponent(notificationId)}/read`, org), {}), org);
}
export async function markAsUnread(notificationId, organizationId) {
  const org = requireOrganizationId(organizationId);
  return notification(await del(scopedPath(`${BASE_PATH}/${encodeURIComponent(notificationId)}/read`, org)), org);
}
export async function markAllAsRead(organizationId, recipientId) {
  return post(scopedPath(`${BASE_PATH}/read-all`, organizationId, { recipient_id: recipientId }), {});
}
export async function deleteNotification(notificationId, organizationId) {
  return del(scopedPath(`${BASE_PATH}/${encodeURIComponent(notificationId)}`, organizationId));
}
export async function getNotificationDeliveryResults(notificationId, organizationId, { limit, offset } = {}) {
  return get(scopedPath(`${BASE_PATH}/${encodeURIComponent(notificationId)}/delivery-results`, organizationId, { limit, offset }));
}
/** An accepted send is not a successful delivery; inspect delivery results separately. */
export async function sendNotification(request) {
  const org = requireOrganizationId(request?.organization_id, 'sending notifications');
  if (request.target?.organization_id != null && request.target.organization_id !== org) {
    throw new Error('Notification target organization must match the selected organization.');
  }
  return notification(await post(`${BASE_PATH}/send`, { ...request, organization_id: org }), org);
}

// Retain imports for existing consumers, but never issue calls to nonexistent owner routes.
function unsupported(feature) {
  const error = new Error(`${feature} are not supported by the notification API.`);
  error.code = 'UNSUPPORTED_OPERATION'; error.status = 501;
  throw error;
}
export async function getNotificationPreferences() { return unsupported('Notification preferences'); }
export async function updateNotificationPreferences() { return unsupported('Notification preferences'); }
export async function listAlertRules() { return unsupported('Alert rules'); }
export async function createAlertRule() { return unsupported('Alert rules'); }
export async function updateAlertRule() { return unsupported('Alert rules'); }
export async function deleteAlertRule() { return unsupported('Alert rules'); }
export async function toggleAlertRule() { return unsupported('Alert rules'); }

export default { listNotifications, getUnreadCount, getNotification, markAsRead, markAsUnread, markAllAsRead, deleteNotification,
  getNotificationDeliveryResults, sendNotification, getNotificationPreferences, updateNotificationPreferences,
  listAlertRules, createAlertRule, updateAlertRule, deleteAlertRule, toggleAlertRule };
