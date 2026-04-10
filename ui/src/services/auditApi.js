/**
 * Audit Logs API Service
 *
 * Fetches audit logs for security-relevant events using the current
 * organization-scoped gateway routes and normalizes the downstream payload
 * shape for the console UI.
 */

import { get } from './api';
import { buildDefinedQueryString, withQuery } from './queryUtils';

const API_BASE = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '');
const SAVED_VIEWS_STORAGE_PREFIX = 'marty.audit.savedViews';
const fallbackSavedViewsStore = new Map();

function requireOrganizationId(organizationId) {
  if (!organizationId) {
    throw new Error('Organization ID is required for audit operations');
  }

  return organizationId;
}

function getBasePath(organizationId) {
  return `/v1/organizations/${encodeURIComponent(requireOrganizationId(organizationId))}/audit-events`;
}

function withApiBase(path) {
  return API_BASE ? `${API_BASE}${path}` : path;
}

function inferSeverity(action = '', metadata = {}) {
  if (metadata.severity) {
    return metadata.severity;
  }

  const normalizedAction = action.toLowerCase();

  if (normalizedAction.includes('failed') || normalizedAction.includes('error')) {
    return 'error';
  }

  if (normalizedAction.includes('warning') || normalizedAction.includes('revoked')) {
    return 'warning';
  }

  if (normalizedAction.includes('completed') || normalizedAction.includes('issued')) {
    return 'success';
  }

  return 'info';
}

function inferCategory(event = {}) {
  const action = (event.action || event.event_type || event.type || '').toLowerCase();
  const resourceType = event.resource_type || event.resourceType || event.resource?.type;

  if (resourceType) {
    return resourceType;
  }

  if (action.includes('auth') || action.includes('login')) {
    return 'authentication';
  }

  if (action.includes('team') || action.includes('member') || action.includes('invite')) {
    return 'team';
  }

  if (action.includes('flow')) {
    return 'flow';
  }

  if (action.includes('credential')) {
    return 'credential';
  }

  if (action.includes('policy')) {
    return 'policy';
  }

  if (action.includes('template')) {
    return 'template';
  }

  return 'settings';
}

function getActorLabel(event = {}) {
  if (typeof event.actor === 'string') {
    return event.actor;
  }

  if (event.actor?.name) {
    return event.actor.name;
  }

  if (event.actor?.email) {
    return event.actor.email;
  }

  if (event.actor_id) {
    return event.actor_id;
  }

  return '';
}

function getResourceLabel(event = {}) {
  if (typeof event.resource === 'string') {
    return event.resource;
  }

  if (event.resource?.name) {
    return event.resource.name;
  }

  if (event.resource_name) {
    return event.resource_name;
  }

  if (event.resource?.id) {
    return event.resource.id;
  }

  if (event.resource_id) {
    return event.resource_id;
  }

  return '';
}

function buildDetails(event = {}) {
  if (event.details) {
    return event.details;
  }

  const details = {
    ...(event.metadata || {}),
  };

  if (event.changes) {
    details.changes = event.changes;
  }

  return details;
}

function normalizeAuditEvent(event = {}) {
  const details = buildDetails(event);
  const action = event.action || event.event_type || event.type || '';
  const resourceType = event.resource_type || event.resourceType || event.resource?.type || inferCategory(event);

  return {
    ...event,
    id: event.id,
    organization_id: event.organization_id || null,
    timestamp: event.timestamp,
    actor: getActorLabel(event),
    actorId: event.actor_id || event.actor?.id || null,
    actorType: event.actor_type || null,
    category: event.category || inferCategory(event),
    action,
    type: event.type || event.event_type || action,
    resource: getResourceLabel(event),
    resource_type: resourceType,
    resource_id: event.resource_id || event.resource?.id || null,
    severity: event.severity || inferSeverity(action, details),
    details,
    ipAddress: event.ipAddress || event.ip_address || details.ip_address || details.ipAddress || null,
    message: event.message || getResourceLabel(event) || action,
  };
}

function normalizeAuditResponse(data) {
  if (Array.isArray(data)) {
    return data.map(normalizeAuditEvent);
  }

  if (Array.isArray(data?.events)) {
    return {
      ...data,
      events: data.events.map(normalizeAuditEvent),
      total: data.total ?? data.events.length,
    };
  }

  return data;
}

function getSavedViewsStorageKey(organizationId) {
  return `${SAVED_VIEWS_STORAGE_PREFIX}:${requireOrganizationId(organizationId)}`;
}

function getSavedViewsStorage() {
  if (typeof window !== 'undefined' && window.localStorage) {
    const storage = window.localStorage;
    if (typeof storage.getItem === 'function' && typeof storage.setItem === 'function') {
      return storage;
    }
  }

  return {
    getItem: (key) => fallbackSavedViewsStore.get(key) ?? null,
    setItem: (key, value) => {
      fallbackSavedViewsStore.set(key, value);
    },
    removeItem: (key) => {
      fallbackSavedViewsStore.delete(key);
    },
  };
}

function readSavedViews(organizationId) {
  try {
    const raw = getSavedViewsStorage().getItem(getSavedViewsStorageKey(organizationId));
    if (!raw) {
      return [];
    }

    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    console.warn('Failed to read audit saved views from local storage:', error);
    return [];
  }
}

function writeSavedViews(organizationId, views) {
  getSavedViewsStorage().setItem(getSavedViewsStorageKey(organizationId), JSON.stringify(views));
}

/**
 * List audit events.
 * @param {string} organizationId - Organization ID
 * @param {Object} filters - Query filters
 * @param {string} filters.actor - Filter by user ID or email
 * @param {string} filters.resource_type - Filter by resource type
 * @param {string} filters.resource_id - Filter by resource ID
 * @param {string} filters.action - Filter by action type
 * @param {string} filters.search - Free-text search
 * @param {string} filters.severity - Filter by severity (info, warning, error)
 * @param {string} filters.ip_address - Filter by IP address
 * @param {string} filters.start_date - Start date (ISO format)
 * @param {string} filters.end_date - End date (ISO format)
 * @param {number} filters.limit - Page size (default: 50)
 * @param {number} filters.offset - Offset for pagination
 * @returns {Promise<Object>} Paginated audit events
 */
export async function listAuditEvents(organizationId, filters = {}) {
  const queryString = buildDefinedQueryString({
    actor: filters.actor,
    resource_type: filters.resource_type,
    resource_id: filters.resource_id,
    action: filters.action,
    search: filters.search,
    severity: filters.severity,
    ip_address: filters.ip_address,
    start_date: filters.start_date,
    end_date: filters.end_date,
    limit: filters.limit,
    offset: filters.offset,
  });

  const data = await get(withQuery(getBasePath(organizationId), queryString));
  return normalizeAuditResponse(data);
}

/**
 * Get audit event by ID.
 * @param {string} organizationId - Organization ID
 * @param {string} eventId - Event ID
 * @returns {Promise<Object>} Audit event details
 */
export async function getAuditEvent(organizationId, eventId) {
  const data = await get(`${getBasePath(organizationId)}/${encodeURIComponent(eventId)}`);
  return normalizeAuditEvent(data);
}

/**
 * Build an audit export download URL.
 * @param {string} organizationId - Organization ID
 * @param {Object} filters - Same filters as listAuditEvents
 * @param {string} format - Export format: 'csv' or 'json'
 * @returns {Promise<Object>} Export details with a download URL
 */
export async function exportAuditEvents(organizationId, filters = {}, format = 'csv') {
  const queryString = buildDefinedQueryString({
    format,
    actor: filters.actor,
    resource_type: filters.resource_type,
    resource_id: filters.resource_id,
    action: filters.action,
    search: filters.search,
    severity: filters.severity,
    ip_address: filters.ip_address,
    start_date: filters.start_date,
    end_date: filters.end_date,
  });

  return {
    download_url: withApiBase(withQuery(`${getBasePath(organizationId)}/export`, queryString)),
  };
}

/**
 * Get critical audit events from the last 24 hours.
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Array>} List of critical audit events
 */
export async function getCriticalEvents(organizationId) {
  const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const data = await listAuditEvents(organizationId, {
    start_date: twentyFourHoursAgo,
    limit: 25,
  });

  const events = Array.isArray(data) ? data : data?.events || [];

  return events
    .filter((event) => {
      if (!event.timestamp) {
        return false;
      }

      return new Date(event.timestamp) >= new Date(twentyFourHoursAgo);
    })
    .filter((event) => (
      event.severity === 'error' ||
      event.severity === 'warning' ||
      event.severity === 'critical' ||
      event.type?.includes('failed') ||
      event.type?.includes('failure') ||
      event.type?.includes('revocation') ||
      event.type?.includes('auth')
    ))
    .slice(0, 10);
}

/**
 * Save a filter view in local, org-scoped storage.
 * @param {string} organizationId - Organization ID
 * @param {Object} view - Filter view configuration
 * @param {string} view.name - View name
 * @param {Object} view.filters - Filter configuration
 * @returns {Promise<Object>} Created filter view
 */
export async function saveFilterView(organizationId, view) {
  const nextView = {
    id: globalThis.crypto?.randomUUID?.() || `audit-view-${Date.now()}`,
    ...view,
    created_at: new Date().toISOString(),
  };

  const existingViews = readSavedViews(organizationId);
  writeSavedViews(organizationId, [nextView, ...existingViews]);

  return nextView;
}

/**
 * List saved filter views from local, org-scoped storage.
 * @param {string} organizationId - Organization ID
 * @returns {Promise<Array>} List of saved views
 */
export async function listFilterViews(organizationId) {
  return readSavedViews(organizationId);
}

export default {
  listAuditEvents,
  getAuditEvent,
  exportAuditEvents,
  getCriticalEvents,
  saveFilterView,
  listFilterViews,
};
