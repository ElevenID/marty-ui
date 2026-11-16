/**
 * Device API Service
 * 
 * Handles device registration and management API calls
 */

import { get, post, del } from './api';
import { buildDefinedQueryString, requireOrganizationId, withQuery } from './queryUtils';

const BASE = '/v1/devices';
const PAGE_SIZE = 100;

async function loadDevices(organizationId, { isCurrent = () => true, userId } = {}) {
  const devices = [];
  const seen = new Set();
  const ensureCurrent = () => {
    if (!isCurrent()) {
      const error = new Error('Device registration scope changed.');
      error.name = 'AbortError';
      throw error;
    }
  };
  for (let offset = 0; ; offset += PAGE_SIZE) {
    ensureCurrent();
    const query = buildDefinedQueryString({ organization_id: organizationId, limit: PAGE_SIZE, offset });
    const page = await get(withQuery(BASE, query));
    ensureCurrent();
    if (!Array.isArray(page) || page.length > PAGE_SIZE || page.some(device => !device
      || typeof device.id !== 'string' || !device.id.trim()
      || typeof device.device_id !== 'string' || device.device_id.length === 0
      || typeof device.user_id !== 'string' || !device.user_id.trim()
      || typeof device.is_active !== 'boolean'
      || !['ios', 'android', 'web'].includes(device.platform)
      || (organizationId && device.organization_id !== organizationId)
      || (userId && device.user_id !== userId))) {
      throw new Error('Device registrations returned an invalid response.');
    }
    for (const device of page) {
      if (seen.has(device.id)) {
        throw new Error('Device registrations changed while loading. Refresh and try again.');
      }
      seen.add(device.id);
      devices.push(device);
    }
    if (page.length < PAGE_SIZE) return devices;
  }
}

/**
 * List all registrations for the current user, including inactive registrations.
 * @param {string} organizationId - Optional org filter
 * @param {{isCurrent?: () => boolean, userId?: string}} options - Request scope
 * @returns {Promise<Array>}
 */
export const listDevices = async (organizationId = null, options = {}) => {
  const orgId = organizationId == null ? null : requireOrganizationId(organizationId, 'loading devices');
  return loadDevices(orgId, options);
};

/**
 * List the current user's devices in an organization, not other members' devices.
 * @param {string} organizationId - Required organization ID
 * @param {{isCurrent?: () => boolean, userId?: string}} options - Request scope
 * @returns {Promise<Array>}
 */
export const listOrganizationDevices = async (organizationId, options = {}) => {
  const orgId = requireOrganizationId(organizationId, 'loading organization devices');
  return loadDevices(orgId, options);
};

/**
 * Get device details.
 * NOTE: Not currently used in the UI — retained for future use.
 * @param {string} deviceId - Device ID
 * @returns {Promise<Object>}
 */
export const getDevice = async (deviceId) => {
  return get(`${BASE}/${encodeURIComponent(deviceId)}`);
};

/**
 * Deactivate a device registration. The route uses the registration's id,
 * not its client-supplied device_id. Historical registrations remain listed.
 * @param {string} registrationId - Registration ID to deactivate
 * @returns {Promise<Object>}
 */
export const unregisterDevice = async (registrationId) => {
  if (typeof registrationId !== 'string' || !registrationId.trim()) {
    throw new Error('A device registration ID is required.');
  }
  return del(`${BASE}/${encodeURIComponent(registrationId)}`);
};

/**
 * Register a new device (for web-based registration).
 * NOTE: Not currently used in the UI — retained for future use.
 * @param {Object} deviceData - Device registration data
 * @returns {Promise<Object>}
 */
export const registerDevice = async (deviceData) => {
  return post(BASE, deviceData);
};
