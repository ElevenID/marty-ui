/**
 * Device API Service
 * 
 * Handles device registration and management API calls
 */

import { get, post, del } from './api';
import { buildTruthyQueryString, withQuery } from './queryUtils';

/**
 * List all devices for the current user
 * @param {string} organizationId - Optional org filter
 * @returns {Promise<{ devices: Array, total: number }>}
 */
export const listDevices = async (organizationId = null) => {
  const queryString = buildTruthyQueryString({ organization_id: organizationId });
  return get(withQuery('/api/devices', queryString));
};

/**
 * Get device details.
 * NOTE: Not currently used in the UI — retained for future use.
 * @param {string} deviceId - Device ID
 * @returns {Promise<Object>}
 */
export const getDevice = async (deviceId) => {
  return get(`/api/devices/${encodeURIComponent(deviceId)}`);
};

/**
 * Unregister a device
 * @param {string} deviceId - Device ID to unregister
 * @returns {Promise<Object>}
 */
export const unregisterDevice = async (deviceId) => {
  return del(`/api/devices/${encodeURIComponent(deviceId)}`);
};

/**
 * Register a new device (for web-based registration).
 * NOTE: Not currently used in the UI — retained for future use.
 * @param {Object} deviceData - Device registration data
 * @returns {Promise<Object>}
 */
export const registerDevice = async (deviceData) => {
  return post('/api/devices/register', deviceData);
};
