/**
 * Device API Service
 * 
 * Handles device registration and management API calls
 */

const API_BASE_URL = import.meta.env.VITE_API_URL || '';

/**
 * List all devices for the current user
 * @param {string} organizationId - Optional org filter
 * @returns {Promise<{ devices: Array, total: number }>}
 */
export const listDevices = async (organizationId = null) => {
  const params = new URLSearchParams();
  if (organizationId) {
    params.append('organization_id', organizationId);
  }
  
  const url = `${API_BASE_URL}/api/devices${params.toString() ? '?' + params.toString() : ''}`;
  const response = await fetch(url, {
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
    },
  });
  
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Failed to list devices' }));
    throw new Error(error.detail || 'Failed to list devices');
  }
  
  return response.json();
};

/**
 * Get device details
 * @param {string} deviceId - Device ID
 * @returns {Promise<Object>}
 */
export const getDevice = async (deviceId) => {
  const response = await fetch(`${API_BASE_URL}/api/devices/${encodeURIComponent(deviceId)}`, {
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
    },
  });
  
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Failed to get device' }));
    throw new Error(error.detail || 'Failed to get device');
  }
  
  return response.json();
};

/**
 * Unregister a device
 * @param {string} deviceId - Device ID to unregister
 * @returns {Promise<Object>}
 */
export const unregisterDevice = async (deviceId) => {
  const response = await fetch(`${API_BASE_URL}/api/devices/${encodeURIComponent(deviceId)}`, {
    method: 'DELETE',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
    },
  });
  
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Failed to unregister device' }));
    throw new Error(error.detail || 'Failed to unregister device');
  }
  
  return response.json();
};

/**
 * Register a new device (for web-based registration)
 * @param {Object} deviceData - Device registration data
 * @returns {Promise<Object>}
 */
export const registerDevice = async (deviceData) => {
  const response = await fetch(`${API_BASE_URL}/api/devices/register`, {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(deviceData),
  });
  
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Failed to register device' }));
    throw new Error(error.detail || 'Failed to register device');
  }
  
  return response.json();
};
