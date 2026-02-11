/**
 * Notification Preferences API Service
 * 
 * Provides functions for managing user notification preferences.
 */

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

/**
 * Get user's notification preferences
 * @returns {Promise<Object>} User's notification preferences
 */
export async function getNotificationPreferences() {
  const response = await fetch(`${API_BASE_URL}/api/notifications/preferences`, {
    method: 'GET',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
    },
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to fetch notification preferences');
  }

  return response.json();
}

/**
 * Update user's notification preferences
 * @param {Object} preferences - Notification preferences to update
 * @param {string} preferences.method - Notification method: "push", "email", or "both"
 * @param {boolean} preferences.email_for_applications - Send email for application updates
 * @param {boolean} preferences.email_for_credentials - Send email for credential issuance
 * @param {boolean} preferences.email_for_membership - Send email for membership updates
 * @returns {Promise<Object>} Updated preferences
 */
export async function updateNotificationPreferences(preferences) {
  const response = await fetch(`${API_BASE_URL}/api/notifications/preferences`, {
    method: 'PUT',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(preferences),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || 'Failed to update notification preferences');
  }

  return response.json();
}
