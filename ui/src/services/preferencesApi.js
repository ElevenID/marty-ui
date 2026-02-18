/**
 * Preferences API Service
 *
 * Provides API calls for user console context preferences.
 */

// Preferences endpoints go through nginx proxy
const PREFS_BASE_URL = '/v1/me/preferences';

/**
 * Map UI console mode values to backend preference values.
 * UI uses: 'applicant' | 'org'
 * Backend expects: 'applicant' | 'org_admin'
 */
function toApiViewMode(viewMode) {
  if (viewMode === 'org') return 'org_admin';
  return viewMode;
}

/**
 * Map backend preference values to UI console mode values.
 */
function fromApiViewMode(viewMode) {
  if (viewMode === 'org_admin') return 'org';
  return viewMode;
}

/**
 * Normalize preference payload from backend to UI shape.
 */
function normalizePreferencesFromApi(raw) {
  return {
    ...raw,
    last_view_mode: fromApiViewMode(raw?.last_view_mode),
    last_active_org_id: raw?.last_active_org_id ?? null,
  };
}

/**
 * Get current user's console context preferences
 * @returns {Promise<{last_view_mode: string, last_active_org_id: string|null}>}
 */
export async function getPreferences() {
  try {
    const response = await fetch(PREFS_BASE_URL, {
      method: 'GET',
      credentials: 'include', // Include cookies
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const raw = await response.json();
    return normalizePreferencesFromApi(raw);
  } catch (error) {
    console.error('Error fetching preferences:', error);
    // Return defaults on error
    return {
      last_view_mode: 'applicant',
      last_active_org_id: null,
    };
  }
}

/**
 * Update user's console context preferences
 * @param {{last_view_mode?: string, last_active_org_id?: string|null}} preferences
 * @returns {Promise<{last_view_mode: string, last_active_org_id: string|null}>}
 */
export async function updatePreferences(preferences) {
  try {
    const payload = {
      ...preferences,
    };

    if (Object.prototype.hasOwnProperty.call(payload, 'last_view_mode')) {
      payload.last_view_mode = toApiViewMode(payload.last_view_mode);
    }

    const response = await fetch(PREFS_BASE_URL, {
      method: 'PUT',
      credentials: 'include', // Include cookies
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
    }

    const raw = await response.json();
    return normalizePreferencesFromApi(raw);
  } catch (error) {
    console.error('Error updating preferences:', error);
    throw error;
  }
}
