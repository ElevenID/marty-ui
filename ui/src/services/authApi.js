/**
 * Authentication API Service
 *
 * Provides API calls for authentication operations.
 */

// Auth endpoints should always use relative paths to go through nginx proxy
// This ensures cookies are sent correctly (same origin)
const AUTH_BASE_URL = '/v1/auth';

/**
 * Get current authenticated user info
 * @returns {Promise<{authenticated: boolean, user: object|null}>}
 */
export async function getCurrentUser() {
  try {
    const response = await fetch(`${AUTH_BASE_URL}/me`, {
      method: 'GET',
      credentials: 'include', // Include cookies
      cache: 'no-store',
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error('Error fetching current user:', error);
    return { authenticated: false, user: null };
  }
}

/**
 * Initiate login by redirecting to OIDC provider
 * @param {string} [redirectUri] - Where to redirect after login
 * @param {string} [locale] - Language code to pass to Keycloak (e.g., 'en', 'de', 'ja')
 */
export function initiateLogin(redirectUri = '/', locale = null) {
  // Build login URL - always use relative path to go through nginx proxy
  let loginPath = `${AUTH_BASE_URL}/login`;
  const params = new URLSearchParams();
  
  if (redirectUri) {
    params.append('redirect_uri', redirectUri);
  }
  
  // Pass locale to Keycloak if provided
  if (locale) {
    params.append('kc_locale', locale);
  }
  
  const queryString = params.toString();
  if (queryString) {
    loginPath += `?${queryString}`;
  }
  
  window.location.href = loginPath;
}

/**
 * Initiate registration by redirecting to Keycloak registration page
 * @param {string} [redirectUri] - Where to redirect after registration
 * @param {string} [locale] - Language code to pass to Keycloak (e.g., 'en', 'de', 'ja')
 */
export function initiateRegister(redirectUri = '/', locale = null) {
  // Build registration URL - always use relative path to go through nginx proxy
  let registerPath = `${AUTH_BASE_URL}/register`;
  const params = new URLSearchParams();
  
  if (redirectUri) {
    params.append('redirect_uri', redirectUri);
  }
  
  // Pass locale to Keycloak if provided
  if (locale) {
    params.append('kc_locale', locale);
  }
  
  const queryString = params.toString();
  if (queryString) {
    registerPath += `?${queryString}`;
  }
  
  window.location.href = registerPath;
}

/**
 * Initiate logout (full SSO logout)
 */
export function initiateLogout() {
  // POST to logout endpoint via nginx proxy, which will redirect to Keycloak logout
  // Using relative path ensures cookies are sent correctly (same origin)
  const form = document.createElement('form');
  form.method = 'POST';
  form.action = `${AUTH_BASE_URL}/logout`;
  document.body.appendChild(form);
  form.submit();
}

/**
 * Check if user is authenticated
 * @returns {Promise<boolean>}
 */
export async function isAuthenticated() {
  const result = await getCurrentUser();
  return result.authenticated;
}

/**
 * Get all organizations for the current user
 * @returns {Promise<Array<{id: string, name: string, attributes: object}>>}
 */
export async function getUserOrganizations() {
  try {
    const response = await fetch(`${AUTH_BASE_URL}/me/organizations`, {
      method: 'GET',
      credentials: 'include', // Include cookies
      cache: 'no-store',
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    return data.organizations || [];
  } catch (error) {
    console.error('Error fetching user organizations:', error);
    return [];
  }
}

/**
 * Update the current user's profile picture
 * @param {string} pictureDataUrl - Data URL of the image (e.g., "data:image/jpeg;base64,...")
 * @returns {Promise<{success: boolean, error?: string}>}
 */
export async function updateProfilePicture(pictureDataUrl) {
  try {
    const response = await fetch(`${AUTH_BASE_URL}/me`, {
      method: 'PATCH',
      credentials: 'include',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ picture: pictureDataUrl }),
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      return { success: false, error: err.detail || `HTTP ${response.status}` };
    }

    return { success: true };
  } catch (error) {
    console.error('Error updating profile picture:', error);
    return { success: false, error: error.message };
  }
}

export default {
  getCurrentUser,
  initiateLogin,
  initiateRegister,
  initiateLogout,
  isAuthenticated,
  getUserOrganizations,
  updateProfilePicture,
};
