/**
 * Authentication API Service
 *
 * Provides API calls for authentication operations.
 */

// API base URL for general API calls
const API_BASE_URL = process.env.REACT_APP_API_URL || '';

// Auth endpoints should always use relative paths to go through nginx proxy
// This ensures cookies are sent correctly (same origin)
const AUTH_BASE_URL = '';

/**
 * Get current authenticated user info
 * @returns {Promise<{authenticated: boolean, user: object|null}>}
 */
export async function getCurrentUser() {
  try {
    const response = await fetch(`${AUTH_BASE_URL}/auth/me`, {
      method: 'GET',
      credentials: 'include', // Include cookies
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
 */
export function initiateLogin(redirectUri = '/') {
  // Build login URL - always use relative path to go through nginx proxy
  let loginPath = `${AUTH_BASE_URL}/auth/login`;
  if (redirectUri) {
    loginPath += `?redirect_uri=${encodeURIComponent(redirectUri)}`;
  }
  window.location.href = loginPath;
}

/**
 * Initiate registration by redirecting to Keycloak registration page
 * @param {string} [redirectUri] - Where to redirect after registration
 */
export function initiateRegister(redirectUri = '/') {
  // Build registration URL - always use relative path to go through nginx proxy
  let registerPath = `${AUTH_BASE_URL}/auth/register`;
  if (redirectUri) {
    registerPath += `?redirect_uri=${encodeURIComponent(redirectUri)}`;
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
  form.action = `${AUTH_BASE_URL}/auth/logout`;
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

export default {
  getCurrentUser,
  initiateLogin,
  initiateRegister,
  initiateLogout,
  isAuthenticated,
};
