/**
 * Authentication API Service
 *
 * Provides API calls for authentication operations.
 */

import { LOGOUT_STARTED_EVENT } from './authEvents';
import { getPublicEntryCanonicalOrigin, publicEntryHref } from '../application/routing/publicEntry';
import { redirectBrowser } from '../application/routing/appHandoff';
import { createProfilePictureBody } from './profilePicturePayload';

// Auth endpoints should always use relative paths to go through nginx proxy
// This ensures cookies are sent correctly (same origin)
const AUTH_BASE_URL = '/v1/auth';

/**
 * Get current authenticated user info
 * @returns {Promise<{authenticated: boolean, user: object|null}>}
 */
export async function getCurrentUser() {
  if (getPublicEntryCanonicalOrigin()) return { authenticated: false, user: null };
  const response = await fetch(`${AUTH_BASE_URL}/me`, {
    method: 'GET',
    credentials: 'include', // Include cookies
    cache: 'no-store',
    headers: {
      'Accept': 'application/json',
    },
  });

  // Only an explicit unauthenticated result ends a known session. Transport,
  // server, and malformed-response failures are not authentication decisions.
  if (response.status === 401) return { authenticated: false, user: null };
  if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
  const result = await response.json();
  if (result?.authenticated === false) return { authenticated: false, user: null };
  const principalId = result?.user?.user_id || result?.user?.sub || result?.user?.id;
  const hasPrincipal = typeof principalId === 'string'
    ? Boolean(principalId.trim())
    : typeof principalId === 'number' && Number.isFinite(principalId);
  if (result?.authenticated !== true || !result.user || Array.isArray(result.user) || !hasPrincipal) {
    throw new Error('The account response could not be read. Please try again.');
  }
  return result;
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
  
  redirectBrowser(publicEntryHref(loginPath), { replace: false });
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
  
  redirectBrowser(publicEntryHref(registerPath), { replace: false });
}

/**
 * Initiate logout (full SSO logout)
 */
export function initiateLogout() {
  const canonical = getPublicEntryCanonicalOrigin();
  if (canonical) {
    redirectBrowser(`${canonical}/`);
    return;
  }
  window.dispatchEvent(new Event(LOGOUT_STARTED_EVENT));
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
  if (getPublicEntryCanonicalOrigin()) return [];
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
  if (getPublicEntryCanonicalOrigin()) {
    return { success: false, error: 'Sign in at the configured application origin to update your profile.' };
  }
  try {
    const response = await fetch(`${AUTH_BASE_URL}/me`, {
      method: 'PATCH',
      credentials: 'include',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
      body: createProfilePictureBody(pictureDataUrl),
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

export async function startPasskeyEnrollment(redirectUri = '/console/applicant/profile') {
  const response = await fetch(`${AUTH_BASE_URL}/passkeys/enroll`, {
    method: 'POST',
    credentials: 'include',
    cache: 'no-store',
    headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({ redirect_uri: redirectUri }),
  });
  const result = await response.json().catch(() => ({}));
  if (response.ok && result.email_sent === true) {
    return { email_sent: true };
  }
  if (!response.ok || typeof result.authorization_url !== 'string') {
    throw new Error(result.detail || 'Passkey enrollment could not be started. Please sign in again and retry.');
  }
  redirectBrowser(result.authorization_url, { replace: false });
}

export default {
  getCurrentUser,
  initiateLogin,
  initiateRegister,
  initiateLogout,
  isAuthenticated,
  getUserOrganizations,
  updateProfilePicture,
  startPasskeyEnrollment,
};
