/**
 * Authentication API Service
 *
 * Provides API calls for authentication operations.
 */

import { LOGOUT_STARTED_EVENT } from './authEvents';
import { getPublicEntryCanonicalOrigin, publicEntryHref } from '../application/routing/publicEntry';
import { redirectBrowser } from '../application/routing/appHandoff';
import { createProfilePictureBody } from './profilePicturePayload';
import { navigateToAuthApi, navigateToPasskeyProvider, resolveAuthBaseUrl } from './authApiOrigin';

// Static consoles call the API directly; self-hosted builds keep relative URLs.
const authUrl = (path) => `${resolveAuthBaseUrl(import.meta.env.VITE_API_URL)}${path}`;
// A fixed API callback needs the console origin in its validated return binding.
const browserReturnUri = (path) => import.meta.env.VITE_API_URL
  ? new URL(path, window.location.href).href : path;
function navigateAuthRequest(destination) {
  if (destination.startsWith('/')) {
    redirectBrowser(publicEntryHref(destination), { replace: false });
  } else {
    navigateToAuthApi(destination, import.meta.env.VITE_API_URL);
  }
}
const SESSION_CHECK_TIMEOUT_MS = 15_000;

function sessionCheckError(message, code, status) {
  const error = new Error(message);
  error.code = code;
  if (status !== undefined) error.status = status;
  return error;
}

/**
 * Get current authenticated user info
 * @returns {Promise<{authenticated: boolean, user: object|null}>}
 */
export async function getCurrentUser() {
  if (getPublicEntryCanonicalOrigin()) return { authenticated: false, user: null };
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), SESSION_CHECK_TIMEOUT_MS);
  try {
    const response = await fetch(authUrl('/me'), {
      method: 'GET',
      credentials: 'include', // Include cookies
      cache: 'no-store',
      signal: controller.signal,
      headers: {
        'Accept': 'application/json',
      },
    });

    // Only an explicit unauthenticated result ends a known session. Transport,
    // server, and malformed-response failures are not authentication decisions.
    if (response.status === 401) return { authenticated: false, user: null };
    if (!response.ok) {
      throw sessionCheckError(`HTTP error! status: ${response.status}`,
        response.status >= 500 ? 'AUTH_UNAVAILABLE' : 'AUTH_CONFIGURATION', response.status);
    }
    let result;
    try {
      result = await response.json();
    } catch {
      throw sessionCheckError('The account response could not be read. Please try again.', 'AUTH_RESPONSE_INVALID');
    }
    if (result?.authenticated === false) return { authenticated: false, user: null };
    const principalId = result?.user?.user_id || result?.user?.sub || result?.user?.id;
    const hasPrincipal = typeof principalId === 'string'
      ? Boolean(principalId.trim())
      : typeof principalId === 'number' && Number.isFinite(principalId);
    if (result?.authenticated !== true || !result.user || Array.isArray(result.user) || !hasPrincipal) {
      throw sessionCheckError('The account response could not be read. Please try again.', 'AUTH_RESPONSE_INVALID');
    }
    return result;
  } catch (error) {
    if (controller.signal.aborted) {
      throw sessionCheckError('The sign-in service took too long to respond.', 'AUTH_TIMEOUT');
    }
    if (typeof error?.code === 'string' && error.code.startsWith('AUTH_')) throw error;
    throw sessionCheckError('The sign-in service could not be reached.', 'AUTH_NETWORK');
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Initiate login by redirecting to OIDC provider
 * @param {string} [redirectUri] - Where to redirect after login
 * @param {string} [locale] - Preferred sign-in language (e.g., 'en', 'de', 'ja')
 */
export function initiateLogin(redirectUri = '/', locale = null) {
  let loginPath = authUrl('/login');
  const params = new URLSearchParams();
  
  if (redirectUri) {
    params.append('redirect_uri', browserReturnUri(redirectUri));
  }
  
  // The Auth service validates and forwards the standard OIDC locale parameter.
  if (locale) {
    params.append('ui_locales', locale);
  }
  
  const queryString = params.toString();
  if (queryString) {
    loginPath += `?${queryString}`;
  }
  
  navigateAuthRequest(loginPath);
}

/**
 * Initiate registration through the configured identity provider
 * @param {string} [redirectUri] - Where to redirect after registration
 * @param {string} [locale] - Preferred sign-in language (e.g., 'en', 'de', 'ja')
 */
export function initiateRegister(redirectUri = '/', locale = null) {
  let registerPath = authUrl('/register');
  const params = new URLSearchParams();
  
  if (redirectUri) {
    params.append('redirect_uri', browserReturnUri(redirectUri));
  }
  
  // Use the same provider-neutral locale contract as login.
  if (locale) {
    params.append('ui_locales', locale);
  }
  
  const queryString = params.toString();
  if (queryString) {
    registerPath += `?${queryString}`;
  }
  
  navigateAuthRequest(registerPath);
}

/**
 * End the application session and use provider logout when available
 */
export function initiateLogout() {
  const canonical = getPublicEntryCanonicalOrigin();
  if (canonical) {
    redirectBrowser(`${canonical}/`);
    return;
  }
  window.dispatchEvent(new Event(LOGOUT_STARTED_EVENT));
  // Auth deletes the local session and redirects to provider logout when supported.
  const form = document.createElement('form');
  form.method = 'POST';
  form.action = authUrl('/logout');
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
    const response = await fetch(authUrl('/me/organizations'), {
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
    const response = await fetch(authUrl('/me'), {
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
  const response = await fetch(authUrl('/passkeys/enroll'), {
    method: 'POST',
    credentials: 'include',
    cache: 'no-store',
    redirect: 'error',
    headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({ redirect_uri: browserReturnUri(redirectUri) }),
  });
  const result = await response.json().catch(() => ({}));
  if (response.ok && result.email_sent === true) {
    return { email_sent: true };
  }
  if (!response.ok || typeof result.authorization_url !== 'string') {
    throw new Error(result.detail || 'Passkey enrollment could not be started. Please sign in again and retry.');
  }
  if (import.meta.env.VITE_API_URL) {
    navigateToPasskeyProvider(result.authorization_url, import.meta.env.VITE_API_URL,
      import.meta.env.VITE_AUTH_PROVIDER_ORIGIN);
  } else if (!redirectBrowser(result.authorization_url, { replace: false })) {
    throw new Error('Passkey enrollment could not open the configured sign-in provider.');
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
  startPasskeyEnrollment,
};
