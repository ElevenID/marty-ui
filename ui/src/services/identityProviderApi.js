import { getPublicEntryCanonicalOrigin } from '../application/routing/publicEntry';
import { resolveAuthBaseUrl } from './authApiOrigin';

const PROVIDER_REQUEST_TIMEOUT_MS = 10_000;
const PROVIDER_UNAVAILABLE = 'Sign-in provider details are temporarily unavailable.';

function accountLink(value) {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string' || value.length > 2048 || value.trim() !== value || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error(PROVIDER_UNAVAILABLE);
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(PROVIDER_UNAVAILABLE);
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
    throw new Error(PROVIDER_UNAVAILABLE);
  }
  return parsed.href;
}

// These capabilities describe the configured identity provider. They never
// grant application permissions or replace the authenticated user response.
function providerDetails(value) {
  const flags = ['registration_supported', 'passkey_enrollment_supported', 'provider_logout_supported'];
  if (!value || Array.isArray(value)
    || !['keycloak', 'external'].includes(value.provider_mode)
    || typeof value.provider_name !== 'string'
    || !value.provider_name.trim() || value.provider_name.length > 80
    || /[\u0000-\u001f\u007f]/.test(value.provider_name)
    || flags.some(flag => typeof value[flag] !== 'boolean')) {
    throw new Error(PROVIDER_UNAVAILABLE);
  }
  return {
    provider_mode: value.provider_mode,
    provider_name: value.provider_name,
    registration_supported: value.registration_supported,
    passkey_enrollment_supported: value.passkey_enrollment_supported,
    provider_logout_supported: value.provider_logout_supported,
    account_url: accountLink(value.account_url),
    recovery_url: accountLink(value.recovery_url),
  };
}

export async function getIdentityProvider({ signal } = {}) {
  if (getPublicEntryCanonicalOrigin()) return null;
  const controller = new AbortController();
  const abort = () => controller.abort();
  if (signal?.aborted) abort();
  signal?.addEventListener('abort', abort, { once: true });
  const timeout = setTimeout(abort, PROVIDER_REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(`${resolveAuthBaseUrl(import.meta.env.VITE_API_URL)}/provider`, {
      method: 'GET',
      credentials: import.meta.env.VITE_API_URL ? 'include' : 'same-origin',
      cache: 'no-store',
      redirect: 'error',
      signal: controller.signal,
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) throw new Error(PROVIDER_UNAVAILABLE);
    return providerDetails(await response.json());
  } catch {
    if (signal?.aborted) throw new DOMException('Request cancelled', 'AbortError');
    throw new Error(PROVIDER_UNAVAILABLE);
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener('abort', abort);
  }
}
