/** Browser API requests must use the configured canonical API origin. */
export function resolveApiBaseUrl(apiOrigin) {
  if (apiOrigin === undefined || apiOrigin === '') return '';
  const invalid = () => Object.assign(new Error(
    'VITE_API_URL must be an HTTPS API origin (HTTP is allowed only on loopback).',
  ), { code: 'AUTH_CONFIGURATION' });
  if (typeof apiOrigin !== 'string' || apiOrigin.length > 2048 || apiOrigin.trim() !== apiOrigin) {
    throw invalid();
  }
  let url;
  try { url = new URL(apiOrigin); } catch { throw invalid(); }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback))
    || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw invalid();
  }
  return url.origin;
}

export function resolveAuthBaseUrl(apiOrigin) {
  return `${resolveApiBaseUrl(apiOrigin)}/v1/auth`;
}

/** First-party API paths cannot select an unrelated host. */
export function resolveApiUrl(path, apiOrigin) {
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//')
    || /[\u0000-\u001f\u007f\\]/.test(path)) {
    throw Object.assign(new Error('A first-party API path is required.'), { code: 'AUTH_CONFIGURATION' });
  }
  return `${resolveApiBaseUrl(apiOrigin)}${path}`;
}

/** The configured API is the only cross-origin destination for starting Auth. */
export function navigateToAuthApi(destination, apiOrigin, location = window.location) {
  const base = new URL(resolveAuthBaseUrl(apiOrigin), location.href);
  const target = new URL(destination, location.href);
  if (target.origin !== base.origin
    || target.username || target.password || target.hash
    || !['/v1/auth/login', '/v1/auth/register'].includes(target.pathname)) {
    throw Object.assign(new Error('Authentication navigation must use the configured API endpoint.'),
      { code: 'AUTH_CONFIGURATION' });
  }
  location.assign(target.href);
}

/** Only the enrollment response from the configured Auth API uses this handoff.
 * A separately hosted Keycloak needs an explicitly configured public origin.
 * This does not broaden application links or general browser navigation.
 */
export function navigateToPasskeyProvider(destination, apiOrigin, providerOrigin, location = window.location) {
  const invalid = () => Object.assign(new Error('Passkey enrollment returned an unsupported provider destination.'),
    { code: 'AUTH_CONFIGURATION' });
  const api = new URL(resolveAuthBaseUrl(apiOrigin), location.href);
  const provider = providerOrigin === undefined || providerOrigin === ''
    ? api : new URL(resolveAuthBaseUrl(providerOrigin), location.href);
  if (typeof destination !== 'string' || destination.trim() !== destination
    || /[\u0000-\u001f\u007f\\]/.test(destination)) throw invalid();
  let target;
  try { target = new URL(destination); } catch { throw invalid(); }
  if (target.origin !== provider.origin || target.protocol !== provider.protocol
    || target.username || target.password || target.hash
    || target.searchParams.getAll('kc_action').length !== 1
    || target.searchParams.get('kc_action') !== 'webauthn-register-passwordless'
    || target.searchParams.getAll('redirect_uri').length !== 1
    || target.searchParams.get('redirect_uri') !== `${api.origin}/v1/auth/callback`) throw invalid();
  location.assign(target.href);
}
