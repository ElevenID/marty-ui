/** Auth cookies and browser navigations must use the configured API origin. */
export function resolveAuthBaseUrl(apiOrigin) {
  if (apiOrigin === undefined || apiOrigin === '') return '/v1/auth';
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
  return `${url.origin}/v1/auth`;
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
