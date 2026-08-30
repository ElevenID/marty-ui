import { randomUUID } from 'node:crypto';

const FORBIDDEN_PATH_PREFIXES = ['/internal/', '/health', '/ready', '/metrics'];
export const MIP_VERSION = '0.5.0';

export function normalizeGatewayOrigin(value) {
  const url = new URL(String(value || ''));
  if (url.protocol !== 'https:') throw new Error('Marty public gateway must use HTTPS');
  if (url.username || url.password || url.search || url.hash || url.pathname !== '/') {
    throw new Error('Marty public gateway must be an origin without credentials, path, query, or fragment');
  }
  return url.origin;
}

export function assertPublicGatewayUrl(origin, candidate) {
  const expectedOrigin = normalizeGatewayOrigin(origin);
  const url = new URL(candidate, `${expectedOrigin}/`);
  if (url.origin !== expectedOrigin) {
    throw new Error(`Direct Marty service access rejected: ${url.origin}`);
  }
  if (!url.pathname.startsWith('/v1/') || FORBIDDEN_PATH_PREFIXES.some((prefix) => url.pathname.startsWith(prefix))) {
    throw new Error(`Non-public Marty route rejected: ${url.pathname}`);
  }
  return url;
}

export function createGatewayClient({ origin, fetchImpl = fetch, observe = () => {} }) {
  const publicOrigin = normalizeGatewayOrigin(origin);
  return async function gatewayRequest(path, {
    method = 'GET',
    organizationId,
    apiKey,
    sessionCookie,
    body,
    idempotencyKey,
  } = {}) {
    const url = assertPublicGatewayUrl(publicOrigin, path);
    const headers = new Headers({ Accept: 'application/json', 'X-MIP-Version': MIP_VERSION });
    if (organizationId) headers.set('X-Organization-ID', organizationId);
    if (apiKey) headers.set('X-API-Key', apiKey);
    if (sessionCookie) headers.set('Cookie', sessionCookie);
    if (body !== undefined) headers.set('Content-Type', 'application/json');
    if (method !== 'GET' && method !== 'HEAD') {
      headers.set('Idempotency-Key', idempotencyKey || `northstar-${randomUUID()}`);
    }
    observe({
      origin: url.origin,
      method,
      path: `${url.pathname}${url.search}`,
      authentication: apiKey ? 'API_KEY' : sessionCookie ? 'SESSION' : 'NONE',
      idempotencyKey: headers.get('Idempotency-Key'),
    });
    const response = await fetchImpl(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: 'error',
    });
    const responseVersion = response.headers.get('x-mip-version');
    if (responseVersion !== MIP_VERSION) {
      throw new Error(`Gateway response did not confirm MIP ${MIP_VERSION}`);
    }
    const text = await response.text();
    let payload = null;
    if (text) {
      try { payload = JSON.parse(text); } catch { payload = { detail: 'Gateway returned a non-JSON response' }; }
    }
    return {
      ok: response.ok,
      status: response.status,
      requestId: response.headers.get('x-request-id') || response.headers.get('x-correlation-id'),
      payload,
    };
  };
}
