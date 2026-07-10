import { post } from './api';

export function createIdempotencyKey(scope = 'mutation') {
  const prefix = String(scope || 'mutation').replace(/[^a-z0-9_.:-]+/gi, '-').toLowerCase();
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return `${prefix}:${crypto.randomUUID()}`;
  }
  return `${prefix}:${Date.now()}:${Math.random().toString(36).slice(2)}`;
}

export function isNetworkAbortLikeError(error) {
  const message = String(error?.message || '');
  return error?.name === 'AbortError'
    || message.includes('Failed to fetch')
    || message.includes('NetworkError')
    || message.includes('ERR_ABORTED');
}

export function withIdempotencyHeaders(options = {}, idempotencyKey) {
  return {
    ...options,
    headers: {
      ...(options.headers || {}),
      'Idempotency-Key': idempotencyKey,
    },
  };
}

export function operationStatusUnknownMessage(error, fallback = 'Operation status unknown') {
  if (!error?.operationStatusUnknown) {
    return error?.message || fallback;
  }
  const key = error.idempotencyKey ? ` Reference key: ${error.idempotencyKey}.` : '';
  return `${fallback}. The request may have completed, but the connection ended before confirmation. Refresh the page before creating another artifact.${key}`;
}

export async function postWithIdempotency(path, body, options = {}) {
  const {
    idempotencyKey = createIdempotencyKey(path),
    retryOnNetworkAbort = true,
    ...requestOptions
  } = options;
  const finalOptions = withIdempotencyHeaders(requestOptions, idempotencyKey);

  try {
    return await post(path, body, finalOptions);
  } catch (error) {
    if (!retryOnNetworkAbort || !isNetworkAbortLikeError(error)) {
      throw error;
    }
    try {
      return await post(path, body, finalOptions);
    } catch (retryError) {
      retryError.idempotencyKey = idempotencyKey;
      retryError.operationStatusUnknown = true;
      throw retryError;
    }
  }
}
