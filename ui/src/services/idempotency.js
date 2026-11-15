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
    // Native Node fetch (used by MSW 3) reports an interrupted transport as a
    // TypeError. An ordinary error with the same message must not retry a POST.
    || (error?.name === 'TypeError' && message === 'fetch failed')
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

// Callers may bind each attempt and its settlement to a logical action owner.
// This does not cancel a request that has already reached the transport.
export async function postWithIdempotency(path, body, options = {}) {
  const {
    idempotencyKey = createIdempotencyKey(path),
    retryOnNetworkAbort = true,
    isCurrent,
    ...requestOptions
  } = options;
  const finalOptions = withIdempotencyHeaders(requestOptions, idempotencyKey);
  const assertCurrent = () => {
    if (isCurrent && !isCurrent()) {
      const error = new Error('The view or action changed.');
      error.name = 'AbortError';
      throw error;
    }
  };

  assertCurrent();
  try {
    const result = await post(path, body, finalOptions);
    assertCurrent();
    return result;
  } catch (error) {
    // An obsolete cancellation must never become another POST attempt.
    assertCurrent();
    if (!retryOnNetworkAbort || !isNetworkAbortLikeError(error)) {
      throw error;
    }
    try {
      assertCurrent();
      const result = await post(path, body, finalOptions);
      assertCurrent();
      return result;
    } catch (retryError) {
      assertCurrent();
      retryError.idempotencyKey = idempotencyKey;
      retryError.operationStatusUnknown = true;
      throw retryError;
    }
  }
}
