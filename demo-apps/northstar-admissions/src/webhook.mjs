import { createHmac, timingSafeEqual } from 'node:crypto';

function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
  }
  return value;
}

export function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

export function expectedSignature(secret, payload) {
  return `sha256=${createHmac('sha256', secret).update(canonicalJson(payload)).digest('hex')}`;
}

function header(headers, name) {
  if (typeof headers?.get === 'function') return headers.get(name) || headers.get(name.toLowerCase());
  return headers?.[name] || headers?.[name.toLowerCase()];
}

export function verifyMartyWebhook({ secret, headers, payload }) {
  if (typeof secret !== 'string' || secret.length < 32) throw new Error('Webhook signing secret is unavailable');
  const provided = header(headers, 'X-MIP-Signature') || '';
  const expected = expectedSignature(secret, payload);
  const providedBytes = Buffer.from(provided);
  const expectedBytes = Buffer.from(expected);
  if (providedBytes.length !== expectedBytes.length || !timingSafeEqual(providedBytes, expectedBytes)) {
    return { ok: false, code: 'INVALID_SIGNATURE' };
  }
  const bindings = [
    ['X-MIP-Event-Id', payload.id],
    ['X-MIP-Event', payload.type],
    ['X-MIP-Timestamp', payload.timestamp],
  ];
  if (bindings.some(([name, value]) => !value || header(headers, name) !== value)) {
    return { ok: false, code: 'HEADER_BODY_MISMATCH' };
  }
  if (payload.type !== 'application.approved') return { ok: false, code: 'UNEXPECTED_EVENT_TYPE' };
  return { ok: true, code: 'VERIFIED' };
}
