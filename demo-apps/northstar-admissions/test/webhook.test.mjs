import assert from 'node:assert/strict';
import test from 'node:test';

import { canonicalJson, expectedSignature, verifyMartyWebhook } from '../src/webhook.mjs';

const secret = '0123456789abcdef0123456789abcdef';
const payload = { type: 'application.approved', id: 'event-1', timestamp: '2026-08-30T00:00:00Z', data: { status: 'APPROVED', application_id: 'app-1' } };

function headers(signature = expectedSignature(secret, payload)) {
  return new Headers({
    'X-MIP-Signature': signature,
    'X-MIP-Event': payload.type,
    'X-MIP-Event-Id': payload.id,
    'X-MIP-Timestamp': payload.timestamp,
  });
}

test('canonical JSON recursively sorts objects without reordering arrays', () => {
  assert.equal(canonicalJson({ z: 1, a: { y: 2, x: [3, { b: 2, a: 1 }] } }), '{"a":{"x":[3,{"a":1,"b":2}],"y":2},"z":1}');
});

test('valid signed application events pass and tampering fails closed', () => {
  assert.deepEqual(verifyMartyWebhook({ secret, headers: headers(), payload }), { ok: true, code: 'VERIFIED' });
  assert.equal(verifyMartyWebhook({ secret, headers: headers(), payload: { ...payload, id: 'tampered' } }).code, 'INVALID_SIGNATURE');
  const mismatched = headers();
  mismatched.set('X-MIP-Event-Id', 'other');
  assert.equal(verifyMartyWebhook({ secret, headers: mismatched, payload }).code, 'HEADER_BODY_MISMATCH');
});
