const { expect, test } = require('@playwright/test');

const { redact } = require('../../scripts/verify-beta-waltid-acceptance');

test('acceptance diagnostics redact protocol URIs and bearer credentials', () => {
  const diagnostic = redact({
    credential_offer_uri: 'https://issuer.example/offers/secret',
    request_uri: 'https://verifier.example/requests/secret',
    token: 'secret-token',
    detail: 'Bearer secret.jwt.value',
    status: 'failed',
  });

  expect(diagnostic).not.toContain('offers/secret');
  expect(diagnostic).not.toContain('requests/secret');
  expect(diagnostic).not.toContain('secret-token');
  expect(diagnostic).not.toContain('secret.jwt.value');
  expect(diagnostic).toContain('"status":"failed"');
  expect(diagnostic.match(/\[redacted\]/g)).toHaveLength(4);
});
