import assert from 'node:assert/strict';
import { test } from 'node:test';
import { devServerOrigin } from './dev-server-origin.mjs';

test('the remote HTTPS edge supplies its exact HMR port and CORS origin', () => {
  assert.deepEqual(devServerOrigin({ VITE_DEV_PUBLIC_ORIGIN: 'https://dev.example.test:8443' }), {
    origin: 'https://dev.example.test:8443',
    allowedHosts: ['localhost', 'dev.example.test'],
    cors: { origin: 'https://dev.example.test:8443' },
    hmr: { protocol: 'wss', host: 'dev.example.test', clientPort: 8443 },
  });
});

test('local development and the legacy public domain remain supported without a wildcard allowlist', () => {
  assert.deepEqual(devServerOrigin({}), { allowedHosts: ['localhost'] });
  assert.equal(devServerOrigin({ PUBLIC_DOMAIN: 'dev.example.test' }).hmr.clientPort, 443);
  assert.equal(devServerOrigin({ PUBLIC_DOMAIN: 'dev.example.test:8443' }).hmr.clientPort, 8443);
  assert.deepEqual(devServerOrigin({ VITE_DEV_PUBLIC_ORIGIN: 'http://localhost:3000/' }).hmr, {
    protocol: 'ws', host: 'localhost', clientPort: 3000,
  });
  assert.equal(devServerOrigin({ VITE_DEV_PUBLIC_ORIGIN: 'https://[::1]:8443' }).hmr.host, '[::1]');
  assert.equal(devServerOrigin({ VITE_DEV_PUBLIC_ORIGIN: 'https://127.0.0.1' }).hmr.clientPort, 443);
});

test('an explicit public origin takes precedence over a legacy domain', () => {
  assert.equal(devServerOrigin({
    VITE_DEV_PUBLIC_ORIGIN: 'https://dev.example.test:8443', PUBLIC_DOMAIN: 'old.example.test',
  }).origin, 'https://dev.example.test:8443');
});

test('rejects malformed origins, wildcard hosts, credentials, and URL suffixes', () => {
  for (const value of [
    'dev.example.test', '//dev.example.test', 'ftp://dev.example.test',
    'https://*.example.test', 'https://.example.test', 'https://dev..example.test',
    'https://-dev.example.test', 'https://dev_.example.test',
    'https://user:password@dev.example.test', 'https://dev.example.test/path',
    'https://@dev.example.test', 'https:////dev.example.test',
    'https://dev.example.test?query=yes', 'https://dev.example.test#fragment',
    'https://dev.example.test?', 'https://dev.example.test#', 'https://dev.\nexample.test',
    ' https://dev.example.test', 'https://dev.example.test\n',
    'https://dev.example.test:0', 'https://dev.example.test:99999',
  ]) assert.throws(() => devServerOrigin({ VITE_DEV_PUBLIC_ORIGIN: value }), /VITE_DEV_PUBLIC_ORIGIN/, value);
});
