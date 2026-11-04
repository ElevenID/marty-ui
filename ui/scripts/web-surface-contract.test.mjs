import assert from 'node:assert/strict';
import { test } from 'node:test';
import { WEB_SURFACE_ROUTES, WEB_ROUTE_CONTRACT, canonicalJson, getWebSurface } from './web-surface-contract.mjs';
import { validateWebSurfaceContract } from '../src/application/routing/webSurfaceContract.mjs';

test('marketing routes are explicit while application, protocol, and unknown routes remain outside', () => {
  for (const route of ['/', '/product', '/pricing', '/resources', '/blog/example', '/demos/latest/example',
    '/_website/abc/assets/main.js', '/robots.txt', '/sitemap-0.xml']) assert.equal(getWebSurface(route), 'website', route);
  for (const route of ['/login', '/login/error', '/auth/callback', '/console', '/console/org', '/docs',
    '/pricing/checkout', '/resources/', '/v1/protocol-support', '/wallet/setup', '/unknown', '/blogger',
    '/sitemap-bad/path.xml', '//other.example/', 'https://other.example/', '/product?x=1']) {
    assert.equal(getWebSurface(route), 'application', route);
  }
});

test('route contract is closed and invalid ownership cannot be admitted', () => {
  for (const mutation of [
    { ...WEB_SURFACE_ROUTES, schema_version: 2 },
    { ...WEB_SURFACE_ROUTES, extra: true },
    { ...WEB_SURFACE_ROUTES, fallback: 'website' },
    { ...WEB_SURFACE_ROUTES, website: { ...WEB_SURFACE_ROUTES.website, path_prefixes: ['/'] } },
    { ...WEB_SURFACE_ROUTES, website: { ...WEB_SURFACE_ROUTES.website, exact_paths: ['/', '/'] } },
    { ...WEB_SURFACE_ROUTES, website: { ...WEB_SURFACE_ROUTES.website, filename_patterns: ['.*'] } },
  ]) assert.throws(() => validateWebSurfaceContract(mutation));
});

test('canonical contract digest uses sorted compact JSON without a trailing newline', () => {
  assert.equal(canonicalJson({ b: 2, a: { d: 4, c: 3 } }), '{"a":{"c":3,"d":4},"b":2}');
  assert.equal(WEB_ROUTE_CONTRACT.version, 1);
  assert.match(WEB_ROUTE_CONTRACT.sha256, /^sha256:[0-9a-f]{64}$/);
});
