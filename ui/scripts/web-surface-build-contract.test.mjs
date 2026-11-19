import assert from 'node:assert/strict';
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';
import { WEBSITE_SOURCE_OWNERSHIP, validateWebsiteSourceOwnership } from './website-source-ownership.mjs';
import { selfhostBuildContractPlugin } from './selfhost-build-contract.mjs';
import { forbiddenWebSurfaceModule, websiteBuildRevision, webSurfaceBuildContractPlugin } from './web-surface-build-contract.mjs';
import { WEB_ROUTE_CONTRACT } from './web-surface-contract.mjs';

const sourceSha = 'a'.repeat(40);
const commerceSha = 'b'.repeat(40);
const chunk = (id) => ({ main: { type: 'chunk', modules: { [id]: {} } } });

test('every website-owned module is rejected from emitted application and customer bundles', () => {
  for (const entry of WEBSITE_SOURCE_OWNERSHIP.modules) {
    const id = `/repo/${entry}`;
    assert.throws(() => selfhostBuildContractPlugin().generateBundle({}, chunk(id)), /marketing/, entry);
    assert.throws(() => webSurfaceBuildContractPlugin({ surface: 'application' }).generateBundle({}, chunk(id)), /forbidden/, entry);
  }
  assert.equal(forbiddenWebSurfaceModule('application', '/repo/ui/src/apps/public/PublicApp.jsx'), false);
});

test('website ownership has a closed schema, unique exact paths, and existing regular files', () => {
  for (const value of [
    { ...WEBSITE_SOURCE_OWNERSHIP, unknown: true },
    { ...WEBSITE_SOURCE_OWNERSHIP, schema_version: 2 },
    { schema_version: 1, modules: [] },
    { schema_version: 1, modules: [WEBSITE_SOURCE_OWNERSHIP.modules[0], WEBSITE_SOURCE_OWNERSHIP.modules[0]] },
    { schema_version: 1, modules: ['ui/src/../package.json'] },
    { schema_version: 1, modules: ['ui/src/does-not-exist.jsx'] },
  ]) assert.throws(() => validateWebsiteSourceOwnership(value));
});

test('application classifies absent website sources while other builds still require them', async (t) => {
  const repositoryRoot = path.resolve(import.meta.dirname, '../..');
  const directory = mkdtempSync(path.join(os.tmpdir(), 'marty-absent-website-source-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  for (const relativePath of [
    'contracts/website-source-ownership.json',
    'contracts/web-surface-routes.json',
    'ui/scripts/website-source-ownership.mjs',
    'ui/scripts/selfhost-build-contract.mjs',
    'ui/scripts/web-surface-build-contract.mjs',
    'ui/scripts/web-surface-contract.mjs',
    'ui/src/application/routing/webSurfaceContract.mjs',
    'ui/src/utils/hasAsciiControlCharacters.js',
  ]) {
    const destination = path.join(directory, relativePath);
    mkdirSync(path.dirname(destination), { recursive: true });
    copyFileSync(path.join(repositoryRoot, relativePath), destination);
  }
  const { webSurfaceBuildContractPlugin: exportedWebPlugin } = await import(pathToFileURL(
    path.join(directory, 'ui/scripts/web-surface-build-contract.mjs'),
  ).href);
  const { selfhostBuildContractPlugin: exportedSelfhostPlugin } = await import(pathToFileURL(
    path.join(directory, 'ui/scripts/selfhost-build-contract.mjs'),
  ).href);

  const applicationPlugin = exportedWebPlugin({ surface: 'application' });
  for (const entry of WEBSITE_SOURCE_OWNERSHIP.modules) {
    assert.throws(() => applicationPlugin.generateBundle({}, chunk(path.join(directory, entry))), /forbidden/, entry);
  }
  for (const surface of ['combined', 'website']) {
    assert.throws(() => exportedWebPlugin({ surface }), { code: 'ENOENT' }, surface);
  }
  assert.throws(() => exportedSelfhostPlugin(), { code: 'ENOENT' });
});

test('website output rejects application services, contexts, consoles and private application modules', () => {
  for (const id of [
    '/repo/ui/node_modules/@elevenid/marty-api-core/index.js',
    '/repo/ui/src/apps/public/PublicApp.jsx', '/repo/ui/src/apps/console/ConsoleApp.jsx',
    '/repo/ui/src/bootstrapApp.jsx', '/repo/ui/src/hooks/useAuth.js',
    '/repo/ui/src/services/api.js', '/repo/ui/src/services/authApi.js',
    '/repo/ui/src/contexts/AuthContext.jsx', '/repo/ui/src/contexts/ConsoleContext.jsx',
    '/repo/commerce-extension/src/contexts/PaymentContext.jsx',
    '/repo/commerce-extension/src/application.jsx', '/repo/commerce-extension/src/extension.jsx',
    '/repo/commerce-extension/src/components/billing/SubscriptionCheckout.jsx',
  ]) {
    const plugin = webSurfaceBuildContractPlugin({ surface: 'website', commerceEntry: '/repo/commerce-extension/src/website.jsx' });
    assert.throws(() => plugin.generateBundle({}, chunk(id)), /forbidden/, id);
  }
  for (const id of ['/repo/ui/src/apps/website/WebsiteApp.jsx', '/repo/ui/src/components/LandingPageContent.jsx']) {
    assert.equal(Boolean(forbiddenWebSurfaceModule('website', id, '/repo/commerce-extension/src/website.jsx')), false, id);
  }
});

test('application rejects private marketing modules in the final host bundle', () => {
  for (const suffix of ['website.jsx', 'components/PricingPage.jsx', 'data/pricingPageContent.js', 'seo/SEOHead.jsx']) {
    assert.equal(forbiddenWebSurfaceModule('application', `/private/src/${suffix}`, '/private/src/application.jsx'), true);
  }
  assert.equal(forbiddenWebSurfaceModule('application', '/private/src/data/pricingPlans.js', '/private/src/application.jsx'), true);
});

test('revision identifies all source inputs and cannot be supplied independently', () => {
  assert.equal(websiteBuildRevision({ sourceSha }), sourceSha);
  assert.equal(websiteBuildRevision({ sourceSha, commerceSha, pages: 'full' }), `${sourceSha}-${commerceSha}`);
  assert.equal(websiteBuildRevision(), 'development');
  for (const options of [
    { sourceSha: '../unsafe' }, { sourceSha, revision: 'next' },
    { sourceSha, pages: 'full' }, { sourceSha, commerceSha, pages: 'public' },
    { sourceSha, pages: 'unknown' },
  ]) assert.throws(() => websiteBuildRevision(options));
});

test('surface metadata preserves exact source inputs and the common route contract', () => {
  for (const surface of ['combined', 'application', 'website']) {
    const emitted = [];
    const plugin = webSurfaceBuildContractPlugin({ surface, sourceSha, pages: 'full', commerceSha });
    plugin.generateBundle.call({ emitFile: (file) => emitted.push(file) }, {}, {});
    assert.equal(emitted.length, 1);
    const metadata = JSON.parse(emitted[0].source);
    assert.deepEqual(metadata.route_contract, WEB_ROUTE_CONTRACT);
    assert.equal(metadata.source_sha, sourceSha);
    assert.equal(metadata.surface, surface);
    if (surface === 'website') {
      assert.equal(emitted[0].fileName, 'marty-website-release.json');
      assert.deepEqual(metadata, {
        schema: 'marty.website-image/v1', audience: 'production', surface,
        repository: 'ElevenID/marty-ui', source_sha: sourceSha, revision: `${sourceSha}-${commerceSha}`,
        production_pages: 'full', route_contract: WEB_ROUTE_CONTRACT,
        commerce_extension: { repository: 'ElevenID/marty-subscriptions', source_sha: commerceSha },
      });
    } else {
      assert.equal(emitted[0].fileName, 'marty-web-routes.json');
      assert.deepEqual(Object.keys(metadata).sort(), ['route_contract', 'schema', 'source_sha', 'surface']);
    }
  }
});


test('every delivered surface rejects private pricing in static and lazy chunks', () => {
  for (const surface of ['combined', 'website', 'application']) {
    const entry = `/private/src/${surface === 'combined' ? 'extension' : surface}.jsx`;
    for (const name of ['components/PricingPage.jsx', 'data/pricingPageContent.js', 'data/pricingContent.js', 'data/pricingPlans.js']) {
      assert.equal(Boolean(forbiddenWebSurfaceModule(surface, `/private/src/${name}`, entry)), true);
      const plugin = webSurfaceBuildContractPlugin({ surface, commerceEntry: entry });
      assert.throws(() => plugin.generateBundle({}, {
        'entry.js': { type: 'chunk', modules: {}, dynamicImports: ['hidden.js'] },
        'hidden.js': { type: 'chunk', modules: { [`/private/src/${name}`]: {} } },
      }), /forbidden/);
    }
  }
});
