import assert from 'node:assert/strict';
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';
import { WEBSITE_SOURCE_OWNERSHIP, assertWebsiteSourceRemoved, validateWebsiteSourceOwnership, validateWebsiteSourceOwnershipSchema } from './website-source-ownership.mjs';
import { selfhostBuildContractPlugin } from './selfhost-build-contract.mjs';
import { forbiddenWebSurfaceModule, websiteBuildRevision, webSurfaceBuildContractPlugin } from './web-surface-build-contract.mjs';
import { WEB_ROUTE_CONTRACT } from './web-surface-contract.mjs';

const sourceSha = 'a'.repeat(40);
const commerceSha = 'b'.repeat(40);
const chunk = (id) => ({ main: { type: 'chunk', modules: { [id]: {} } } });

test('every retired website module is rejected from emitted application and customer bundles', () => {
  for (const entry of WEBSITE_SOURCE_OWNERSHIP.modules) {
    const id = `/repo/${entry}`;
    assert.throws(() => selfhostBuildContractPlugin().generateBundle({}, chunk(id)), /marketing/, entry);
    assert.throws(() => webSurfaceBuildContractPlugin({ surface: 'application' }).generateBundle({}, chunk(id)), /forbidden/, entry);
  }
  assert.equal(forbiddenWebSurfaceModule('application', '/repo/ui/src/apps/public/PublicApp.jsx'), false);
});

test('the retained website roster has a closed schema and unique exact paths', () => {
  for (const value of [
    { ...WEBSITE_SOURCE_OWNERSHIP, unknown: true },
    { ...WEBSITE_SOURCE_OWNERSHIP, schema_version: 2 },
    { schema_version: 1, modules: [] },
    { schema_version: 1, modules: [WEBSITE_SOURCE_OWNERSHIP.modules[0], WEBSITE_SOURCE_OWNERSHIP.modules[0]] },
    { schema_version: 1, modules: ['ui/src/../package.json'] },
  ]) assert.throws(() => validateWebsiteSourceOwnershipSchema(value));
  assert.strictEqual(assertWebsiteSourceRemoved(), WEBSITE_SOURCE_OWNERSHIP);
});

test('retired source cannot return as a file, directory, or dangling symlink', (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'marty-retired-website-source-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const entry = WEBSITE_SOURCE_OWNERSHIP.modules[0];
  const target = path.join(root, entry);
  mkdirSync(path.dirname(target), { recursive: true });
  for (const create of [
    () => writeFileSync(target, 'export default null;\n'),
    () => mkdirSync(target),
    () => symlinkSync(path.join(root, 'missing-target'), target),
  ]) {
    assert.doesNotThrow(() => assertWebsiteSourceRemoved(WEBSITE_SOURCE_OWNERSHIP, root));
    create();
    assert.throws(() => assertWebsiteSourceRemoved(WEBSITE_SOURCE_OWNERSHIP, root), /must remain absent/);
    rmSync(target, { recursive: true });
  }
});

test('historical source validation still requires an existing ordinary file', (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'marty-historical-website-source-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const roster = { schema_version: 1, modules: [WEBSITE_SOURCE_OWNERSHIP.modules[0]] };
  const target = path.join(root, roster.modules[0]);
  mkdirSync(path.dirname(target), { recursive: true });
  assert.throws(() => validateWebsiteSourceOwnership(roster, root), { code: 'ENOENT' });
  writeFileSync(target, 'export default null;\n');
  assert.strictEqual(validateWebsiteSourceOwnership(roster, root), roster);
  rmSync(target);
  symlinkSync(path.join(root, 'missing-target'), target);
  assert.throws(() => validateWebsiteSourceOwnership(roster, root), /not a regular file/);
});

test('application and customer build contracts work after website source removal', async (t) => {
  const repositoryRoot = path.resolve(import.meta.dirname, '../..');
  const directory = mkdtempSync(path.join(os.tmpdir(), 'marty-absent-website-source-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  for (const relativePath of [
    'contracts/website-source-ownership.json', 'contracts/web-surface-routes.json',
    'ui/scripts/website-source-ownership.mjs', 'ui/scripts/selfhost-build-contract.mjs',
    'ui/scripts/web-surface-build-contract.mjs', 'ui/scripts/web-surface-contract.mjs',
    'ui/src/application/routing/webSurfaceContract.mjs', 'ui/src/utils/hasAsciiControlCharacters.js',
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
  const customerPlugin = exportedSelfhostPlugin();
  for (const entry of WEBSITE_SOURCE_OWNERSHIP.modules) {
    const bundle = chunk(path.join(directory, entry));
    assert.throws(() => applicationPlugin.generateBundle({}, bundle), /forbidden/, entry);
    assert.throws(() => customerPlugin.generateBundle({}, bundle), /marketing/, entry);
  }
  for (const surface of ['combined', 'website']) {
    assert.throws(() => exportedWebPlugin({ surface }), /Only the application/, surface);
  }
});

test('historical website module classification still rejects application and private contexts', () => {
  for (const id of [
    '/repo/ui/node_modules/@elevenid/marty-api-core/index.js',
    '/repo/ui/src/apps/public/PublicApp.jsx', '/repo/ui/src/apps/console/ConsoleApp.jsx',
    '/repo/ui/src/bootstrapApp.jsx', '/repo/ui/src/hooks/useAuth.js',
    '/repo/ui/src/services/api.js', '/repo/ui/src/services/authApi.js',
    '/repo/ui/src/contexts/AuthContext.jsx', '/repo/ui/src/contexts/ConsoleContext.jsx',
    '/repo/commerce-extension/src/contexts/PaymentContext.jsx',
    '/repo/commerce-extension/src/application.jsx', '/repo/commerce-extension/src/extension.jsx',
    '/repo/commerce-extension/src/components/billing/SubscriptionCheckout.jsx',
  ]) assert.equal(Boolean(forbiddenWebSurfaceModule('website', id, '/repo/commerce-extension/src/website.jsx')), true, id);
});

test('application rejects private marketing modules in the final host bundle', () => {
  for (const suffix of ['website.jsx', 'components/PricingPage.jsx', 'data/pricingPageContent.js', 'seo/SEOHead.jsx']) {
    assert.equal(forbiddenWebSurfaceModule('application', `/private/src/${suffix}`, '/private/src/application.jsx'), true);
  }
  assert.equal(forbiddenWebSurfaceModule('application', '/private/src/data/pricingPlans.js', '/private/src/application.jsx'), true);
});

test('historical website revisions retain exact source input binding', () => {
  assert.equal(websiteBuildRevision({ sourceSha }), sourceSha);
  assert.equal(websiteBuildRevision({ sourceSha, commerceSha, pages: 'full' }), `${sourceSha}-${commerceSha}`);
  assert.equal(websiteBuildRevision(), 'development');
  for (const options of [
    { sourceSha: '../unsafe' }, { sourceSha, revision: 'next' },
    { sourceSha, pages: 'full' }, { sourceSha, commerceSha, pages: 'public' },
    { sourceSha, pages: 'unknown' },
  ]) assert.throws(() => websiteBuildRevision(options));
});

test('application metadata preserves exact source input and the common route contract', () => {
  const emitted = [];
  const plugin = webSurfaceBuildContractPlugin({ sourceSha });
  plugin.generateBundle.call({ emitFile: (file) => emitted.push(file) }, {}, {});
  assert.equal(emitted.length, 1);
  assert.equal(emitted[0].fileName, 'marty-web-routes.json');
  assert.deepEqual(JSON.parse(emitted[0].source), {
    schema: 'marty.application-web-compatibility/v1', surface: 'application', source_sha: sourceSha,
    route_contract: WEB_ROUTE_CONTRACT,
  });
});

test('private pricing remains forbidden in historical classifiers and current lazy application chunks', () => {
  for (const surface of ['combined', 'website', 'application']) {
    const entry = `/private/src/${surface === 'combined' ? 'extension' : surface}.jsx`;
    for (const name of ['components/PricingPage.jsx', 'data/pricingPageContent.js', 'data/pricingContent.js', 'data/pricingPlans.js']) {
      assert.equal(Boolean(forbiddenWebSurfaceModule(surface, `/private/src/${name}`, entry)), true);
      const plugin = webSurfaceBuildContractPlugin({ commerceEntry: '/private/src/application.jsx' });
      assert.throws(() => plugin.generateBundle({}, {
        'entry.js': { type: 'chunk', modules: {}, dynamicImports: ['hidden.js'] },
        'hidden.js': { type: 'chunk', modules: { [`/private/src/${name}`]: {} } },
      }), /forbidden/);
    }
  }
});
