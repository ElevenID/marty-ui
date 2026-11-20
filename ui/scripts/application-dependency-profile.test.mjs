import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import {
  APPLICATION_REMOVED_DEPENDENCY_ROOTS, APPLICATION_PROFILE_SCRIPTS,
  validateApplicationDependencyProfile,
} from './application-dependency-profile.mjs';

function write(root, name, value) {
  const filename = path.join(root, name);
  mkdirSync(path.dirname(filename), { recursive: true });
  writeFileSync(filename, `${JSON.stringify(value, null, 2)}\n`);
}

function read(root, name) { return JSON.parse(readFileSync(path.join(root, name), 'utf8')); }
function mutate(root, name, action) { const value = read(root, name); action(value); write(root, name, value); }
const ROOT_MANIFEST = 'ui/package.json';
const ROOT_LOCK = 'ui/package-lock.json';
const PROFILE_MANIFEST = 'ui/profiles/application/package.json';
const PROFILE_LOCK = 'ui/profiles/application/package-lock.json';

function fixture(t) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'marty-application-profile-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const manifest = {
    name: 'application-profile-fixture', version: '1.0.0', private: true, type: 'module',
    scripts: { build: 'combined-build', postinstall: 'both-reviewed-patches' },
    dependencies: { '@elevenid/marty-blog': '1.0.0', retained: '2.0.0' },
    devDependencies: Object.fromEntries(APPLICATION_REMOVED_DEPENDENCY_ROOTS.slice(1).map((name) => [name, '1.0.0'])),
  };
  const rootPackage = { name: manifest.name, version: manifest.version, hasInstallScript: true,
    dependencies: structuredClone(manifest.dependencies), devDependencies: structuredClone(manifest.devDependencies) };
  const packages = { '': rootPackage };
  for (const name of [...APPLICATION_REMOVED_DEPENDENCY_ROOTS, 'retained', 'shared-child', 'website-child']) {
    packages[`node_modules/${name}`] = { version: name === 'retained' ? '2.0.0' : '1.0.0',
      resolved: `https://registry.npmjs.org/${name}/-/fixture.tgz`, integrity: `sha512-${'a'.repeat(86)}==` };
  }
  packages['node_modules/retained'].dependencies = { 'shared-child': '1.0.0' };
  packages['node_modules/@elevenid/marty-blog'].dependencies = { 'shared-child': '1.0.0', 'website-child': '1.0.0' };
  const lock = { name: manifest.name, version: manifest.version, lockfileVersion: 3, requires: true, packages };
  const profile = structuredClone(manifest);
  const profileLock = structuredClone(lock);
  for (const name of APPLICATION_REMOVED_DEPENDENCY_ROOTS) {
    for (const field of ['dependencies', 'devDependencies']) {
      delete profile[field][name];
      delete profileLock.packages[''][field][name];
    }
    delete profileLock.packages[`node_modules/${name}`];
  }
  delete profileLock.packages['node_modules/website-child'];
  profile.scripts = { ...APPLICATION_PROFILE_SCRIPTS };
  write(root, ROOT_MANIFEST, manifest); write(root, ROOT_LOCK, lock);
  write(root, PROFILE_MANIFEST, profile); write(root, PROFILE_LOCK, profileLock);
  return root;
}

test('profile preserves retained package identities and records exact substitutions without changing inputs', (t) => {
  const root = fixture(t);
  const before = [ROOT_MANIFEST, ROOT_LOCK, PROFILE_MANIFEST, PROFILE_LOCK].map((name) => readFileSync(path.join(root, name)));
  const result = validateApplicationDependencyProfile({ repositoryRoot: root });
  assert.equal(result.name, 'application');
  assert.deepEqual(result.scripts, APPLICATION_PROFILE_SCRIPTS);
  assert.equal(result.lock_graph.baseline_packages, 7);
  assert.equal(result.lock_graph.application_packages, 2);
  assert.equal(result.lock_graph.removed_package_paths.length, 5);
  assert.deepEqual(result.lock_graph.retained_identity_changes, []);
  assert.equal(result.bun_lock_selected, false);
  assert.equal(result.package_graph_minimized, false);
  for (const [index, entry] of result.substitutions.entries()) {
    assert.equal(entry.path, [ROOT_MANIFEST, ROOT_LOCK][index]);
    const bytes = readFileSync(path.join(root, entry.selected.path));
    assert.equal(entry.selected.bytes, bytes.length);
    assert.equal(entry.selected.sha256, `sha256:${createHash('sha256').update(bytes).digest('hex')}`);
  }
  assert.deepEqual([ROOT_MANIFEST, ROOT_LOCK, PROFILE_MANIFEST, PROFILE_LOCK].map((name) => readFileSync(path.join(root, name))), before);
});

test('normal root script changes do not change the exact selected application script map', (t) => {
  const root = fixture(t);
  mutate(root, ROOT_MANIFEST, (value) => { value.scripts.test = 'new-full-repository-test-list'; });
  assert.deepEqual(validateApplicationDependencyProfile({ repositoryRoot: root }).scripts, APPLICATION_PROFILE_SCRIPTS);
});

for (const [label, action] of [
  ['a restored website dependency', (value) => { value.dependencies['@elevenid/marty-blog'] = '1.0.0'; }],
  ['a combined prebuild hook', (value) => { value.scripts.prebuild = 'generate-website-manifests'; }],
  ['the combined default build', (value) => { value.scripts.build = 'combined-build'; }],
  ['the full prerender postinstall', (value) => { value.scripts.postinstall = 'both-reviewed-patches'; }],
  ['an unreviewed package metadata change', (value) => { value.private = false; }],
]) test(`rejects ${label}`, (t) => {
  const root = fixture(t); mutate(root, PROFILE_MANIFEST, action);
  assert.throws(() => validateApplicationDependencyProfile({ repositoryRoot: root }), /manifest drifted/);
});

test('root dependency changes require the application profile to be refreshed', (t) => {
  const root = fixture(t);
  mutate(root, ROOT_MANIFEST, (value) => { value.dependencies.retained = '3.0.0'; });
  mutate(root, ROOT_LOCK, (value) => { value.packages[''].dependencies.retained = '3.0.0'; });
  assert.throws(() => validateApplicationDependencyProfile({ repositoryRoot: root }), /manifest drifted/);
});

for (const field of ['version', 'resolved', 'integrity', 'dev']) test(`rejects retained lock ${field} drift`, (t) => {
  const root = fixture(t);
  mutate(root, PROFILE_LOCK, (value) => { value.packages['node_modules/retained'][field] = 'changed'; });
  assert.throws(() => validateApplicationDependencyProfile({ repositoryRoot: root }), /changed a retained package/);
});

test('rejects an added lock package', (t) => {
  const root = fixture(t);
  mutate(root, PROFILE_LOCK, (value) => { value.packages['node_modules/extra'] = { version: '1.0.0' }; });
  assert.throws(() => validateApplicationDependencyProfile({ repositoryRoot: root }), /added an unreviewed package/);
});

test('rejects a missing retained dependency even when it is not a direct root', (t) => {
  const root = fixture(t);
  mutate(root, PROFILE_LOCK, (value) => { delete value.packages['node_modules/shared-child']; });
  assert.throws(() => validateApplicationDependencyProfile({ repositoryRoot: root }), /omitted a retained dependency/);
});

for (const optional of [false, true]) test(`${optional ? 'allows' : 'rejects'} removal of an ${optional ? 'optional' : 'already locked required'} peer`, (t) => {
  const root = fixture(t);
  for (const name of [ROOT_LOCK, PROFILE_LOCK]) mutate(root, name, (value) => {
    const row = value.packages['node_modules/retained'];
    delete row.dependencies;
    row.peerDependencies = { 'shared-child': '1.0.0' };
    if (optional) row.peerDependenciesMeta = { 'shared-child': { optional: true } };
  });
  mutate(root, PROFILE_LOCK, (value) => { delete value.packages['node_modules/shared-child']; });
  if (optional) assert.equal(validateApplicationDependencyProfile({ repositoryRoot: root }).lock_graph.application_packages, 1);
  else assert.throws(() => validateApplicationDependencyProfile({ repositoryRoot: root }), /omitted a retained dependency/);
});

test('rejects a removed dependency hidden under a nested lock path', (t) => {
  const root = fixture(t);
  for (const name of [ROOT_LOCK, PROFILE_LOCK]) mutate(root, name, (value) => {
    value.packages['node_modules/retained/node_modules/@prerenderer/rollup-plugin'] = { version: '1.0.0' };
  });
  assert.throws(() => validateApplicationDependencyProfile({ repositoryRoot: root }), /retained a removed/);
});

test('rejects a removed dependency identity hidden under an alias package path', (t) => {
  const root = fixture(t);
  for (const name of [ROOT_LOCK, PROFILE_LOCK]) mutate(root, name, (value) => {
    value.packages['node_modules/retained'].name = '@elevenid/marty-blog';
  });
  assert.throws(() => validateApplicationDependencyProfile({ repositoryRoot: root }), /retained a removed/);
});

for (const alias of ['npm:@elevenid/marty-blog@1.0.0', 'npm:vite-plugin-sitemap@1.0.0']) {
  test(`rejects the removed dependency selector ${alias}`, (t) => {
    const root = fixture(t);
    for (const name of [ROOT_MANIFEST, PROFILE_MANIFEST]) mutate(root, name, (value) => { value.dependencies.retained = alias; });
    for (const name of [ROOT_LOCK, PROFILE_LOCK]) mutate(root, name, (value) => { value.packages[''].dependencies.retained = alias; });
    assert.throws(() => validateApplicationDependencyProfile({ repositoryRoot: root }), /aliases a removed/);
  });
}

test('rejects duplicate JSON keys before applying dependency selection', (t) => {
  const root = fixture(t);
  const filename = path.join(root, ROOT_MANIFEST);
  writeFileSync(filename, readFileSync(filename, 'utf8').replace('"private": true,', '"private": false, "private": true,'));
  assert.throws(() => validateApplicationDependencyProfile({ repositoryRoot: root }), /Duplicate dependency JSON key/);
});

test('rejects a symlinked selected manifest', (t) => {
  const root = fixture(t);
  rmSync(path.join(root, PROFILE_MANIFEST));
  symlinkSync(path.join(root, ROOT_MANIFEST), path.join(root, PROFILE_MANIFEST));
  assert.throws(() => validateApplicationDependencyProfile({ repositoryRoot: root }), /must be a regular file/);
});
