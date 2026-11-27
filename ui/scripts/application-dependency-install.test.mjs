import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { setTimeout as delay } from 'node:timers/promises';
import {
  APPLICATION_INSTALL_INPUTS, installApplicationDependencies,
  inspectInstalledApplicationDependencies, isWithinDependencyDirectory, runOwnedInstallCommand,
} from './application-dependency-install.mjs';
import { APPLICATION_PROFILE_POSTINSTALL, APPLICATION_REMOVED_DEPENDENCY_ROOTS } from './application-dependency-profile.mjs';

const sha = (value) => createHash('sha256').update(value).digest('hex');
const sdkName = '@elevenid/marty-api-core';
const postinstall = 'node scripts/patch-prerenderer-ts-deepmerge.cjs && node scripts/patch-checker-worker-cleanup.mjs';

for (const [label, paths, root] of [
  ['POSIX', path.posix, '/workspace/ui/node_modules'],
  ['Windows', path.win32, 'C:\\workspace\\ui\\node_modules'],
]) {
  test(`${label} dependency containment accepts packages and rejects directory escapes`, () => {
    for (const child of ['package', '@scope/package', 'package/node_modules/nested']) {
      assert.equal(isWithinDependencyDirectory(root, paths.join(root, child), paths), true, child);
    }
    for (const location of [
      root,
      paths.dirname(root),
      `${root}-other/package`,
      paths.join(root, '../../outside'),
    ]) {
      assert.equal(isWithinDependencyDirectory(root, location, paths), false, location);
    }
  });
}

test('Windows dependency containment handles casing, separators, drives, and UNC shares', () => {
  const root = 'C:\\workspace\\ui\\node_modules';
  for (const location of [
    'c:\\WORKSPACE\\ui\\node_modules\\package',
    'C:/workspace/ui/node_modules/@scope/package',
  ]) {
    assert.equal(isWithinDependencyDirectory(root, location, path.win32), true, location);
  }
  for (const location of [
    'D:\\workspace\\ui\\node_modules\\package',
    '\\\\server\\share\\ui\\node_modules\\package',
  ]) {
    assert.equal(isWithinDependencyDirectory(root, location, path.win32), false, location);
  }
  const unc = '\\\\server\\share\\ui\\node_modules';
  assert.equal(isWithinDependencyDirectory(unc, `${unc}\\package`, path.win32), true);
  assert.equal(isWithinDependencyDirectory(unc,
    '\\\\server\\other\\ui\\node_modules\\package', path.win32), false);
});

function put(root, relative, content) {
  const filename = path.join(root, relative);
  mkdirSync(path.dirname(filename), { recursive: true });
  writeFileSync(filename, content);
}

function fixture(t, { skipPrerender = false, skipChecker = false, mutateLock = false, failScript = false,
  applicationProfile = false, mutateSelectedProfile = false } = {}) {
  const temporaryRoot = mkdtempSync(path.join(os.tmpdir(), 'marty-application-install-'));
  t.after(() => rmSync(temporaryRoot, { recursive: true, force: true }));
  const uiRoot = path.join(temporaryRoot, 'source/ui');
  mkdirSync(uiRoot, { recursive: true });
  const packages = {};
  const dependencies = {};
  function pack(name, version, files, extra = {}) {
    const label = name.split('/').at(-1);
    const directory = path.join(temporaryRoot, 'packages', label);
    const manifest = { name, version, ...extra };
    put(directory, 'package/package.json', JSON.stringify(manifest));
    for (const [relative, content] of Object.entries(files)) put(directory, `package/${relative}`, content);
    const relative = `vendor/${label}.tgz`;
    mkdirSync(path.join(uiRoot, 'vendor'), { recursive: true });
    execFileSync('tar', ['-czf', path.join(uiRoot, relative), '-C', directory, 'package']);
    const integrity = `sha512-${createHash('sha512').update(readFileSync(path.join(uiRoot, relative))).digest('base64')}`;
    dependencies[name] = `file:${relative}`;
    packages[`node_modules/${name}`] = { version, resolved: `file:${relative}`, integrity };
  }
  pack(sdkName, '0.3.6', {
    'src/index.js': `import { readFileSync } from 'node:fs';
await WebAssembly.compile(readFileSync(new URL('./wasm/marty_api_client_bg.wasm', import.meta.url)));
export const createApiClient = () => ({ get() { throw new Error('No API calls in install verification'); } });\n`,
    'src/wasm/marty_api_client_bg.wasm': Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]),
  }, { type: 'module', exports: './src/index.js' });
  if (!applicationProfile) pack('@prerenderer/prerenderer', '1.2.5', { 'index.js': 'module.exports = ts_deepmerge_1.default;\n' });
  const checkerBefore = '// unpatched checker\n';
  const checkerAfter = '// reviewed patched checker\n';
  pack('vite-plugin-checker', '0.14.5', { 'dist/main.js': checkerBefore }, { type: 'module' });
  const manifest = { name: 'application-install-fixture', version: '1.0.0', private: true,
    type: 'module', scripts: { postinstall: applicationProfile ? APPLICATION_PROFILE_POSTINSTALL : postinstall }, dependencies, devDependencies: {} };
  put(uiRoot, 'package.json', JSON.stringify(manifest));
  put(uiRoot, 'package-lock.json', JSON.stringify({ name: manifest.name, version: manifest.version,
    lockfileVersion: 3, requires: true, packages: {
      '': { name: manifest.name, version: manifest.version, hasInstallScript: true, dependencies, devDependencies: {} }, ...packages,
    } }));
  if (applicationProfile) {
    for (const name of ['package.json', 'package-lock.json']) {
      put(uiRoot, `profiles/application/${name}`, readFileSync(path.join(uiRoot, name)));
    }
  }
  put(uiRoot, 'bun.lock', 'The unchanged Bun lock is recorded, not used by this npm fixture.\n');
  put(uiRoot, 'scripts/checker-worker-cleanup.mjs', '// reviewed helper fixture\n');
  put(uiRoot, 'scripts/patch-prerenderer-ts-deepmerge.cjs', `
const assert = require('node:assert/strict');
const fs = require('node:fs');
assert.equal(process.env.PUPPETEER_SKIP_DOWNLOAD, 'true');
assert.equal(process.env.NODE_OPTIONS, undefined);
assert.equal(process.env.NODE_PATH, undefined);
assert.notEqual(process.env.NODE_ENV, 'production');
assert.notEqual(process.env.npm_config_ignore_scripts, 'true');
${failScript ? 'process.exit(9);' : ''}
${applicationProfile ? "throw new Error('Application installation must not execute the prerender patch');" : ''}
${skipPrerender ? '' : `const filename = 'node_modules/@prerenderer/prerenderer/index.js';
fs.writeFileSync(filename, fs.readFileSync(filename, 'utf8').replaceAll('ts_deepmerge_1.default', '(ts_deepmerge_1.default || ts_deepmerge_1.merge)'));`}
${mutateLock ? "fs.appendFileSync('package-lock.json', '\\n');" : ''}
`);
  put(uiRoot, 'scripts/patch-checker-worker-cleanup.mjs', `
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
export const checkerVersion = '0.14.5';
export const cleanupFilename = 'marty-checker-cleanup.js';
export const patches = [{file: 'dist/main.js', before: '${sha(checkerBefore)}', after: '${sha(checkerAfter)}'}];
if (path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
${applicationProfile && failScript ? 'process.exit(9);' : ''}
${mutateSelectedProfile ? "fs.appendFileSync('profiles/application/package-lock.json', '\\n');" : ''}
${skipChecker ? '' : `fs.writeFileSync('node_modules/vite-plugin-checker/dist/main.js', ${JSON.stringify(checkerAfter)});
fs.copyFileSync('scripts/checker-worker-cleanup.mjs', 'node_modules/vite-plugin-checker/dist/marty-checker-cleanup.js');`}
}
`);
  return { uiRoot, temporaryRoot };
}

test('real npm ci installs only into a fresh export, runs both patches, and initializes its own SDK WASM', (t) => {
  const input = fixture(t);
  const original = APPLICATION_INSTALL_INPUTS.map((name) => readFileSync(path.join(input.uiRoot, name)));
  const inherited = { NODE_ENV: 'production', NODE_OPTIONS: '--require /missing-node-injection.cjs',
    NODE_PATH: '/missing-borrowed-modules', npm_config_ignore_scripts: 'true',
    npm_config_registry: 'https://example.invalid', NPM_CONFIG_USERCONFIG: '/missing-user-config' };
  const previous = Object.fromEntries(Object.keys(inherited).map((name) => [name, process.env[name]]));
  let report;
  try {
    Object.assign(process.env, inherited);
    report = installApplicationDependencies(input);
  } finally {
    for (const [name, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
  assert.equal(report.status, 'passed');
  assert.equal(report.mode, 'fresh-npm-ci');
  assert.equal(report.independent_dependency_installation, true);
  assert.equal(report.package_graph_minimized, false);
  assert.equal(report.browser_download_skipped, true);
  assert.equal(report.graph.package_count, 3);
  assert.equal(report.postinstall.verified, true);
  assert.equal(report.postinstall.prerender_files.length, 1);
  assert.equal(report.postinstall.checker_files.length, 2);
  assert.equal(report.sdk.version, '0.3.6');
  assert.equal(report.sdk.initialized_in_node, true);
  assert.equal(report.sdk.browser_execution_observed, false);
  assert.equal(report.sdk.wasm.bytes, 8);
  assert.deepEqual(APPLICATION_INSTALL_INPUTS.map((name) => readFileSync(path.join(input.uiRoot, name))), original);
  assert.ok(report.command.includes('--ignore-scripts=false'));
  assert.ok(report.command.includes('--include=dev'));
});

test('the explicit application profile runs checker only, binds materialized inputs, and installs none of the four removed roots', (t) => {
  const input = fixture(t, { applicationProfile: true });
  const report = installApplicationDependencies({ ...input, dependencyProfile: 'application' });
  assert.equal(report.status, 'passed');
  assert.equal(report.dependency_profile, 'application');
  assert.equal(report.bun_lock_selected, false);
  assert.equal(report.postinstall.command, APPLICATION_PROFILE_POSTINSTALL);
  assert.equal(report.postinstall.prerender_selected, false);
  assert.deepEqual(report.postinstall.prerender_files, []);
  assert.equal(report.postinstall.checker_files.length, 2);
  assert.equal(report.graph.package_count, 2);
  assert.deepEqual(report.removed_website_dependencies, { roots: [...APPLICATION_REMOVED_DEPENDENCY_ROOTS],
    absent_from_manifest: true, absent_from_lock: true, absent_from_installed_graph: true, absent_from_installed_packages: true });
  assert.equal(report.source_inputs.length, APPLICATION_INSTALL_INPUTS.length + 2);
  assert.equal(report.package_graph_minimized, false);
});

test('an application materialization cannot differ from the selected profile bytes or reselect the full postinstall', (t) => {
  const input = fixture(t, { applicationProfile: true });
  const original = readFileSync(path.join(input.uiRoot, 'package.json'));
  put(input.uiRoot, 'package.json', `${original.toString()}\n`);
  assert.throws(() => installApplicationDependencies({ ...input, dependencyProfile: 'application' }), /differs from the selected profile/);
  put(input.uiRoot, 'package.json', original);
  const manifest = JSON.parse(original);
  manifest.scripts.postinstall = postinstall;
  for (const name of ['package.json', 'profiles/application/package.json']) put(input.uiRoot, name, JSON.stringify(manifest));
  assert.throws(() => installApplicationDependencies({ ...input, dependencyProfile: 'application' }), /only the reviewed checker patch/);
  assert.equal(existsSync(path.join(input.uiRoot, 'node_modules')), false);
});

for (const [label, options, refusal] of [
  ['checker patch was not applied', { skipChecker: true }, /postinstall or SDK verification failed/],
  ['selected profile was rewritten', { mutateSelectedProfile: true }, /changed a reviewed manifest, lock or postinstall source/],
]) {
  test(`an application install refuses when its ${label}`, (t) => {
    const input = fixture(t, { applicationProfile: true, ...options });
    assert.throws(() => installApplicationDependencies({ ...input, dependencyProfile: 'application' }), refusal);
  });
}

test('a removed website package cannot be nested in the profile lock or restored outside npm installed records', async (t) => {
  const input = fixture(t, { applicationProfile: true });
  const lock = JSON.parse(readFileSync(path.join(input.uiRoot, 'package-lock.json')));
  const removed = `node_modules/vite-plugin-checker/node_modules/${APPLICATION_REMOVED_DEPENDENCY_ROOTS[0]}`;
  lock.packages[removed] = { version: '1.0.0', resolved: 'https://example.invalid/removed.tgz', integrity: 'sha512-YQ==' };
  for (const name of ['package-lock.json', 'profiles/application/package-lock.json']) put(input.uiRoot, name, JSON.stringify(lock));
  assert.throws(() => installApplicationDependencies({ ...input, dependencyProfile: 'application' }), /retained a removed website dependency/);
  delete lock.packages[removed];
  for (const name of ['package-lock.json', 'profiles/application/package-lock.json']) put(input.uiRoot, name, JSON.stringify(lock));
  installApplicationDependencies({ ...input, dependencyProfile: 'application' });
  put(input.uiRoot, `${removed}/package.json`, '{"name":"unrecorded website package"}');
  await assert.rejects(inspectInstalledApplicationDependencies(input.uiRoot, { dependencyProfile: 'application' }),
    /removed website dependency exists outside the installed lock/);
});

test('removed website identities cannot hide under lock aliases or actual nested aliases', async (t) => {
  const input = fixture(t, { applicationProfile: true });
  const lock = JSON.parse(readFileSync(path.join(input.uiRoot, 'package-lock.json')));
  const alias = 'node_modules/vite-plugin-checker/node_modules/renamed-website-tool';
  lock.packages[alias] = { name: APPLICATION_REMOVED_DEPENDENCY_ROOTS[1], version: '1.0.0',
    resolved: 'https://example.invalid/alias.tgz', integrity: 'sha512-YQ==' };
  for (const name of ['package-lock.json', 'profiles/application/package-lock.json']) put(input.uiRoot, name, JSON.stringify(lock));
  assert.throws(() => installApplicationDependencies({ ...input, dependencyProfile: 'application' }), /retained a removed website dependency/);
  delete lock.packages[alias];
  for (const name of ['package-lock.json', 'profiles/application/package-lock.json']) put(input.uiRoot, name, JSON.stringify(lock));
  installApplicationDependencies({ ...input, dependencyProfile: 'application' });
  put(input.uiRoot, `${alias}/package.json`, JSON.stringify({ name: APPLICATION_REMOVED_DEPENDENCY_ROOTS[2] }));
  await assert.rejects(inspectInstalledApplicationDependencies(input.uiRoot, { dependencyProfile: 'application' }),
    /removed website dependency exists under an installed alias/);
  rmSync(path.join(input.uiRoot, alias), { recursive: true });
  const installedPath = path.join(input.uiRoot, 'node_modules/.package-lock.json');
  const installed = JSON.parse(readFileSync(installedPath));
  installed.packages['node_modules/vite-plugin-checker'].name = APPLICATION_REMOVED_DEPENDENCY_ROOTS[3];
  writeFileSync(installedPath, JSON.stringify(installed));
  await assert.rejects(inspectInstalledApplicationDependencies(input.uiRoot, { dependencyProfile: 'application' }),
    /removed website dependency is recorded under an installed alias/);
});

for (const [label, options, refusal] of [
  ['prerender patch', { skipPrerender: true }, /postinstall or SDK verification failed/],
  ['checker patch', { skipChecker: true }, /postinstall or SDK verification failed/],
  ['lock rewrite', { mutateLock: true }, /changed a reviewed manifest, lock or postinstall source/],
  ['failed lifecycle script', { failScript: true }, /Frozen npm installation failed/],
]) {
  test(`a successful or partial install cannot conceal ${label}`, (t) => {
    assert.throws(() => installApplicationDependencies(fixture(t, options)), refusal);
  });
}

test('a manifest/lock mismatch is refused before any dependency installation', (t) => {
  const input = fixture(t);
  const manifest = JSON.parse(readFileSync(path.join(input.uiRoot, 'package.json'), 'utf8'));
  manifest.dependencies.unreviewed = '1.0.0';
  put(input.uiRoot, 'package.json', JSON.stringify(manifest));
  assert.throws(() => installApplicationDependencies(input), /lock dependencies differ/);
  assert.equal(existsSync(path.join(input.uiRoot, 'node_modules')), false);
});

test('npm rejects changed locked tarball bytes without resolving a replacement graph', (t) => {
  const input = fixture(t);
  put(input.uiRoot, 'vendor/marty-api-core.tgz', 'changed artifact');
  const original = readFileSync(path.join(input.uiRoot, 'package-lock.json'));
  assert.throws(() => installApplicationDependencies(input), /Frozen npm installation failed/);
  assert.deepEqual(readFileSync(path.join(input.uiRoot, 'package-lock.json')), original);
});

test('an existing or symlinked node_modules directory cannot satisfy fresh installation', (t) => {
  const input = fixture(t);
  mkdirSync(path.join(input.uiRoot, 'node_modules'));
  assert.throws(() => installApplicationDependencies(input), /cannot borrow/);
  rmSync(path.join(input.uiRoot, 'node_modules'), { recursive: true });
  symlinkSync('/missing-dependency-target', path.join(input.uiRoot, 'node_modules'));
  assert.throws(() => installApplicationDependencies(input), /cannot borrow/);
});

for (const filename of ['.npmrc', '.npm-extension.mjs', '.npm-extension.cjs', 'npm-shrinkwrap.json']) {
  test(`unreviewed project configuration cannot override the fresh contract: ${filename}`, (t) => {
    const input = fixture(t);
    put(input.uiRoot, filename, 'unreviewed configuration');
    assert.throws(() => installApplicationDependencies(input), /Unreviewed project install configuration/);
    assert.equal(existsSync(path.join(input.uiRoot, 'node_modules')), false);
  });
}

test('post-install graph and SDK tampering are rejected against the committed lock', async (t) => {
  const input = fixture(t);
  installApplicationDependencies(input);
  const lockPath = path.join(input.uiRoot, 'node_modules/.package-lock.json');
  const original = readFileSync(lockPath);
  const installed = JSON.parse(original);
  installed.packages[`node_modules/${sdkName}`].integrity = 'sha512-different';
  writeFileSync(lockPath, JSON.stringify(installed));
  await assert.rejects(inspectInstalledApplicationDependencies(input.uiRoot), /differs from the committed lock/);
  writeFileSync(lockPath, original);
  put(input.uiRoot, `node_modules/${sdkName}/src/wasm/marty_api_client_bg.wasm`, 'invalid wasm');
  await assert.rejects(inspectInstalledApplicationDependencies(input.uiRoot), /SDK WASM is invalid/);
});

test('the owned command deadline kills a lifecycle descendant and cannot wait on its inherited stdout', async (t) => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'marty-install-descendant-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const heartbeat = path.join(directory, 'heartbeat');
  const childPid = path.join(directory, 'child.pid');
  const childCode = `const fs=require('node:fs'); process.on('SIGTERM',()=>{});
fs.writeFileSync(${JSON.stringify(childPid)}, String(process.pid));
setInterval(()=>fs.appendFileSync(${JSON.stringify(heartbeat)},'x'),10);`;
  const parentCode = `require('node:child_process').spawn(process.execPath,['-e',${JSON.stringify(childCode)}],{stdio:'inherit'});
process.on('SIGTERM',()=>{}); setInterval(()=>{},1000);`;
  t.after(() => {
    if (existsSync(childPid)) try { process.kill(Number(readFileSync(childPid, 'utf8')), 'SIGKILL'); } catch (error) {
      if (error.code !== 'ESRCH') throw error;
    }
  });
  const started = performance.now();
  const result = runOwnedInstallCommand(process.execPath, ['-e', parentCode], {
    cwd: directory, env: { PATH: process.env.PATH }, timeout: 500,
    stdoutFile: path.join(directory, 'stdout'),
  });
  assert.equal(result.error?.code, 'ETIMEDOUT');
  assert.ok(performance.now() - started < 4000, 'An ignored SIGTERM must not extend the deadline');
  const stopped = readFileSync(heartbeat);
  assert.ok(stopped.length > 0, 'The actual descendant must have run before the deadline');
  await delay(100);
  assert.deepEqual(readFileSync(heartbeat), stopped, 'The lifecycle descendant must stop after its owner exits');
});
