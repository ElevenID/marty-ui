import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const SELF = fileURLToPath(import.meta.url);
const MAX_INPUT_BYTES = 16 * 1024 * 1024;
export const APPLICATION_REMOVED_DEPENDENCY_ROOTS = Object.freeze([
  '@elevenid/marty-blog', '@prerenderer/rollup-plugin',
  '@prerenderer/renderer-puppeteer', 'vite-plugin-sitemap',
]);
export const APPLICATION_PROFILE_POSTINSTALL = 'node scripts/patch-checker-worker-cleanup.mjs';
export const APPLICATION_BUN_PACKAGE_MANAGER = Object.freeze({ name: 'bun', version: '1.4.4', lock_file: 'bun.lock' });
export const APPLICATION_TRUSTED_DEPENDENCIES = Object.freeze(['esbuild', 'fsevents', 'puppeteer']);
export const APPLICATION_DEPENDENCY_PROFILE_INPUTS = Object.freeze([
  'ui/profiles/application/package.json', 'ui/profiles/application/package-lock.json',
]);
export function applicationDependencyProfileInputs(packageManager) {
  return [...APPLICATION_DEPENDENCY_PROFILE_INPUTS,
    ...(packageManager === 'bun' ? ['ui/profiles/application/bun.lock'] : [])];
}
export function applicationPackageManager(manifest, selected) {
  require(manifest.packageManager === undefined || manifest.packageManager === 'bun@1.4.4',
    'Unreviewed application packageManager pin; migration must be explicit');
  const manager = selected ?? (manifest.packageManager === 'bun@1.4.4' ? 'bun' : 'npm');
  require(['bun', 'npm'].includes(manager), 'Unsupported application package manager');
  if (manager === 'bun') {
    require(manifest.packageManager === 'bun@1.4.4', 'Bun installation requires the reviewed bun@1.4.4 packageManager pin');
    assert.deepEqual(manifest.trustedDependencies, APPLICATION_TRUSTED_DEPENDENCIES,
      'Bun installation requires the reviewed dependency lifecycle allowlist');
  }
  return manager;
}

// Bun's committed text lock is JSON with trailing commas. Remove those only
// outside strings, then reuse the bounded duplicate-key JSON parser. No source
// evaluation, comment execution, or dependency-provided parser is involved.
export function parseApplicationBunLock(bytes) {
  const source = bytes.toString('utf8');
  require(Buffer.from(source).equals(bytes) && bytes.length <= MAX_INPUT_BYTES, 'Bun lock must be bounded UTF-8');
  let text = ''; let quoted = false; let escaped = false;
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    if (quoted) {
      text += char;
      if (escaped) escaped = false;
      else if (char === '\\') escaped = true;
      else if (char === '"') quoted = false;
    } else if (char === '"') { quoted = true; text += char; }
    else if (char !== ',' || !/^\s*[}\]]/.test(source.slice(index + 1))) text += char;
  }
  return document(Buffer.from(text));
}

function packageName(relative) { return relative.split('node_modules/').at(-1); }
function bunSelector(row) {
  require(Array.isArray(row) && [3, 4].includes(row.length) && typeof row[0] === 'string', 'Invalid Bun package record');
  const boundary = row[0].indexOf('@', row[0].startsWith('@') ? 1 : 0);
  require(boundary > 0, 'Invalid Bun package selector');
  const name = row[0].slice(0, boundary); const selector = row[0].slice(boundary + 1);
  const metadata = object(row.at(-2), 'Bun package metadata');
  const integrity = row.at(-1);
  require(/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(integrity), 'Bun package requires locked SHA-512 integrity');
  if (row.length === 4) require(row[1] === '', 'Unreviewed Bun registry override');
  return { name, selector, metadata, integrity };
}

export function validateApplicationBunLock(manifest, npmLock, lock) {
  require(lock.lockfileVersion === 2 && lock.configVersion === 0, 'Expected the reviewed Bun text lock format and hoisted configuration');
  assert.deepEqual(Object.keys(lock).sort(), ['configVersion', 'lockfileVersion', ...(lock.overrides ? ['overrides'] : []), 'packages', 'trustedDependencies', 'workspaces']);
  assert.deepEqual(lock.workspaces, { '': { name: manifest.name,
    ...Object.fromEntries(['dependencies', 'devDependencies'].filter((field) => Object.keys(manifest[field] || {}).length)
      .map((field) => [field, manifest[field]])) } },
    'Bun lock root differs from the selected manifest');
  assert.deepEqual(lock.overrides || {}, manifest.overrides || {}, 'Bun lock overrides differ from the manifest');
  assert.deepEqual(lock.trustedDependencies, APPLICATION_TRUSTED_DEPENDENCIES, 'Bun lock lifecycle policy differs');
  const references = Object.entries(npmLock.packages).filter(([relative]) => relative).map(([relative, row]) => ({
    name: row.name || packageName(relative), ...row,
  }));
  const covered = new Set();
  const records = [];
  for (const [location, row] of Object.entries(object(lock.packages, 'Bun packages'))) {
    require(location && !/[\\\x00-\x1f\x7f]/.test(location)
      && location.split('/').every((part) => part && part !== '.' && part !== '..'), 'Unsafe Bun package location');
    const parsed = bunSelector(row);
    const roots = { ...manifest.dependencies, ...manifest.devDependencies };
    const physical = `node_modules/${location.match(/@[^/]+\/[^/]+|[^/]+/g).join('/node_modules/')}`;
    const lockedLocation = npmLock.packages[physical];
    const locationName = (lockedLocation?.name || packageName(physical));
    require(locationName === parsed.name, `Bun lock redirected a dependency name: ${location}`);
    if (Object.hasOwn(roots, location)) require(lockedLocation && lockedLocation.integrity === parsed.integrity
      && (row.length === 4 ? lockedLocation.version === parsed.selector : (lockedLocation.resolved === parsed.selector
        || (lockedLocation.resolved?.startsWith('file:') && lockedLocation.resolved.slice(5) === parsed.selector))),
    `Bun lock redirected a declared dependency: ${location}`);
    const matches = references.filter((reference) => reference.name === parsed.name && reference.integrity === parsed.integrity
      && (row.length === 4 ? reference.version === parsed.selector : (reference.resolved === parsed.selector
        || (reference.resolved?.startsWith('file:') && reference.resolved.slice(5) === parsed.selector))));
    require(matches.length > 0, `Bun lock changed a retained dependency identity: ${location}`);
    // Migration may collapse duplicate physical npm records but may not change
    // dependency edges, platform selection, executable mappings or lifecycle flags.
    require(matches.some((reference) => {
      const metadata = Object.fromEntries(['dependencies', 'optionalDependencies', 'peerDependencies', 'bin', 'os', 'cpu', 'hasInstallScript']
        .filter((field) => reference[field] !== undefined).map((field) => [field, reference[field]]));
      for (const field of ['os', 'cpu']) if (metadata[field]?.length === 1) metadata[field] = metadata[field][0];
      // These unsupported-platform sentinels are emitted by the pinned 1.4.4
      // npm migration. They preserve the existing Bun lock's platform policy.
      if (['loong64', 'mips64el', 'riscv64', 'wasm32'].includes(metadata.cpu)) metadata.cpu = 'none';
      if (['netbsd', 'openharmony'].includes(metadata.os)) metadata.os = 'none';
      if (metadata.peerDependencies) {
        metadata.peerDependencies = Object.fromEntries(Object.entries(metadata.peerDependencies)
          .filter(([name]) => !Object.hasOwn(metadata.dependencies || {}, name)));
        if (!Object.keys(metadata.peerDependencies).length) delete metadata.peerDependencies;
      }
      if (!reference.name.startsWith('@') && metadata.bin && typeof metadata.bin === 'object' && Object.keys(metadata.bin).length === 1
        && Object.hasOwn(metadata.bin, reference.name.split('/').at(-1))) metadata.bin = metadata.bin[reference.name.split('/').at(-1)];
      const optional = Object.keys(reference.peerDependenciesMeta || {}).filter((name) => reference.peerDependenciesMeta[name].optional && Object.hasOwn(metadata.peerDependencies || {}, name)).sort();
      if (optional.length) metadata.optionalPeers = optional;
      const actual = { ...parsed.metadata, ...(parsed.metadata.optionalPeers ? { optionalPeers: [...parsed.metadata.optionalPeers].sort() } : {}) };
      try { assert.deepEqual(actual, metadata); return true; } catch { return false; }
    }), `Bun lock changed retained dependency metadata: ${location}`);
    for (const reference of matches) covered.add(JSON.stringify([reference.name, reference.version, reference.resolved, reference.integrity]));
    records.push({ location, name: parsed.name, version: matches[0].version, resolved: matches[0].resolved, integrity: parsed.integrity });
  }
  require(references.every((reference) => covered.has(JSON.stringify([reference.name, reference.version, reference.resolved, reference.integrity]))),
    'Bun lock omitted a retained dependency identity');
  for (const name of Object.keys({ ...manifest.dependencies, ...manifest.devDependencies })) require(lock.packages[name], `Bun lock omitted declared root ${name}`);
  return records;
}
export const APPLICATION_PROFILE_SCRIPTS = Object.freeze({
  build: 'node scripts/build-web-surface.mjs application',
  'build:application': 'node scripts/build-web-surface.mjs application',
  test: 'vitest run --config vitest.application.config.ts',
  'test:application': 'vitest run --config vitest.application.config.ts',
  postinstall: APPLICATION_PROFILE_POSTINSTALL,
});

function require(condition, message) {
  if (!condition) throw new Error(message);
}

function input(root, relative) {
  let parent = root;
  for (const part of relative.split('/').slice(0, -1)) {
    parent = path.join(parent, part);
    const metadata = lstatSync(parent);
    require(metadata.isDirectory() && !metadata.isSymbolicLink(), 'Dependency profile input has a nonordinary parent');
  }
  const filename = path.join(root, relative);
  const metadata = lstatSync(filename);
  require(metadata.isFile() && !metadata.isSymbolicLink(), 'Dependency profile input must be a regular file');
  const descriptor = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const opened = fstatSync(descriptor);
    require(opened.isFile() && opened.size <= MAX_INPUT_BYTES, 'Dependency profile input exceeds its bound');
    const bytes = readFileSync(descriptor);
    require(bytes.length === opened.size, 'Dependency profile input changed during reading');
    return { bytes, record: { path: relative, bytes: bytes.length,
      sha256: `sha256:${createHash('sha256').update(bytes).digest('hex')}`, mode: opened.mode & 0o777 } };
  } finally { closeSync(descriptor); }
}

// JSON.parse validates the grammar; this second traversal rejects repeated keys
// before any manifest or lock interpretation can hide an earlier value.
function document(bytes) {
  const text = bytes.toString('utf8');
  const parsed = JSON.parse(text);
  let index = 0;
  const whitespace = () => { while (/\s/.test(text[index] || '') && index < text.length) index += 1; };
  const string = () => {
    const start = index++;
    while (index < text.length) {
      if (text[index++] === '"') return JSON.parse(text.slice(start, index));
      if (text[index - 1] === '\\') index += 1;
    }
    throw new Error('Incomplete dependency JSON string');
  };
  function value(depth = 0) {
    require(depth <= 128, 'Dependency JSON nesting exceeds its bound');
    whitespace();
    if (text[index] === '{') {
      index += 1;
      whitespace();
      const keys = new Set();
      while (text[index] !== '}') {
        const key = string();
        require(!keys.has(key), `Duplicate dependency JSON key: ${key}`);
        keys.add(key);
        whitespace();
        index += 1;
        value(depth + 1);
        whitespace();
        if (text[index] === ',') { index += 1; whitespace(); }
      }
      index += 1;
    } else if (text[index] === '[') {
      index += 1;
      whitespace();
      while (text[index] !== ']') {
        value(depth + 1);
        whitespace();
        if (text[index] === ',') { index += 1; whitespace(); }
      }
      index += 1;
    } else if (text[index] === '"') string();
    else { while (index < text.length && !/[\s,}\]]/.test(text[index])) index += 1; }
  }
  value();
  require(parsed && typeof parsed === 'object' && !Array.isArray(parsed), 'Expected a dependency JSON object');
  return parsed;
}

function object(value, label) {
  require(value && typeof value === 'object' && !Array.isArray(value), `Expected ${label} object`);
  return value;
}

function removedPath(relative) {
  return APPLICATION_REMOVED_DEPENDENCY_ROOTS.some((name) => relative === `node_modules/${name}`
    || relative.endsWith(`/node_modules/${name}`));
}

function removedAlias(value) {
  if (typeof value !== 'string' || !value.startsWith('npm:')) return false;
  const target = value.slice(4);
  const separator = target.indexOf('@', target.startsWith('@') ? 1 : 0);
  return APPLICATION_REMOVED_DEPENDENCY_ROOTS.includes(separator < 0 ? target : target.slice(0, separator));
}

function rejectRemovedSelectors(value) {
  if (value && typeof value === 'object') {
    for (const entry of Object.values(value)) rejectRemovedSelectors(entry);
  } else require(!removedAlias(value), 'The application profile aliases a removed website dependency');
}

function resolveLockedPackage(packages, location, name) {
  let current = location;
  while (true) {
    const candidate = `${current ? `${current}/` : ''}node_modules/${name}`;
    if (Object.hasOwn(packages, candidate)) return candidate;
    if (!current) return null;
    const boundary = current.lastIndexOf('/node_modules/');
    current = boundary < 0 ? '' : current.slice(0, boundary);
  }
}

export function validateApplicationDependencyProfile({ repositoryRoot = DEFAULT_ROOT, packageManager } = {}) {
  const root = path.resolve(repositoryRoot);
  require(realpathSync(root) === root && lstatSync(root).isDirectory(), 'Dependency profile root must have ordinary parents');
  const baseline = ['ui/package.json', 'ui/package-lock.json'].map((name) => input(root, name));
  const [manifest, lock] = baseline.map((entry) => document(entry.bytes));
  packageManager = applicationPackageManager(manifest, packageManager);
  const selected = applicationDependencyProfileInputs(packageManager).map((name) => input(root, name));
  const [application, applicationLock] = selected.slice(0, 2).map((entry) => document(entry.bytes));
  require(lock.lockfileVersion === 3 && applicationLock.lockfileVersion === 3, 'Dependency profiles require npm lock version 3');
  object(lock.packages, 'baseline lock packages');
  object(applicationLock.packages, 'application lock packages');
  object(lock.packages[''], 'baseline lock root');
  object(applicationLock.packages[''], 'application lock root');
  for (const field of ['dependencies', 'devDependencies']) {
    assert.deepEqual(lock.packages[''][field], object(manifest[field], `baseline ${field}`),
      `Baseline lock ${field} differ from its manifest`);
  }
  const expected = structuredClone(manifest);
  const expectedLockRoot = structuredClone(lock.packages['']);
  for (const name of APPLICATION_REMOVED_DEPENDENCY_ROOTS) {
    const declared = ['dependencies', 'devDependencies'].filter((field) => Object.hasOwn(expected[field], name));
    require(declared.length === 1, `Baseline must declare exactly one reviewed website dependency: ${name}`);
    delete expected[declared[0]][name];
    delete expectedLockRoot[declared[0]][name];
  }
  expected.scripts = { ...APPLICATION_PROFILE_SCRIPTS };
  assert.deepEqual(application, expected, 'Application manifest drifted from its reviewed dependency and script profile');
  assert.deepEqual(applicationLock.packages[''], expectedLockRoot, 'Application lock root drifted from its selected manifest');
  const { packages: _baselinePackages, ...baselineMetadata } = lock;
  const { packages: _applicationPackages, ...applicationMetadata } = applicationLock;
  assert.deepEqual(applicationMetadata, baselineMetadata, 'Application lock metadata differs from the baseline');
  rejectRemovedSelectors(application);
  const retained = Object.entries(applicationLock.packages).filter(([name]) => name);
  require(retained.length > 0, 'Application lock has no packages');
  for (const [name, row] of retained) {
    require(/^node_modules\//.test(name) && !/[\\\x00-\x1f\x7f]/.test(name)
      && name.split('/').every((part) => part && part !== '.' && part !== '..'), 'Application lock has an unsafe package path');
    object(row, 'application package');
    require(!row.link && !removedPath(name) && !APPLICATION_REMOVED_DEPENDENCY_ROOTS.includes(row.name),
      'Application lock retained a removed or linked website dependency');
    require(Object.hasOwn(lock.packages, name), `Application lock added an unreviewed package: ${name}`);
    assert.deepEqual(row, lock.packages[name], `Application lock changed a retained package: ${name}`);
    rejectRemovedSelectors(row);
    for (const field of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
      for (const dependency of Object.keys(row[field] || {})) {
        require(!APPLICATION_REMOVED_DEPENDENCY_ROOTS.includes(dependency),
          'Application lock still refers to a removed website dependency');
      }
    }
  }
  // Preserve every required dependency and every already-locked optional child
  // of retained packages. Optional peers may disappear when their sole owning
  // root is removed, as with rollup's optional visualizer/pluginutils peers.
  for (const [name, row] of Object.entries(applicationLock.packages)) {
    const fields = name ? ['dependencies', 'optionalDependencies', 'peerDependencies'] : ['dependencies', 'devDependencies'];
    for (const field of fields) {
      for (const dependency of Object.keys(row[field] || {})) {
        const before = resolveLockedPackage(lock.packages, name, dependency);
        if (field === 'peerDependencies' && (row.peerDependenciesMeta?.[dependency]?.optional || !before)) continue;
        if (field !== 'optionalDependencies' || before) {
          require(resolveLockedPackage(applicationLock.packages, name, dependency),
            `Application lock omitted a retained dependency: ${name || '<root>'} -> ${dependency}`);
        }
      }
    }
  }
  const removedPaths = Object.keys(lock.packages).filter((name) => name && !Object.hasOwn(applicationLock.packages, name)).sort();
  require(APPLICATION_REMOVED_DEPENDENCY_ROOTS.every((name) => removedPaths.includes(`node_modules/${name}`)),
    'Application lock did not remove every reviewed website root');
  let bunGraph;
  if (packageManager === 'bun') {
    baseline.push(input(root, 'ui/bun.lock'));
    const rootBun = parseApplicationBunLock(baseline[2].bytes);
    const selectedBun = parseApplicationBunLock(selected[2].bytes);
    validateApplicationBunLock(manifest, lock, rootBun);
    const retainedBun = validateApplicationBunLock(application, applicationLock, selectedBun);
    for (const [name, row] of Object.entries(selectedBun.packages)) {
      assert.deepEqual(row, rootBun.packages[name], `Application Bun lock changed a retained package: ${name}`);
      require(!APPLICATION_REMOVED_DEPENDENCY_ROOTS.includes(bunSelector(row).name), 'Application Bun lock retained a website dependency');
    }
    bunGraph = { baseline_packages: Object.keys(rootBun.packages).length, application_packages: retainedBun.length,
      retained_identity_changes: [], npm_reference_identities_preserved: true };
  }
  return {
    schema: `marty.application-dependency-profile/${packageManager === 'bun' ? 'v2' : 'v1'}`, name: 'application',
    ...(bunGraph ? { package_manager: { ...APPLICATION_BUN_PACKAGE_MANAGER }, bun_lock_graph: bunGraph } : {}),
    removed_roots: [...APPLICATION_REMOVED_DEPENDENCY_ROOTS],
    baseline_inputs: baseline.map((entry) => entry.record), source_inputs: selected.map((entry) => entry.record),
    substitutions: baseline.map((entry, index) => ({ path: entry.record.path,
      baseline: entry.record, selected: selected[index].record })),
    lock_graph: { baseline_packages: Object.keys(lock.packages).length - 1,
      application_packages: retained.length, removed_package_paths: removedPaths, retained_identity_changes: [] },
    scripts: { ...APPLICATION_PROFILE_SCRIPTS }, bun_lock_selected: packageManager === 'bun', package_graph_minimized: false,
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === SELF) {
  try {
    require(process.argv.length === 3 && process.argv[2] === '--check', 'Use --check to validate the committed application dependency profile');
    process.stdout.write(`${JSON.stringify(validateApplicationDependencyProfile(), null, 2)}\n`);
  } catch (error) {
    console.error(`Application dependency profile failed: ${error.message || error}`);
    process.exitCode = 1;
  }
}
