import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readdirSync,
  readSync, realpathSync, writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  applicationDependencyProfileInputs, applicationPackageManager, APPLICATION_REMOVED_DEPENDENCY_ROOTS,
  APPLICATION_PROFILE_POSTINSTALL, APPLICATION_BUN_PACKAGE_MANAGER, parseApplicationBunLock, validateApplicationBunLock,
} from './application-dependency-profile.mjs';

const SELF = fileURLToPath(import.meta.url);
const SDK = '@elevenid/marty-api-core';
const POSTINSTALL = 'node scripts/patch-prerenderer-ts-deepmerge.cjs && node scripts/patch-checker-worker-cleanup.mjs';
const MAX_FILE_BYTES = 64 * 1024 * 1024;
export const APPLICATION_INSTALL_INPUTS = Object.freeze([
  'package.json', 'package-lock.json', 'bun.lock',
  'scripts/patch-prerenderer-ts-deepmerge.cjs',
  'scripts/patch-checker-worker-cleanup.mjs', 'scripts/checker-worker-cleanup.mjs',
]);

// Package lifecycle scripts inherit this process group. Use files for captured
// output: an orphaned descendant must not keep a spawnSync pipe open after the
// parent deadline. Fresh installation is deliberately a Linux qualification.
export function runOwnedInstallCommand(command, args, { cwd, env, timeout, stdoutFile, stderrFile } = {}) {
  require(process.platform === 'linux', 'Fresh installation requires Linux process-group cleanup');
  let descriptor;
  let errorDescriptor;
  let child;
  try {
    if (stdoutFile) descriptor = openSync(stdoutFile,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    if (stderrFile) errorDescriptor = openSync(stderrFile,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    child = spawnSync(command, args, { cwd, env, timeout, killSignal: 'SIGKILL', detached: true,
      stdio: ['ignore', descriptor ?? 2, errorDescriptor ?? 2], shell: false });
    return child;
  } finally {
    try {
      if (Number.isInteger(child?.pid) && child.pid > 0) {
        try { process.kill(-child.pid, 'SIGKILL'); } catch (error) {
          if (error.code !== 'ESRCH') throw error;
        }
      }
    } finally {
      if (descriptor !== undefined) closeSync(descriptor);
      if (errorDescriptor !== undefined) closeSync(errorDescriptor);
    }
  }
}

function require(condition, message) {
  if (!condition) throw new Error(message);
}

function digest(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function ordinaryDirectory(directory) {
  const absolute = path.resolve(directory);
  const metadata = lstatSync(absolute);
  require(metadata.isDirectory() && !metadata.isSymbolicLink() && realpathSync(absolute) === absolute,
    'Fresh dependency directory must have ordinary parents');
  return absolute;
}

function absent(filename) {
  try { lstatSync(filename); } catch (error) {
    if (error.code === 'ENOENT') return true;
    throw error;
  }
  return false;
}

function input(root, relative) {
  require(typeof relative === 'string' && relative && !path.isAbsolute(relative)
    && !/[\\\x00-\x1f\x7f]/.test(relative)
    && relative.split('/').every((part) => part && part !== '.' && part !== '..'), 'Unsafe dependency input path');
  let filename = root;
  for (const part of relative.split('/').slice(0, -1)) {
    filename = path.join(filename, part);
    const metadata = lstatSync(filename);
    require(metadata.isDirectory() && !metadata.isSymbolicLink(), 'Dependency input has a nonordinary parent');
  }
  filename = path.join(root, relative);
  const metadata = lstatSync(filename);
  require(metadata.isFile() && !metadata.isSymbolicLink(), `Dependency input is not a regular file: ${relative}`);
  const descriptor = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const opened = fstatSync(descriptor);
    require(opened.isFile() && opened.size <= MAX_FILE_BYTES, 'Dependency input exceeds its file bound');
    const buffer = Buffer.alloc(opened.size + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = readSync(descriptor, buffer, length, buffer.length - length, null);
      if (count === 0) break;
      length += count;
    }
    require(length === opened.size, 'Dependency input changed while reading');
    const bytes = buffer.subarray(0, length);
    return { bytes, record: { path: relative, bytes: length, sha256: digest(bytes), mode: opened.mode & 0o777 } };
  } finally { closeSync(descriptor); }
}

function document(root, relative) {
  const result = JSON.parse(input(root, relative).bytes.toString('utf8'));
  require(result && typeof result === 'object' && !Array.isArray(result), `Expected dependency object: ${relative}`);
  return result;
}

function installationEnvironment() {
  const environment = {};
  // Keep required network transport settings, but never npm configuration,
  // Node injection or application production settings from the parent.
  for (const key of ['PATH', 'HOME', 'TMPDIR', 'TMP', 'TEMP', 'SystemRoot', 'ComSpec',
    'USERPROFILE', 'LOCALAPPDATA', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
    'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy', 'NODE_EXTRA_CA_CERTS', 'SSL_CERT_FILE']) {
    if (process.env[key] !== undefined) environment[key] = process.env[key];
  }
  return { ...environment, PUPPETEER_SKIP_DOWNLOAD: 'true' };
}

export { installationEnvironment as applicationInstallationEnvironment };

function profileInputs(dependencyProfile, packageManager = 'npm') {
  require(['full', 'application'].includes(dependencyProfile), 'Unsupported dependency installation profile');
  return dependencyProfile === 'application'
    ? [...APPLICATION_INSTALL_INPUTS, ...applicationDependencyProfileInputs(packageManager).map((name) => name.slice('ui/'.length))]
    : [...APPLICATION_INSTALL_INPUTS];
}

function removedRootPath(relative) {
  return APPLICATION_REMOVED_DEPENDENCY_ROOTS.some((name) => relative === `node_modules/${name}`
    || relative.endsWith(`/node_modules/${name}`));
}

function removedRootIdentity(row) {
  return row && APPLICATION_REMOVED_DEPENDENCY_ROOTS.includes(row.name);
}

function manifestContract(uiRoot, dependencyProfile, selectedManager) {
  profileInputs(dependencyProfile);
  for (const name of ['.npmrc', '.npm-extension.mjs', '.npm-extension.cjs', 'npm-shrinkwrap.json']) {
    require(absent(path.join(uiRoot, name)), `Unreviewed project install configuration: ${name}`);
  }
  const manifest = document(uiRoot, 'package.json');
  const packageManager = applicationPackageManager(manifest, selectedManager);
  const lock = document(uiRoot, 'package-lock.json');
  require(lock.lockfileVersion === 3 && lock.packages && lock.packages[''], 'Expected the committed npm v3 lock');
  assert.deepEqual(lock.packages[''].dependencies, manifest.dependencies, 'npm lock dependencies differ from the manifest');
  assert.deepEqual(lock.packages[''].devDependencies, manifest.devDependencies, 'npm lock development dependencies differ from the manifest');
  if (dependencyProfile === 'application') {
    for (const name of ['package.json', 'package-lock.json', ...(packageManager === 'bun' ? ['bun.lock'] : [])]) {
      require(input(uiRoot, name).bytes.equals(input(uiRoot, `profiles/application/${name}`).bytes),
        `Materialized application ${name} differs from the selected profile`);
    }
    require(manifest.scripts?.postinstall === APPLICATION_PROFILE_POSTINSTALL,
      'The application profile must select only the reviewed checker patch');
    require(APPLICATION_REMOVED_DEPENDENCY_ROOTS.every((name) => !Object.hasOwn(manifest.dependencies || {}, name)
      && !Object.hasOwn(manifest.devDependencies || {}, name))
      && !Object.entries(lock.packages).some(([relative, row]) => removedRootPath(relative) || removedRootIdentity(row)),
    'The application profile retained a removed website dependency');
  } else {
    require(manifest.scripts?.postinstall === POSTINSTALL, 'Both reviewed postinstall patches must remain selected');
  }
  const sdk = lock.packages[`node_modules/${SDK}`];
  require(sdk && typeof sdk.version === 'string' && typeof sdk.resolved === 'string'
    && /^sha512-[A-Za-z0-9+/]+={0,2}$/.test(sdk.integrity), 'The SDK requires its original locked artifact integrity');
  const bunLock = packageManager === 'bun' ? parseApplicationBunLock(input(uiRoot, 'bun.lock').bytes) : undefined;
  const bunRecords = bunLock ? validateApplicationBunLock(manifest, lock, bunLock) : undefined;
  return { manifest, lock, packageManager, bunLock, bunRecords };
}

function verifyRemovedPackagesAbsent(uiRoot, graph) {
  require(!graph.packages.some((row) => removedRootPath(row.path)), 'A removed website dependency is installed');
  let visited = 0;
  // Check actual npm package directories as well as its hidden lock. A lifecycle
  // script must not be able to restore an unrecorded removed package.
  function visit(directory, depth = 0) {
    require(depth <= 32, 'Installed package nesting exceeds its bound');
    ordinaryDirectory(directory);
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.name.startsWith('.')) continue;
      require(++visited <= 8192 && entry.isDirectory() && !entry.isSymbolicLink(),
        'Installed application graph contains an unexpected package entry');
      const location = path.join(directory, entry.name);
      if (entry.name.startsWith('@')) {
        for (const scoped of readdirSync(location, { withFileTypes: true })) {
          require(++visited <= 8192 && scoped.isDirectory() && !scoped.isSymbolicLink(),
            'Installed application graph contains an unexpected scoped entry');
          checkPackage(path.join(location, scoped.name), depth);
        }
      } else checkPackage(location, depth);
    }
  }
  function checkPackage(directory, depth) {
    require(!removedRootPath(path.relative(uiRoot, directory).split(path.sep).join('/')),
      'A removed website dependency exists outside the installed lock');
    require(!removedRootIdentity(document(directory, 'package.json')),
      'A removed website dependency exists under an installed alias');
    const nested = path.join(directory, 'node_modules');
    if (!absent(nested)) visit(nested, depth + 1);
  }
  visit(path.join(uiRoot, 'node_modules'));
  return { roots: [...APPLICATION_REMOVED_DEPENDENCY_ROOTS], absent_from_manifest: true,
    absent_from_lock: true, absent_from_installed_graph: true, absent_from_installed_packages: true };
}

function installedGraph(uiRoot, manifest, lock) {
  ordinaryDirectory(path.join(uiRoot, 'node_modules'));
  const installed = document(uiRoot, 'node_modules/.package-lock.json');
  require(installed.lockfileVersion === 3 && installed.packages, 'npm did not record its installed dependency graph');
  const records = [];
  for (const [relative, row] of Object.entries(installed.packages)) {
    require(relative.startsWith('node_modules/') && row && !row.link, 'Installed graph contains a linked or invalid package');
    if (manifest.scripts?.postinstall === APPLICATION_PROFILE_POSTINSTALL) {
      require(!removedRootIdentity(row), 'A removed website dependency is recorded under an installed alias');
    }
    const expected = lock.packages[relative];
    require(expected && ['version', 'resolved', 'integrity'].every((key) => row[key] === expected[key]),
      `Installed package differs from the committed lock: ${relative}`);
    const location = ordinaryDirectory(path.join(uiRoot, relative));
    require(location.startsWith(`${uiRoot}/node_modules/`), 'Installed package escaped its fresh dependency directory');
    records.push({ path: relative, version: row.version, resolved: row.resolved, integrity: row.integrity });
  }
  for (const name of Object.keys({ ...manifest.dependencies, ...manifest.devDependencies })) {
    require(installed.packages[`node_modules/${name}`], `Fresh installation omitted a declared dependency: ${name}`);
  }
  require(records.length > 0, 'Fresh installation has no dependency evidence');
  records.sort((a, b) => a.path.localeCompare(b.path));
  return { package_count: records.length, inventory_sha256: digest(JSON.stringify(records)), packages: records };
}

function installedBunGraph(uiRoot, manifest, lock, identities) {
  const records = []; const installed = new Map(); const reviewed = new Map(identities.map((row) => [row.location, row]));
  function visit(directory, prefix = '', depth = 0) {
    require(depth <= 32, 'Installed Bun graph nesting exceeds its bound'); ordinaryDirectory(directory);
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (entry.name.startsWith('.')) {
        require(['.bin', '.cache', '.vite', '.vite-temp', '.vitest-cache'].includes(entry.name), 'Unexpected hidden Bun install state');
        continue;
      }
      require(entry.isDirectory() && !entry.isSymbolicLink(), 'Bun hoisted graph contains a nonordinary package');
      const location = path.join(directory, entry.name);
      if (entry.name.startsWith('@')) {
        for (const scoped of readdirSync(location, { withFileTypes: true })) {
          require(scoped.isDirectory() && !scoped.isSymbolicLink(), 'Bun scoped graph contains a nonordinary package');
          check(path.join(location, scoped.name), `${prefix}${entry.name}/${scoped.name}`, depth);
        }
      } else check(location, `${prefix}${entry.name}`, depth);
    }
  }
  function check(directory, key, depth) {
    require(records.length < 8192 && !installed.has(key), 'Bun installed graph exceeds its bound or repeats a package');
    ordinaryDirectory(directory);
    const actual = document(directory, 'package.json'); const expected = reviewed.get(key);
    require(expected && actual.name === expected.name && actual.version === expected.version,
      `Installed Bun package differs from the committed lock: ${key}`);
    const relative = path.relative(uiRoot, directory).split(path.sep).join('/');
    installed.set(key, expected);
    records.push({ path: relative, version: expected.version, resolved: expected.resolved, integrity: expected.integrity,
      manifest_sha256: input(directory, 'package.json').record.sha256 });
    if (!absent(path.join(directory, 'node_modules'))) visit(path.join(directory, 'node_modules'), `${key}/`, depth + 1);
  }
  visit(path.join(uiRoot, 'node_modules'));
  const resolve = (key, name, packages) => {
    const parts = key ? key.match(/@[^/]+\/[^/]+|[^/]+/g) : [];
    while (true) {
      const candidate = [...parts, name].join('/');
      if (packages.has(candidate)) return candidate;
      if (!parts.length) return undefined;
      parts.pop();
    }
  };
  for (const name of Object.keys({ ...manifest.dependencies, ...manifest.devDependencies })) {
    require(installed.has(name), `Bun installation omitted a declared dependency: ${name}`);
  }
  for (const key of installed.keys()) {
    const metadata = lock.packages[key].at(-2);
    for (const name of Object.keys({ ...metadata.dependencies, ...metadata.peerDependencies })) {
      if (metadata.optionalPeers?.includes(name)) continue;
      const expected = resolve(key, name, reviewed);
      if (expected) require(resolve(key, name, installed) === expected, `Bun installation omitted or redirected a required dependency: ${key} -> ${name}`);
      else require(!Object.hasOwn(metadata.dependencies || {}, name), `Bun lock omitted a required dependency: ${key} -> ${name}`);
    }
  }
  require(records.length > 0, 'Fresh Bun installation has no dependency evidence');
  records.sort((a, b) => a.path.localeCompare(b.path));
  return { package_count: records.length, inventory_sha256: digest(JSON.stringify(records)), packages: records,
    identity_source: 'committed-bun-lock-and-installed-manifests' };
}

function prerenderPatchEvidence(uiRoot) {
  const prefix = 'node_modules/@prerenderer';
  ordinaryDirectory(path.join(uiRoot, prefix));
  const files = [];
  let entries = 0;
  const before = 'ts_deepmerge_1.default';
  const after = '(ts_deepmerge_1.default || ts_deepmerge_1.merge)';
  function visit(relative, depth = 0) {
    require(depth < 32, 'Prerender package nesting exceeds its bound');
    for (const entry of readdirSync(path.join(uiRoot, relative), { withFileTypes: true })) {
      require(++entries <= 4096 && !entry.isSymbolicLink(), 'Prerender package contains unexpected entries');
      const name = `${relative}/${entry.name}`;
      if (entry.isDirectory()) visit(name, depth + 1);
      else {
        require(entry.isFile(), 'Prerender package contains a non-file');
        if (!name.endsWith('.js')) continue;
        const source = input(uiRoot, name);
        const text = source.bytes.toString('utf8');
        if (!text.includes(before)) continue;
        require(text.includes(after) && !text.replaceAll(after, '').includes(before), 'Prerender postinstall patch did not run');
        files.push(source.record);
      }
    }
  }
  visit(prefix);
  require(files.length > 0, 'Prerender postinstall patch has no verified targets');
  return files.sort((a, b) => a.path.localeCompare(b.path));
}

export async function inspectInstalledApplicationDependencies(directory, { dependencyProfile = 'full', packageManager } = {}) {
  const uiRoot = ordinaryDirectory(directory);
  const contract = manifestContract(uiRoot, dependencyProfile, packageManager);
  const { manifest, lock } = contract;
  const graph = contract.packageManager === 'bun' ? installedBunGraph(uiRoot, manifest, contract.bunLock, contract.bunRecords)
    : installedGraph(uiRoot, manifest, lock);
  const removedDependencies = dependencyProfile === 'application' ? verifyRemovedPackagesAbsent(uiRoot, graph) : undefined;
  const prerenderFiles = dependencyProfile === 'application' ? [] : prerenderPatchEvidence(uiRoot);
  const checker = await import(pathToFileURL(path.join(uiRoot, 'scripts/patch-checker-worker-cleanup.mjs')).href);
  require(Array.isArray(checker.patches) && checker.patches.length > 0, 'Checker patch has no verified targets');
  const checkerPackage = document(uiRoot, 'node_modules/vite-plugin-checker/package.json');
  require(checkerPackage.version === checker.checkerVersion, 'Installed checker differs from its reviewed patch version');
  const checkerFiles = checker.patches.map((patch) => {
    const source = input(uiRoot, `node_modules/vite-plugin-checker/${patch.file}`);
    require(source.record.sha256 === `sha256:${patch.after}`, 'Checker postinstall patch did not run');
    return source.record;
  });
  const helper = input(uiRoot, `node_modules/vite-plugin-checker/dist/${checker.cleanupFilename}`);
  require(helper.record.sha256 === input(uiRoot, 'scripts/checker-worker-cleanup.mjs').record.sha256,
    'Installed checker cleanup helper differs from its source');
  checkerFiles.push(helper.record);

  const packagePrefix = `node_modules/${SDK}`;
  const packageJson = document(uiRoot, `${packagePrefix}/package.json`);
  const locked = lock.packages[packagePrefix];
  require(packageJson.name === SDK && packageJson.version === locked.version, 'Installed SDK differs from the locked version');
  const entry = createRequire(path.join(uiRoot, 'package.json')).resolve(SDK);
  require(realpathSync(entry) === path.join(uiRoot, packagePrefix, 'src/index.js'), 'SDK resolved outside its fresh locked package');
  const wasm = input(uiRoot, `${packagePrefix}/src/wasm/marty_api_client_bg.wasm`);
  require(WebAssembly.validate(wasm.bytes), 'Installed SDK WASM is invalid');
  const originalFetch = globalThis.fetch;
  globalThis.fetch = () => { throw new Error('SDK initialization must not make a network request'); };
  try {
    const sdk = await import(pathToFileURL(entry).href);
    require(typeof sdk.createApiClient === 'function', 'Installed SDK has no client constructor');
    const client = sdk.createApiClient({ baseUrl: '' });
    require(client && typeof client.get === 'function', 'Installed SDK client could not initialize');
  } finally { globalThis.fetch = originalFetch; }
  return {
    ...(contract.packageManager === 'bun' ? { package_manager: { ...APPLICATION_BUN_PACKAGE_MANAGER } } : {}),
    graph, ...(removedDependencies ? { removed_website_dependencies: removedDependencies } : {}),
    postinstall: { command: manifest.scripts.postinstall, verified: true, prerender_selected: dependencyProfile === 'full',
      prerender_files: prerenderFiles, checker_files: checkerFiles },
    sdk: { name: SDK, version: packageJson.version, resolved: locked.resolved, integrity: locked.integrity,
      entry: input(uiRoot, `${packagePrefix}/src/index.js`).record, wasm: wasm.record,
      initialized_in_node: true, browser_execution_observed: false },
  };
}

export function prepareApplicationInstall(temporary, packageManager) {
  const cache = path.join(temporary, `${packageManager}-cache`);
  require(absent(cache), 'Fresh package-manager state must be new'); mkdirSync(cache, { mode: 0o700 });
  if (packageManager === 'bun') {
    const home = path.join(temporary, 'bun-home'); mkdirSync(home, { mode: 0o700 });
    const config = path.join(temporary, 'bunfig.toml'); writeFileSync(config, '', { mode: 0o600, flag: 'wx' });
    return { environment: { ...installationEnvironment(), HOME: home, XDG_CONFIG_HOME: home, BUN_INSTALL_CACHE_DIR: cache,
      BUN_CONFIG_REGISTRY: 'https://registry.npmjs.org' }, configuration: 'explicit-empty-home-and-config', cache,
    versionArgs: ['--version'], args: ['install', '--frozen-lockfile', '--linker=hoisted', '--backend=copyfile',
      '--no-env-file', `--config=${config}`, `--cache-dir=${cache}`, '--registry=https://registry.npmjs.org'] };
  }
  require(packageManager === 'npm', 'Unsupported package manager');
  const userConfig = path.join(temporary, 'npm-user-config'); const globalConfig = path.join(temporary, 'npm-global-config');
  for (const filename of [userConfig, globalConfig]) writeFileSync(filename, '', { mode: 0o600, flag: 'wx' });
  const environment = { ...installationEnvironment(), npm_config_cache: cache, npm_config_userconfig: userConfig,
    npm_config_globalconfig: globalConfig, npm_config_include: 'dev', npm_config_ignore_scripts: 'false',
    npm_config_audit: 'false', npm_config_fund: 'false', npm_config_package_lock: 'true', npm_config_install_strategy: 'hoisted',
    npm_config_legacy_peer_deps: 'false', npm_config_install_links: 'false', npm_config_registry: 'https://registry.npmjs.org' };
  return { environment, configuration: 'explicit-empty-user-and-global', cache,
    versionArgs: ['--version', '--userconfig', userConfig, '--globalconfig', globalConfig],
    args: ['ci', '--include=dev', '--ignore-scripts=false', '--audit=false', '--fund=false', '--package-lock=true',
      '--install-strategy=hoisted', '--legacy-peer-deps=false', '--install-links=false', '--registry=https://registry.npmjs.org',
      '--cache', cache, '--userconfig', userConfig, '--globalconfig', globalConfig] };
}

export function installApplicationDependencies({ uiRoot: directory, temporaryRoot, dependencyProfile = 'full', packageManager }) {
  const uiRoot = ordinaryDirectory(directory);
  const temporary = ordinaryDirectory(temporaryRoot);
  require(uiRoot !== temporary && uiRoot.startsWith(`${temporary}${path.sep}`), 'Fresh install must remain in its disposable export');
  require(absent(path.join(uiRoot, 'node_modules')), 'Fresh install cannot borrow an existing dependency directory');
  packageManager = manifestContract(uiRoot, dependencyProfile, packageManager).packageManager;
  const selectedInputs = profileInputs(dependencyProfile, packageManager);
  const original = selectedInputs.map((name) => input(uiRoot, name).record);
  const { environment, args, versionArgs, configuration } = prepareApplicationInstall(temporary, packageManager);
  let managerVersion;
  let evidence;
  try {
    const version = runOwnedInstallCommand(packageManager, versionArgs, {
      cwd: uiRoot, env: environment, timeout: 30_000, stdoutFile: path.join(temporary, `${packageManager}-version.txt`),
    });
    if (version.error) throw version.error;
    const versionOutput = input(temporary, `${packageManager}-version.txt`).bytes;
    require(versionOutput.length <= 64 * 1024, 'Installer version output exceeds its bound');
    managerVersion = versionOutput.toString('utf8').trim();
    require(version.status === 0 && /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(managerVersion), 'Unable to identify the installer');
    if (packageManager === 'bun') require(managerVersion === APPLICATION_BUN_PACKAGE_MANAGER.version, 'Bun installer differs from the reviewed 1.4.4 pin');
    const installed = runOwnedInstallCommand(packageManager, args, {
      cwd: uiRoot, env: environment, timeout: 8 * 60_000,
    });
    if (installed.error) throw installed.error;
    require(installed.status === 0, `Frozen ${packageManager} installation failed with exit code ${installed.status}`);
    const inspected = runOwnedInstallCommand(process.execPath, [SELF, '--inspect-installed', uiRoot, dependencyProfile, packageManager], {
      cwd: uiRoot, env: environment, timeout: 30_000,
      stdoutFile: path.join(temporary, 'dependency-inspection.json'),
    });
    if (inspected.error) throw inspected.error;
    require(inspected.status === 0, 'Fresh dependency, postinstall or SDK verification failed');
    const inspectionOutput = input(temporary, 'dependency-inspection.json').bytes;
    require(inspectionOutput.length <= 2 * 1024 * 1024, 'Dependency inspection exceeds its report bound');
    evidence = JSON.parse(inspectionOutput.toString('utf8'));
  } finally {
    assert.deepEqual(selectedInputs.map((name) => input(uiRoot, name).record), original,
      'Fresh installation changed a reviewed manifest, lock or postinstall source');
  }
  return { status: 'passed', mode: packageManager === 'bun' ? 'fresh-bun-frozen' : 'fresh-npm-ci', dependency_profile: dependencyProfile,
    command: [packageManager, ...args], node_version: process.version,
    [`${packageManager}_version`]: managerVersion, cache_mode: 'new-temporary-cache', [`${packageManager}_configuration`]: configuration,
    browser_download_skipped: true, bun_lock_selected: packageManager === 'bun', source_inputs: original, ...evidence,
    package_graph_minimized: false, independent_dependency_installation: true };
}

if (process.argv[1] && path.resolve(process.argv[1]) === SELF) {
  try {
    require([5, 6].includes(process.argv.length) && process.argv[2] === '--inspect-installed', 'Unsupported dependency inspection command');
    process.stdout.write(`${JSON.stringify(await inspectInstalledApplicationDependencies(process.argv[3],
      { dependencyProfile: process.argv[4], packageManager: process.argv[5] }))}\n`);
  } catch (error) {
    console.error(`Application dependency verification failed: ${error.message || error}`);
    process.exitCode = 1;
  }
}
