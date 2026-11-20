import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import {
  chmodSync, closeSync, constants, fstatSync, lstatSync, mkdirSync, mkdtempSync, openSync,
  readSync, readdirSync, realpathSync, rmSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import { APPLICATION_RETAINED_PUBLIC_FILES, APPLICATION_RESOURCE_MIME_TYPES } from './application-public-assets.mjs';
import { runOwnedInstallCommand } from './application-dependency-install.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const MANIFEST = 'application-runtime-context.json';
const MAX_BYTES = 64 * 1024 * 1024;
const MAX_TOTAL_BYTES = 256 * 1024 * 1024;
const MAX_ENTRIES = 4096;
export const APPLICATION_RUNTIME_BASE_IMAGE = 'nginx:1.29.1-alpine@sha256:42a516af16b852e33b7682d5ef8acbd5d13fe08fecadc7ed98605ba5e3b26ab8';
export const APPLICATION_RUNTIME_INPUTS = Object.freeze([
  { path: 'ui/scripts/application-runtime.Dockerfile', target: 'Dockerfile', mode: 0o644 },
  { path: 'ui/nginx.prod.conf', target: 'nginx.conf', mode: 0o644 },
  { path: 'scripts/load-secrets-env.sh', target: 'scripts/load-secrets-env.sh', mode: 0o755 },
  { path: 'scripts/ui-production-start.sh', target: 'scripts/ui-production-start.sh', mode: 0o755 },
]);

function require(condition, message) { if (!condition) throw new Error(message); }
function digest(bytes) { return `sha256:${createHash('sha256').update(bytes).digest('hex')}`; }
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function within(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!path.isAbsolute(relative) && relative !== '..' && !relative.startsWith(`..${path.sep}`));
}
function safePath(value) {
  require(typeof value === 'string' && value.length > 0 && value.length < 1024
    && /^[A-Za-z0-9_./-]+$/.test(value) && !path.isAbsolute(value)
    && value.split('/').every((part) => part && part !== '.' && part !== '..'), 'Unsafe runtime context path');
  return value;
}
function directory(value) {
  const resolved = path.resolve(value);
  const metadata = lstatSync(resolved);
  require(metadata.isDirectory() && !metadata.isSymbolicLink() && realpathSync(resolved) === resolved,
    'Runtime paths must use ordinary directories without symlink parents');
  return resolved;
}
function absent(value) {
  try { lstatSync(value); } catch (error) { if (error.code === 'ENOENT') return; throw error; }
  throw new Error('Runtime destination already exists');
}
function newDestination(value, forbiddenRoots = []) {
  require(typeof value === 'string' && path.isAbsolute(value), 'Runtime destination must be absolute');
  const resolved = path.resolve(value);
  directory(path.dirname(resolved));
  require(!forbiddenRoots.some((root) => within(root, resolved)), 'Runtime destination must be outside source and output');
  absent(resolved);
  return resolved;
}
function read(root, relative) {
  const parts = safePath(relative).split('/');
  let target = root;
  for (const part of parts.slice(0, -1)) {
    target = path.join(target, part);
    const metadata = lstatSync(target);
    require(metadata.isDirectory() && !metadata.isSymbolicLink(), `Runtime parent is not an ordinary directory: ${relative}`);
  }
  target = path.join(target, parts.at(-1));
  const metadata = lstatSync(target);
  require(metadata.isFile() && !metadata.isSymbolicLink(), `Runtime input is not a regular file: ${relative}`);
  const fd = openSync(target, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const opened = fstatSync(fd);
    require(opened.isFile() && opened.size <= MAX_BYTES, 'Runtime input exceeds the file bound');
    const buffer = Buffer.alloc(opened.size + 1);
    let size = 0;
    while (size < buffer.length) {
      const count = readSync(fd, buffer, size, buffer.length - size, null);
      if (!count) break;
      size += count;
    }
    require(size === opened.size, `Runtime input changed while reading: ${relative}`);
    const bytes = buffer.subarray(0, size);
    return { bytes, record: { path: relative, bytes: size, sha256: digest(bytes), mode: opened.mode & 0o777 } };
  } finally { closeSync(fd); }
}
function inventory(root) {
  const files = [];
  const directories = [];
  let entries = 0;
  let total = 0;
  function walk(relative = '', depth = 0) {
    require(depth < 32, 'Runtime directory nesting exceeds the bound');
    for (const entry of readdirSync(path.join(root, relative), { withFileTypes: true })) {
      require(++entries <= MAX_ENTRIES, 'Runtime inventory exceeds the entry bound');
      const name = safePath(relative ? `${relative}/${entry.name}` : entry.name);
      require(!entry.isSymbolicLink(), `Runtime tree contains a symlink: ${name}`);
      if (entry.isDirectory()) {
        directories.push({ path: name, mode: lstatSync(path.join(root, name)).mode & 0o777 });
        walk(name, depth + 1);
      } else {
        require(entry.isFile(), `Runtime tree contains a non-file: ${name}`);
        const item = read(root, name).record;
        total += item.bytes;
        require(total <= MAX_TOTAL_BYTES, 'Runtime inventory exceeds the byte bound');
        files.push(item);
      }
    }
  }
  walk();
  return { files: files.sort((a, b) => a.path.localeCompare(b.path, 'en')), directories };
}
function byteRecord(record) { return { path: record.path, bytes: record.bytes, sha256: record.sha256 }; }
function sourceInputs(sourceRoot) {
  return APPLICATION_RUNTIME_INPUTS.map((input) => {
    const snapshot = read(sourceRoot, input.path);
    return { ...input, ...byteRecord(snapshot.record), source_mode: snapshot.record.mode,
      packaged_mode: input.mode, target: input.target };
  });
}
function verifiedOutput(outputRoot, sourceCommit, outputInventory, resourceResult) {
  require(/^[0-9a-f]{40}$/.test(sourceCommit), 'Expected a canonical source commit');
  const actual = inventory(outputRoot).files;
  const ordered = [...outputInventory.files].sort((a, b) => a.path.localeCompare(b.path, 'en'));
  assert.deepEqual(actual, ordered, 'Runtime output differs from the verified output inventory');
  require(outputInventory.inventory_sha256 === digest(canonical(outputInventory.files)), 'Invalid output inventory digest');
  const byPath = new Map(actual.map((item) => [item.path, item]));
  require(resourceResult?.schema === 'marty.application-resource-smoke/v1' && resourceResult.status === 'passed'
    && resourceResult.preview?.closed === true, 'Runtime requires the completed M21 resource proof');
  assert.deepEqual(resourceResult.qualification, { resources_served: true, locale_fallback_observed: true,
    browser_startup_observed: false, host_deployment_tested: false, oidc_journey_tested: false }, 'Invalid resource qualification');
  const expectedPublic = APPLICATION_RETAINED_PUBLIC_FILES.map((name) => {
    require(byPath.has(name), `Runtime public resource is missing: ${name}`);
    return byteRecord(byPath.get(name));
  });
  assert.deepEqual(resourceResult.public_resources, expectedPublic, 'Runtime public resources differ from M21');
  const required = new Set([...APPLICATION_RETAINED_PUBLIC_FILES, 'index.html', 'console/index.html',
    ...actual.filter((item) => /\.(?:m?js|wasm|css)$/.test(item.path)).map((item) => item.path)]);
  const seen = new Set();
  require(Array.isArray(resourceResult.served_resources), 'Runtime served resources are missing');
  for (const row of resourceResult.served_resources) {
    require(row && !seen.has(row.path) && byPath.has(row.path) && row.status === 200,
      'Invalid or duplicate M21 served resource');
    assert.deepEqual(byteRecord(row), byteRecord(byPath.get(row.path)), 'Runtime served bytes differ from M21');
    require(APPLICATION_RESOURCE_MIME_TYPES[path.extname(row.path)]?.includes(row.content_type), 'Invalid M21 content type');
    seen.add(row.path);
  }
  require([...required].every((name) => seen.has(name)), 'M21 omitted a required runtime resource');
  const wasm = actual.filter((item) => /^assets\/marty_api_client_bg[-.A-Za-z0-9_]*\.wasm$/.test(item.path));
  require(wasm.length === 1 && wasm[0].bytes >= 8, 'Runtime requires exactly one emitted API-core WASM');
  assert.deepEqual([...read(outputRoot, wasm[0].path).bytes.subarray(0, 8)], [0, 97, 115, 109, 1, 0, 0, 0], 'Invalid SDK WASM header');
  const marker = JSON.parse(read(outputRoot, 'marty-web-routes.json').bytes.toString('utf8'));
  require(marker.schema === 'marty.application-web-compatibility/v1' && marker.surface === 'application'
    && [sourceCommit, 'development'].includes(marker.source_sha), 'Runtime application source marker differs');
  return { files: actual, sourceMarker: marker.source_sha, wasm: wasm[0].path };
}
function makeParents(root, relative) {
  let target = root;
  for (const part of safePath(relative).split('/').slice(0, -1)) {
    target = path.join(target, part);
    try { mkdirSync(target, { mode: 0o755 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    require(lstatSync(target).isDirectory() && !lstatSync(target).isSymbolicLink(), 'Unsafe runtime destination parent');
    chmodSync(target, 0o755);
  }
}
function writeNew(root, relative, bytes, mode) {
  makeParents(root, relative);
  const target = path.join(root, relative);
  writeFileSync(target, bytes, { flag: 'wx', mode });
  chmodSync(target, mode);
}

export function createApplicationRuntimeContext({ sourceRoot, outputRoot, destination, sourceCommit, outputInventory, resourceResult }) {
  const source = directory(sourceRoot);
  const output = directory(outputRoot);
  const target = newDestination(destination, [source, output]);
  const verified = verifiedOutput(output, sourceCommit, outputInventory, resourceResult);
  const inputs = sourceInputs(source);
  // Context preparation cannot replace the reviewed recipe or source hooks.
  const canonicalInputs = sourceInputs(ROOT);
  assert.deepEqual(inputs.map(({ source_mode, ...item }) => item), canonicalInputs.map(({ source_mode, ...item }) => item),
    'Runtime source inputs differ from the reviewed source');
  let created = false;
  try {
    mkdirSync(target, { mode: 0o755 });
    created = true;
    chmodSync(target, 0o755);
    const transformations = [];
    for (const item of outputInventory.files) {
      writeNew(target, `html/${item.path}`, read(output, item.path).bytes, 0o644);
      transformations.push({ path: `html/${item.path}`, source_mode: item.mode, packaged_mode: 0o644 });
    }
    for (const item of inputs) {
      writeNew(target, item.target, read(source, item.path).bytes, item.packaged_mode);
      transformations.push({ path: item.target, source_mode: item.source_mode, packaged_mode: item.packaged_mode });
    }
    const packaged = inventory(target);
    assert.deepEqual(inventory(output).files, verified.files, 'Runtime preparation changed or raced the source output');
    assert.deepEqual(sourceInputs(source), inputs, 'Runtime preparation changed or raced the source inputs');
    const manifest = {
      schema: 'marty.application-runtime-context/v1', source_commit: sourceCommit,
      effective_source_sha: verified.sourceMarker, exact_committed_source: verified.sourceMarker === sourceCommit,
      base_image: APPLICATION_RUNTIME_BASE_IMAGE, sdk_wasm: verified.wasm,
      source_inputs: inputs, output_inventory: outputInventory, resource_result: resourceResult,
      context_inventory: packaged.files, directory_mode: 0o755, mode_transformations: transformations,
      qualification: { context_prepared: true, container_image_built: false, container_resources_checked: false,
        browser_startup_observed: false, host_deployment_tested: false, oidc_journey_tested: false },
    };
    const bytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
    writeNew(target, MANIFEST, bytes, 0o644);
    return { ...manifest, path: target, manifest_sha256: digest(bytes) };
  } catch (error) {
    if (created) rmSync(target, { recursive: true, force: true });
    throw error;
  }
}

export function validateApplicationRuntimeContext(context) {
  const root = directory(context);
  require((lstatSync(root).mode & 0o777) === 0o755, 'Runtime context root must be mode 0755');
  const raw = read(root, MANIFEST);
  require(raw.record.mode === 0o644, 'Runtime manifest must be mode 0644');
  const manifest = JSON.parse(raw.bytes.toString('utf8'));
  const keys = ['schema', 'source_commit', 'effective_source_sha', 'exact_committed_source', 'base_image', 'sdk_wasm',
    'source_inputs', 'output_inventory', 'resource_result', 'context_inventory', 'directory_mode', 'mode_transformations', 'qualification'];
  assert.deepEqual(Object.keys(manifest).sort(), keys.sort(), 'Runtime manifest fields changed');
  require(manifest.schema === 'marty.application-runtime-context/v1' && manifest.base_image === APPLICATION_RUNTIME_BASE_IMAGE,
    'Runtime context schema or pinned base changed');
  const current = inventory(root);
  assert.deepEqual(current.files.filter((item) => item.path !== MANIFEST), manifest.context_inventory,
    'Runtime context contains changed, missing, or extra files');
  require(manifest.directory_mode === 0o755 && current.directories.every((item) => item.mode === 0o755),
    'Runtime context directories must be mode 0755');
  const expectedDirectories = new Set();
  for (const item of current.files) {
    const parts = item.path.split('/');
    while (parts.length > 1) { parts.pop(); expectedDirectories.add(parts.join('/')); }
  }
  assert.deepEqual(current.directories.map((item) => item.path).sort(), [...expectedDirectories].sort(),
    'Runtime context contains an unexpected empty directory');
  assert.deepEqual(manifest.source_inputs.map(({ source_mode, ...item }) => item),
    sourceInputs(ROOT).map(({ source_mode, ...item }) => item), 'Runtime inputs differ from the reviewed source');
  const expected = [
    ...manifest.output_inventory.files.map((item) => ({ ...item, path: `html/${item.path}`, mode: 0o644 })),
    ...manifest.source_inputs.map((item) => ({ path: item.target, bytes: item.bytes, sha256: item.sha256, mode: item.packaged_mode })),
  ].sort((a, b) => a.path.localeCompare(b.path, 'en'));
  assert.deepEqual(current.files.filter((item) => item.path !== MANIFEST), expected, 'Runtime packaging changed bytes or required modes');
  const modes = [...manifest.output_inventory.files.map((item) => ({ path: `html/${item.path}`, source_mode: item.mode, packaged_mode: 0o644 })),
    ...manifest.source_inputs.map((item) => ({ path: item.target, source_mode: item.source_mode, packaged_mode: item.packaged_mode }))];
  assert.deepEqual(manifest.mode_transformations, modes, 'Runtime mode transformations differ');
  require(manifest.output_inventory.inventory_sha256 === digest(canonical(manifest.output_inventory.files)),
    'Original runtime output inventory digest differs');
  const packagedOutput = { ...manifest.output_inventory,
    files: manifest.output_inventory.files.map((item) => ({ ...item, mode: 0o644 })) };
  packagedOutput.inventory_sha256 = digest(canonical(packagedOutput.files));
  const verified = verifiedOutput(path.join(root, 'html'), manifest.source_commit, packagedOutput, manifest.resource_result);
  require(manifest.effective_source_sha === verified.sourceMarker
    && manifest.exact_committed_source === (verified.sourceMarker === manifest.source_commit)
    && manifest.sdk_wasm === verified.wasm, 'Runtime source identity differs from its output marker');
  assert.deepEqual(manifest.qualification, { context_prepared: true, container_image_built: false, container_resources_checked: false,
    browser_startup_observed: false, host_deployment_tested: false, oidc_journey_tested: false }, 'Prepared context overstates qualification');
  return { root, manifest, manifest_sha256: raw.record.sha256 };
}

export function expectedDefaultRuntimeBytes(relative, bytes) {
  if (relative === 'runtime-config.js') return Buffer.from(
    "window.__MARTY_RUNTIME_CONFIG__ = Object.assign({}, window.__MARTY_RUNTIME_CONFIG__, {\n"
    + "  googleAnalyticsMeasurementId: '',\n  organizationCreationEnabled: false\n});\n",
  );
  if (relative.endsWith('.html') && bytes.length) {
    const text = bytes.toString('utf8');
    // Model the existing sed hook one line at a time, including its final newline.
    const lines = (text.endsWith('\n') ? text.slice(0, -1) : text).split('\n');
    return Buffer.from(`${lines.map((line) => line.replace(/<meta name="google-site-verification"[^>]*>/g, '')).join('\n')}\n`);
  }
  return bytes;
}

async function requestResource(origin, relative, bytes, timeout = 5000) {
  safePath(relative);
  const base = new URL(origin);
  require(base.protocol === 'http:' && base.hostname === '127.0.0.1' && base.port && base.pathname === '/', 'Runtime HTTP origin must be loopback');
  const response = await fetch(`${base.origin}/${relative}`, {
    redirect: 'manual', signal: AbortSignal.timeout(timeout), headers: { Accept: '*/*', 'Accept-Encoding': 'identity' },
  });
  const contentType = (response.headers.get('content-type') || '').split(';', 1)[0].trim().toLowerCase();
  if (response.status !== 200 || !APPLICATION_RESOURCE_MIME_TYPES[path.extname(relative)]?.includes(contentType)) {
    await response.body?.cancel();
    throw new Error(`Runtime resource ${relative} has status ${response.status} or incorrect content type ${contentType}`);
  }
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      size += item.value.length;
      if (size > bytes.length) { await reader.cancel(); throw new Error(`Runtime resource bytes differ: ${relative}`); }
      chunks.push(item.value);
    }
  } finally { reader.releaseLock(); }
  const actual = Buffer.concat(chunks, size);
  require(size === bytes.length && digest(actual) === digest(bytes), `Runtime resource bytes differ: ${relative}`);
  return { path: relative, bytes: size, sha256: digest(actual), status: 200, content_type: contentType };
}

async function defaultDocker(args, { timeout = 30_000, allowFailure = false } = {}) {
  const endpoint = process.env.DOCKER_HOST || 'unix:///var/run/docker.sock';
  require(/^unix:\/\/\/[A-Za-z0-9_./-]+$/.test(endpoint), 'Only a local Unix Docker endpoint is permitted');
  const environment = { ...process.env, DOCKER_BUILDKIT: '1', BUILDX_BUILDER: 'default' };
  for (const name of ['DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']) delete environment[name];
  const temporary = mkdtempSync(path.join(os.tmpdir(), 'marty-runtime-docker-'));
  try {
    const result = runOwnedInstallCommand('docker', ['--host', endpoint, ...args], {
      cwd: ROOT, env: environment, timeout,
      stdoutFile: path.join(temporary, 'stdout'), stderrFile: path.join(temporary, 'stderr'),
    });
    const stdout = read(temporary, 'stdout').bytes;
    const stderr = read(temporary, 'stderr').bytes;
    require(stdout.length <= 2 * 1024 * 1024 && stderr.length <= 2 * 1024 * 1024, 'Docker output exceeds the capture bound');
    if (result.error) throw result.error;
    require(Number.isInteger(result.status), `Docker command terminated by ${result.signal || 'an unknown signal'}`);
    if (result.status !== 0 && !allowFailure) throw new Error(`Docker ${args[0]} failed: ${stderr.toString('utf8')}`);
    return { stdout: stdout.toString('utf8'), stderr: stderr.toString('utf8'), code: result.status };
  } finally { rmSync(temporary, { recursive: true, force: true }); }
}

// A substituted runner is only for protocol fixtures; it can never issue a
// report claiming that a real Docker image or container was qualified.
export async function checkApplicationRuntimeContainer({ context, reportPath }, { docker = defaultDocker } = {}) {
  const verified = validateApplicationRuntimeContext(context);
  const report = newDestination(reportPath, [verified.root]);
  require(path.extname(report) === '.json', 'Runtime report must use a JSON path');
  const fixture = docker !== defaultDocker;
  const operationDeadline = Date.now() + 8 * 60_000;
  const remaining = (limit = 30_000) => {
    require(Date.now() < operationDeadline, 'Runtime container check deadline exceeded');
    return Math.min(limit, operationDeadline - Date.now());
  };
  const command = (args, options = {}) => docker(args, { ...options, timeout: remaining(options.timeout || 30_000) });
  const { root, manifest, manifest_sha256: contextSha } = verified;
  const suffix = randomUUID().replaceAll('-', '');
  const tag = `marty-application-runtime-check:${suffix}`;
  const name = `marty-application-runtime-${suffix}`;
  let imageId;
  let containerId;
  let buildAttempted = false;
  let runAttempted = false;
  let failure;
  let result;
  const cleanup = { container_removed: false, image_removed: false };
  try {
    buildAttempted = true;
    await command(['build', '--pull', '--network=none', '--build-arg', `APPLICATION_CONTEXT_SHA=${contextSha}`,
      '--tag', tag, '--file', path.join(root, 'Dockerfile'), root], { timeout: 300_000 });
    const image = JSON.parse((await command(['image', 'inspect', tag])).stdout);
    require(Array.isArray(image) && image.length === 1 && /^sha256:[0-9a-f]{64}$/.test(image[0].Id), 'Docker did not identify the built image');
    require(image[0].Config?.Labels?.['io.elevenid.application-runtime.scope'] === 'diagnostic'
      && image[0].Config.Labels['io.elevenid.application-runtime.context-sha256'] === contextSha, 'Runtime image diagnostic labels differ');
    imageId = image[0].Id;
    runAttempted = true;
    containerId = (await command(['run', '--detach', '--rm', '--name', name,
      '--label', `io.elevenid.application-runtime.owner=${suffix}`,
      '--publish', '127.0.0.1::80', '--env', 'GOOGLE_ANALYTICS_MEASUREMENT_ID=',
      '--env', 'GOOGLE_SITE_VERIFICATION=', '--env', 'ORGANIZATION_CREATION_ENABLED=false', imageId])).stdout.trim();
    require(/^[0-9a-f]{64}$/.test(containerId), 'Docker did not identify the started container');
    const inspect = JSON.parse((await command(['container', 'inspect', containerId])).stdout);
    require(Array.isArray(inspect) && inspect.length === 1 && inspect[0].State?.Running === true
      && inspect[0].Image === imageId
      && inspect[0].Config?.Labels?.['io.elevenid.application-runtime.owner'] === suffix, 'Runtime container identity differs');
    const bindings = inspect[0].NetworkSettings?.Ports;
    require(bindings && Object.keys(bindings).length === 1 && Array.isArray(bindings['80/tcp'])
      && bindings['80/tcp'].length === 1 && bindings['80/tcp'][0].HostIp === '127.0.0.1'
      && /^[1-9][0-9]{0,4}$/.test(bindings['80/tcp'][0].HostPort), 'Runtime container is not published exclusively on loopback');
    const port = Number(bindings['80/tcp'][0].HostPort);
    require(port <= 65535, 'Invalid runtime loopback port');
    const origin = `http://127.0.0.1:${port}`;
    const expected = new Map(manifest.output_inventory.files.map((item) => [item.path,
      expectedDefaultRuntimeBytes(item.path, read(root, `html/${item.path}`).bytes)]));
    const readinessDeadline = Date.now() + 20_000;
    while (true) {
      try { await requestResource(origin, 'runtime-config.js', expected.get('runtime-config.js'), remaining(1000)); break; }
      catch (error) {
        if (Date.now() >= readinessDeadline) throw error;
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    }
    await command(['exec', containerId, 'nginx', '-t']);
    const paths = manifest.output_inventory.files.map((item) => `/usr/share/nginx/html/${item.path}`);
    require(paths.join('\0').length < 120_000, 'Runtime readability command exceeds its argument bound');
    const readable = await command(['exec', '--user', 'nginx', containerId, '/bin/sh', '-c',
      'for target do [ -f "$target" ] && [ ! -L "$target" ] && [ -r "$target" ] || exit 1; stat -c "%a:%s:%n" "$target" || exit 1; done',
      'runtime-readability', ...paths]);
    const lines = readable.stdout.trimEnd().split('\n');
    require(lines.length === paths.length, 'Runtime readability evidence is incomplete');
    for (let index = 0; index < paths.length; index++) {
      const relative = manifest.output_inventory.files[index].path;
      require(lines[index] === `644:${expected.get(relative).length}:${paths[index]}`, `Runtime resource mode or size differs: ${relative}`);
    }
    const served = [];
    for (const item of manifest.resource_result.served_resources) served.push(await requestResource(origin, item.path, expected.get(item.path), remaining(5000)));
    const routeMetadata = await requestResource(origin, 'marty-web-routes.json', expected.get('marty-web-routes.json'), remaining(5000));
    const missing = [];
    for (const relative of ['locales/en/__runtime_missing__.json', 'assets/__runtime_missing__.js', '__runtime_missing__.png']) {
      const response = await fetch(`${origin}/${relative}`, { redirect: 'manual', signal: AbortSignal.timeout(remaining(5000)) });
      await response.body?.cancel();
      require(response.status === 404, `Missing runtime resource did not return 404: ${relative}`);
      missing.push({ path: relative, status: response.status });
    }
    require(served.find((item) => item.path === manifest.sdk_wasm)?.content_type === 'application/wasm', 'SDK WASM MIME was not observed');
    require(validateApplicationRuntimeContext(root).manifest_sha256 === contextSha, 'Runtime checker changed its closed context');
    result = {
      schema: 'marty.application-runtime-container/v1', status: fixture ? 'fixture-passed' : 'passed',
      fixture, context_sha256: contextSha, source_commit: manifest.source_commit,
      effective_source_sha: manifest.effective_source_sha, exact_committed_source: manifest.exact_committed_source,
      base_image: APPLICATION_RUNTIME_BASE_IMAGE, image_id: imageId, container_id: containerId,
      endpoint: { host: '127.0.0.1', port }, public_resources_readable: [...APPLICATION_RETAINED_PUBLIC_FILES],
      all_output_resources_readable: manifest.output_inventory.files.map((item) => item.path),
      served_resources: served, route_metadata: routeMetadata, missing_resources: missing,
      runtime_transformations: manifest.output_inventory.files.filter((item) => item.path === 'runtime-config.js' || item.path.endsWith('.html'))
        .map((item) => ({ path: item.path, original_sha256: item.sha256, runtime_sha256: digest(expected.get(item.path)), mode: 0o644 })),
      qualification: { context_prepared: true, container_image_built: !fixture, container_resources_checked: !fixture,
        browser_startup_observed: false, host_deployment_tested: false, oidc_journey_tested: false,
        published: false, activated: false }, cleanup,
    };
  } catch (error) { failure = error; }
  finally {
    const cleanupErrors = [];
    try {
      if (runAttempted) {
        await docker(['container', 'rm', '--force', name], { allowFailure: true, timeout: 15_000 });
        const gone = await docker(['container', 'inspect', name], { allowFailure: true, timeout: 15_000 });
        require(gone.code !== 0 && /No such (?:object|container)/i.test(gone.stderr), 'Owned runtime container was not removed');
        cleanup.container_removed = true;
      }
    } catch (error) { cleanupErrors.push(error); }
    try {
      if (buildAttempted) {
        const remaining = await docker(['image', 'inspect', tag], { allowFailure: true, timeout: 15_000 });
        if (remaining.code === 0) {
          const metadata = JSON.parse(remaining.stdout);
          require(metadata.length === 1 && (!imageId || metadata[0].Id === imageId)
            && metadata[0].Config?.Labels?.['io.elevenid.application-runtime.scope'] === 'diagnostic'
            && metadata[0].Config.Labels['io.elevenid.application-runtime.context-sha256'] === contextSha,
            'Refusing cleanup of an image with a different owner');
          await docker(['image', 'rm', '--force', tag], { timeout: 15_000 });
        } else require(/No such (?:object|image)/i.test(remaining.stderr), 'Could not inspect owned runtime image during cleanup');
        const gone = await docker(['image', 'inspect', tag], { allowFailure: true, timeout: 15_000 });
        require(gone.code !== 0 && /No such (?:object|image)/i.test(gone.stderr), 'Owned runtime image was not removed');
        cleanup.image_removed = true;
      }
    } catch (error) { cleanupErrors.push(error); }
    if (cleanupErrors.length) failure = new AggregateError([...(failure ? [failure] : []), ...cleanupErrors], 'Runtime check or cleanup failed');
  }
  if (failure) throw failure;
  require(cleanup.container_removed && cleanup.image_removed, 'Runtime cleanup was incomplete');
  writeFileSync(report, `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  return result;
}

function cli(args) {
  const options = {};
  for (let index = 0; index < args.length; index++) {
    const flag = args[index];
    if (flag === '--check-container') { require(!options.check, 'Duplicate runtime option'); options.check = true; }
    else if (flag === '--context' || flag === '--report') {
      require(!options[flag] && args[index + 1], 'Duplicate or missing runtime option');
      options[flag] = args[++index];
    } else throw new Error(`Unknown runtime option: ${flag}`);
  }
  require(options.check && options['--context'] && options['--report'],
    'Usage: application-runtime-context.mjs --context ABS_DIR --report ABS_NEW_JSON --check-container');
  return { context: options['--context'], reportPath: options['--report'] };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = await checkApplicationRuntimeContainer(cli(process.argv.slice(2)));
    console.log(JSON.stringify({ status: result.status, context_sha256: result.context_sha256,
      served_resources: result.served_resources.length, public_resources: result.public_resources_readable.length, cleanup: result.cleanup }));
  } catch (error) {
    console.error(`Application runtime check failed: ${error.message}`);
    if (error instanceof AggregateError) for (const cause of error.errors) console.error(cause.message);
    process.exitCode = 1;
  }
}
