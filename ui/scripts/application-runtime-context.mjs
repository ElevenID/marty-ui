import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
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
const BROWSER_WORKER = fileURLToPath(new URL('./application-browser-startup.mjs', import.meta.url));
const BROWSER_PROCESS_BRIDGE = fileURLToPath(new URL('./application-browser-process.py', import.meta.url));
const BROWSER_DRIVER_INPUTS = Object.freeze([
  'ui/scripts/application-runtime-context.mjs', 'ui/scripts/application-browser-startup.mjs',
  'ui/scripts/application-browser-process.py', 'scripts/installer_startup_process.py',
]);
export const APPLICATION_RUNTIME_BASE_IMAGE = 'nginx:1.29.1-alpine@sha256:42a516af16b852e33b7682d5ef8acbd5d13fe08fecadc7ed98605ba5e3b26ab8';
export const APPLICATION_RELEASE_IMAGE = 'ghcr.io/elevenid/marty-ui-oss/application';
const RELEASE_RECIPE = 'docker/application.Dockerfile';
const RELEASE_SCHEMA = 'marty.application-image-check/v1';
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

function browserEnvironment() {
  const environment = {};
  for (const name of ['PATH', 'HOME', 'TMPDIR', 'TMP', 'TEMP', 'LANG', 'LC_ALL', 'LC_CTYPE']) {
    if (process.env[name] !== undefined) environment[name] = process.env[name];
  }
  require(typeof environment.HOME === 'string' && path.isAbsolute(environment.HOME), 'Browser process requires the unchanged absolute HOME');
  return environment;
}

// The existing Linux owner is a kernel subreaper: even a Chrome process that
// detaches and outlives a failed launcher is adopted, killed and reaped. A
// process-group timeout alone cannot provide that guarantee for Puppeteer.
export async function runApplicationBrowserProcess({ argv, timeoutMs = 120_000 }) {
  require(process.platform === 'linux' && Array.isArray(argv) && path.isAbsolute(argv[0]),
    'Application browser ownership requires a fixed absolute Linux command');
  require(Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= 120_000, 'Invalid browser process deadline');
  const environment = browserEnvironment();
  const result = await new Promise((resolve, reject) => {
    const child = spawn('python3', ['-I', '-S', BROWSER_PROCESS_BRIDGE,
      '--parent', String(process.pid), '--timeout', String(timeoutMs / 1000), '--', ...argv],
    { cwd: ROOT, env: environment, stdio: ['ignore', 'pipe', 'pipe'], shell: false });
    const output = [];
    let bytes = 0;
    let overflow = false;
    let timedOut = false;
    let settled = false;
    let cancellationDeadline;
    const finish = ({ code = null, signal = null, abandoned = false } = {}, error) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      clearTimeout(cancellationDeadline);
      if (abandoned) {
        // Stop waiting on this controller without terminating the independent
        // subreaper. Unknown ownership preserves the temporary browser state.
        child.stdout.destroy();
        child.stderr.destroy();
        child.unref();
      }
      if (error) reject(error);
      else resolve({ code, signal, overflow, timedOut, stdout: Buffer.concat(output).toString('utf8') });
    };
    const cancel = () => {
      child.kill('SIGTERM');
      cancellationDeadline ??= setTimeout(() => finish({ abandoned: true }), 2000);
    };
    // The owner implements the workload deadline and its own cleanup window.
    // This outer deadline cancels only its controller, never the subreaper,
    // then bounds the remaining wait even if the controller cannot exit.
    const deadline = setTimeout(() => { timedOut = true; cancel(); }, timeoutMs + 15_000);
    const capture = (chunk, stdout) => {
      bytes += chunk.length;
      if (bytes > 64 * 1024) { overflow = true; cancel(); }
      else if (stdout) output.push(chunk);
    };
    child.stdout.on('data', (chunk) => capture(chunk, true));
    child.stderr.on('data', (chunk) => capture(chunk, false));
    child.once('error', (error) => finish({}, error));
    child.once('close', (code, signal) => finish({ code, signal }));
  });
  let evidence;
  if (!result.overflow && !result.timedOut && result.signal === null) {
    try { evidence = JSON.parse(result.stdout); } catch { /* No ownership proof. */ }
  }
  const valid = evidence?.schema === 'marty.application-browser-process/v1'
    && ['passed', 'failed', 'cleanup-pending'].includes(evidence.status)
    && typeof evidence.descendants_reaped === 'boolean'
    && evidence.guardian?.path === 'scripts/installer_startup_process.py'
    && evidence.guardian.sha256 === read(ROOT, 'scripts/installer_startup_process.py').record.sha256;
  if (!valid || result.code !== 0 || evidence.status !== 'passed' || !evidence.descendants_reaped) {
    const error = new Error(valid && evidence.descendants_reaped
      ? 'Application browser worker failed after descendant cleanup'
      : 'Application browser process cleanup is unproven; its isolated owner remains responsible when available');
    error.cleanupComplete = Boolean(valid && evidence.descendants_reaped);
    error.processEvidence = valid ? evidence : undefined;
    throw error;
  }
  return evidence;
}

async function defaultBrowserWorker({ origin, runtimeContext, contextManifestSha256, channel, timeoutMs }) {
  const drivers = BROWSER_DRIVER_INPUTS.map((name) => read(ROOT, name).record);
  const temporary = mkdtempSync(path.join(os.tmpdir(), 'marty-application-browser-'));
  const output = path.join(temporary, 'browser.json');
  let cleaned = false;
  let processEvidence;
  let workerReport;
  const readReport = () => {
    const raw = read(temporary, 'browser.json');
    require(raw.record.bytes <= 1024 * 1024, 'Application browser report exceeds its bound');
    return JSON.parse(raw.bytes.toString('utf8'));
  };
  try {
    processEvidence = await runApplicationBrowserProcess({ timeoutMs,
      argv: [process.execPath, BROWSER_WORKER, '--worker', '--origin', origin, '--context', runtimeContext,
        '--manifest-sha256', contextManifestSha256, '--temporary-root', temporary, '--report', output, '--channel', channel] });
    cleaned = true;
    workerReport = readReport();
    assert.deepEqual(BROWSER_DRIVER_INPUTS.map((name) => read(ROOT, name).record), drivers, 'Browser diagnostic tool source changed');
    return { report: workerReport, process_evidence: processEvidence, driver_inputs: drivers };
  } catch (error) {
    cleaned ||= error.cleanupComplete === true;
    processEvidence ||= error.processEvidence;
    if (cleaned) {
      try {
        workerReport ||= readReport();
        const phase = workerReport.failure?.phase;
        if (workerReport.status === 'failed' && typeof phase === 'string' && /^[a-z0-9:/?=%&_-]{1,128}$/i.test(phase)) {
          error.message += ` (worker stage: ${phase})`;
          const detail = workerReport.failure?.message;
          if (typeof detail === 'string' && detail.length <= 1000) {
            error.message += `: ${detail.replace(/[^\x20-\x7e]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 800)}`;
          }
        }
      } catch { /* A missing failure diagnostic cannot hide the process failure. */ }
    } else error.message += `; retained owned diagnostic directory: ${temporary}`;
    // Preserve bounded diagnostics for a failed artifact after the outer
    // runtime cleanup. They never become a successful qualification.
    error.browserDiagnostics = { report: workerReport, process_evidence: processEvidence, driver_inputs: drivers,
      retained_directory: cleaned ? null : temporary };
    throw error;
  } finally {
    // CleanupPending deliberately leaves the directory with its surviving
    // owner. Never remove a live browser profile or call that case successful.
    if (cleaned) rmSync(temporary, { recursive: true, force: true });
  }
}

// Reuse the same byte-bound observation checks when the reviewed producer
// records a release. This validates evidence and never launches a browser.
export async function verifyApplicationBrowserResult(browser, { origin, root, manifest, contextSha, channel }) {
  require(browser?.schema === 'marty.application-browser-startup/v1' && ['passed', 'fixture-passed'].includes(browser.status)
    && typeof browser.fixture === 'boolean' && (browser.status === 'fixture-passed') === browser.fixture,
  'Application browser worker did not complete its qualification');
  require(browser.context_sha256 === contextSha && browser.origin === origin
    && browser.source_commit === manifest.source_commit && browser.effective_source_sha === manifest.effective_source_sha
    && browser.exact_committed_source === manifest.exact_committed_source,
  'Application browser report differs from the owned runtime identity');
  require(browser.browser?.channel === channel && browser.browser.sandboxed === !browser.fixture
    && typeof browser.browser.version === 'string' && browser.browser.version.length > 0,
  'Application browser did not prove the selected sandboxed browser');
  require(browser.cleanup?.browser_closed === true && browser.cleanup.chromium_exited === true
    && browser.cleanup.contexts_closed === true && browser.cleanup.profile_removed === true,
  'Application browser cleanup was incomplete');
  for (const key of ['browser_startup_observed', 'sdk_wasm_initialized_in_browser']) {
    require(browser.qualification?.[key] === !browser.fixture, 'Application browser fixture overstates its qualification');
  }
  for (const key of ['host_deployment_tested', 'oidc_journey_tested', 'published', 'activated']) {
    require(browser.qualification?.[key] === false, 'Application browser report broadened its qualification');
  }
  // Importing the observation validator never loads Puppeteer. The browser
  // dependency itself is resolved only by the explicit, separately owned worker.
  const { APPLICATION_BROWSER_ROUTES, validateApplicationBrowserRouteEvidence } = await import('./application-browser-startup.mjs');
  require(Array.isArray(browser.routes) && browser.routes.length === APPLICATION_BROWSER_ROUTES.length,
    'Application browser omitted a required entrypoint');
  const wasm = manifest.output_inventory.files.find((row) => row.path === manifest.sdk_wasm);
  const expected = new Map(manifest.output_inventory.files.map((row) => [row.path,
    expectedDefaultRuntimeBytes(row.path, read(root, `html/${row.path}`).bytes)]));
  const policy = read(ROOT, 'ui/nginx.prod.conf').bytes.toString('utf8').match(/add_header Content-Security-Policy "([^"]+)" always;/)?.[1];
  require(policy, 'Reviewed runtime CSP is missing');
  function bindObservedResources(route, negative = false) {
    const navigationPath = route.route.startsWith('/console') ? 'console/index.html' : 'index.html';
    const document = expected.get(navigationPath);
    require(route.navigation.bytes === document.length && route.navigation.sha256 === digest(document)
      && route.navigation.content_security_policy === policy, 'Browser document bytes or CSP differ from the owned runtime');
    const seen = new Set();
    for (const item of route.assets) {
      const bytes = expected.get(item.path);
      const url = new URL(item.url);
      require(bytes && item.bytes === bytes.length && item.sha256 === digest(bytes)
        && url.origin === origin && url.pathname === `/${item.path}`
        && (!url.search || (item.path === 'favicon.ico' && url.search === '?v=2')),
      'Browser asset bytes or identity differ from the owned runtime');
      seen.add(item.path);
    }
    for (const name of ['runtime-config.js', 'startup.js', ...(negative ? [] : ['config.json', 'locales/en/common.json', wasm.path])]) {
      require(seen.has(name), `Browser did not observe a required startup resource: ${name}`);
    }
  }
  for (let index = 0; index < APPLICATION_BROWSER_ROUTES.length; index++) {
    validateApplicationBrowserRouteEvidence(browser.routes[index], { origin, route: APPLICATION_BROWSER_ROUTES[index], wasm });
    bindObservedResources(browser.routes[index]);
  }
  validateApplicationBrowserRouteEvidence(browser.negative_control,
    { origin, route: APPLICATION_BROWSER_ROUTES[0], wasm, negative: true });
  bindObservedResources(browser.negative_control, true);
}

function failureMessages(error) {
  const pending = [error];
  const messages = [];
  let inspected = 0;
  while (pending.length && messages.length < 8 && inspected++ < 16) {
    const item = pending.shift();
    if (item instanceof AggregateError && item.errors.length) pending.unshift(...item.errors.slice(0, 8));
    else messages.push(String(item?.message || item).replace(/[^\x20-\x7e]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 1000));
  }
  return messages;
}

function failedBrowserReport({ error, phase, fixture, manifest, contextSha, contextUnchanged, origin,
  imageId, containerId, cleanup, evidence, diagnostics, runtimeSchema, imageIdentity }) {
  const observation = evidence?.report || diagnostics?.report;
  const processEvidence = evidence?.process_evidence || diagnostics?.process_evidence;
  let validProcess = false;
  try {
    validProcess = processEvidence?.schema === 'marty.application-browser-process/v1'
      && ['passed', 'failed', 'cleanup-pending'].includes(processEvidence.status)
      && typeof processEvidence.descendants_reaped === 'boolean'
      && processEvidence.guardian?.path === 'scripts/installer_startup_process.py'
      && processEvidence.guardian.sha256 === read(ROOT, 'scripts/installer_startup_process.py').record.sha256;
  } catch { /* Changed or missing diagnostic source proves no process cleanup. */ }
  const identified = observation?.schema === 'marty.application-browser-startup/v1'
    && observation.context_sha256 === contextSha && observation.source_commit === manifest.source_commit
    && observation.effective_source_sha === manifest.effective_source_sha && observation.origin === origin;
  return {
    schema: 'marty.application-browser-startup/v1', status: 'failed', fixture: fixture || observation?.fixture === true,
    context_sha256: contextSha, source_commit: manifest.source_commit,
    effective_source_sha: manifest.effective_source_sha, exact_committed_source: manifest.exact_committed_source,
    origin, context_unchanged: contextUnchanged,
    qualification: { browser_startup_observed: false, sdk_wasm_initialized_in_browser: false,
      host_deployment_tested: false, oidc_journey_tested: false, published: false, activated: false },
    cleanup: { ...Object.fromEntries(['browser_closed', 'chromium_exited', 'contexts_closed', 'profile_removed']
      .map((key) => [key, Boolean(identified && observation.cleanup?.[key] === true)])),
    worker_descendants_reaped: Boolean(validProcess && processEvidence.descendants_reaped) },
    process_evidence: validProcess ? processEvidence : null,
    diagnostic_tool_inputs: evidence?.driver_inputs || diagnostics?.driver_inputs || [],
    retained_diagnostic_directory: diagnostics?.retained_directory || null,
    runtime: { schema: runtimeSchema, ...imageIdentity, context_sha256: contextSha,
      image_id: imageId || null, container_id: containerId || null,
      endpoint: origin ? { host: '127.0.0.1', port: Number(new URL(origin).port) } : null, cleanup: { ...cleanup } },
    failure: { phase, messages: failureMessages(error) },
  };
}

// A substituted runner is only for protocol fixtures; it can never issue a
// report claiming that a real Docker image or container was qualified.
export async function checkApplicationRuntimeContainer({ context, reportPath, browserStartup = false,
  browserReportPath, browserChannel, imageReference, buildReleaseImage = false },
{ docker = defaultDocker, browserWorker = defaultBrowserWorker } = {}) {
  const verified = validateApplicationRuntimeContext(context);
  require(typeof buildReleaseImage === 'boolean' && !(buildReleaseImage && imageReference !== undefined),
    'Select one application image mode');
  require(imageReference === undefined || (typeof imageReference === 'string'
    && imageReference.startsWith(`${APPLICATION_RELEASE_IMAGE}@`)
    && /^sha256:[0-9a-f]{64}$/.test(imageReference.slice(APPLICATION_RELEASE_IMAGE.length + 1))),
  'Application image reference must use the fixed repository and a canonical digest');
  const releaseImage = buildReleaseImage || imageReference !== undefined;
  require(!releaseImage || (verified.manifest.exact_committed_source
    && verified.manifest.effective_source_sha === verified.manifest.source_commit),
  'Application release image requires exact committed source');
  const runtimeSchema = releaseImage ? RELEASE_SCHEMA : 'marty.application-runtime-container/v1';
  const imageIdentity = releaseImage ? { image_mode: imageReference ? 'published-digest' : 'local-release-build',
    image_reference: imageReference || null, recipe_input: read(ROOT, RELEASE_RECIPE).record } : {};
  const report = newDestination(reportPath, [verified.root]);
  require(path.extname(report) === '.json', 'Runtime report must use a JSON path');
  require(typeof browserStartup === 'boolean' && (browserStartup
    ? Boolean(browserReportPath) && browserChannel === 'chrome' : !browserReportPath && !browserChannel),
  'Browser startup requires a separate report and the sandboxed chrome channel');
  const browserReport = browserStartup ? newDestination(browserReportPath, [verified.root]) : undefined;
  require(!browserReport || (path.extname(browserReport) === '.json' && browserReport !== report), 'Browser and runtime reports must be distinct JSON files');
  const fixture = docker !== defaultDocker || (browserStartup && browserWorker !== defaultBrowserWorker);
  require(!browserStartup || docker === defaultDocker || browserWorker !== defaultBrowserWorker,
    'A Docker protocol fixture must also supply a browser fixture');
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
  let browserEvidence;
  let browserDiagnostics;
  let origin = null;
  let phase = imageReference ? 'image-pull' : 'image-build';
  let failurePhase;
  let contextUnchanged = false;
  const cleanup = { container_removed: false, image_removed: false,
    ...(releaseImage ? { image_cache_retained: Boolean(imageReference) } : {}) };
  const correctImageLabels = (metadata) => {
    const labels = metadata?.Config?.Labels;
    return releaseImage
      ? metadata.Os === 'linux' && metadata.Architecture === 'amd64'
        && labels?.['org.opencontainers.image.source'] === 'https://github.com/ElevenID/marty-ui'
        && labels['org.opencontainers.image.revision'] === manifest.source_commit
        && labels['io.elevenid.ui.audience'] === 'production'
        && labels['io.elevenid.ui.surface'] === 'application'
        && labels['io.elevenid.application.context-sha256'] === contextSha
      : labels?.['io.elevenid.application-runtime.scope'] === 'diagnostic'
        && labels['io.elevenid.application-runtime.context-sha256'] === contextSha;
  };
  const verifyImmutableInputs = () => {
    require(validateApplicationRuntimeContext(root).manifest_sha256 === contextSha,
      'Runtime check or cleanup changed its closed context');
    if (releaseImage) assert.deepEqual(read(ROOT, RELEASE_RECIPE).record, imageIdentity.recipe_input,
      'Application image recipe changed during its runtime check');
  };
  try {
    if (imageReference) await command(['pull', '--platform', 'linux/amd64', imageReference], { timeout: 300_000 });
    else {
      buildAttempted = true;
      await command(['build', '--pull', '--network=none',
        ...(releaseImage ? ['--platform', 'linux/amd64', '--build-arg', `APPLICATION_SOURCE_SHA=${manifest.source_commit}`] : []),
        '--build-arg', `APPLICATION_CONTEXT_SHA=${contextSha}`,
        '--tag', tag, '--file', releaseImage ? path.join(ROOT, RELEASE_RECIPE) : path.join(root, 'Dockerfile'), root],
      { timeout: 300_000 });
    }
    const image = JSON.parse((await command(['image', 'inspect', imageReference || tag])).stdout);
    require(Array.isArray(image) && image.length === 1 && /^sha256:[0-9a-f]{64}$/.test(image[0].Id), 'Docker did not identify the selected image');
    require(correctImageLabels(image[0]), releaseImage ? 'Application image source, platform or labels differ' : 'Runtime image diagnostic labels differ');
    require(!imageReference || (Array.isArray(image[0].RepoDigests) && image[0].RepoDigests.includes(imageReference)),
      'Application image digest differs from the requested immutable reference');
    imageId = image[0].Id;
    phase = 'runtime-startup';
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
    origin = `http://127.0.0.1:${port}`;
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
    phase = 'runtime-resources';
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
    let verifiedOutputResources;
    if (releaseImage) {
      // The image check also closes the container's complete output roster.
      // HTTP/browser probes cover behavior; this binds every runtime file,
      // including resources that the observed startup does not request.
      const listing = await command(['exec', containerId, 'find', '/usr/share/nginx/html', '-mindepth', '1', '!', '-type', 'd', '-print']);
      assert.deepEqual(listing.stdout.trimEnd().split('\n').sort(), [...paths].sort(),
        'Application image output membership differs from its qualified context');
      const hashes = await command(['exec', containerId, 'sha256sum', ...paths]);
      const lines = hashes.stdout.trimEnd().split('\n');
      require(lines.length === paths.length, 'Application image byte evidence is incomplete');
      verifiedOutputResources = manifest.output_inventory.files.map((item, index) => {
        const bytes = expected.get(item.path);
        const sha256 = digest(bytes);
        require(lines[index] === `${sha256.slice(7)}  ${paths[index]}`,
          `Application image output bytes differ: ${item.path}`);
        return { path: item.path, bytes: bytes.length, sha256, mode: 0o644 };
      });
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
    if (browserStartup) {
      phase = 'browser-worker';
      browserEvidence = await browserWorker({ origin, runtimeContext: root, contextManifestSha256: contextSha,
        channel: browserChannel, timeoutMs: remaining(120_000) });
      phase = 'browser-evidence';
      require(browserEvidence?.process_evidence?.status === 'passed' && browserEvidence.process_evidence.descendants_reaped === true,
        'Application browser did not prove complete worker descendant cleanup');
      assert.deepEqual(browserEvidence.driver_inputs, BROWSER_DRIVER_INPUTS.map((name) => read(ROOT, name).record),
        'Application browser diagnostic tool identity differs');
      require(browserEvidence.process_evidence.guardian?.path === 'scripts/installer_startup_process.py'
        && browserEvidence.process_evidence.guardian.sha256 === read(ROOT, 'scripts/installer_startup_process.py').record.sha256,
      'Application browser used a different process guardian');
      await verifyApplicationBrowserResult(browserEvidence.report, { origin, root, manifest, contextSha, channel: browserChannel });
    }
    phase = 'context-revalidation';
    verifyImmutableInputs();
    const qualificationFixture = fixture || Boolean(browserEvidence?.report.fixture);
    result = {
      schema: runtimeSchema, ...imageIdentity, status: qualificationFixture ? 'fixture-passed' : 'passed',
      fixture: qualificationFixture, context_sha256: contextSha, source_commit: manifest.source_commit,
      effective_source_sha: manifest.effective_source_sha, exact_committed_source: manifest.exact_committed_source,
      base_image: APPLICATION_RUNTIME_BASE_IMAGE, image_id: imageId, container_id: containerId,
      endpoint: { host: '127.0.0.1', port }, public_resources_readable: [...APPLICATION_RETAINED_PUBLIC_FILES],
      all_output_resources_readable: manifest.output_inventory.files.map((item) => item.path),
      ...(releaseImage ? { output_resources_verified: verifiedOutputResources } : {}),
      served_resources: served, route_metadata: routeMetadata, missing_resources: missing,
      runtime_transformations: manifest.output_inventory.files.filter((item) => item.path === 'runtime-config.js' || item.path.endsWith('.html'))
        .map((item) => ({ path: item.path, original_sha256: item.sha256, runtime_sha256: digest(expected.get(item.path)), mode: 0o644 })),
      qualification: { context_prepared: true, container_image_built: !qualificationFixture && !imageReference,
        ...(releaseImage ? { immutable_image_verified: !qualificationFixture && Boolean(imageReference) } : {}),
        container_resources_checked: !qualificationFixture,
        browser_startup_observed: browserStartup && !qualificationFixture, host_deployment_tested: false, oidc_journey_tested: false,
        published: false, activated: false }, cleanup,
    };
  } catch (error) {
    failure = error;
    failurePhase = phase;
    browserDiagnostics = error.browserDiagnostics;
  }
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
            && correctImageLabels(metadata[0]),
            'Refusing cleanup of an image with a different owner');
          await docker(['image', 'rm', '--force', tag], { timeout: 15_000 });
        } else require(/No such (?:object|image)/i.test(remaining.stderr), 'Could not inspect owned runtime image during cleanup');
        const gone = await docker(['image', 'inspect', tag], { allowFailure: true, timeout: 15_000 });
        require(gone.code !== 0 && /No such (?:object|image)/i.test(gone.stderr), 'Owned runtime image was not removed');
        cleanup.image_removed = true;
      }
    } catch (error) { cleanupErrors.push(error); }
    try {
      verifyImmutableInputs();
      contextUnchanged = true;
    } catch (error) { cleanupErrors.push(error); }
    if (cleanupErrors.length) {
      failurePhase ||= 'runtime-cleanup';
      failure = new AggregateError([...(failure ? [failure] : []), ...cleanupErrors], 'Runtime check or cleanup failed');
    }
  }
  if (failure) {
    // Browser failures must survive the always-upload CI step, but a failed
    // artifact cannot assert any successful qualification. Publish only after
    // both independent runtime cleanup attempts and context revalidation.
    if (browserStartup) {
      try {
        const browser = failedBrowserReport({ error: failure, phase: failurePhase, fixture, manifest, contextSha,
          contextUnchanged, origin, imageId, containerId, cleanup, evidence: browserEvidence, diagnostics: browserDiagnostics,
          runtimeSchema, imageIdentity });
        const bytes = Buffer.from(`${JSON.stringify(browser, null, 2)}\n`);
        writeFileSync(browserReport, bytes, { flag: 'wx', mode: 0o600 });
        const failedRuntime = { schema: runtimeSchema, ...imageIdentity, status: 'failed', fixture: browser.fixture,
          context_sha256: contextSha, source_commit: manifest.source_commit,
          effective_source_sha: manifest.effective_source_sha, exact_committed_source: manifest.exact_committed_source,
          base_image: APPLICATION_RUNTIME_BASE_IMAGE, image_id: imageId || null, container_id: containerId || null,
          endpoint: browser.runtime.endpoint, context_unchanged: contextUnchanged,
          qualification: { context_prepared: false, container_image_built: false, container_resources_checked: false,
            ...(releaseImage ? { immutable_image_verified: false } : {}),
            browser_startup_observed: false, host_deployment_tested: false, oidc_journey_tested: false,
            published: false, activated: false }, cleanup: { ...cleanup }, failure: browser.failure,
          browser_startup: { report_path: browserReport, bytes: bytes.length, sha256: digest(bytes), schema: browser.schema,
            status: 'failed', sdk_wasm_initialized_in_browser: false,
            worker_descendants_reaped: browser.cleanup.worker_descendants_reaped } };
        writeFileSync(report, `${JSON.stringify(failedRuntime, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
      } catch (error) { throw new AggregateError([failure, error], 'Runtime failed and could not preserve its browser diagnostics'); }
    }
    throw failure;
  }
  require(cleanup.container_removed && (imageReference ? cleanup.image_cache_retained && !cleanup.image_removed : cleanup.image_removed),
    'Runtime cleanup was incomplete');
  if (browserStartup) {
    const observation = browserEvidence.report;
    const browser = { ...observation, status: result.fixture ? 'fixture-passed' : 'passed', fixture: result.fixture,
      browser: { ...observation.browser, sandboxed: !result.fixture },
      qualification: { ...observation.qualification, browser_startup_observed: !result.fixture,
        sdk_wasm_initialized_in_browser: !result.fixture },
      process_evidence: browserEvidence.process_evidence, diagnostic_tool_inputs: browserEvidence.driver_inputs,
      runtime: { schema: result.schema, ...imageIdentity, context_sha256: contextSha, image_id: imageId, container_id: containerId,
        endpoint: result.endpoint, cleanup: { ...cleanup } } };
    const bytes = Buffer.from(`${JSON.stringify(browser, null, 2)}\n`);
    writeFileSync(browserReport, bytes, { flag: 'wx', mode: 0o600 });
    result.browser_startup = { report_path: browserReport, bytes: bytes.length, sha256: digest(bytes),
      schema: browser.schema, status: browser.status, sdk_wasm_initialized_in_browser: !result.fixture,
      worker_descendants_reaped: true };
  }
  writeFileSync(report, `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  return result;
}

function cli(args) {
  const options = {};
  for (let index = 0; index < args.length; index++) {
    const flag = args[index];
    if (flag === '--check-container') { require(!options.check, 'Duplicate runtime option'); options.check = true; }
    else if (flag === '--browser-startup') { require(!options.browserStartup, 'Duplicate runtime option'); options.browserStartup = true; }
    else if (flag === '--build-release-image') { require(!options.buildReleaseImage, 'Duplicate runtime option'); options.buildReleaseImage = true; }
    else if (['--context', '--report', '--browser-report', '--browser-channel', '--image-reference'].includes(flag)) {
      require(!options[flag] && args[index + 1] && !args[index + 1].startsWith('--'), 'Duplicate or missing runtime option');
      options[flag] = args[++index];
    } else throw new Error(`Unknown runtime option: ${flag}`);
  }
  require(options.check && options['--context'] && options['--report'],
    'Usage: application-runtime-context.mjs --context ABS_DIR --report ABS_NEW_JSON --check-container');
  return { context: options['--context'], reportPath: options['--report'], browserStartup: Boolean(options.browserStartup),
    browserReportPath: options['--browser-report'], browserChannel: options['--browser-channel'],
    imageReference: options['--image-reference'], buildReleaseImage: Boolean(options.buildReleaseImage) };
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
