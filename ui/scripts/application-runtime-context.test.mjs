import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { createServer } from 'node:http';
import {
  chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync,
  rmSync, symlinkSync, unlinkSync, writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { APPLICATION_RETAINED_PUBLIC_FILES, APPLICATION_RESOURCE_MIME_TYPES } from './application-public-assets.mjs';
import {
  APPLICATION_RUNTIME_BASE_IMAGE, APPLICATION_RUNTIME_INPUTS, checkApplicationRuntimeContainer,
  createApplicationRuntimeContext, expectedDefaultRuntimeBytes, validateApplicationRuntimeContext,
} from './application-runtime-context.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const execFileAsync = promisify(execFile);
const COMMIT = 'a'.repeat(40);
const SDK = 'assets/marty_api_client_bg-fixture.wasm';
function digest(bytes) { return `sha256:${createHash('sha256').update(bytes).digest('hex')}`; }
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function write(root, relative, bytes, mode = 0o644) {
  const target = path.join(root, relative);
  mkdirSync(path.dirname(target), { recursive: true, mode: 0o755 });
  writeFileSync(target, bytes);
  chmodSync(target, mode);
}
function files(root, relative = '') {
  return readdirSync(path.join(root, relative), { withFileTypes: true }).flatMap((entry) => {
    const name = relative ? `${relative}/${entry.name}` : entry.name;
    return entry.isDirectory() ? files(root, name) : [name];
  }).sort();
}
function record(root, relative) {
  const bytes = readFileSync(path.join(root, relative));
  return { path: relative, bytes: bytes.length, sha256: digest(bytes), mode: lstatSync(path.join(root, relative)).mode & 0o777 };
}
function byteRecord({ path: name, bytes, sha256 }) { return { path: name, bytes, sha256 }; }
function fixture(t, marker = COMMIT) {
  const temporary = mkdtempSync(path.join(os.tmpdir(), 'marty-runtime-context-'));
  t.after(() => rmSync(temporary, { recursive: true, force: true }));
  const sourceRoot = path.join(temporary, 'source');
  const outputRoot = path.join(temporary, 'output');
  mkdirSync(sourceRoot);
  mkdirSync(outputRoot);
  for (const input of APPLICATION_RUNTIME_INPUTS) write(sourceRoot, input.path, readFileSync(path.join(ROOT, input.path)));
  for (const name of APPLICATION_RETAINED_PUBLIC_FILES) write(outputRoot, name, readFileSync(path.join(ROOT, 'ui/public', name)), 0o600);
  const html = '<!doctype html><html><head><meta name="google-site-verification" content="old"></head><body>Application</body></html>\n';
  write(outputRoot, 'index.html', html);
  write(outputRoot, 'console/index.html', html);
  write(outputRoot, 'assets/application.js', 'export const application = true;\n');
  write(outputRoot, 'assets/application.css', 'body { color: black; }\n');
  write(outputRoot, SDK, Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]));
  write(outputRoot, 'marty-web-routes.json', JSON.stringify({ schema: 'marty.application-web-compatibility/v1',
    surface: 'application', source_sha: marker, route_contract: { version: 1, sha256: `sha256:${'b'.repeat(64)}` } }));
  const outputFiles = files(outputRoot).map((name) => record(outputRoot, name));
  const publicResources = APPLICATION_RETAINED_PUBLIC_FILES.map((name) => byteRecord(record(outputRoot, name)));
  const outputInventory = { files: outputFiles, inventory_sha256: digest(canonical(outputFiles)), public_resources: publicResources };
  const resourceResult = { schema: 'marty.application-resource-smoke/v1', status: 'passed',
    public_resources: publicResources,
    served_resources: outputFiles.filter((item) => item.path !== 'marty-web-routes.json').map((item) => ({
      ...byteRecord(item), content_type: APPLICATION_RESOURCE_MIME_TYPES[path.extname(item.path)][0], status: 200,
    })), preview: { host: '127.0.0.1', port: 12345, closed: true },
    qualification: { resources_served: true, locale_fallback_observed: true, browser_startup_observed: false,
      host_deployment_tested: false, oidc_journey_tested: false } };
  return { temporary, sourceRoot, outputRoot, destination: path.join(temporary, 'context'),
    sourceCommit: COMMIT, outputInventory, resourceResult };
}

test('closed runtime context preserves bytes and records all public mode conversions', (t) => {
  const input = fixture(t);
  const created = createApplicationRuntimeContext(input);
  const checked = validateApplicationRuntimeContext(input.destination);
  assert.equal(created.manifest_sha256, checked.manifest_sha256);
  assert.equal(created.base_image, APPLICATION_RUNTIME_BASE_IMAGE);
  assert.equal(created.exact_committed_source, true);
  assert.equal(created.effective_source_sha, COMMIT);
  for (const name of APPLICATION_RETAINED_PUBLIC_FILES) {
    const original = record(input.outputRoot, name);
    const packaged = record(input.destination, `html/${name}`);
    assert.equal(original.mode, 0o600);
    assert.equal(packaged.mode, 0o644);
    assert.equal(packaged.sha256, original.sha256);
    assert.deepEqual(created.mode_transformations.find((item) => item.path === `html/${name}`),
      { path: `html/${name}`, source_mode: 0o600, packaged_mode: 0o644 });
  }
  for (const name of ['scripts/ui-production-start.sh', 'scripts/load-secrets-env.sh']) {
    assert.equal(record(input.destination, name).mode, 0o755);
    assert.deepEqual(readFileSync(path.join(input.destination, name)), readFileSync(path.join(ROOT, name)));
  }
  assert.deepEqual(created.output_inventory, input.outputInventory);
  assert.equal(created.qualification.container_image_built, false);
  assert.equal(created.qualification.host_deployment_tested, false);
  assert.deepEqual(files(input.destination), [...created.context_inventory.map((item) => item.path), 'application-runtime-context.json'].sort());
});

test('development output never acquires exact-commit qualification from its base HEAD', (t) => {
  const input = fixture(t, 'development');
  const created = createApplicationRuntimeContext(input);
  assert.equal(created.source_commit, COMMIT);
  assert.equal(created.effective_source_sha, 'development');
  assert.equal(created.exact_committed_source, false);
  validateApplicationRuntimeContext(input.destination);
});

test('the original output inventory digest stays bound before packaging mode normalization', (t) => {
  const input = fixture(t);
  createApplicationRuntimeContext(input);
  const filename = 'application-runtime-context.json';
  const manifest = JSON.parse(readFileSync(path.join(input.destination, filename)));
  manifest.output_inventory.inventory_sha256 = `sha256:${'0'.repeat(64)}`;
  write(input.destination, filename, JSON.stringify(manifest));
  assert.throws(() => validateApplicationRuntimeContext(input.destination), /Original runtime output inventory digest differs/);
});

test('changed output, incomplete resource evidence, missing SDK and changed hooks fail before publication', (t) => {
  const input = fixture(t);
  const original = readFileSync(path.join(input.outputRoot, 'assets/application.js'));
  write(input.outputRoot, 'assets/application.js', 'changed');
  assert.throws(() => createApplicationRuntimeContext(input), /verified output inventory/);
  write(input.outputRoot, 'assets/application.js', original);
  const removed = input.resourceResult.served_resources.pop();
  assert.throws(() => createApplicationRuntimeContext(input), /omitted a required runtime resource/);
  input.resourceResult.served_resources.push(removed);
  const sdkBytes = readFileSync(path.join(input.outputRoot, SDK));
  unlinkSync(path.join(input.outputRoot, SDK));
  assert.throws(() => createApplicationRuntimeContext(input), /verified output inventory/);
  write(input.outputRoot, SDK, sdkBytes);
  write(input.sourceRoot, 'scripts/ui-production-start.sh', '#!/bin/sh\nexit 0\n');
  assert.throws(() => createApplicationRuntimeContext(input), /reviewed source/);
  assert.equal(existsSync(input.destination), false);
});

for (const alteration of ['extra-file', 'empty-directory', 'asset-bytes', 'unreadable-asset', 'script-mode', 'symlink']) {
  test(`context checker refuses ${alteration} before Docker use`, async (t) => {
    const input = fixture(t);
    createApplicationRuntimeContext(input);
    if (alteration === 'extra-file') write(input.destination, 'unreviewed.txt', 'extra');
    if (alteration === 'empty-directory') mkdirSync(path.join(input.destination, 'extra'));
    if (alteration === 'asset-bytes') write(input.destination, 'html/config.json', '{}');
    if (alteration === 'unreadable-asset') chmodSync(path.join(input.destination, 'html/config.json'), 0o600);
    if (alteration === 'script-mode') chmodSync(path.join(input.destination, 'scripts/ui-production-start.sh'), 0o644);
    if (alteration === 'symlink') {
      unlinkSync(path.join(input.destination, 'html/config.json'));
      symlinkSync(path.join(input.outputRoot, 'config.json'), path.join(input.destination, 'html/config.json'));
    }
    let called = false;
    await assert.rejects(checkApplicationRuntimeContainer({ context: input.destination, reportPath: path.join(input.temporary, 'runtime.json') },
      { docker: async () => { called = true; throw new Error('Docker must not run'); } }));
    assert.equal(called, false);
  });
}

test('context destination must be new and outside the source and output', (t) => {
  const input = fixture(t);
  assert.throws(() => createApplicationRuntimeContext({ ...input, destination: path.join(input.sourceRoot, 'context') }), /outside source and output/);
  assert.throws(() => createApplicationRuntimeContext({ ...input, destination: path.join(input.outputRoot, 'context') }), /outside source and output/);
  mkdirSync(input.destination);
  assert.throws(() => createApplicationRuntimeContext(input), /already exists/);
});

test('expected runtime transformations match the actual unchanged shell hook with default settings', async (t) => {
  const input = fixture(t);
  const actualRoot = path.join(input.temporary, 'hook-output');
  mkdirSync(actualRoot);
  for (const name of files(input.outputRoot)) write(actualRoot, name, readFileSync(path.join(input.outputRoot, name)));
  const originalHook = readFileSync(path.join(ROOT, 'scripts/ui-production-start.sh'), 'utf8');
  // All published HTML currently ends in a newline. GNU sed preserves an
  // unterminated line; the Alpine runtime model separately accounts for the
  // BusyBox/POSIX newline, so this host fixture covers their common behavior.
  for (const name of files(input.outputRoot).filter((name) => name.endsWith('.html'))) {
    assert.equal(readFileSync(path.join(input.outputRoot, name)).at(-1), 10);
  }
  const hook = originalHook.replace('TARGET_DIR="/usr/share/nginx/html"', `TARGET_DIR="${actualRoot}"`)
    .replace('. /scripts/load-secrets-env.sh', `. "${path.join(input.sourceRoot, 'scripts/load-secrets-env.sh')}"`);
  write(input.temporary, 'isolated-hook.sh', hook);
  await execFileAsync('/bin/sh', [path.join(input.temporary, 'isolated-hook.sh')], { env: { PATH: process.env.PATH }, timeout: 5000 });
  for (const name of files(input.outputRoot)) {
    assert.deepEqual(readFileSync(path.join(actualRoot, name)), expectedDefaultRuntimeBytes(name, readFileSync(path.join(input.outputRoot, name))), name);
  }
});

async function dockerFixture(t, input, { corrupt, unreadable = false, badPort = false, buildFails = false, cleanupFails = false } = {}) {
  const manifest = createApplicationRuntimeContext(input);
  const requests = [];
  const expected = new Map(input.outputInventory.files.map((item) => [item.path,
    expectedDefaultRuntimeBytes(item.path, readFileSync(path.join(input.outputRoot, item.path)))]));
  const server = createServer((request, response) => {
    const relative = new URL(request.url, 'http://127.0.0.1').pathname.slice(1);
    requests.push(relative);
    if (!expected.has(relative)) { response.writeHead(404); response.end('absent'); return; }
    const bytes = relative === corrupt ? Buffer.from('corrupted runtime bytes') : expected.get(relative);
    response.setHeader('Content-Type', APPLICATION_RESOURCE_MIME_TYPES[path.extname(relative)][0]);
    response.end(bytes);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }));
  const imageId = `sha256:${'1'.repeat(64)}`;
  const containerId = '2'.repeat(64);
  const calls = [];
  let tag;
  let name;
  let owner;
  let imageExists = false;
  let containerExists = false;
  const image = () => [{ Id: imageId, Config: { Labels: {
    'io.elevenid.application-runtime.scope': 'diagnostic',
    'io.elevenid.application-runtime.context-sha256': manifest.manifest_sha256,
  } } }];
  const docker = async (args) => {
    calls.push(args);
    const okay = (stdout = '') => ({ code: 0, stdout, stderr: '' });
    if (args[0] === 'build') {
      tag = args[args.indexOf('--tag') + 1];
      if (buildFails) throw new Error('fixture Docker build failed');
      assert.ok(args.includes('--pull'));
      assert.ok(args.includes('--network=none'));
      imageExists = true;
      return okay();
    }
    if (args[0] === 'image' && args[1] === 'inspect') return imageExists ? okay(JSON.stringify(image()))
      : { code: 1, stdout: '', stderr: 'Error: No such image' };
    if (args[0] === 'run') {
      assert.equal(args[args.indexOf('--publish') + 1], '127.0.0.1::80');
      name = args[args.indexOf('--name') + 1];
      owner = args[args.indexOf('--label') + 1].split('=')[1];
      containerExists = true;
      return okay(containerId);
    }
    if (args[0] === 'container' && args[1] === 'inspect') return containerExists ? okay(JSON.stringify([{
      Id: containerId, State: { Running: true }, Image: imageId,
      Config: { Labels: { 'io.elevenid.application-runtime.owner': owner } },
      NetworkSettings: { Ports: { '80/tcp': [{ HostIp: badPort ? '0.0.0.0' : '127.0.0.1', HostPort: String(server.address().port) }] } },
    }])) : { code: 1, stdout: '', stderr: 'Error: No such container' };
    if (args[0] === 'exec' && args[1] === '--user') {
      assert.equal(args[2], 'nginx');
      if (unreadable) throw new Error('fixture Nginx user cannot read output');
      return okay(input.outputInventory.files.map((item) => `644:${expected.get(item.path).length}:/usr/share/nginx/html/${item.path}`).join('\n') + '\n');
    }
    if (args[0] === 'exec') { assert.deepEqual(args.slice(2), ['nginx', '-t']); return okay(); }
    if (args[0] === 'container' && args[1] === 'rm') {
      assert.equal(args.at(-1), name);
      if (cleanupFails) throw new Error('fixture container cleanup failed');
      containerExists = false;
      return okay();
    }
    if (args[0] === 'image' && args[1] === 'rm') {
      assert.equal(args.at(-1), tag);
      imageExists = false;
      return okay();
    }
    throw new Error(`Unexpected fixture Docker command: ${JSON.stringify(args)}`);
  };
  return { docker, calls, requests, states: () => ({ imageExists, containerExists }) };
}

test('a mock Docker protocol fixture cannot claim real container qualification', async (t) => {
  const input = fixture(t);
  const protocol = await dockerFixture(t, input);
  const reportPath = path.join(input.temporary, 'runtime.json');
  const result = await checkApplicationRuntimeContainer({ context: input.destination, reportPath }, protocol);
  assert.equal(result.status, 'fixture-passed');
  assert.equal(result.fixture, true);
  assert.equal(result.qualification.container_image_built, false);
  assert.equal(result.qualification.container_resources_checked, false);
  assert.equal(result.served_resources.length, input.resourceResult.served_resources.length);
  assert.deepEqual(result.public_resources_readable, [...APPLICATION_RETAINED_PUBLIC_FILES]);
  assert.equal(result.served_resources.find((item) => item.path === SDK).content_type, 'application/wasm');
  assert.deepEqual(result.cleanup, { container_removed: true, image_removed: true });
  assert.deepEqual(protocol.states(), { imageExists: false, containerExists: false });
  assert.deepEqual(JSON.parse(readFileSync(reportPath)), result);
});

for (const [label, options] of [
  ['corrupt immutable resource', { corrupt: 'assets/application.js' }],
  ['unreadable Nginx resource', { unreadable: true }],
  ['non-loopback published port', { badPort: true }],
  ['failed image build', { buildFails: true }],
  ['failed container cleanup', { cleanupFails: true }],
]) {
  test(`Docker fixture rejects ${label} and attempts owned cleanup without a report`, async (t) => {
    const input = fixture(t);
    const protocol = await dockerFixture(t, input, options);
    const reportPath = path.join(input.temporary, 'runtime.json');
    await assert.rejects(checkApplicationRuntimeContainer({ context: input.destination, reportPath }, protocol));
    assert.equal(existsSync(reportPath), false);
    assert.equal(protocol.states().imageExists, false);
    if (!options.cleanupFails) assert.equal(protocol.states().containerExists, false);
  });
}
