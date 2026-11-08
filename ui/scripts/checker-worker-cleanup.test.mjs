import assert from 'node:assert/strict';
import { EventEmitter, once } from 'node:events';
import { spawn } from 'node:child_process';
import { existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { test } from 'node:test';
import { createServer } from 'vite';
import { applyCheckerPatch, patches, sha256, cleanupFilename } from './patch-checker-worker-cleanup.mjs';
import { DISPOSE_REQUEST, DISPOSE_COMPLETE, DISPOSE_ERROR, disposeCheckerWorker, disposeDiagnostic, stopOwnedProcess } from './checker-worker-cleanup.mjs';

const uiRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const installedChecker = path.join(uiRoot, 'node_modules/vite-plugin-checker');
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};

function copyPristinePackage(t) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'marty-checker-package-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  writeFileSync(path.join(root, 'package.json'), JSON.stringify({ version: '0.14.5' }));
  for (const patch of patches) {
    let source = readFileSync(path.join(installedChecker, patch.file), 'utf8');
    if (sha256(source) === patch.after) {
      for (const [before, after] of [...patch.replacements].reverse()) source = source.replace(after, before);
    }
    assert.equal(sha256(source), patch.before, `fixture matches the locked release: ${patch.file}`);
    const target = path.join(root, patch.file);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, source);
  }
  return root;
}

test('the locked package patch is complete and idempotent', (t) => {
  const root = copyPristinePackage(t);
  assert.equal(applyCheckerPatch(root), 3);
  assert.equal(applyCheckerPatch(root), 0);
  for (const patch of patches) assert.equal(sha256(readFileSync(path.join(root, patch.file))), patch.after);
  assert.equal(readFileSync(path.join(root, 'dist', cleanupFilename), 'utf8'), readFileSync(new URL('./checker-worker-cleanup.mjs', import.meta.url), 'utf8'));
});

test('an omitted development dependency requires no patch', (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'marty-no-checker-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  assert.equal(applyCheckerPatch(path.join(root, 'absent-checker')), 0);
  assert.deepEqual(readdirSync(root), []);
});

test('patching an install does not mutate a hardlinked package-cache file', (t) => {
  const root = copyPristinePackage(t);
  const cached = path.join(root, 'cached-main.js');
  linkSync(path.join(root, patches[0].file), cached);
  applyCheckerPatch(root);
  assert.equal(sha256(readFileSync(cached)), patches[0].before);
  assert.equal(sha256(readFileSync(path.join(root, patches[0].file))), patches[0].after);
});

test('unknown package versions and changed files fail before any dependency rewrite', (t) => {
  const root = copyPristinePackage(t);
  const first = path.join(root, patches[0].file);
  const original = readFileSync(first, 'utf8');
  writeFileSync(path.join(root, 'package.json'), JSON.stringify({ version: '0.14.6' }));
  assert.throws(() => applyCheckerPatch(root), /requires vite-plugin-checker 0\.14\.5/);
  assert.equal(readFileSync(first, 'utf8'), original);
  writeFileSync(path.join(root, 'package.json'), JSON.stringify({ version: '0.14.5' }));
  writeFileSync(path.join(root, patches[2].file), 'unexpected package contents');
  assert.throws(() => applyCheckerPatch(root), /Unrecognized vite-plugin-checker contents/);
  assert.equal(readFileSync(first, 'utf8'), original);
});

test('an unknown installed helper is rejected before patching other files', (t) => {
  const root = copyPristinePackage(t);
  writeFileSync(path.join(root, 'dist', cleanupFilename), 'unexpected helper');
  assert.throws(() => applyCheckerPatch(root), /Unrecognized installed checker cleanup helper/);
  for (const patch of patches) assert.equal(sha256(readFileSync(path.join(root, patch.file))), patch.before);
});

test('diagnostic disposal waits for startup and owned child cleanup before acknowledgement', async () => {
  const startup = deferred(), childClosed = deferred();
  const messages = [];
  let stops = 0;
  const closing = disposeDiagnostic({ dispose: () => { stops++; return childClosed.promise; } }, startup.promise, { postMessage: (value) => messages.push(value) });
  await delay(0);
  assert.equal(stops, 0);
  startup.resolve();
  await delay(0);
  assert.equal(stops, 1);
  assert.deepEqual(messages, []);
  childClosed.resolve();
  await closing;
  assert.deepEqual(messages, [{ type: DISPOSE_COMPLETE }]);
});

test('startup rejection during closing still disposes, and disposal rejection is reported', async () => {
  const startup = deferred();
  const messages = [];
  let stopped = false;
  const closing = disposeDiagnostic({ dispose: async () => { stopped = true; } }, startup.promise, { postMessage: (value) => messages.push(value) });
  startup.reject(new Error('startup failed'));
  await closing;
  assert.equal(stopped, true);
  assert.deepEqual(messages, [{ type: DISPOSE_COMPLETE }]);
  messages.length = 0;
  await disposeDiagnostic({ dispose: async () => { throw new Error('child did not exit'); } }, Promise.resolve(), { postMessage: (value) => messages.push(value) });
  assert.deepEqual(messages, [{ type: DISPOSE_ERROR, payload: 'child did not exit' }]);
});

class WorkerDouble extends EventEmitter {
  threadId = 1;
  sent = [];
  terminations = 0;
  terminated = deferred();
  postMessage(value) { this.sent.push(value); }
  terminate() { this.terminations++; return this.terminated.promise; }
}

test('worker termination happens only after acknowledgement and is itself awaited', async () => {
  const worker = new WorkerDouble();
  const closing = disposeCheckerWorker(worker);
  assert.equal(disposeCheckerWorker(worker), closing);
  assert.deepEqual(worker.sent, [{ type: DISPOSE_REQUEST }]);
  assert.equal(worker.terminations, 0);
  worker.emit('message', { type: DISPOSE_COMPLETE });
  await delay(0);
  assert.equal(worker.terminations, 1);
  let finished = false;
  closing.then(() => { finished = true; });
  await delay(0);
  assert.equal(finished, false);
  worker.terminated.resolve();
  await closing;
});

test('timeout and diagnostic failure never force an unconfirmed worker termination', async () => {
  const unresponsive = new WorkerDouble();
  await assert.rejects(disposeCheckerWorker(unresponsive, { timeoutMs: 10 }), /Timed out waiting/);
  assert.equal(unresponsive.terminations, 0);
  const failed = new WorkerDouble();
  const closing = disposeCheckerWorker(failed);
  failed.emit('message', { type: DISPOSE_ERROR, payload: 'cannot stop child' });
  await assert.rejects(closing, /cannot stop child/);
  assert.equal(failed.terminations, 0);
});

test('owned process shutdown escalates a stubborn child without killing another child', async (t) => {
  const source = "process.on('SIGTERM',()=>{});process.stdout.write('ready\\n');setInterval(()=>{},1000)";
  const child = spawn(process.execPath, ['-e', source], { stdio: ['ignore', 'pipe', 'pipe'] });
  const other = spawn(process.execPath, ['-e', source], { stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(() => { child.kill('SIGKILL'); other.kill('SIGKILL'); });
  await Promise.all([once(child.stdout, 'data'), once(other.stdout, 'data')]);
  const stopping = stopOwnedProcess(child, { graceMs: 20, timeoutMs: 1_000 });
  assert.equal(stopOwnedProcess(child), stopping);
  await stopping;
  assert.equal(child.signalCode, 'SIGKILL');
  assert.equal(other.exitCode, null);
  assert.equal(other.signalCode, null);
});

test('a child that never closes produces an explicit bounded cleanup failure', async () => {
  const child = Object.assign(new EventEmitter(), { pid: 1, exitCode: null, signalCode: null, signals: [], kill(signal) { this.signals.push(signal); } });
  await assert.rejects(stopOwnedProcess(child, { graceMs: 5, timeoutMs: 20 }), /did not exit/);
  assert.deepEqual(child.signals, ['SIGTERM', 'SIGKILL']);
});

async function waitFor(check, message, timeout = 15_000) {
  const deadline = Date.now() + timeout;
  while (!check()) {
    if (Date.now() > deadline) throw new Error(typeof message === 'function' ? message() : message);
    await delay(20);
  }
}

test('real Vite restarts retain both diagnostics and reap each previous native TypeScript watcher', { skip: process.platform !== 'linux', timeout: 45_000 }, async (t) => {
  applyCheckerPatch();
  // Native TypeScript uses fanotify, which cannot watch this executor's overlayfs.
  // Keep the small fixture on tmpfs and supply its globals locally so no default
  // library under an overlay-backed node_modules directory needs watching.
  const root = mkdtempSync(path.join(existsSync('/dev/shm') ? '/dev/shm' : os.tmpdir(), 'marty-checker-live-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  symlinkSync(path.join(uiRoot, 'node_modules'), path.join(root, 'node_modules'), 'dir');
  const tsconfig = path.join(root, 'tsconfig.json');
  writeFileSync(tsconfig, JSON.stringify({ compilerOptions: { strict: true, noLib: true, types: [] }, files: ['globals.d.ts', 'source.ts'] }));
  writeFileSync(path.join(root, 'globals.d.ts'), ['Array<T>', 'Boolean', 'Function', 'IArguments', 'Number', 'Object', 'RegExp', 'String', 'CallableFunction', 'NewableFunction'].map((name) => `interface ${name} {}`).join('\n'));
  writeFileSync(path.join(root, 'source.ts'), 'const value: string = 42;\n');
  writeFileSync(path.join(root, 'source.js'), 'const unused = 42;\n');
  writeFileSync(path.join(root, 'eslint.config.mjs'), 'export default [{ rules: { "no-unused-vars": "error" } }];\n');
  const configFile = path.join(root, 'vite.config.mjs');
  writeFileSync(configFile, `import checker from 'vite-plugin-checker';\nexport default { plugins: [checker({ typescript: { tsconfigPath: 'tsconfig.json', typescriptPath: ${JSON.stringify(path.join(uiRoot, 'node_modules/typescript/lib/version.cjs'))} }, eslint: { lintCommand: 'eslint source.js' } })] };\n`);
  const watchers = () => readdirSync('/proc').filter((name) => /^\d+$/.test(name)).filter((name) => {
    try { const args = readFileSync(`/proc/${name}/cmdline`, 'utf8').split('\0'); return args.includes('--watch') && args.includes(tsconfig); }
    catch { return false; }
  }).map(Number);
  const logs = [];
  const log = (message) => logs.push(String(message));
  const logger = { info: log, warn: log, error: log, warnOnce: log, clearScreen() {}, hasWarned: false, hasErrorLogged: () => false };
  let server;
  t.after(async () => { if (server) await server.close(); });
  server = await createServer({ root, configFile, customLogger: logger, server: { middlewareMode: true, watch: { ignored: ['**/vite.config.mjs'] } }, appType: 'custom' });
  const diagnosticsReady = () => logs.some((line) => line.includes('TS2322'))
    && logs.some((line) => line.includes('no-unused-vars'))
    && logs.some((line) => line.includes('[TypeScript]') && line.includes('Found 1 error'))
    && logs.some((line) => line.includes('[ESLint]') && line.includes('Found 1 error'));
  await waitFor(diagnosticsReady, () => `both checkers must report their real errors: ${logs.join('\n')}\nwatchers: ${watchers()}`);
  assert.equal(watchers().length, 1);
  for (let iteration = 0; iteration < 3; iteration++) {
    const previous = watchers()[0];
    logs.length = 0;
    await server.restart();
    await waitFor(diagnosticsReady, `both checkers must survive restart ${iteration + 1}`);
    assert.equal(watchers().length, 1, `only one watcher after restart ${iteration + 1}`);
    assert.notEqual(watchers()[0], previous);
  }
  await server.close();
  server = null;
  assert.deepEqual(watchers(), [], 'no native checker remains after server close');
});

test('ordinary native checker startup errors remain observable', { timeout: 10_000 }, async () => {
  applyCheckerPatch();
  const { createServeAndBuild } = await import(pathToFileURL(path.join(installedChecker, 'dist/checkers/typescript/main.js')).href);
  const instance = createServeAndBuild({ typescript: { tsconfigPath: 'missing-config.json', typescriptPath: path.join(uiRoot, 'node_modules/typescript/lib/version.cjs') } }, { command: 'serve' });
  const failed = once(instance.serve.worker, 'error');
  instance.serve.config({ enableOverlay: true, enableTerminal: true });
  instance.serve.configureServer({ root: os.tmpdir() });
  const [error] = await failed;
  assert.match(error.message, /Failed to find tsconfig/);
  await instance.serve.worker.terminate();
});
