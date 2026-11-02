import assert from 'node:assert/strict';
import { EventEmitter, once } from 'node:events';
import { createServer } from 'node:http';
import test from 'node:test';
import { installGracefulShutdown } from '../src/server.mjs';

test('TERM and INT drain only once and report completion only after close callback', () => {
  const signals = new EventEmitter(); let closeCount = 0, idleCount = 0, closedCount = 0, finish;
  const server = { close(callback) { closeCount += 1; finish = callback; }, closeIdleConnections() { idleCount += 1; } };
  const dispose = installGracefulShutdown(server, signals, () => { closedCount += 1; });
  signals.emit('SIGTERM'); signals.emit('SIGINT'); signals.emit('SIGTERM');
  assert.equal(closeCount, 1); assert.equal(idleCount, 1);
  assert.equal(signals.exitCode, undefined); assert.equal(closedCount, 0);
  finish(); assert.equal(signals.exitCode, 0); assert.equal(closedCount, 1);
  dispose(); assert.equal(signals.listenerCount('SIGTERM'), 0); assert.equal(signals.listenerCount('SIGINT'), 0);
});

test('failed close or an existing failure is never relabeled success', () => {
  for (const failedClose of [false, true]) {
    const signals = new EventEmitter(); signals.exitCode = 2;
    const dispose = installGracefulShutdown({ close(callback) { callback(failedClose ? new Error('test') : undefined); } }, signals);
    signals.emit('SIGINT'); assert.equal(signals.exitCode, failedClose ? 1 : 2); dispose();
  }
});

test('real local HTTP response finishes before shutdown completion', async () => {
  const signals = new EventEmitter(); let release, complete;
  const entered = new Promise((resolve) => {
    const server = createServer((_request, response) => { release = () => response.end('local-only'); resolve(); });
    complete = { server };
  });
  const server = complete.server;
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  let didClose = false;
  const finished = new Promise((resolve) => { complete.finish = resolve; });
  const dispose = installGracefulShutdown(server, signals, () => { didClose = true; complete.finish(); });
  try {
    const response = fetch(`http://127.0.0.1:${server.address().port}/`);
    await entered; signals.emit('SIGTERM'); signals.emit('SIGINT');
    assert.equal(didClose, false); assert.equal(signals.exitCode, undefined);
    release(); assert.equal(await (await response).text(), 'local-only'); await finished;
    assert.equal(signals.exitCode, 0); assert.equal(didClose, true);
  } finally { dispose(); server.closeAllConnections(); server.close(); }
});
