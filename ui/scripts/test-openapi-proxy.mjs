import http from 'node:http';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

// Exercise the real development proxy, without a running Marty deployment.
const spec = {
  openapi: '3.1.0', info: { title: 'Gateway fixture', version: 'test' },
  paths: { '/v1/credential-templates': { get: { responses: { 200: { description: 'OK' } } } } },
};
const gateway = http.createServer((request, response) => {
  if (request.url !== '/openapi.json') {
    response.writeHead(404); response.end(); return;
  }
  response.writeHead(200, { 'Content-Type': 'application/json' });
  response.end(JSON.stringify(spec));
});
await new Promise((resolve) => gateway.listen(0, '127.0.0.1', resolve));
process.env.VITE_DEV_PROXY_TARGET = `http://127.0.0.1:${gateway.address().port}`;
let vite;
try {
  vite = await createServer({
    configFile: fileURLToPath(new URL('../vite.config.ts', import.meta.url)),
    server: { host: '127.0.0.1', port: 0 }, logLevel: 'error',
  });
  await vite.listen();
  const base = `http://127.0.0.1:${vite.httpServer.address().port}`;
  for (const path of ['/openapi.json', '/openapi.yaml']) {
    const response = await fetch(base + path);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), spec);
  }
  console.log('PASS: live Vite serves canonical and legacy URLs from the same gateway document');
} finally {
  await vite?.close();
  await new Promise((resolve) => gateway.close(resolve));
}
