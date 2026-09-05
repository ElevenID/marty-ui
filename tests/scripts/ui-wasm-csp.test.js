'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const test = require('node:test');
const { chromium } = require('@playwright/test');

const config = fs.readFileSync(path.resolve(__dirname, '../../ui/nginx.prod.conf'), 'utf8');
const match = config.match(/add_header Content-Security-Policy "([^"]+)" always;/);
assert.ok(match, 'Production nginx must declare an enforcing CSP');
const productionPolicy = match[1];

test('production script policy allows WASM without JavaScript eval or inline permission', () => {
  const directives = new Map(productionPolicy.split(';').filter(x => x.trim()).map(x => {
    const [name, ...sources] = x.trim().split(/\s+/);
    return [name, sources];
  }));
  assert.deepEqual(directives.get('script-src'), [
    "'self'", "'wasm-unsafe-eval'", 'https://cdn.redoc.ly', 'https://cdn.jsdelivr.net',
  ]);
  assert.deepEqual(directives.get('connect-src'), ["'self'"]);
  assert.deepEqual(directives.get('frame-src'), ["'self'"]);
});

test('browser enforces production policy while compiling same-origin WASM', async () => {
  const wasm = Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]);
  const app = `
    window.inlineRan = window.inlineRan === true;
    (async () => {
      const result = { inlineBlocked: !window.inlineRan };
      try { eval('1 + 1'); result.evalBlocked = false; } catch { result.evalBlocked = true; }
      try { new Function('return 2')(); result.functionBlocked = false; } catch { result.functionBlocked = true; }
      try { await WebAssembly.instantiateStreaming(fetch('/module.wasm')); result.wasm = true; }
      catch { result.wasm = false; }
      window.cspResult = result;
    })();
  `;
  const server = http.createServer((request, response) => {
    response.setHeader('Content-Security-Policy', request.url === '/negative' ? productionPolicy.replace(" 'wasm-unsafe-eval'", '') : productionPolicy);
    if (request.url === '/module.wasm') {
      response.setHeader('Content-Type', 'application/wasm'); response.end(wasm);
    } else if (request.url === '/app.js') {
      response.setHeader('Content-Type', 'application/javascript'); response.end(app);
    } else {
      response.setHeader('Content-Type', 'text/html');
      response.end('<!doctype html><script>window.inlineRan=true</script><script src="/app.js"></script>');
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    const origin = `http://127.0.0.1:${server.address().port}`;
    for (const [route, wasmAllowed] of [['/', true], ['/negative', false]]) {
      await page.goto(origin + route);
      await page.waitForFunction(() => Boolean(window.cspResult));
      assert.deepEqual(await page.evaluate(() => window.cspResult), {
        wasm: wasmAllowed, evalBlocked: true, functionBlocked: true, inlineBlocked: true,
      });
    }
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
});
