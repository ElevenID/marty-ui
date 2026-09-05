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
    'https://static.cloudflareinsights.com',
  ]);
  assert.deepEqual(directives.get('connect-src'), ["'self'", 'https://cloudflareinsights.com']);
  assert.deepEqual(directives.get('frame-src'), ["'self'", 'https://www.youtube-nocookie.com']);
});

test('production policy preserves consented demo embeds and configured edge analytics', async () => {
  const playerUrl = 'https://www.youtube-nocookie.com/embed/test-video?cc_load_policy=1';
  const beaconUrl = 'https://static.cloudflareinsights.com/beacon.min.js/version';
  const rumUrl = 'https://cloudflareinsights.com/cdn-cgi/rum';
  const server = http.createServer((request, response) => {
    response.setHeader('Content-Security-Policy', productionPolicy);
    if (request.url === '/app.js') {
      response.setHeader('Content-Type', 'application/javascript');
      response.end(`
        window.policyViolations = [];
        document.addEventListener('securitypolicyviolation', event => {
          window.policyViolations.push({ uri: event.blockedURI, directive: event.effectiveDirective });
        });
        document.querySelector('button').addEventListener('click', () => {
          const player = document.createElement('iframe');
          player.title = 'Consented demo';
          player.src = ${JSON.stringify(playerUrl)};
          document.body.append(player);
        });
      `);
    } else {
      response.setHeader('Content-Type', 'text/html');
      response.end('<!doctype html><button>Load demo</button><script src="/app.js"></script>');
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    page.setDefaultTimeout(5000);
    const externalRequests = [];
    // Keep the browser's CSP enforcement; no real third-party traffic is needed.
    await page.route('https://**/*', route => {
      externalRequests.push(route.request().url());
      const url = route.request().url();
      return route.fulfill({
        status: 200,
        headers: { 'Access-Control-Allow-Origin': '*' },
        contentType: url === beaconUrl ? 'application/javascript' : 'text/html',
        body: url === beaconUrl ? 'window.beaconLoaded = true;' : '<!doctype html><h1>Demo player</h1>',
      });
    });
    await page.goto(`http://127.0.0.1:${server.address().port}`);
    assert.equal(await page.locator('iframe').count(), 0);
    assert.deepEqual(externalRequests, []);
    await page.getByRole('button', { name: 'Load demo' }).click();
    await page.frameLocator('iframe').getByRole('heading', { name: 'Demo player' }).waitFor();
    assert.equal(await page.locator('iframe').getAttribute('src'), playerUrl);
    await page.addScriptTag({ url: beaconUrl });
    assert.equal(await page.evaluate(() => window.beaconLoaded), true);
    assert.equal(await page.evaluate(async url => (await fetch(url)).ok, rumUrl), true);
    assert.deepEqual(externalRequests.sort(), [playerUrl, beaconUrl, rumUrl].sort());
    assert.deepEqual(await page.evaluate(() => window.policyViolations), []);

    for (const url of [
      'https://www.youtube.com/embed/test-video',
      'https://www.youtube-nocookie.com.example.test/embed/test-video',
    ]) {
      await page.evaluate(url => {
        const frame = document.createElement('iframe');
        frame.src = url;
        document.body.append(frame);
      }, url);
      await page.waitForFunction(origin => window.policyViolations.some(
        item => new URL(item.uri).origin === origin && item.directive === 'frame-src',
      ), new URL(url).origin);
    }
    await assert.rejects(page.addScriptTag({ url: 'https://static.cloudflareinsights.com.example.test/beacon.js' }));
    assert.equal(await page.evaluate(async () => {
      try { await fetch('https://cloudflareinsights.com.example.test/cdn-cgi/rum'); return false; }
      catch { return true; }
    }), true);
    assert.deepEqual(externalRequests.sort(), [playerUrl, beaconUrl, rumUrl].sort());
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
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
