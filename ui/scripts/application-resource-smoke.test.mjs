import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { preview } from 'vite';
import { APPLICATION_LOCALE_NAMESPACES, APPLICATION_RETAINED_PUBLIC_FILES } from './application-public-assets.mjs';
import { runApplicationResourceSmoke, verifyServedResource } from './application-resource-smoke.mjs';

const execFileAsync = promisify(execFile);
const CLI = fileURLToPath(new URL('./application-resource-smoke.mjs', import.meta.url));
const HTML = '<!doctype html><html><head><link rel="manifest" href="/manifest.json">'
  + '<link rel="icon" href="/favicon.ico?v=2"><link rel="stylesheet" href="/assets/app.css">'
  + '<link rel="stylesheet" href="https://example.invalid/fonts.css">'
  + '<script src="/runtime-config.js"></script><script src="/startup.js"></script></head>'
  + '<body><div id="root"></div><script>throw new Error("HTML must not execute")</script>'
  + '<script type="module" src="/assets/app.js"></script></body></html>';

function write(directory, relative, bytes) {
  const target = path.join(directory, relative);
  mkdirSync(path.dirname(target), { recursive: true });
  writeFileSync(target, bytes);
}

function fixture(t) {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'marty-resource-smoke-'));
  const distDir = path.join(directory, 'dist-application');
  mkdirSync(distDir);
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  for (const relative of APPLICATION_RETAINED_PUBLIC_FILES) {
    let content = 'fixture';
    if (relative.endsWith('.json')) content = '{}';
    else if (relative.endsWith('.js')) content = '// fixture resource\n';
    else if (relative.endsWith('.html')) content = '<!doctype html><html><head></head><body>Fixture</body></html>';
    else if (relative.endsWith('.svg')) content = '<svg xmlns="http://www.w3.org/2000/svg"/>';
    write(distDir, relative, content);
  }
  write(distDir, 'locales/de/common.json', JSON.stringify({ actions: { cancel: 'Abbrechen' }, common: {} }));
  write(distDir, 'locales/en/common.json', JSON.stringify({ actions: { cancel: 'Cancel' }, common: { login: 'Login' } }));
  write(distDir, 'manifest.json', JSON.stringify({ icons: [
    { src: 'logo192.png', sizes: '192x192', type: 'image/png' },
    { src: '/logo512.png', sizes: '512x512', type: 'image/png' },
  ] }));
  write(distDir, 'index.html', HTML);
  write(distDir, 'console/index.html', HTML);
  write(distDir, 'assets/app.js', 'export const fixture = true;\n');
  write(distDir, 'assets/module.mjs', 'export default 1;\n');
  write(distDir, 'assets/app.css', 'body { color: green; }\n');
  write(distDir, 'assets/module.wasm', Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]));
  // The smoke must not import the application Vite configuration or execute it.
  write(directory, 'vite.config.mjs', 'throw new Error("project configuration must not load");\n');
  return { directory, distDir, reportPath: path.join(directory, 'resource-report.json') };
}

function expectedResource(distDir, relative) {
  const bytes = readFileSync(path.join(distDir, relative));
  return { path: relative, bytes: bytes.length,
    sha256: `sha256:${createHash('sha256').update(bytes).digest('hex')}` };
}

async function realPreview(distDir, callback, plugins = []) {
  const server = await preview({
    configFile: false, envFile: false, root: path.dirname(distDir), publicDir: false,
    logLevel: 'silent', clearScreen: false, appType: 'spa', build: { outDir: distDir },
    preview: { host: '127.0.0.1', port: 0, strictPort: true, open: false, cors: false }, plugins,
  });
  try {
    const address = server.httpServer.address();
    assert.equal(address.address, '127.0.0.1');
    return await callback(`http://127.0.0.1:${address.port}`);
  } finally {
    server.httpServer.closeAllConnections();
    await server.close();
    assert.equal(server.httpServer.listening, false);
  }
}

test('real preview serves all retained bytes and i18next observes German plus English fallback', async (t) => {
  const input = fixture(t);
  const original = APPLICATION_RETAINED_PUBLIC_FILES.map((name) => expectedResource(input.distDir, name));
  const result = await runApplicationResourceSmoke(input);

  assert.equal(result.schema, 'marty.application-resource-smoke/v1');
  assert.equal(result.status, 'passed');
  assert.deepEqual(result.public_resources, original);
  assert.deepEqual(result.public_resources, APPLICATION_RETAINED_PUBLIC_FILES.map((name) => expectedResource(input.distDir, name)));
  assert.equal(result.served_resources.length, 60);
  for (const record of result.served_resources) {
    assert.deepEqual({ path: record.path, bytes: record.bytes, sha256: record.sha256 }, expectedResource(input.distDir, record.path));
    assert.equal(record.status, 200);
    assert.ok(record.content_type.length > 0);
  }
  assert.deepEqual(result.locale_probe, {
    language: 'de', fallback_language: 'en', key: 'common.login', resolved_language: 'en', fallback_value: 'Login',
    localized_key: 'actions.cancel', localized_language: 'de', localized_value: 'Abbrechen',
    requests: ['de', 'en'].flatMap((language) => APPLICATION_LOCALE_NAMESPACES.map(
      (namespace) => `/locales/${language}/${namespace}.json`,
    )).sort(),
  });
  assert.ok(result.entry_references.some((entry) => entry.external && entry.url === 'https://example.invalid/fonts.css'));
  assert.deepEqual(result.manifest_icons.map((entry) => entry.path), ['logo192.png', 'logo512.png']);
  assert.deepEqual(result.qualification, { resources_served: true, locale_fallback_observed: true,
    browser_startup_observed: false, host_deployment_tested: false, oidc_journey_tested: false });
  assert.deepEqual(JSON.parse(readFileSync(input.reportPath, 'utf8')), result);
  assert.equal(result.preview.closed, true);
  await assert.rejects(fetch(`http://127.0.0.1:${result.preview.port}/index.html`, { signal: AbortSignal.timeout(1000) }));
});

test('the real CLI writes only a new external report and leaves its production inputs intact', async (t) => {
  const input = fixture(t);
  const before = readFileSync(path.join(input.distDir, 'index.html'));
  const command = await execFileAsync(process.execPath, [CLI, '--dist', input.distDir, '--report', input.reportPath], {
    cwd: input.directory, timeout: 55_000,
  });
  const summary = JSON.parse(command.stdout.trim());
  assert.equal(summary.status, 'passed');
  assert.equal(summary.preview_closed, true);
  assert.deepEqual(readFileSync(path.join(input.distDir, 'index.html')), before);
  const originalReport = readFileSync(input.reportPath);
  await assert.rejects(execFileAsync(process.execPath, [CLI, '--dist', input.distDir, '--report', input.reportPath], {
    cwd: input.directory, timeout: 55_000,
  }), /Report already exists/);
  assert.deepEqual(readFileSync(input.reportPath), originalReport);
});

test('a failure after preview starts closes its socket and cannot publish a passing report', async (t) => {
  const input = fixture(t);
  // Isolate the fetch injection in a child, even if this test file is later
  // configured to run cases concurrently. The server itself is the real Vite API.
  const script = `
    import assert from 'node:assert/strict';
    import { existsSync } from 'node:fs';
    import { pathToFileURL } from 'node:url';
    const input = JSON.parse(process.argv[1]);
    const { runApplicationResourceSmoke } = await import(pathToFileURL(input.cli).href);
    const originalFetch = globalThis.fetch;
    let origin;
    globalThis.fetch = (value, options) => {
      const url = new URL(value);
      assert.equal(url.protocol, 'http:');
      assert.equal(url.hostname, '127.0.0.1');
      if (url.pathname === '/assets/app.js') {
        origin = url.origin;
        throw new Error('Injected local resource failure');
      }
      return originalFetch(value, options);
    };
    try {
      await assert.rejects(runApplicationResourceSmoke(input), /Injected local resource failure/);
    } finally {
      globalThis.fetch = originalFetch;
    }
    assert.ok(origin, 'The resource failure must occur after the real preview listens');
    assert.equal(existsSync(input.reportPath), false);
    await assert.rejects(originalFetch(origin + '/index.html', { signal: AbortSignal.timeout(1000) }));
    console.log('failure cleanup verified');
  `;
  const result = await execFileAsync(process.execPath, ['--input-type=module', '--eval', script, '--',
    JSON.stringify({ ...input, cli: CLI })], { cwd: input.directory, timeout: 55_000 });
  assert.equal(result.stdout.trim(), 'failure cleanup verified');
});

for (const relative of ['locales/en/common.json', 'apple-touch-icon.png', 'assets/app.js']) {
  test(`real SPA preview cannot disguise a missing ${relative} as a successful asset`, async (t) => {
    const input = fixture(t);
    const expected = expectedResource(input.distDir, relative);
    unlinkSync(path.join(input.distDir, relative));
    await realPreview(input.distDir, async (origin) => {
      const fallback = await fetch(`${origin}/${relative}`);
      assert.equal(fallback.status, 200);
      assert.match(fallback.headers.get('content-type'), /^text\/html/);
      assert.match(await fallback.text(), /<!doctype html>/i);
      await assert.rejects(verifyServedResource(origin, expected), /Invalid HTTP resource/);
    });
    await assert.rejects(runApplicationResourceSmoke(input), /ENOENT/);
    assert.throws(() => readFileSync(input.reportPath), /ENOENT/);
  });
}

test('a changed response body and HTML served as JavaScript both fail with a real preview', async (t) => {
  const input = fixture(t);
  const expected = expectedResource(input.distDir, 'assets/app.js');
  write(input.distDir, 'assets/app.js', 'export const fixture = false;\n');
  await realPreview(input.distDir, async (origin) => {
    await assert.rejects(verifyServedResource(origin, expected), /HTTP resource bytes differ/);
  });
  write(input.distDir, 'assets/app.js', '<!doctype html><html><head></head><body>Wrong asset</body></html>');
  const wrongBytes = expectedResource(input.distDir, 'assets/app.js');
  await realPreview(input.distDir, async (origin) => {
    await assert.rejects(verifyServedResource(origin, wrongBytes), /HTML masquerades as an asset/);
  });
});

test('a local redirect is refused before following its external destination', async (t) => {
  const input = fixture(t);
  await realPreview(input.distDir, async (origin) => {
    await assert.rejects(verifyServedResource(origin, expectedResource(input.distDir, 'assets/app.js')),
      /Invalid HTTP resource.*status 302/);
  }, [{ name: 'negative-redirect', configurePreviewServer(server) {
    server.middlewares.use((request, response, next) => {
      if (request.url !== '/assets/app.js') return next();
      response.statusCode = 302;
      response.setHeader('Location', 'https://example.invalid/must-not-fetch');
      response.end();
    });
  } }]);
});

test('fallback cannot be claimed after the German dictionary supplies the tested key', async (t) => {
  const input = fixture(t);
  write(input.distDir, 'locales/de/common.json', JSON.stringify({ actions: { cancel: 'Abbrechen' }, common: { login: 'Anmelden' } }));
  await assert.rejects(runApplicationResourceSmoke(input), /German common.login must be absent/);
  assert.throws(() => readFileSync(input.reportPath), /ENOENT/);
});

test('the fallback proof derives nonempty English wording from the actual served dictionary', async (t) => {
  const input = fixture(t);
  write(input.distDir, 'locales/en/common.json', JSON.stringify({ actions: { cancel: 'Cancel' }, common: { login: 'Sign in' } }));
  const result = await runApplicationResourceSmoke(input);
  assert.equal(result.locale_probe.fallback_value, 'Sign in');
  assert.equal(result.locale_probe.resolved_language, 'en');
  assert.equal(result.preview.closed, true);
});

for (const reference of ['../../escape.js', '/%2e%2e/escape.js', 'javascript:alert(1)', '/assets%2fapp.js']) {
  test(`HTML target ${reference} is rejected without requesting it`, async (t) => {
    const input = fixture(t);
    write(input.distDir, 'index.html', HTML.replace('/assets/app.js', reference));
    await assert.rejects(runApplicationResourceSmoke(input), /Traversal resource URL|Unsupported resource URL|Encoded path separator/);
    assert.throws(() => readFileSync(input.reportPath), /ENOENT/);
  });
}

test('malformed entries, manifest targets, and unreviewed base overrides fail closed', async (t) => {
  const input = fixture(t);
  write(input.distDir, 'index.html', '<p>This is not a built entry</p>');
  await assert.rejects(runApplicationResourceSmoke(input), /Malformed HTML entry/);
  write(input.distDir, 'index.html', HTML.replace('<head>', '<head><base href="/elsewhere/">'));
  await assert.rejects(runApplicationResourceSmoke(input), /HTML base overrides/);
  write(input.distDir, 'index.html', HTML);
  write(input.distDir, 'manifest.json', JSON.stringify({ icons: [{ src: '../escape.png' }] }));
  await assert.rejects(runApplicationResourceSmoke(input), /Traversal resource URL/);
  write(input.distDir, 'manifest.json', JSON.stringify({ icons: 'not-an-array' }));
  await assert.rejects(runApplicationResourceSmoke(input), /Manifest must declare/);
  assert.throws(() => readFileSync(input.reportPath), /ENOENT/);
});

const WRONG_ROLES = [
  ['script', HTML.replace('/assets/app.js', '/index.html')],
  ['modulepreload', HTML.replace('<head>', '<head><link rel="modulepreload" href="/index.html">')],
  ['stylesheet', HTML.replace('/assets/app.css', '/index.html')],
  ['manifest', HTML.replace('/manifest.json', '/assets/app.js')],
  ['icon', HTML.replace('/favicon.ico?v=2', '/assets/app.js')],
  ['image', HTML.replace('<body>', '<body><img src="/assets/app.js">')],
];
for (const [role, html] of WRONG_ROLES) {
  test(`a local ${role} reference must have the content type required by its HTML role`, async (t) => {
    const input = fixture(t);
    write(input.distDir, 'index.html', html);
    await assert.rejects(runApplicationResourceSmoke(input), /Invalid local .* target/);
    assert.throws(() => readFileSync(input.reportPath), /ENOENT/);
  });
}

test('a manifest icon cannot point to a script that otherwise passes HTTP byte checks', async (t) => {
  const input = fixture(t);
  write(input.distDir, 'manifest.json', JSON.stringify({ icons: [{ src: '/assets/app.js' }] }));
  await assert.rejects(runApplicationResourceSmoke(input), /Invalid local manifest icon target/);
  assert.throws(() => readFileSync(input.reportPath), /ENOENT/);
});

test('symlink resources and symlink report destinations cannot escape the disposable output', async (t) => {
  const input = fixture(t);
  const outside = path.join(input.directory, 'outside.js');
  writeFileSync(outside, 'outside bytes');
  symlinkSync(outside, path.join(input.distDir, 'assets', 'escape.js'));
  await assert.rejects(runApplicationResourceSmoke(input), /Output contains a symlink/);
  unlinkSync(path.join(input.distDir, 'assets', 'escape.js'));
  symlinkSync(path.join(input.directory, 'absent.json'), input.reportPath);
  await assert.rejects(runApplicationResourceSmoke(input), /Report already exists/);
  assert.equal(readFileSync(outside, 'utf8'), 'outside bytes');
});

test('reports inside the output and non-loopback resource origins are rejected', async (t) => {
  const input = fixture(t);
  await assert.rejects(runApplicationResourceSmoke({ ...input, reportPath: path.join(input.distDir, 'report.json') }),
    /Report must be outside/);
  await assert.rejects(verifyServedResource('https://example.invalid', expectedResource(input.distDir, 'assets/app.js')),
    /Only a loopback/);
});
