import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const UI_ROOT = fileURLToPath(new URL('../', import.meta.url));

function configProbe({ surface, mode = 'production', profile = 'full' } = {}) {
  const environment = Object.fromEntries(Object.entries(process.env).filter(([name]) => !/^(?:MARTY_|VITE_|PRERENDER_|DISABLE_PRERENDER$|ANALYZE_BUNDLE$)/.test(name)));
  return spawnSync(process.execPath, ['--input-type=module', '--eval', `
    import assert from 'node:assert/strict';
    import path from 'node:path';
    import { loadConfigFromFile } from 'vite';
    const { config } = await loadConfigFromFile({ command: 'build', mode: ${JSON.stringify(mode)} });
    const plugins = config.plugins.flat(Infinity).filter(Boolean);
    const names = plugins.map(plugin => plugin.name);
    for (const retired of ['Prerender Plugin', 'vite-plugin-sitemap', 'promote-prerendered-root', 'website-assets', 'prerender-locale-assets']) {
      assert.ok(!names.includes(retired), retired);
    }
    const variant = ${JSON.stringify(mode)} === 'selfhost' ? 'selfhost' : 'application';
    assert.equal(config.resolve.alias['@ui-public-config'], path.resolve('src/variants/publicConfig.' + variant + '.js'));
    assert.equal(config.resolve.alias['@ui-public-routes'], path.resolve('src/variants/publicSite.' + variant + '.jsx'));
    assert.equal(config.build.outDir, variant === 'selfhost' ? 'dist-selfhost' : ${JSON.stringify(surface === undefined ? 'dist' : 'dist-application')});
    assert.deepEqual(Object.keys(config.build.rollupOptions.input).sort(), ['console', 'main']);
    assert.equal(config.publicDir, 'public');
    assert.equal(config.build.assetsDir, 'assets');
    assert.ok(names.includes(variant === 'selfhost' ? 'selfhost-build-contract' : 'web-surface-build-contract'));
    assert.deepEqual(Object.keys(config.server.proxy).sort(), ['/api', '/auth', '/health', '/openapi.json', '/openapi.yaml', '/v1']);
    const rewritePlugin = plugins.find(plugin => plugin.name === 'console-entry-rewrite');
    assert.ok(rewritePlugin);
    for (const hook of ['configureServer', 'configurePreviewServer']) {
      let handler;
      rewritePlugin[hook]({ middlewares: { use: value => { handler = value; } } });
      for (const [url, expected] of [['/console/org/example?tab=members', '/console/index.html'], ['/console/assets/app.js', '/console/assets/app.js'], ['/login?next=%2Fconsole', '/login?next=%2Fconsole']]) {
        const request = { url };
        let continued = false;
        handler(request, null, () => { continued = true; });
        assert.equal(request.url, expected);
        assert.equal(continued, true);
      }
    }
    console.log(JSON.stringify({ variant, output: config.build.outDir }));
  `], { cwd: UI_ROOT, env: { ...environment,
    ...(surface === undefined ? {} : { MARTY_UI_SURFACE: surface }),
    MARTY_PRODUCTION_PAGES: 'public', VITE_UI_VARIANT: 'public', VITE_SELFHOST_PUBLIC_PROFILE: profile,
  }, encoding: 'utf8', timeout: 30_000, maxBuffer: 2 * 1024 * 1024 });
}

function accepted(result) {
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr || result.stdout);
}

test('default production and development configurations serve the application from the usual dist directory', () => {
  assert.equal(existsSync(new URL('./website-build-tools.mjs', import.meta.url)), false);
  assert.equal(existsSync(new URL('../src/services/platformDemoScenarios.js', import.meta.url)), false);
  accepted(configProbe());
  accepted(configProbe({ mode: 'development' }));
});

test('explicit application builds keep the portable dist-application output', () => {
  accepted(configProbe({ surface: 'application' }));
});

test('both customer profiles build without marketing source or crawler plugins', () => {
  for (const profile of ['full', 'tester']) {
    accepted(configProbe({ mode: 'selfhost', profile }));
    accepted(configProbe({ surface: 'application', mode: 'selfhost', profile }));
  }
});

test('retired combined and website production surfaces fail closed', () => {
  for (const surface of ['combined', 'website']) {
    const result = configProbe({ surface });
    assert.ifError(result.error);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Only the application UI surface is available/);
    assert.match(result.stderr, /ElevenID\/website/);
  }
});
