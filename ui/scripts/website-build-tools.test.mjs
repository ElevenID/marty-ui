import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const UI_ROOT = fileURLToPath(new URL('../', import.meta.url));

function fixture(t, { omitWebsiteHelper = false } = {}) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'marty-website-build-tools-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const ui = path.join(root, 'ui');
  mkdirSync(ui);
  for (const name of ['scripts', 'src', 'public', 'vite.config.ts', 'package.json']) {
    cpSync(path.join(UI_ROOT, name), path.join(ui, name), { recursive: true });
  }
  cpSync(path.join(UI_ROOT, '../contracts'), path.join(root, 'contracts'), { recursive: true });
  symlinkSync(realpathSync(path.join(UI_ROOT, 'node_modules')), path.join(ui, 'node_modules'), 'dir');
  if (omitWebsiteHelper) {
    rmSync(path.join(ui, 'scripts/website-build-tools.mjs'));
    rmSync(path.join(ui, 'src/services/platformDemoScenarios.js'));
  }
  return ui;
}

function configProbe(ui, { surface = 'combined', mode = 'production', disablePrerender = false, probe = 'plugins' } = {}) {
  const environment = Object.fromEntries(Object.entries(process.env).filter(([name]) => !/^(?:MARTY_|VITE_|PRERENDER_|DISABLE_PRERENDER$|ANALYZE_BUNDLE$)/.test(name)));
  return spawnSync(process.execPath, ['--input-type=module', '--eval', `
    import assert from 'node:assert/strict';
    import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
    import path from 'node:path';
    import { loadConfigFromFile } from 'vite';
    const { config } = await loadConfigFromFile({command:'build', mode:${JSON.stringify(mode)}});
    const plugins = config.plugins.flat(Infinity).filter(Boolean);
    const names = plugins.map(plugin => plugin.name);
    if (${JSON.stringify(probe)} === 'crawler') {
      assert.ok(!names.includes('Prerender Plugin'));
      assert.ok(!names.includes('promote-prerendered-root'));
      const sitemap = plugins.filter(plugin => plugin.name === 'vite-plugin-sitemap');
      assert.equal(sitemap.length, 1);
      const output = path.resolve(config.build.outDir || 'dist');
      mkdirSync(output, {recursive:true});
      writeFileSync(path.join(output, 'index.html'), '<html><head></head><body>fixture</body></html>');
      sitemap[0].closeBundle();
      const sitemapPath = path.join(output, 'sitemap.xml');
      for (let attempt=0; attempt<20 && !existsSync(sitemapPath); attempt++) await new Promise(setImmediate);
      const xml = readFileSync(sitemapPath, 'utf8');
      const robots = readFileSync(path.join(output, 'robots.txt'), 'utf8');
      const urls = [...xml.matchAll(new RegExp('<loc>(.*?)</loc>', 'g'))].map(match=>match[1]);
      assert.equal(urls.length, new Set(urls).size);
      for (const route of ['/', '/product', '/blog', '/authors', '/demos', '/ai', '/what-is-credential-verification']) {
        assert.ok(urls.includes('https://elevenidllc.com'+route), 'missing crawler route '+route);
      }
      assert.equal(urls.includes('https://elevenidllc.com/docs'), ${JSON.stringify(surface)} === 'combined');
      assert.ok(urls.some(url=>url.includes('/blog/') && !url.endsWith('/blog/')));
      assert.ok(urls.some(url=>url.includes('/demos/')));
      for (const route of ['/console', '/applicant', '/auth/login']) assert.ok(!urls.includes('https://elevenidllc.com'+route));
      for (const rule of ['Disallow: /console/*', 'Disallow: /auth/*', 'Disallow: /api/*', 'Disallow: /v1/*']) assert.ok(robots.includes(rule), rule);
      console.log(JSON.stringify({names, crawler_routes:urls.length}));
    } else console.log(JSON.stringify({names}));
  `], { cwd: ui, env: { ...environment, MARTY_UI_SURFACE: surface, MARTY_PRODUCTION_PAGES: 'public',
    VITE_UI_VARIANT: 'public', DISABLE_PRERENDER: disablePrerender ? '1' : '0' },
  encoding: 'utf8', timeout: 30_000, maxBuffer: 2 * 1024 * 1024 });
}

function accepted(result) {
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return JSON.parse(result.stdout.trim().split('\n').at(-1));
}

test('application and customer config load without the website package helper or demo module', (t) => {
  const ui = fixture(t, { omitWebsiteHelper: true });
  for (const options of [{ surface: 'application' }, { surface: 'combined', mode: 'selfhost' }]) {
    const { names } = accepted(configProbe(ui, options));
    for (const name of ['Prerender Plugin', 'vite-plugin-sitemap', 'promote-prerendered-root', 'website-assets']) {
      assert.ok(!names.includes(name), name);
    }
    assert.ok(names.includes('console-entry-rewrite'));
  }
});

test('combined config requires its actual website package helper', (t) => {
  const ui = fixture(t, { omitWebsiteHelper: true });
  const result = configProbe(ui, { disablePrerender: true });
  assert.ifError(result.error);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /website-build-tools\.mjs/);
});

for (const surface of ['website', 'combined']) {
  test(`${surface} still emits crawler routes and robots when browser prerendering is disabled`, (t) => {
    const result = accepted(configProbe(fixture(t), { surface, disablePrerender: true, probe: 'crawler' }));
    assert.ok(result.crawler_routes > 20);
  });

  test(`${surface} keeps its prerender and crawler plugins in the normal production config`, (t) => {
    const { names } = accepted(configProbe(fixture(t), { surface }));
    for (const name of ['Prerender Plugin', 'vite-plugin-sitemap', 'promote-prerendered-root']) {
      assert.equal(names.filter((entry) => entry === name).length, 1, name);
    }
    assert.equal(names.includes('website-assets'), surface === 'website');
    assert.equal(names.includes('prerender-locale-assets'), surface === 'combined');
  });
}
