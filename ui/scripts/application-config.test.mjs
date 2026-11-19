import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import * as applicationConfig from '../src/variants/publicConfig.application.js';
import * as publicConfig from '../src/variants/publicConfig.public.js';
import { pruneSelfhostDist } from './prune-selfhost-dist.mjs';

test('application preserves public capabilities and website handoff links', () => {
  assert.deepEqual(Object.keys(applicationConfig), Object.keys(publicConfig));
  for (const key of Object.keys(publicConfig)) {
    if (key !== 'I18N_NAMESPACES') assert.strictEqual(applicationConfig[key], publicConfig[key], key);
  }
  assert.ok(publicConfig.I18N_NAMESPACES.includes('marketing'));
  assert.deepEqual(applicationConfig.I18N_NAMESPACES, publicConfig.I18N_NAMESPACES.filter((namespace) => namespace !== 'marketing'));
});

test('the production application build resolves its application locale configuration', () => {
  const result = spawnSync(process.execPath, ['--input-type=module', '--eval', `
    import assert from 'node:assert/strict';
    import path from 'node:path';
    import { pathToFileURL } from 'node:url';
    import { loadConfigFromFile } from 'vite';
    const { config } = await loadConfigFromFile({ command: 'build', mode: 'production' });
    const configurationPath = config.resolve.alias['@ui-public-config'];
    assert.equal(configurationPath, path.resolve('src/variants/publicConfig.application.js'));
    const { I18N_NAMESPACES } = await import(pathToFileURL(configurationPath).href);
    assert.ok(!I18N_NAMESPACES.includes('marketing'));
  `], {
    cwd: fileURLToPath(new URL('../', import.meta.url)),
    env: { ...process.env, MARTY_UI_SURFACE: 'application', MARTY_PRODUCTION_PAGES: 'public', VITE_UI_VARIANT: 'public' },
    encoding: 'utf8', timeout: 30000,
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr || result.stdout);
});

test('application translation namespaces have fallback assets after application pruning', (t) => {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'marty-application-locales-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  cpSync(new URL('../public/locales/', import.meta.url), path.join(directory, 'locales'), { recursive: true });

  pruneSelfhostDist(directory);

  assert.equal(existsSync(path.join(directory, 'locales/en/marketing.json')), false);
  for (const namespace of applicationConfig.I18N_NAMESPACES) {
    const fallback = path.join(directory, 'locales/en', `${namespace}.json`);
    assert.ok(existsSync(fallback), `Application requests a missing fallback namespace: ${namespace}`);
    assert.equal(typeof JSON.parse(readFileSync(fallback, 'utf8')), 'object');
  }
});
