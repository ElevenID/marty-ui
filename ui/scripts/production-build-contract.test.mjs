import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { productionBuildContract, productionBuildContractPlugin } from './production-build-contract.mjs';

const sourceSha = 'a'.repeat(40);

test('full production refuses an absent private extension and customer audience', () => {
  assert.throws(() => productionBuildContract({ pages: 'full' }), /require the exact/);
  assert.throws(() => productionBuildContract({ pages: 'full', selfhost: true }), /Customer UI/);
  assert.equal(productionBuildContract({ pages: 'public', selfhost: true }), null);
  assert.throws(() => productionBuildContract({ extensionPath: '/unbound/extension.jsx' }), /require the full/);
});

test('full production binds the exact private source and requires it in the emitted bundle', () => {
  const root = mkdtempSync(path.join(tmpdir(), 'production-commerce-contract-'));
  try {
    const entry = path.join(root, 'src', 'extension.jsx');
    mkdirSync(path.dirname(entry));
    writeFileSync(entry, 'export const commerceExtensionEnabled = true;\n');
    writeFileSync(path.join(root, 'commerce-source.json'), JSON.stringify({
      repository: 'ElevenID/marty-subscriptions', source_sha: sourceSha,
    }));
    const args = { pages: 'full', extensionPath: entry, sourceSha };
    assert.throws(() => productionBuildContract(args), /application commerce adapter is missing/);
    assert.throws(() => productionBuildContract({ ...args, sourceSha: 'b'.repeat(40) }), /identity differs/);
    const adapter = path.join(root, 'src', 'application.jsx');
    writeFileSync(adapter, 'export const commerceExtensionEnabled = true;\n');
    assert.equal(productionBuildContract(args), adapter);
    assert.equal(productionBuildContract({ ...args, surface: 'application' }), adapter);
    for (const surface of ['combined', 'website']) {
      assert.throws(() => productionBuildContract({ ...args, surface }), /Only the application/);
    }
    const plugin = productionBuildContractPlugin(adapter);
    plugin.generateBundle({}, { 'main.js': { type: 'chunk', modules: { [adapter]: {} } } });
    plugin.generateBundle({}, { 'main.js': { type: 'chunk', modules: { [adapter.replaceAll('\\', '/') + '?version=1']: {} } } });
    assert.throws(() => plugin.generateBundle({}, {
      'main.js': { type: 'chunk', modules: { '/src/extensions/commerce/publicStub.jsx': {} } },
    }), /omitted/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('retired production surfaces fail before accepting public or private page inputs', () => {
  for (const surface of ['combined', 'website', 'unknown']) {
    for (const pages of ['public', 'full']) {
      assert.throws(() => productionBuildContract({ surface, pages }), /Only the application/);
    }
  }
});
