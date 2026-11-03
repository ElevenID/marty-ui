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
    assert.equal(productionBuildContract(args), entry);
    assert.throws(() => productionBuildContract({ ...args, sourceSha: 'b'.repeat(40) }), /identity differs/);
    const plugin = productionBuildContractPlugin(entry);
    plugin.generateBundle({}, { 'main.js': { type: 'chunk', modules: { [entry]: {} } } });
    assert.throws(() => plugin.generateBundle({}, {
      'main.js': { type: 'chunk', modules: { '/src/extensions/commerce/publicStub.jsx': {} } },
    }), /omitted/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
