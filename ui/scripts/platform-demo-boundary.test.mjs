import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { platformDemoScenarios } from '../src/services/platformDemoScenarios.js';

test('current routes preserve every retained archived scenario and its order without mutating evidence', () => {
  for (const version of ['2026.07.0', '2026.08.0']) {
    const manifest = JSON.parse(readFileSync(new URL(`../public/demos/manifests/${version}.json`, import.meta.url)));
    const original = JSON.stringify(manifest);
    const expected = manifest.scenarios.filter((scenario) => !['canvas-learning-achievement','external-evidence-to-credential'].includes(scenario.slug));
    assert.equal(manifest.scenarios.length - expected.length, version === '2026.07.0' ? 1 : 2);
    assert.deepEqual(platformDemoScenarios(manifest.scenarios), expected);
    assert.equal(JSON.stringify(manifest), original);
  }
});

test('retired IDs and slugs cannot restore a route through renaming', () => {
  const retained = { demo_id:'D-12',slug:'physical-passport-issuance-evidence' };
  assert.deepEqual(platformDemoScenarios([
    { demo_id:'D-07',slug:'renamed-provider-demo' },
    { demo_id:'D-08',slug:'renamed-evidence-demo' },
    { demo_id:'D-04',slug:'canvas-learning-achievement' },
    { demo_id:'D-05',slug:'external-evidence-to-credential' },
    retained,
  ]), [retained]);
});
