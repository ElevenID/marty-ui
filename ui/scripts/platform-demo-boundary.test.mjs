import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { platformDemoScenarios } from '../src/services/platformDemoScenarios.js';

test('current route enumeration preserves every other archived scenario and its order', () => {
  for (const version of ['2026.07.0', '2026.08.0']) {
    const manifest = JSON.parse(readFileSync(new URL(`../public/demos/manifests/${version}.json`, import.meta.url)));
    const original = JSON.stringify(manifest);
    const expected = manifest.scenarios.filter((scenario) => scenario.slug !== 'canvas-learning-achievement');
    assert.equal(expected.length, manifest.scenarios.length - 1);
    assert.deepEqual(platformDemoScenarios(manifest.scenarios), expected);
    assert.equal(JSON.stringify(manifest), original);
  }
});

test('a renamed slug cannot restore the reserved retired demonstration', () => {
  assert.deepEqual(platformDemoScenarios([
    { demo_id: 'D-07', slug: 'renamed-provider-demo' },
    { demo_id: 'D-08', slug: 'external-evidence-to-credential' },
  ]), [{ demo_id: 'D-08', slug: 'external-evidence-to-credential' }]);
});
