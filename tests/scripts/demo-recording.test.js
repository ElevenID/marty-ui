'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { VIDEO_SIZE, buildVerificationDisplay, createArtifactDir } = require('./demo-recording');

test('release recording uses the governed 16:9 capture size', () => {
  assert.deepEqual(VIDEO_SIZE, { width: 1920, height: 1080 });
  assert.equal(Object.isFrozen(VIDEO_SIZE), true);
});

test('artifact directory honors the recorder-owned output path', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'marty-demo-recording-'));
  try {
    const configured = path.join(root, 'external-artifacts');
    assert.equal(
      createArtifactDir(root, 'fallback', { DEMO_ARTIFACT_DIR: configured }),
      path.resolve(configured),
    );
    assert.equal(fs.statSync(configured).isDirectory(), true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('artifact directory falls back to the timestamped audit location', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'marty-demo-recording-'));
  try {
    const expected = path.join(root, 'tests', 'artifacts', 'audit-run');
    assert.equal(createArtifactDir(root, 'audit-run', {}), expected);
    assert.equal(fs.statSync(expected).isDirectory(), true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('verification display preserves the machine decision and a stable presentation test id', () => {
  assert.deepEqual(
    buildVerificationDisplay(
      { decision: 'deny', decisionReason: 'Credential is suspended' },
      {
        actor: 'Marty status-aware verifier',
        testId: 'lifecycle-pres-01',
        evaluatedState: 'suspended',
        comparison: 'Active -> suspended',
      },
    ),
    {
      actor: 'Marty status-aware verifier',
      testId: 'LIFECYCLE-PRES-01',
      decision: 'DENIED',
      reason: 'Credential is suspended',
      evaluatedState: 'SUSPENDED',
      comparison: 'Active -> suspended',
    },
  );
});

test('verification display fails closed without a governed identity', () => {
  assert.throws(
    () => buildVerificationDisplay({ decision: 'allow' }, { actor: '', testId: 'test-01' }),
    /actor is required/,
  );
  assert.throws(
    () => buildVerificationDisplay({ decision: 'allow' }, { actor: 'Verifier', testId: 'unsafe id' }),
    /stable presentation-safe identifier/,
  );
  assert.throws(
    () => buildVerificationDisplay(
      { decision: 'allow' },
      { actor: 'Verifier', testId: 'test-01', evaluatedState: 'not safe!' },
    ),
    /evaluatedState/,
  );
});
