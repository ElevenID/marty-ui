'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { VIDEO_SIZE, buildVerificationDisplay, createArtifactDir, createActionRecording } = require('./demo-recording');

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

test('functional action runs still fail if the production control is missing', async () => {
  const recording = createActionRecording({ enabled: false, scenario: 'employee' });
  let clicked = false;
  const missing = { waitFor: async () => { throw new Error('control missing'); }, click: async () => { clicked = true; } };
  await assert.rejects(recording.click({}, missing, { action: 'approve' }), /control missing/);
  assert.equal(clicked, false);
  assert.equal(recording.events.length, 0);
});

test('action cues carry measured control bounds without claiming frame or OS click timing', async () => {
  let clock = 4000;
  let clicked = false;
  const recording = createActionRecording({ enabled: true, scenario: 'employee', pageName: 'reviewer', now: () => clock });
  const bounds = { x: 100, y: 200, width: 90, height: 40 };
  const locator = { waitFor: async () => {}, scrollIntoViewIfNeeded: async () => {}, boundingBox: async () => bounds,
    click: async () => { clicked = true; clock += 50; } };
  await recording.click({ waitForTimeout: async (ms) => { clock += ms; } }, locator, { action: 'approve', durationMs: 3200 });
  assert.equal(clicked, true);
  assert.deepEqual(recording.events.map(({ phase }) => phase), [
    'control-visible', 'control-hold-end', 'control-click-dispatched', 'control-click-completed',
  ]);
  assert.equal(recording.events[2].elapsedSeconds, 3.2);
  assert.deepEqual(recording.events[2].bounds, bounds);
  assert.equal(recording.evidence.pageName, 'reviewer');
  assert.equal(recording.evidence.videoFrameAlignmentEstablished, false);
  assert.equal(recording.evidence.editorMustAlignToSourceFrames, true);
});

test('a failed click never becomes a completed action cue', async () => {
  const recording = createActionRecording({ enabled: true, scenario: 'employee' });
  const locator = { waitFor: async () => {}, scrollIntoViewIfNeeded: async () => {},
    click: async () => { throw new Error('button disabled'); } };
  await assert.rejects(recording.click({ waitForTimeout: async () => {} }, locator, { action: 'approve' }), /button disabled/);
  assert.equal(recording.events.at(-1).phase, 'control-click-dispatched');
});
