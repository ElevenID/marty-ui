const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  assertLiveDeployment,
  assertPendingTemplate,
  readBoundManifest,
  referenceFromEnvironment,
} = require('./demo-deployment-binding');

const revision = (character) => character.repeat(40);
const digest = (character) => `sha256:${character.repeat(64)}`;

function pendingTemplate() {
  return {
    stack_version: '2026.08.0',
    mip_version: '0.5.0',
    binding_state: 'PENDING_DEPLOYMENT',
    deployment_release_marker: null,
    demo_application_revision: null,
    component_revisions: [],
    image_digests: [],
    release_evidence: { source_marker: null },
  };
}

function boundManifest() {
  return {
    ...pendingTemplate(),
    binding_state: 'DEPLOYED_PENDING_EVIDENCE',
    deployment_release_marker: '2026.08.0',
    demo_application_revision: revision('a'),
    component_revisions: [
      { component: 'marty-core', revision: revision('b') },
      { component: 'marty-ui', revision: revision('a') },
    ],
    image_digests: [
      { component: 'gateway', digest: digest('c') },
      { component: 'ui-prod', digest: digest('d') },
    ],
    release_evidence: { source_marker: revision('e') },
  };
}

function liveMarker() {
  return {
    stack_version: '2026.08.0',
    mip_version: '0.5.0',
    release_version: '2026.08.0',
    deployment_release_marker: '2026.08.0',
    marty_ui_sha: revision('e'),
    component_revisions: {
      'marty-core': revision('b'),
      'marty-ui': revision('a'),
    },
    image_digests: {
      gateway: digest('c'),
      'ui-prod': digest('d'),
    },
  };
}

test('keeps the public manifest honestly pending deployment', () => {
  assert.doesNotThrow(() => assertPendingTemplate(pendingTemplate()));
  const dishonest = pendingTemplate();
  dishonest.deployment_release_marker = '2026.08.0';
  assert.throws(() => assertPendingTemplate(dishonest), /Expected values to be strictly equal/);
});

test('compares the live marker with every field in the post-deploy artifact', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'demo-binding-'));
  try {
    const file = path.join(directory, 'deployed-demo-manifest.json');
    fs.writeFileSync(file, JSON.stringify(boundManifest()));
    const reference = readBoundManifest(file);
    assert.doesNotThrow(() => assertLiveDeployment(pendingTemplate(), liveMarker(), reference));

    const drifted = liveMarker();
    drifted.image_digests.gateway = digest('f');
    assert.throws(
      () => assertLiveDeployment(pendingTemplate(), drifted, reference),
      /Expected values to be strictly deep-equal/,
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('uses exact protected-workflow dispatch values when no local artifact exists', () => {
  const reference = referenceFromEnvironment({
    EXPECTED_RELEASE_VERSION: '2026.08.0',
    EXPECTED_BETA_SOURCE_ID: revision('e'),
    EXPECTED_MARTY_UI_REVISION: revision('a'),
  });
  assert.equal(reference.kind, 'dispatch');
  assert.doesNotThrow(() => assertLiveDeployment(pendingTemplate(), liveMarker(), reference));

  const drifted = liveMarker();
  drifted.component_revisions['marty-ui'] = revision('f');
  assert.throws(
    () => assertLiveDeployment(pendingTemplate(), drifted, reference),
    /Expected values to be strictly equal/,
  );
});

test('fails closed without a post-deploy artifact or complete dispatch binding', () => {
  assert.throws(
    () => referenceFromEnvironment({}),
    /EXPECTED_RELEASE_VERSION is required/,
  );
  assert.throws(
    () => referenceFromEnvironment({
      EXPECTED_RELEASE_VERSION: '2026.08.0',
      EXPECTED_BETA_SOURCE_ID: 'not-a-sha',
      EXPECTED_MARTY_UI_REVISION: revision('a'),
    }),
    /EXPECTED_BETA_SOURCE_ID/,
  );
});
