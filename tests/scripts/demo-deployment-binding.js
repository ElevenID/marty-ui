const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;

function assertRecord(value, label) {
  assert(value && typeof value === 'object' && !Array.isArray(value), `${label} must be an object`);
}

function componentMap(entries, label) {
  assert(Array.isArray(entries) && entries.length > 0, `${label} must be a non-empty array`);
  const result = {};
  for (const entry of entries) {
    assertRecord(entry, `${label} entry`);
    assert(typeof entry.component === 'string' && entry.component, `${label} component is required`);
    assert(SHA40.test(entry.revision), `${label} revision must be a full lowercase Git SHA`);
    assert(!(entry.component in result), `${label} component is duplicated: ${entry.component}`);
    result[entry.component] = entry.revision;
  }
  return result;
}

function imageMap(entries, label) {
  assert(Array.isArray(entries) && entries.length > 0, `${label} must be a non-empty array`);
  const result = {};
  for (const entry of entries) {
    assertRecord(entry, `${label} entry`);
    assert(typeof entry.component === 'string' && entry.component, `${label} component is required`);
    assert(SHA256.test(entry.digest), `${label} digest must be a lowercase SHA-256 image digest`);
    assert(!(entry.component in result), `${label} component is duplicated: ${entry.component}`);
    result[entry.component] = entry.digest;
  }
  return result;
}

function assertPendingTemplate(manifest) {
  assertRecord(manifest, 'Public demo manifest');
  assert.equal(manifest.binding_state, 'PENDING_DEPLOYMENT');
  assert.equal(manifest.deployment_release_marker, null);
  assert.equal(manifest.demo_application_revision, null);
  assert.deepEqual(manifest.component_revisions, []);
  assert.deepEqual(manifest.image_digests, []);
  assertRecord(manifest.release_evidence, 'Public demo release evidence');
  assert.equal(manifest.release_evidence.source_marker, null);
}

function readBoundManifest(file, cwd = process.cwd()) {
  assert(typeof file === 'string' && file.trim(), 'DEPLOYED_DEMO_MANIFEST_PATH must name an evidence file');
  const resolved = path.resolve(cwd, file);
  const manifest = JSON.parse(fs.readFileSync(resolved, 'utf8'));
  assertRecord(manifest, 'Deployed demo manifest');
  assert.equal(manifest.binding_state, 'DEPLOYED_PENDING_EVIDENCE');
  assertRecord(manifest.release_evidence, 'Deployed demo release evidence');
  assert(
    typeof manifest.deployment_release_marker === 'string' && manifest.deployment_release_marker,
    'Deployed demo release marker is required',
  );
  assert(typeof manifest.stack_version === 'string' && manifest.stack_version, 'Deployed demo stack version is required');
  assert(typeof manifest.mip_version === 'string' && manifest.mip_version, 'Deployed demo MIP version is required');
  assert(SHA40.test(manifest.release_evidence.source_marker), 'Deployed demo source marker must be a full lowercase SHA');
  assert(SHA40.test(manifest.demo_application_revision), 'Deployed demo application revision must be a full lowercase Git SHA');
  return {
    kind: 'artifact',
    stackVersion: manifest.stack_version,
    mipVersion: manifest.mip_version,
    releaseVersion: manifest.deployment_release_marker,
    sourceId: manifest.release_evidence.source_marker,
    martyUiRevision: manifest.demo_application_revision,
    componentRevisions: componentMap(manifest.component_revisions, 'Deployed demo component revisions'),
    imageDigests: imageMap(manifest.image_digests, 'Deployed demo image digests'),
  };
}

function referenceFromEnvironment(environment = process.env, cwd = process.cwd()) {
  if (environment.DEPLOYED_DEMO_MANIFEST_PATH) {
    return readBoundManifest(environment.DEPLOYED_DEMO_MANIFEST_PATH, cwd);
  }
  const releaseVersion = environment.EXPECTED_RELEASE_VERSION;
  const sourceId = environment.EXPECTED_BETA_SOURCE_ID;
  const martyUiRevision = environment.EXPECTED_MARTY_UI_REVISION;
  assert(releaseVersion, 'EXPECTED_RELEASE_VERSION is required when no deployed demo manifest is supplied');
  assert(SHA40.test(sourceId), 'EXPECTED_BETA_SOURCE_ID must be a full lowercase SHA');
  assert(SHA40.test(martyUiRevision), 'EXPECTED_MARTY_UI_REVISION must be a full lowercase Git SHA');
  return {
    kind: 'dispatch',
    releaseVersion,
    sourceId,
    martyUiRevision,
  };
}

function assertLiveMap(map, valuePattern, label) {
  assertRecord(map, label);
  assert(Object.keys(map).length > 0, `${label} must not be empty`);
  for (const [component, value] of Object.entries(map)) {
    assert(component, `${label} contains an empty component name`);
    assert(typeof value === 'string' && valuePattern.test(value), `${label} contains an invalid value for ${component}`);
  }
}

function assertLiveDeployment(template, deployed, reference) {
  assertPendingTemplate(template);
  assertRecord(deployed, 'Live deployment marker');
  assert.equal(deployed.stack_version, template.stack_version);
  assert.equal(deployed.mip_version, template.mip_version);
  assert.equal(deployed.release_version, reference.releaseVersion);
  assert.equal(deployed.deployment_release_marker, reference.releaseVersion);
  assert.equal(deployed.marty_ui_sha, reference.sourceId);
  assertLiveMap(deployed.component_revisions, SHA40, 'Live component revisions');
  assertLiveMap(deployed.image_digests, SHA256, 'Live image digests');
  assert.equal(deployed.component_revisions['marty-ui'], reference.martyUiRevision);

  if (reference.kind === 'artifact') {
    assert.equal(reference.stackVersion, template.stack_version);
    assert.equal(reference.mipVersion, template.mip_version);
    assert.deepEqual(deployed.component_revisions, reference.componentRevisions);
    assert.deepEqual(deployed.image_digests, reference.imageDigests);
  }
}

module.exports = {
  assertLiveDeployment,
  assertPendingTemplate,
  readBoundManifest,
  referenceFromEnvironment,
};
