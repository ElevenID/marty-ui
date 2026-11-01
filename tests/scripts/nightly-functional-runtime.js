"use strict";
// Closed current-nightly image binding for functional demos; no installer/release admission.
const assert = require('node:assert/strict');
const SOURCE = '225818494f4ba716e75df7225d6c43d71b038879';
const RELEASE = 'v1.1.263-nightly.20261029.40946723707';
const LOCK_SHA = '4c7f07d0c1a1b6094da115771c7cc1b7fae655eacd32340372b5c05df3bfbd4c';
const SERVICES = 'ghcr.io/elevenid/marty-ui-oss/services@sha256:166c1c1bcbb2d952c354c4fa59268c23367687fbb96caa3dff374a9d1df4108d';
const UI = 'ghcr.io/elevenid/marty-ui-oss/ui-selfhost@sha256:6adcb1ed54d29fb0510c4c778fa0e070e8f082187b9526e5099d95703013ffea';
const ROLES = Object.freeze(['applicant','auth','canvas-sync-worker','compliance-profile','credential-template',
  'deployment-profile','device-registration','event-stream','flow','gateway','issuance','issuance-native',
  'notification','organization','passport-beta-bureau','passport-callback-signer','presentation-policy',
  'revocation-profile','signing-keys','trust-profile','verification','ui-prod']);
const HASH = /^[a-f0-9]{64}$/;
function binary(role) {
  if (role === 'ui-prod') return null;
  return ['issuance','issuance-native'].includes(role) ? 'marty-issuance-service'
    : role === 'verification' ? 'marty-verification-service' : 'marty-' + role;
}
function organizationSuccessor(ref, original, restoreRef, engineId, tools) {
  const value = tools.boundJson(ref);
  assert.equal(value.schema, 'marty.functional-organization-bootstrap-successor/v1');
  assert.equal(typeof tools.verifyBoundFile, 'function');
  tools.verifyBoundFile(value.operator, 1024 * 1024);
  const input = tools.boundJson(value.input), intent = tools.boundJson(value.intent);
  assert.equal(input.schema, 'marty.nightly-d05-synthetic-org-admin-operator-input/v1');
  assert.equal(input.sourceSha256, value.operator.sha256); assert.equal(intent.sourceSha256, value.operator.sha256);
  assert.equal(input.phase3Result.sha256, restoreRef.sha256); assert.equal(intent.phase3Sha256, restoreRef.sha256);
  assert.equal(input.engineId, engineId); assert.equal(intent.oldCid, original.Id);
  const permission = tools.boundJson(value.permission), retired = tools.boundJson(value.retirement);
  assert.equal(permission.schema, 'marty.nightly-d05-org-permission-reconciliation/v1');
  assert.equal(permission.state, 'PUBLIC_KMS_ADMIN_CONTROL_VISIBLE'); assert.equal(permission.probeExit, 0);
  assert.equal(permission.originalOperatorFailureRetained, true);
  assert.equal(permission.probeSourceSha256, value.permissionProbe.sha256);
  tools.verifyBoundFile(value.permissionProbe, 1024 * 1024);
  for (const [field, digestField] of [['probeStdout', 'stdoutSha256'], ['probeStderr', 'stderrSha256']]) {
    tools.verifyBoundFile(value[field], 1024 * 1024, 0); assert.equal(value[field].sha256, permission[digestField]);
  }
  assert.equal(retired.state, 'OWNED_LOCK_RETIRED'); assert.equal(retired.originalOperatorFailureRetained, true);
  for (const operation of [value.createTerminal, value.startTerminal]) {
    const terminal = tools.boundJson(operation); assert.equal(terminal.exit, 0);
    tools.verifyBoundFile(terminal.stdout, 1024 * 1024, 0); tools.verifyBoundFile(terminal.stderr, 1024 * 1024, 0);
  }
  const rows = tools.boundJson(value.inspect); assert(Array.isArray(rows) && rows.length === 1);
  const row = rows[0]; assert.equal(row.Id, permission.newCid); assert.equal(row.Id, retired.newCid);
  assert.notEqual(row.Id, original.Id); assert(HASH.test(row.Id));
  assert.equal(row.Name, original.Name); assert.equal(row.Image, original.Image);
  assert.deepEqual(row.HostConfig, original.HostConfig);
  const mounts = record => {const map = new Map(record.Mounts.map(item => [item.Destination, item])); assert.equal(map.size, record.Mounts.length); return Object.fromEntries([...map].sort());};
  assert.deepEqual(mounts(row), mounts(original));
  const config = record => {const result = {...record.Config}; delete result.Hostname; delete result.Env; delete result.Labels; return result;};
  assert.deepEqual(config(row), config(original));
  const env = record => {const result = {}; for (const item of record.Config.Env) {const at = item.indexOf('='); assert(at > 0); const key = item.slice(0, at); assert(!Object.hasOwn(result, key)); result[key] = item.slice(at + 1);} return result;};
  const expectedEnv = env(original); assert.equal(typeof input.newAdminEmail, 'string'); assert(input.newAdminEmail.includes('@'));
  expectedEnv.MARTY_ORG_ADMIN_EMAIL = input.newAdminEmail; assert.deepEqual(env(row), expectedEnv);
  assert.equal(row.Config.Labels['com.docker.compose.service'], 'organization');
  assert.equal(row.Config.Labels['com.docker.compose.project'], 'elevenid-beta');
  const networks = record => Object.fromEntries(Object.entries(record.NetworkSettings.Networks).map(([name, endpoint]) => [name, endpoint.NetworkID]));
  assert.deepEqual(networks(row), networks(original));
  assert.equal(row.State.Running, true); assert.equal(row.State.OOMKilled, false);
  assert.equal(row.State.Health.Status, 'healthy');
  assert(Date.parse(row.State.StartedAt) > Date.parse(original.State.StartedAt));
  assert(Number.isSafeInteger(row.State.Pid) && row.State.Pid > 0);
  return row;
}
function authority(profile, {boundJson, verifyBoundFile}) {
  assert.equal(profile.schema, 'marty.functional-mixed-runtime/v2');
  assert.equal(profile.scope, 'FUNCTIONAL_ONLY');
  assert.equal(profile.releaseQualified, false); assert.equal(profile.recordingQualified, false);
  assert(!profile.nativeOverlay && !profile.nativeMaintenance && !profile.maintenanceRestart && !profile.baseProfile,
    'Select one runtime authority');
  const refs = profile.signedImageDeployment;
  assert(refs && refs.releaseLock.sha256 === LOCK_SHA, 'Exact signed nightly image lock required');
  const lock = boundJson(refs.releaseLock), deployed = boundJson(refs.deployment), restored = boundJson(refs.writerRestore);
  assert.equal(lock.release, 'marty-ui@' + RELEASE.slice(1));
  assert.equal(deployed.state, 'PHASE2_MIXED_INFRA_STARTED'); assert.equal(deployed.release, RELEASE);
  assert.equal(deployed.fullNightlyQualified, false);
  assert.equal(restored.state, 'OPENBAO_NIGHTLY_IMAGE_AND_PLUGIN_RUNNING');
  assert.equal(restored.fullNightlyQualified, false); assert.equal(restored.keysGenerated, false);
  assert.equal(restored.writersRemainQuiesced, false);
  const raw = restored.restoredWriters;
  assert(Array.isArray(raw) && raw.length === 24);
  const byRole = new Map(raw.map(row => [row.Config?.Labels?.['com.docker.compose.service'], row]));
  assert.equal(byRole.size, 24);
  assert.deepEqual([...byRole.keys()].sort(), [...ROLES, 'keycloak', 'nginx-proxy'].sort());
  const phase1 = boundJson(refs.phase1Input);
  assert.equal(phase1.release, RELEASE); assert.equal(phase1.betaOnly, true);
  assert.equal(typeof phase1.engineId, 'string'); assert(phase1.engineId.length > 0);
  assert.equal(byRole.get('organization').Id, deployed.newCids.organization, 'Original organization lineage differs');
  const successor = refs.organizationSuccessor ? organizationSuccessor(refs.organizationSuccessor,
    byRole.get('organization'), refs.writerRestore, phase1.engineId, {boundJson, verifyBoundFile}) : null;
  if (successor) byRole.set('organization', successor);
  const rows = ROLES.map(role => {
    const row = byRole.get(role), reference = role === 'ui-prod' ? UI : SERVICES;
    assert.equal(lock.services[role === 'ui-prod' ? 'ui' : role] || (role.startsWith('passport-') ? SERVICES : null), reference);
    assert.equal(row.Config.Image, reference); assert.equal(row.Id, role === 'organization' && successor ? successor.Id : deployed.newCids[role]);
    assert(HASH.test(row.Id) && /^sha256:[a-f0-9]{64}$/.test(row.Image));
    assert.equal(row.State.Running, true); assert.equal(row.State.OOMKilled, false);
    const project = role === 'ui-prod' ? 'elevenid-beta-ui' : 'elevenid-beta';
    assert.equal(row.Config.Labels['com.docker.compose.project'], project);
    return {role, binary: binary(role), source: SOURCE, kind: 'SIGNED_NIGHTLY_IMAGE',
      imageId: row.Image, project, reference, requiredContainerId: row.Id,
      requiredStartedAt: row.State.StartedAt, requiredHostPid: row.State.Pid};
  });
  return {rows, engineId: phase1.engineId, refs};
}
function validateImages(images, rows) {
  assert(Array.isArray(images) && images.length === 2);
  const byRef = new Map(images.map(image => [image.reference, image])); assert.equal(byRef.size, 2);
  for (const row of rows) {
    const image = byRef.get(row.reference); assert(image);
    assert.equal(image.imageId, row.imageId);
    assert(Array.isArray(image.repoDigests) && image.repoDigests.includes(row.reference));
    assert.equal(image.sourceRevision, SOURCE);
    if (row.role === 'ui-prod') assert.equal(image.publicProfile, 'tester');
  }
}
function expected(profile, tools) {
  const {rows, engineId, refs} = authority(profile, tools), readback = tools.boundJson(refs.observation);
  assert.equal(readback.schema, 'marty.functional-signed-image-observation/v1');
  assert.equal(readback.release, RELEASE); assert.equal(readback.source, SOURCE);
  assert.equal(readback.engineId, engineId);
  assert.equal(readback.deploymentSha256, refs.deployment.sha256);
  assert.equal(readback.writerRestoreSha256, refs.writerRestore.sha256);
  assert.equal(readback.organizationSuccessorSha256 ?? null, refs.organizationSuccessor?.sha256 ?? null);
  assert.equal(readback.releaseQualified, false); assert.equal(readback.recordingQualified, false);
  validateImages(readback.images, rows);
  assert(Array.isArray(readback.roles) && readback.roles.length === 22);
  const observed = new Map(readback.roles.map(row => [row.role, row])); assert.equal(observed.size, 22);
  return rows.map(row => {
    const actual = observed.get(row.role); assert(actual);
    assert.equal(actual.containerId, row.requiredContainerId); assert.equal(actual.imageId, row.imageId);
    assert.equal(actual.startedAt, row.requiredStartedAt); assert.equal(actual.hostPid, row.requiredHostPid);
    assert.deepEqual(actual.binaryMounts, []); // Signed image executables cannot be overlaid.
    if (row.binary) {
      assert(HASH.test(actual.binarySha256)); assert.equal(actual.binarySha256, actual.processExecutableSha256);
      assert.equal(actual.effectiveUid, 10001); assert.equal(actual.configuredRuntimeUid, 10001);
      assert.equal(actual.executablePath, '/usr/local/bin/' + row.binary);
    } else assert.equal(actual.binarySha256, null);
    const expectation = {...row, sha256: actual.binarySha256,
      requiredObservation: Object.fromEntries(Object.entries(actual))};
    tools.validateRuntimeObservation(expectation, actual);
    return expectation;
  });
}
function produce(profile, {readDocker, boundJson, verifyBoundFile, observeDocker, validateRuntimeObservation}) {
  assert.equal(typeof readDocker, 'function');
  const {rows, engineId, refs} = authority(profile, {boundJson, verifyBoundFile});
  const engine = () => JSON.parse(readDocker(['info', '--format', '{{json .}}'])).ID;
  assert.equal(engine(), engineId);
  const images = [SERVICES, UI].map(reference => {
    const values = JSON.parse(readDocker(['image', 'inspect', reference])); assert.equal(values.length, 1);
    const image = values[0];
    return {reference, imageId: image.Id, repoDigests: image.RepoDigests,
      sourceRevision: image.Config?.Labels?.['org.opencontainers.image.revision'],
      ...(reference === UI ? {publicProfile: image.Config?.Labels?.['io.elevenid.selfhost.public-profile']} : {})};
  });
  validateImages(images, rows);
  const roles = rows.map(row => {
    const actual = observeDocker(row, readDocker);
    assert.deepEqual(actual.binaryMounts, []);
    const expectation = {...row, sha256: actual.binarySha256};
    if (row.binary) {
      assert(HASH.test(actual.binarySha256)); assert.equal(actual.effectiveUid, 10001);
      assert.equal(actual.configuredRuntimeUid, 10001);
    }
    validateRuntimeObservation(expectation, actual);
    return actual;
  });
  assert.equal(engine(), engineId);
  return {schema: 'marty.functional-signed-image-observation/v1', release: RELEASE, source: SOURCE,
    engineId, deploymentSha256: refs.deployment.sha256, writerRestoreSha256: refs.writerRestore.sha256,
    images, roles, organizationSuccessorSha256: refs.organizationSuccessor?.sha256 ?? null, releaseQualified: false, recordingQualified: false};
}
module.exports = {authority, expected, produce, ROLES, SOURCE, RELEASE, LOCK_SHA, SERVICES, UI};
