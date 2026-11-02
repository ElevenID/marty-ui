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
const AUTH_OPERATOR_SHA = '02991b6b5f03c00d099eb33a00b68c5109ccdd65e2ce4d26f6eef46094fca500';
const same = (actual, expected, reason) => assert(require('node:util').isDeepStrictEqual(actual, expected), reason);
function uniqueMounts(rows, key) {
  assert(Array.isArray(rows));
  const map = new Map(rows.map(row => {assert(typeof row[key] === 'string' && row[key]); return [row[key], row];}));
  assert.equal(map.size, rows.length, 'Duplicate mount destination');
  return Object.fromEntries([...map].sort());
}
function environment(record) {
  const result = {};
  for (const item of record.Config.Env) {const at = item.indexOf('='); assert(at > 0);
    const key = item.slice(0, at); assert(!Object.hasOwn(result, key)); result[key] = item.slice(at + 1);}
  return result;
}
function replacement(original, row, role, changes) {
  assert.notEqual(row.Id, original.Id); assert(HASH.test(row.Id));
  assert.equal(row.Name, original.Name); assert.equal(row.Image, original.Image);
  const host = record => {const value = {...record.HostConfig};
    if (Object.hasOwn(value, 'Mounts')) value.Mounts = uniqueMounts(value.Mounts, 'Target'); return value;};
  same(host(row), host(original), 'Replacement HostConfig changed');
  same(uniqueMounts(row.Mounts, 'Destination'), uniqueMounts(original.Mounts, 'Destination'), 'Replacement mount fields changed');
  const config = record => {const result = {...record.Config}; delete result.Hostname; delete result.Env; delete result.Labels; return result;};
  same(config(row), config(original), 'Replacement Config changed');
  same(environment(row), {...environment(original), ...changes}, 'Replacement environment changed');
  assert.equal(row.Config.Labels['com.docker.compose.service'], role);
  assert.equal(row.Config.Labels['com.docker.compose.project'], 'elevenid-beta');
  const networks = record => Object.fromEntries(Object.entries(record.NetworkSettings.Networks).map(([name, endpoint]) => [name, endpoint.NetworkID]));
  same(networks(row), networks(original), 'Replacement networks changed');
  assert.equal(row.State.Running, true); assert.equal(row.State.OOMKilled, false);
  assert.equal(row.State.Health.Status, 'healthy');
  assert(Date.parse(row.State.StartedAt) > Date.parse(original.State.StartedAt));
  assert(Number.isSafeInteger(row.State.Pid) && row.State.Pid > 0);
  return row;
}
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
  assert.equal(typeof input.newAdminEmail, 'string'); assert(input.newAdminEmail.includes('@'));
  return replacement(original, row, 'organization', {MARTY_ORG_ADMIN_EMAIL: input.newAdminEmail});
}
function authSuccessor(ref, original, restoreRef, engineId, tools) {
  const value = tools.boundJson(ref);
  assert.equal(value.schema, 'marty.functional-auth-login-successor/v1');
  assert.equal(value.operator.sha256, AUTH_OPERATOR_SHA); tools.verifyBoundFile(value.operator, 1024 * 1024);
  const input = tools.boundJson(value.input), intent = tools.boundJson(value.intent), result = tools.boundJson(value.result);
  assert.equal(input.schema, 'marty.d05-auth-login-binding-input/v1');
  assert.equal(input.sourceSha256, AUTH_OPERATOR_SHA); assert.equal(intent.sourceSha256, AUTH_OPERATOR_SHA);
  assert.equal(input.executeAuthorized, true); assert.equal(input.engineId, engineId);
  assert.equal(input.phase3Result.sha256, restoreRef.sha256);
  assert.equal(input.organizationId, '00000000-0000-0000-0000-000000000001');
  assert.equal(input.policyId, '2e87a728-3c3a-4ce8-bb1a-f0a38542f536');
  assert.equal(input.issuerDid, 'did:web:beta.elevenidllc.com:orgs:marty-identity-platform');
  assert.equal(intent.state, 'AUTH_CREATE_UNKNOWN_UNTIL_TERMINAL'); assert.equal(intent.oldCid, original.Id);
  assert.equal(result.state, 'D05_AUTH_BINDING_UPDATED_HEALTHY'); assert.equal(result.qualified, false);
  assert.equal(result.oldCid, original.Id); assert.equal(value.model.sha256, result.modelSha256);
  const base = tools.boundJson(input.baseModel), model = tools.boundJson(value.model), expected = structuredClone(base);
  assert.equal(base.name, 'elevenid-beta');
  assert.equal(base.services.auth.environment.CREDENTIAL_LOGIN_POLICY_ID, '50000000-0000-0000-0000-000000000004');
  assert.equal(base.services.auth.environment.CREDENTIAL_LOGIN_ISSUER_DID, 'did:web:beta.elevenidllc.com:orgs:marty');
  const changes = {CREDENTIAL_LOGIN_POLICY_ID: input.policyId, CREDENTIAL_LOGIN_ISSUER_DID: input.issuerDid};
  Object.assign(expected.services.auth.environment, changes); same(model, expected, 'Auth model changed outside exact login bindings');
  const createIntent = tools.boundJson(value.createIntent), created = tools.boundJson(value.created);
  assert.equal(createIntent.oldCid, original.Id); assert.equal(createIntent.role, 'auth');
  assert.equal(createIntent.modelSha256, value.model.sha256);
  for (const flag of ['noBuild','noPull','noDeps','noStart']) assert.equal(createIntent[flag], true);
  assert.equal(created.cid, result.newCid); assert.equal(created.imageId, original.Image);
  assert.equal(created.modelSha256, result.modelSha256);
  for (const operation of [value.createTerminal, value.startTerminal]) {
    const terminal = tools.boundJson(operation); assert.equal(terminal.exit, 0);
    tools.verifyBoundFile(terminal.stdout, 1024 * 1024, 0); tools.verifyBoundFile(terminal.stderr, 1024 * 1024, 0);
  }
  const baseline = tools.boundJson(value.baseline); assert.equal(baseline.oldCid, original.Id);
  assert(Array.isArray(baseline.allIds) && baseline.allIds.every(id => HASH.test(id)));
  assert.equal(new Set(baseline.allIds).size, baseline.allIds.length); assert(baseline.allIds.includes(original.Id));
  tools.verifyBoundFile(value.afterIds, 1024 * 1024);
  const afterIds = tools.boundBytes(value.afterIds).toString('utf8').trim().split(/\r?\n/);
  assert(afterIds.every(id => HASH.test(id))); assert.equal(new Set(afterIds).size, afterIds.length);
  assert.deepEqual(afterIds.sort(), baseline.allIds.filter(id => id !== original.Id).concat(result.newCid).sort());
  const rows = tools.boundJson(value.inspect); assert(Array.isArray(rows) && rows.length === 1);
  const row = rows[0]; assert.equal(row.Id, result.newCid);
  // Compose may change only these generated provenance labels for this model.
  const labels = record => {const value = {...record.Config.Labels};
    for (const key of ['com.docker.compose.config-hash','com.docker.compose.project.config_files','com.docker.compose.project.working_dir']) delete value[key]; return value;};
  same(labels(row), labels(original), 'Auth provenance labels changed');
  return replacement(original, row, 'auth', changes);
}
function authority(profile, {boundJson, verifyBoundFile, boundBytes}) {
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
  let byRole = new Map(raw.map(row => [row.Config?.Labels?.['com.docker.compose.service'], row]));
  assert.equal(byRole.size, 24);
  assert.deepEqual([...byRole.keys()].sort(), [...ROLES, 'keycloak', 'nginx-proxy'].sort());
  const phase1 = boundJson(refs.phase1Input);
  assert.equal(phase1.release, RELEASE); assert.equal(phase1.betaOnly, true);
  assert.equal(typeof phase1.engineId, 'string'); assert(phase1.engineId.length > 0);
  assert.equal(byRole.get('organization').Id, deployed.newCids.organization, 'Original organization lineage differs');
  const successor = refs.organizationSuccessor ? organizationSuccessor(refs.organizationSuccessor,
    byRole.get('organization'), refs.writerRestore, phase1.engineId, {boundJson, verifyBoundFile}) : null;
  if (successor) byRole.set('organization', successor);
  assert.equal(byRole.get('auth').Id, deployed.newCids.auth, 'Original Auth lineage differs');
  const auth = refs.authSuccessor ? authSuccessor(refs.authSuccessor, byRole.get('auth'),
    refs.writerRestore, phase1.engineId, {boundJson, verifyBoundFile, boundBytes}) : null;
  if (auth) byRole.set('auth', auth);
  if (refs.restartSuccessor) byRole = require('./signed-nightly-restart').restartSuccessor(
    refs.restartSuccessor, byRole, ROLES, {boundJson, verifyBoundFile});
  if (refs.metadataRecovery) byRole = require('./signed-nightly-metadata').metadataRecovery(
    refs.metadataRecovery, byRole, {boundJson, verifyBoundFile});
  if (refs.metadataSuccessor) byRole = require('./signed-nightly-metadata').metadataSuccessor(
    refs.metadataSuccessor, byRole, {boundJson, verifyBoundFile});
  const rows = ROLES.map(role => {
    const row = byRole.get(role), reference = role === 'ui-prod' ? UI : SERVICES;
    assert.equal(lock.services[role === 'ui-prod' ? 'ui' : role] || (role.startsWith('passport-') ? SERVICES : null), reference);
    assert.equal(row.Config.Image, reference); assert.equal(row.Id, ((refs.metadataSuccessor && ['ui-prod','gateway'].includes(role)) || (refs.metadataRecovery && role==='ui-prod')) ? byRole.get(role).Id : role === 'organization' && successor ? successor.Id : role === 'auth' && auth ? auth.Id : deployed.newCids[role]);
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
  assert.equal(readback.authSuccessorSha256 ?? null, refs.authSuccessor?.sha256 ?? null);
  assert.equal(readback.restartSuccessorSha256 ?? null, refs.restartSuccessor?.sha256 ?? null);
  assert.equal(readback.metadataSuccessorSha256 ?? null, refs.metadataSuccessor?.sha256 ?? null);
  assert.equal(readback.metadataRecoverySha256 ?? null, refs.metadataRecovery?.sha256 ?? null);
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
function produce(profile, {readDocker, boundJson, verifyBoundFile, boundBytes, observeDocker, validateRuntimeObservation, validateRestartObservation}) {
  assert.equal(typeof readDocker, 'function');
  const {rows, engineId, refs} = authority(profile, {boundJson, verifyBoundFile, boundBytes});
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
  const previous = refs.restartSuccessor ? boundJson(boundJson(refs.restartSuccessor).previousObservation) : null;
  if (previous) {
    assert.equal(previous.schema,'marty.functional-signed-image-observation/v1');
    assert.equal(previous.source,SOURCE); assert.equal(previous.release,RELEASE);
    assert.equal(previous.engineId,engineId);
    assert.equal(previous.deploymentSha256,refs.deployment.sha256);
    assert.equal(previous.writerRestoreSha256,refs.writerRestore.sha256);
    assert.equal(previous.authSuccessorSha256 ?? null,refs.authSuccessor?.sha256 ?? null);
    assert.equal(previous.organizationSuccessorSha256 ?? null,refs.organizationSuccessor?.sha256 ?? null);
    assert.equal(previous.roles.length,22);
  }
  const roles = rows.map(row => {
    const actual = observeDocker(row, readDocker);
    assert.deepEqual(actual.binaryMounts, []);
    const expectation = {...row, sha256: actual.binarySha256};
    if (row.binary) {
      assert(HASH.test(actual.binarySha256)); assert.equal(actual.effectiveUid, 10001);
      assert.equal(actual.configuredRuntimeUid, 10001);
    }
    if (previous && !((refs.metadataSuccessor && ['ui-prod','gateway'].includes(row.role)) || (refs.metadataRecovery && row.role==='ui-prod'))) {
      const old=previous.roles.filter(value=>value.role===row.role); assert.equal(old.length,1);
      assert.equal(typeof validateRestartObservation,'function');
      validateRestartObservation({...expectation,requiredStartedAt:old[0].startedAt,requiredHostPid:old[0].hostPid,requiredObservation:old[0]},actual);
    }
    validateRuntimeObservation(expectation, actual);
    return actual;
  });
  assert.equal(engine(), engineId);
  return {schema: 'marty.functional-signed-image-observation/v1', release: RELEASE, source: SOURCE,
    engineId, deploymentSha256: refs.deployment.sha256, writerRestoreSha256: refs.writerRestore.sha256,
    images, roles, metadataRecoverySha256:refs.metadataRecovery?.sha256 ?? null, metadataSuccessorSha256: refs.metadataSuccessor?.sha256 ?? null, restartSuccessorSha256: refs.restartSuccessor?.sha256 ?? null, organizationSuccessorSha256: refs.organizationSuccessor?.sha256 ?? null,
    authSuccessorSha256: refs.authSuccessor?.sha256 ?? null, releaseQualified: false, recordingQualified: false};
}
module.exports = {authority, expected, produce, ROLES, SOURCE, RELEASE, LOCK_SHA, SERVICES, UI};
