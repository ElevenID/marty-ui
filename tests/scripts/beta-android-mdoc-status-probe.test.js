'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  STATUS_PROBE_MODES: MODES,
  statusProbeModeFromEnvironment,
  statusProbePolicyFragment,
  assertStatusProbeResult,
} = require('./beta-android-mdoc-status-probe');

// Assertion controls only. These objects are not wallet/demo execution evidence.
function observedStatus(revoked) {
  return {
    httpStatus: 200,
    result: revoked ? 'failed' : 'passed',
    decision: revoked ? 'deny' : 'allow',
    credentialResultCount: 1,
    credentialResults: [{
      signatureValid: true,
      revocationChecked: true,
      notRevoked: !revoked,
      revocationStatus: revoked ? 'revoked' : 'active',
    }],
  };
}

test('resolved active and revoked cases require status policy and actual matching evidence', () => {
  assert.equal(statusProbeModeFromEnvironment({ ANDROID_REQUIRE_RESOLVED_STATUS: '1' }), MODES.RESOLVED);
  assert.deepEqual(statusProbePolicyFragment(MODES.RESOLVED), { freshness: { require_not_revoked: true } });
  for (const revoked of [false, true]) {
    const proof = assertStatusProbeResult(MODES.RESOLVED, observedStatus(revoked), { revoked });
    assert.equal(proof.credentialSpecificRevocationResolved, true);
    assert.equal(proof.resolvedCredentialStatus, revoked ? 'revoked' : 'active');
    assert(proof.state.endsWith('NOT_DEMO_QUALIFIED'));
  }
});

test('old missing-status denial remains distinct and cannot satisfy resolved revocation', () => {
  const missing = observedStatus(true);
  Object.assign(missing.credentialResults[0], { revocationChecked: false, notRevoked: null, revocationStatus: null });
  assert.equal(statusProbeModeFromEnvironment({ ANDROID_REQUIRE_NOT_REVOKED_DIAGNOSTIC: '1' }), MODES.MISSING);
  assert.deepEqual(statusProbePolicyFragment(MODES.MISSING), { freshness: { require_not_revoked: true } });
  const proof = assertStatusProbeResult(MODES.MISSING, missing, { revoked: true });
  assert.equal(proof.credentialSpecificRevocationResolved, false);
  assert.equal(proof.state, 'REQUIRED_STATUS_STOCK_WALLET_VERIFIER_DENY_LOCAL_DIAGNOSTIC_NOT_CREDENTIAL_REVOCATION_RESOLUTION');
  assert.throws(() => assertStatusProbeResult(MODES.RESOLVED, missing, { revoked: true }));
  assert.throws(() => assertStatusProbeResult(MODES.MISSING, observedStatus(false)));
});

test('unresolved, unauthenticated, inconsistent and wrong lifecycle output fails resolved proof', () => {
  for (const change of [
    value => { value.credentialResults[0].signatureValid = false; },
    value => { value.credentialResults[0].revocationChecked = false; },
    value => { value.credentialResults[0].notRevoked = null; },
    value => { value.credentialResults[0].revocationStatus = null; },
    value => { value.credentialResults[0].revocationStatus = 'active'; },
    value => { value.credentialResultCount = 2; },
    value => { value.credentialResults = []; value.credentialResultCount = 0; },
    value => { value.decision = 'allow'; },
    value => { value.result = 'passed'; },
    value => { value.httpStatus = 409; },
  ]) {
    const value = observedStatus(true);
    change(value);
    assert.throws(() => assertStatusProbeResult(MODES.RESOLVED, value, { revoked: true }));
  }
  assert.throws(() => assertStatusProbeResult(MODES.RESOLVED, observedStatus(true), { revoked: false }));
  assert.throws(() => assertStatusProbeResult(MODES.RESOLVED, observedStatus(false), { revoked: true }));
});

test('conflicting modes and untrusted-root status resolution fail before feature actions', () => {
  assert.throws(() => statusProbeModeFromEnvironment({
    ANDROID_REQUIRE_RESOLVED_STATUS: '1', ANDROID_REQUIRE_NOT_REVOKED_DIAGNOSTIC: '1',
  }));
  assert.throws(() => statusProbeModeFromEnvironment({
    ANDROID_REQUIRE_RESOLVED_STATUS: '1', ANDROID_UNTRUSTED_ROOT_DIAGNOSTIC: '1',
  }));
  assert.throws(() => statusProbePolicyFragment('unknown'));
});

test('optional mode preserves policy and makes no credential-status proof claim', () => {
  assert.equal(statusProbeModeFromEnvironment({}), MODES.OPTIONAL);
  assert.deepEqual(statusProbePolicyFragment(MODES.OPTIONAL), {});
  assert.deepEqual(assertStatusProbeResult(MODES.OPTIONAL, {}), {});
});
