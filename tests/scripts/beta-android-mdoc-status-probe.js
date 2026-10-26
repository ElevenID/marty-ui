'use strict';

const assert = require('node:assert/strict');

const STATUS_PROBE_MODES = Object.freeze({
  OPTIONAL: 'optional',
  MISSING: 'missing-status-denial',
  RESOLVED: 'resolved-credential-status',
});

// ANDROID_REQUIRE_RESOLVED_STATUS=1 selects actual active/revoked status proof.
// The runtime driver supplies revoked=true only when it reuses its exact owned
// revoked credential. The old flag remains a separate missing-status scenario.
function statusProbeModeFromEnvironment(environment) {
  const missing = environment.ANDROID_REQUIRE_NOT_REVOKED_DIAGNOSTIC === '1';
  const resolved = environment.ANDROID_REQUIRE_RESOLVED_STATUS === '1';
  assert(!(missing && resolved), 'Missing-status and resolved-status probes are distinct scenarios');
  if (resolved) {
    assert.notEqual(environment.ANDROID_UNTRUSTED_ROOT_DIAGNOSTIC, '1',
      'Resolved status requires an authenticated trusted issuer, not an untrusted-root scenario');
  }
  return resolved ? STATUS_PROBE_MODES.RESOLVED
    : missing ? STATUS_PROBE_MODES.MISSING : STATUS_PROBE_MODES.OPTIONAL;
}

function requireKnownMode(mode) {
  assert(Object.values(STATUS_PROBE_MODES).includes(mode), 'Unknown status probe mode');
}

function statusProbePolicyFragment(mode) {
  requireKnownMode(mode);
  return mode === STATUS_PROBE_MODES.OPTIONAL ? {} : { freshness: { require_not_revoked: true } };
}

// These assertions consume actual public verifier output. They do not perform
// cryptographic verification, resolve a credential, or qualify a demo themselves.
function assertStatusProbeResult(mode, result, { revoked = false } = {}) {
  requireKnownMode(mode);
  if (mode === STATUS_PROBE_MODES.OPTIONAL) return {};
  assert.equal(result.httpStatus, 200);
  assert(Array.isArray(result.credentialResults), 'Credential evidence must be present');
  assert(result.credentialResults.length > 0, 'Empty credential evidence is not status proof');
  assert.equal(result.credentialResults.length, result.credentialResultCount);

  if (mode === STATUS_PROBE_MODES.MISSING) {
    assert.equal(result.result, 'failed');
    assert.equal(result.decision, 'deny');
    assert(result.credentialResults.every(item => item.notRevoked !== true));
    return {
      state: 'REQUIRED_STATUS_STOCK_WALLET_VERIFIER_DENY_LOCAL_DIAGNOSTIC_NOT_CREDENTIAL_REVOCATION_RESOLUTION',
      credentialSpecificRevocationResolved: false,
    };
  }

  const expectedStatus = revoked ? 'revoked' : 'active';
  assert.equal(result.result, revoked ? 'failed' : 'passed');
  assert.equal(result.decision, revoked ? 'deny' : 'allow');
  for (const item of result.credentialResults) {
    assert.equal(item.signatureValid, true, 'Status proof requires authenticated credential evidence');
    assert.equal(item.revocationChecked, true, 'Missing-status denial is not credential status resolution');
    assert.equal(item.notRevoked, !revoked);
    assert.equal(item.revocationStatus, expectedStatus);
  }
  return {
    state: revoked
      ? 'RESOLVED_STATUS_REVOKED_STOCK_WALLET_VERIFIER_DENY_LOCAL_DIAGNOSTIC_NOT_DEMO_QUALIFIED'
      : 'RESOLVED_STATUS_ACTIVE_STOCK_WALLET_VERIFIER_ALLOW_LOCAL_DIAGNOSTIC_NOT_DEMO_QUALIFIED',
    credentialSpecificRevocationResolved: true,
    resolvedCredentialStatus: expectedStatus,
  };
}

module.exports = {
  STATUS_PROBE_MODES,
  statusProbeModeFromEnvironment,
  statusProbePolicyFragment,
  assertStatusProbeResult,
};
