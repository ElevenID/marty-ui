'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  passportClearanceBehaviorAssertions,
  validEvidenceDigest,
} = require('./beta-passport-clearance-contract');

const evidenceDigest = 'a'.repeat(64);

function passingReport() {
  return {
    passportEvidenceSha256: evidenceDigest,
    configuration: { vct: 'https://beta.example/credentials/pre-boarding-clearance' },
    application: {
      created: true,
      submittedStatus: 'SUBMITTED',
      lockAcquired: true,
      approvedStatus: 'APPROVED',
      passportEvidenceSha256: evidenceDigest,
    },
    issuance: {
      issueOk: true,
      walletReceived: true,
      walletEvidenceBound: true,
      credentialId: 'credential-1',
      vct: 'https://beta.example/credentials/pre-boarding-clearance',
      passportEvidenceSha256: evidenceDigest,
    },
    rapidGate: {
      walletPresented: true,
      result: { decision: 'allow', decisionReason: 'Requirements satisfied' },
    },
  };
}

test('accepts only an exact lower-case SHA-256 passport evidence digest', () => {
  assert.equal(validEvidenceDigest(evidenceDigest), true);
  assert.equal(validEvidenceDigest('A'.repeat(64)), false);
  assert.equal(validEvidenceDigest('a'.repeat(63)), false);
  assert.equal(validEvidenceDigest(`${'a'.repeat(63)}g`), false);
});

test('requires causally bound approval, issuance, wallet receipt, and gate allow', () => {
  assert.deepEqual(passportClearanceBehaviorAssertions(passingReport()), {
    pre_boarding_credential_issuance: true,
    rapid_gate_verification: true,
  });
});

test('rejects missing or drifted passport evidence and fail-open gate results', () => {
  const driftedApplication = passingReport();
  driftedApplication.application.passportEvidenceSha256 = 'b'.repeat(64);
  assert.equal(
    passportClearanceBehaviorAssertions(driftedApplication).pre_boarding_credential_issuance,
    false,
  );

  const unobservedWalletClaim = passingReport();
  unobservedWalletClaim.issuance.walletEvidenceBound = false;
  assert.equal(
    passportClearanceBehaviorAssertions(unobservedWalletClaim).pre_boarding_credential_issuance,
    false,
  );

  const denied = passingReport();
  denied.rapidGate.result = { decision: 'deny', decisionReason: 'Requirements not satisfied' };
  assert.equal(passportClearanceBehaviorAssertions(denied).rapid_gate_verification, false);
});
