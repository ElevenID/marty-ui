'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  passportClearanceBehaviorAssertions,
  subjectClaimsHash,
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

test('computes the issuance protocol subject-claims hash independent of key order', () => {
  const expected = '3a0c122ae8c5df2e88d088417fb059ff88027e550329c09e87de4f40aaec645d';
  assert.equal(subjectClaimsHash({ clearance_status: 'CLEARED', employee_id: 'A-1' }), expected);
  assert.equal(subjectClaimsHash({ employee_id: 'A-1', clearance_status: 'CLEARED' }), expected);
  assert.equal(subjectClaimsHash({
    z: { 'é': '😀', a: [{ 'β': 2, a: 1 }] },
    a: 'value',
  }), 'be5045f98f252157fbf980794d4b1013b27307718523969a9c4fb576382d52fa');
  assert.throws(() => subjectClaimsHash([]), /must be an object/);
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
