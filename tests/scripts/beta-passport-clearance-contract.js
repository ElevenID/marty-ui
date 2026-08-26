'use strict';

const PASSPORT_EVIDENCE_SHA256 = /^[a-f0-9]{64}$/;

function validEvidenceDigest(value) {
  return typeof value === 'string' && PASSPORT_EVIDENCE_SHA256.test(value);
}

function passportClearanceBehaviorAssertions(report = {}) {
  const evidenceDigest = report.passportEvidenceSha256;
  const application = report.application || {};
  const issuance = report.issuance || {};
  const gate = report.rapidGate || {};
  const exactEvidenceBinding = validEvidenceDigest(evidenceDigest)
    && application.passportEvidenceSha256 === evidenceDigest
    && issuance.passportEvidenceSha256 === evidenceDigest;

  return {
    pre_boarding_credential_issuance: Boolean(
      exactEvidenceBinding
      && application.created
      && String(application.submittedStatus || '').toUpperCase() === 'SUBMITTED'
      && application.lockAcquired
      && String(application.approvedStatus || '').toUpperCase() === 'APPROVED'
      && issuance.issueOk
      && issuance.walletReceived
      && issuance.walletEvidenceBound
      && issuance.credentialId
      && issuance.vct
      && issuance.vct === report.configuration?.vct,
    ),
    rapid_gate_verification: Boolean(
      gate.walletPresented
      && gate.result?.decision === 'allow',
    ),
  };
}

module.exports = {
  PASSPORT_EVIDENCE_SHA256,
  passportClearanceBehaviorAssertions,
  validEvidenceDigest,
};
