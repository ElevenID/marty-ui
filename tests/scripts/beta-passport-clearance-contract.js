'use strict';

const crypto = require('node:crypto');

const PASSPORT_EVIDENCE_SHA256 = /^[a-f0-9]{64}$/;

function validEvidenceDigest(value) {
  return typeof value === 'string' && PASSPORT_EVIDENCE_SHA256.test(value);
}

function unicodeCodePointOrder(left, right) {
  const leftPoints = Array.from(left, (character) => character.codePointAt(0));
  const rightPoints = Array.from(right, (character) => character.codePointAt(0));
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index += 1) {
    if (leftPoints[index] !== rightPoints[index]) return leftPoints[index] - rightPoints[index];
  }
  return leftPoints.length - rightPoints.length;
}

function canonicalSubjectClaims(value) {
  if (Array.isArray(value)) return value.map(canonicalSubjectClaims);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.entries(value)
      .sort(([left], [right]) => unicodeCodePointOrder(left, right))
      .map(([name, item]) => [name, canonicalSubjectClaims(item)]),
  );
}

function subjectClaimsHash(claims) {
  if (!claims || typeof claims !== 'object' || Array.isArray(claims)) {
    throw new TypeError('subject claims must be an object');
  }
  const canonical = JSON.stringify(canonicalSubjectClaims(claims)).replace(
    /[\u007f-\uffff]/g,
    (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, '0')}`,
  );
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
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
  subjectClaimsHash,
  validEvidenceDigest,
};
