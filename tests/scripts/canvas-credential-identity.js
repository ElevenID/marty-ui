'use strict';

const assert = require('node:assert/strict');

function walletExpectationForTemplate(template) {
  assert.ok(typeof template?.vct === 'string' && template.vct,
    'Canvas credential template requires its exact type URI');
  const format = String(template.credential_payload_format || '').toUpperCase();
  if (format === 'VC_JWT') {
    assert.equal(template.credential_type, 'OpenBadgeCredential',
      'Canvas VC-JWT requires the selected Open Badge type');
    return { format: 'jwt_vc_json', credentialConfigurationId: template.credential_type,
      achievementId: template.vct, credentialTypes: ['VerifiableCredential', 'OpenBadgeCredential'] };
  }
  assert.equal(format, 'SD_JWT_VC', 'Canvas credential format must be an explicitly supported Open Badge format');
  return template.vct;
}

function requireWalletReceiptBinding(receipt, expectation) {
  if (typeof expectation === 'string') {
    assert.equal(receipt?.vct, expectation, 'Wallet stored the wrong credential type');
  } else {
    assert.equal(receipt?.format, expectation.format, 'Wallet stored the wrong credential format');
    assert.equal(receipt?.credentialConfigurationId, expectation.credentialConfigurationId,
      'Wallet stored the wrong credential configuration');
    assert.equal(receipt?.achievementId, expectation.achievementId,
      'Wallet stored a different Open Badge achievement');
    assert.ok(Array.isArray(receipt?.credentialTypes)
      && expectation.credentialTypes.every(type => receipt.credentialTypes.includes(type)),
    'Wallet stored a credential without the selected Open Badge types');
  }
}

function requireSignedCredentialBinding(payload, template) {
  walletExpectationForTemplate(template);
  if (template.issuer_did) {
    assert.equal(payload?.iss, template.issuer_did, 'Signed credential issuer differs from selected template');
  }
  if (String(template.credential_payload_format || '').toUpperCase() === 'VC_JWT') {
    assert.ok(Array.isArray(payload?.vc?.type)
      && payload.vc.type.includes('VerifiableCredential')
      && payload.vc.type.includes('OpenBadgeCredential'),
    'Signed VC-JWT lacks the selected Open Badge type');
    assert.equal(payload?.vc?.credentialSubject?.achievement?.id, template.vct,
      'Signed Open Badge achievement differs from selected template');
  } else {
    assert.equal(payload?.vct, template.vct,
      'Signed SD-JWT differs from selected Open Badge template');
  }
}

module.exports = { walletExpectationForTemplate, requireWalletReceiptBinding, requireSignedCredentialBinding };
