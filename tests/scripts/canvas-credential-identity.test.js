'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  walletExpectationForTemplate,
  requireWalletReceiptBinding,
  requireSignedCredentialBinding,
} = require('./canvas-credential-identity');
const { walletReceiptMatchesExpectation } = require('./audit-beta-credential-lifecycle');

const vct = 'https://beta.elevenidllc.com/credentials/canvas-interoperability-foundations-badge';
const issuer = 'did:web:beta.elevenidllc.com:orgs:marty-identity-platform';
const vcTemplate = { vct, credential_type: 'OpenBadgeCredential', credential_payload_format: 'VC_JWT', issuer_did: issuer };

test('VC-JWT wallet receipt binds to its exact configuration rather than an absent top-level VCT', () => {
  const expectation = walletExpectationForTemplate(vcTemplate);
  assert.deepEqual(expectation, { format: 'jwt_vc_json', credentialConfigurationId: 'OpenBadgeCredential',
    achievementId: vct, credentialTypes: ['VerifiableCredential', 'OpenBadgeCredential'] });
  const body = { format: 'jwt_vc_json', credential_configuration_id: 'OpenBadgeCredential', vct: null,
    achievement_id: vct, credential_types: ['VerifiableCredential', 'OpenBadgeCredential'] };
  assert.equal(walletReceiptMatchesExpectation(body, 'OpenBadgeCredential', expectation), true);
  requireWalletReceiptBinding({ format: body.format, credentialConfigurationId: body.credential_configuration_id,
    achievementId: body.achievement_id, credentialTypes: body.credential_types }, expectation);
  assert.equal(walletReceiptMatchesExpectation({ ...body, format: 'dc+sd-jwt' }, 'OpenBadgeCredential', expectation), false);
  assert.equal(walletReceiptMatchesExpectation({ ...body, credential_configuration_id: 'OtherCredential' }, 'OpenBadgeCredential', expectation), false);
  assert.equal(walletReceiptMatchesExpectation({ ...body, achievement_id: 'https://other.example/badge' }, 'OpenBadgeCredential', expectation), false);
  assert.equal(walletReceiptMatchesExpectation({ ...body, credential_types: ['VerifiableCredential'] }, 'OpenBadgeCredential', expectation), false);
  assert.equal(walletReceiptMatchesExpectation(body, 'OtherCredential', expectation), false);
  assert.throws(() => requireWalletReceiptBinding({ format: 'jwt_vc_json', credentialConfigurationId: 'OtherCredential',
    achievementId: vct, credentialTypes: body.credential_types }, expectation));
});

test('verified VC-JWT binds issuer, VC type and achievement URI to selected Open Badge template', () => {
  const signed = { iss: issuer, vc: { type: ['VerifiableCredential', 'OpenBadgeCredential'],
    credentialSubject: { achievement: { id: vct } } } };
  requireSignedCredentialBinding(signed, vcTemplate);
  for (const invalid of [
    { ...signed, iss: 'did:web:other.example' },
    { ...signed, vc: { ...signed.vc, type: ['VerifiableCredential'] } },
    { ...signed, vc: { ...signed.vc, credentialSubject: { achievement: { id: 'https://other.example/badge' } } } },
  ]) assert.throws(() => requireSignedCredentialBinding(invalid, vcTemplate));
});

test('SD-JWT keeps exact VCT binding', () => {
  const sdTemplate = { vct, credential_type: 'OpenBadgeCredential', credential_payload_format: 'SD_JWT_VC' };
  assert.equal(walletExpectationForTemplate(sdTemplate), vct);
  assert.equal(walletReceiptMatchesExpectation({ format: 'dc+sd-jwt' }, `Badge ${vct}`, vct), true);
  requireSignedCredentialBinding({ vct }, sdTemplate);
  assert.throws(() => requireSignedCredentialBinding({ vct: 'https://other.example/badge' }, sdTemplate));
});

test('unsupported or unstated Canvas credential formats fail before wallet receipt matching', () => {
  for (const format of [undefined, '', 'MDOC', 'W3C_VCDM_V2_SD_JWT']) {
    assert.throws(() => walletExpectationForTemplate({ ...vcTemplate, credential_payload_format: format }));
  }
});
