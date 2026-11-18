'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  providerSwitchBehaviorAssertions,
} = require('./beta-issuer-provider-switch-contract');

function passingReport() {
  const issuerDid = 'did:web:beta.example:orgs:d02';
  return {
    identityCreation: { ok: true, identity: { issuer_did: issuerDid, status: 'active' } },
    providerA: {
      issuance: { ok: true },
      credential: { verified: true, issuerDid, kid: `${issuerDid}#provider-a` },
      reverifiedAfterSwitch: true,
    },
    providerBConfig: { defaultServiceId: 'provider-b', serviceId: 'provider-b' },
    rebind: { ok: true, changed: true },
    providerB: {
      issuance: { ok: true },
      credential: { verified: true, issuerDid, kid: `${issuerDid}#provider-b` },
    },
    didAfterSwitch: {
      assertionMethodIds: [`${issuerDid}#provider-a`, `${issuerDid}#provider-b`],
    },
    unpublishedReplacement: {
      rebindStatus: 503,
      rebindOk: false,
      issueAfterDenial: { ok: true },
      credentialAfterDenial: { verified: true, issuerDid, kid: `${issuerDid}#provider-b` },
    },
  };
}

test('requires every D-02 happy and failure behavior from observable evidence', () => {
  assert.deepEqual(providerSwitchBehaviorAssertions(passingReport()), {
    create_issuer_profile: true,
    issue_with_provider_a: true,
    switch_signing_provider: true,
    verify_same_did_identity: true,
    unpublished_signing_key_denied: true,
  });
});

test('does not accept a metadata-only switch or a failed-cutover key change', () => {
  const sameKey = passingReport();
  sameKey.providerB.credential.kid = sameKey.providerA.credential.kid;
  assert.equal(providerSwitchBehaviorAssertions(sameKey).switch_signing_provider, false);

  const failOpen = passingReport();
  failOpen.unpublishedReplacement.credentialAfterDenial.kid = 'did:web:beta.example:orgs:d02#missing';
  assert.equal(providerSwitchBehaviorAssertions(failOpen).unpublished_signing_key_denied, false);
});
