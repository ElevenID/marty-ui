'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  DEFAULT_BETA_ORGANIZATION_ID,
  DEFAULT_LIFECYCLE_POLICY_ID,
  DEFAULT_LIFECYCLE_SOURCE_TEMPLATE_ID,
  DEFAULT_LOGIN_BADGE_CONFIGURATION_ID,
  DEFAULT_LOGIN_BADGE_TEMPLATE_ID,
  credentialConfigurationIdForWaltid,
  credentialInventoryEvidence,
} = require('./beta-credential-contract');

test('beta gates target the canonical Marty organization and Open Badge login contract', () => {
  assert.equal(DEFAULT_BETA_ORGANIZATION_ID, '00000000-0000-0000-0000-000000000001');
  assert.equal(DEFAULT_LOGIN_BADGE_TEMPLATE_ID, '50000000-0000-0000-0000-000000000040');
  assert.equal(DEFAULT_LOGIN_BADGE_CONFIGURATION_ID, 'open_badge');
  assert.equal(DEFAULT_LIFECYCLE_POLICY_ID, '50000000-0000-0000-0000-000000000002');
  assert.equal(DEFAULT_LIFECYCLE_SOURCE_TEMPLATE_ID, '50000000-0000-0000-0000-000000000010');
});

test('wallet inventory accepts the exact VC-JWT configuration or legacy VCT evidence', () => {
  assert.deepEqual(
    credentialInventoryEvidence('[jwt_vc_json] open_badge (email, member_id)', {
      vct: 'https://beta.elevenidllc.com/credentials/marty-verified-member-badge',
      configurationId: 'open_badge',
    }),
    {
      storedExactVct: false,
      storedExpectedConfigurationId: true,
      storedExpectedCredential: true,
      storedExpectedVct: true,
    },
  );
  assert.equal(
    credentialInventoryEvidence('unrelated credential', { configurationId: 'open_badge' })
      .storedExpectedCredential,
    false,
  );
});

test('walt.id compatibility keeps its explicit SD-JWT route aliases deterministic', () => {
  assert.equal(credentialConfigurationIdForWaltid('open_badge'), 'open_badge#sd-jwt');
  assert.equal(credentialConfigurationIdForWaltid('open_badge#sd-jwt'), 'open_badge#sd-jwt');
  assert.equal(credentialConfigurationIdForWaltid('open_badge#apple-wallet'), 'open_badge#sd-jwt');
});
