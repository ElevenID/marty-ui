'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  DEFAULT_BETA_ORGANIZATION_ID,
  DEFAULT_LIFECYCLE_POLICY_ID,
  DEFAULT_LIFECYCLE_SOURCE_TEMPLATE_ID,
  requireLifecycleSourceSelection,
  DEFAULT_LOGIN_BADGE_CONFIGURATION_ID,
  DEFAULT_LOGIN_BADGE_TEMPLATE_ID,
  credentialConfigurationIdForWaltid,
  credentialLifecycleBehaviorAssertions,
  credentialInventoryEvidence,
  membershipLoginBehaviorAssertions,
  requireCompletedLoginNonce,
  loginNonceCompletionEvidence,
  isExactLoginNonceStatusUrl,
  isTerminalLoginNonceStatus,
  verificationResultEvidence,
  verificationSessionRequest,
} = require('./beta-credential-contract');

test('functional lifecycle requires explicit governed source before fixture intake; released default remains unchanged',()=>{
  for(const value of [undefined,'',' ',' source','source\n'])
    assert.throws(()=>requireLifecycleSourceSelection({RECORD_VIDEO:'0',BETA_AUDIT_TEMPLATE_ID:value}),/explicit governed/);
  for(const name of ['DEMO_LOCAL_FUNCTIONAL_RUNTIME_RECEIPT','DEMO_LOCAL_FUNCTIONAL_RUNTIME_SHA256',
    'DEMO_LOCAL_FUNCTIONAL_WALLET_RECEIPT','DEMO_LOCAL_FUNCTIONAL_WALLET_SHA256',
    'DEMO_LOCAL_FUNCTIONAL_WALLET_AUTHORITY_INPUT','DEMO_LOCAL_FUNCTIONAL_WALLET_AUTHORITY_SHA256']){
    for(const value of ['', 'SOURCE_ONLY_INPUT'])assert.throws(()=>requireLifecycleSourceSelection({RECORD_VIDEO:'1',[name]:value}),/explicit governed/);
    assert.equal(requireLifecycleSourceSelection({[name]:'SOURCE_ONLY_INPUT',BETA_AUDIT_TEMPLATE_ID:'owned-current-source'}),'owned-current-source');
  }
  assert.equal(requireLifecycleSourceSelection({RECORD_VIDEO:'0',BETA_AUDIT_TEMPLATE_ID:'owned-current-source'}),'owned-current-source');
  assert.equal(requireLifecycleSourceSelection({RECORD_VIDEO:'1'}),DEFAULT_LIFECYCLE_SOURCE_TEMPLATE_ID);
  assert.equal(requireLifecycleSourceSelection({}),DEFAULT_LIFECYCLE_SOURCE_TEMPLATE_ID);
});

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

test('verification evidence follows the canonical flat public result contract', () => {
  assert.deepEqual(
    verificationResultEvidence({
      status: 'completed',
      result: 'passed',
      decision: 'allow',
      decision_reason: 'All checks passed',
      error_codes: [],
      warnings: ['non-blocking notice'],
    }, 200),
    {
      httpStatus: 200,
      status: 'COMPLETED',
      evaluation: 'passed',
      decision: 'allow',
      decisionReason: 'All checks passed',
      errorCodes: [],
      warnings: ['non-blocking notice'],
    },
  );
});

test('verification evidence rejects the retired nested result contract', () => {
  const evidence = verificationResultEvidence({
    status: 'COMPLETED',
    result: {
      evaluation_result: 'passed',
      decision: 'allow',
      decision_reason: 'Retired response shape',
    },
  }, 200);

  assert.equal(evidence.status, 'COMPLETED');
  assert.equal(evidence.evaluation, null);
  assert.equal(evidence.decision, null);
  assert.equal(evidence.decisionReason, null);
});

test('verification evidence fails closed for malformed response bodies and lists', () => {
  assert.deepEqual(verificationResultEvidence(null, 502), {
    httpStatus: 502,
    status: null,
    evaluation: null,
    decision: null,
    decisionReason: null,
    errorCodes: [],
    warnings: [],
  });
  assert.deepEqual(
    verificationResultEvidence({ status: [], result: true, error_codes: ['valid', 7] }),
    {
      httpStatus: null,
      status: null,
      evaluation: null,
      decision: null,
      decisionReason: null,
      errorCodes: [],
      warnings: [],
    },
  );
});

test('verification session request includes the public verifier identity contract', () => {
  assert.deepEqual(verificationSessionRequest({
    organizationId: '10000000-0000-0000-0000-000000000001',
    presentationPolicyId: '10000000-0000-0000-0000-000000000002',
    issuerDid: 'did:web:beta.example:orgs:audit',
    externalReference: 'Suspended credential audit',
  }), {
    organization_id: '10000000-0000-0000-0000-000000000001',
    presentation_policy_id: '10000000-0000-0000-0000-000000000002',
    issuer_did: 'did:web:beta.example:orgs:audit',
    external_reference: 'Suspended credential audit',
  });
});

test('verification session request fails closed without exact public identifiers', () => {
  const valid = {
    organizationId: '10000000-0000-0000-0000-000000000001',
    presentationPolicyId: '10000000-0000-0000-0000-000000000002',
    issuerDid: 'did:web:beta.example:orgs:audit',
    externalReference: 'Lifecycle audit',
  };
  assert.throws(() => verificationSessionRequest({ ...valid, organizationId: 'org' }), /UUID/);
  assert.throws(() => verificationSessionRequest({ ...valid, presentationPolicyId: '' }), /UUID/);
  assert.throws(() => verificationSessionRequest({ ...valid, issuerDid: '' }), /DID/);
  assert.throws(() => verificationSessionRequest({ ...valid, externalReference: '' }), /non-empty/);
});

test('membership recording exposes the three exact happy-path behavior assertions', () => {
  const nonce = 'sample_-nonce';
  const exact = `https://beta.elevenidllc.com/v1/auth/credential-login/status?nonce=${nonce}`;
  assert.equal(isExactLoginNonceStatusUrl(exact, 'https://beta.elevenidllc.com', nonce), true);
  assert.equal(isExactLoginNonceStatusUrl(exact.replace('_', '%5F'),
    'https://beta.elevenidllc.com', nonce), true);
  assert.equal(isExactLoginNonceStatusUrl(exact.replace('beta.', 'foreign.'),
    'https://beta.elevenidllc.com', nonce), false);
  assert.equal(isExactLoginNonceStatusUrl(`${exact}&nonce=${nonce}`,
    'https://beta.elevenidllc.com', nonce), false);
  assert.equal(isExactLoginNonceStatusUrl(`${exact}&other=1`,
    'https://beta.elevenidllc.com', nonce), false);
  assert.equal(isExactLoginNonceStatusUrl(exact, 'https://beta.elevenidllc.com', 'different'), false);
  assert.deepEqual(loginNonceCompletionEvidence({ status: 'completed', reason_code: 'ignored' }), {
    status: 'completed', observedNonceStatus: 'completed',
  });
  assert.deepEqual(loginNonceCompletionEvidence({ status: 'failed', reason_code: 'issuer_not_trusted' }), {
    status: 'failed', observedNonceStatus: 'failed', reasonCode: 'issuer_not_trusted',
  });
  assert.deepEqual(loginNonceCompletionEvidence({ status: 'failed', reason_code: 'secret=do-not-log' }), {
    status: 'failed', observedNonceStatus: 'failed', reasonCode: 'unclassified',
  });
  assert.equal(loginNonceCompletionEvidence({ status: 'failed', reason_code: 'unknown_private_value' }).reasonCode,
    'unclassified');
  assert.deepEqual(loginNonceCompletionEvidence({ status: 'pending-timeout' }), {
    status: 'pending-timeout', observedNonceStatus: 'pending-timeout',
  });
  assert.deepEqual(loginNonceCompletionEvidence({ status: 'private-value' }), {
    status: 'invalid-response', observedNonceStatus: 'invalid-response',
  });
  for (const status of ['completed', 'failed', 'expired']) {
    assert.equal(isTerminalLoginNonceStatus({ status }), true);
  }
  for (const status of ['pending', 'pending-timeout', undefined]) {
    assert.equal(isTerminalLoginNonceStatus({ status }), false);
  }
  assert.doesNotThrow(() => requireCompletedLoginNonce('completed'));
  for (const status of ['failed', 'expired', 'pending-timeout', undefined]) {
    assert.throws(() => requireCompletedLoginNonce(status), /nonce did not complete/);
  }
  assert.deepEqual(membershipLoginBehaviorAssertions({
    badge: {
      offerSource: 'canonical-ui', loggedOut: true, accepted: true, storedExpectedCredential: true,
    },
    presentation: { accepted: true },
    completion: { status: 'completed', observedNonceStatus: 'completed', authenticated: true },
  }), {
    governed_claim: true,
    conformant_open_badge_issuance: true,
    same_device_passwordless_login: true,
  });
  assert.equal(membershipLoginBehaviorAssertions({}).governed_claim, false);
  for (const observedNonceStatus of ['failed', 'expired', 'pending-timeout', null]) {
    assert.equal(membershipLoginBehaviorAssertions({
      presentation: { accepted: true },
      completion: { status: 'completed', observedNonceStatus, authenticated: true },
    }).same_device_passwordless_login, false,
    'An authenticated browser cannot substitute for completion of this login nonce');
  }
  assert.equal(membershipLoginBehaviorAssertions({
    presentation: { accepted: true },
    completion: { status: 'pending-timeout', observedNonceStatus: 'pending-timeout',
      authenticated: false, timeoutDiagnostic: { status: 'completed', authenticated: true } },
  }).same_device_passwordless_login, false,
  'A late diagnostic completion cannot qualify the missing observed UI completion');
});

test('lifecycle recording requires status-aware allow and deny decisions', () => {
  const assertions = credentialLifecycleBehaviorAssertions({
    renewal: { ok: true },
    suspend: {
      ok: true,
      current: { lifecycleStatus: 'SUSPENDED' },
      verification: { result: { decision: 'deny', decisionReason: 'Credential suspended' } },
    },
    reinstate: {
      ok: true,
      current: { lifecycleStatus: 'ACTIVE' },
      verification: { result: { decision: 'allow' } },
    },
    revoke: {
      ok: true,
      current: { lifecycleStatus: 'REVOKED' },
      verification: { result: { decision: 'deny', decisionReason: 'Credential revoked' } },
    },
  });
  assert.deepEqual(assertions, {
    renew: true,
    suspend: true,
    reinstate: true,
    revoke: true,
    suspended_and_revoked_states_denied: true,
  });
  assert.equal(credentialLifecycleBehaviorAssertions({}).suspended_and_revoked_states_denied, false);
});
