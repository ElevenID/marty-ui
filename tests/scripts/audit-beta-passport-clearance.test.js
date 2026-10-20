'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  approveAndIssue,
  createAndSubmitApplication,
  clearanceApplicationTemplatePayload,
  clearanceCredentialPayload,
  clearanceFlowPayload,
  clearancePolicyPayload,
  clearanceTrustProfilePayload,
  requireConfigurationBinding,
} = require('./audit-beta-passport-clearance');
const { DEFAULT_BETA_ORGANIZATION_ID } = require('./beta-credential-contract');

function ownedRun(extra = {}) {
  return {
    organizationId: process.env.BETA_AUDIT_ORG_ID || DEFAULT_BETA_ORGANIZATION_ID,
    applicationTemplateId: 'passport-application-template',
    credentialTemplateId: 'passport-credential-template',
    applicantId: 'passport-applicant',
    runId: 'passport-run',
    applicationId: null,
    uncertainMutations: [],
    ...extra,
  };
}

function application(owned, extra = {}) {
  return {
    id: owned.applicationId || 'passport-application/1',
    organization_id: owned.organizationId,
    application_template_id: owned.applicationTemplateId,
    credential_template_id: owned.credentialTemplateId,
    applicant_id: owned.applicantId,
    integration_context: { demo_run_id: owned.runId },
    status: 'DRAFT',
    ...extra,
  };
}

function fakePage(responses) {
  const requests = [];
  return {
    requests,
    async evaluate(_callback, request) {
      requests.push(request);
      assert.ok(responses.length, `Unexpected request to ${request.requestPath}`);
      const response = responses.shift();
      if (response instanceof Error) throw response;
      return response;
    },
  };
}

const source = {
  issuer_did: 'did:web:beta.example:orgs:issuer',
  compliance_profile_id: 'compliance-1',
  revocation_profile_id: 'revocation-1',
  trust_profile_id: 'trust-1',
  privacy_posture: 'SELECTIVE_DISCLOSURE',
  supported_formats: ['SD_JWT_VC'],
};

function configuration() {
  const credential = {
    id: 'credential-1',
    status: 'ACTIVE',
    ...clearanceCredentialPayload(source),
    issuance_protocol: 'OID4VCI_PRE_AUTH',
    trust_profile_id: 'trust-1',
    compliance_profile_id: 'compliance-1',
  };
  return {
    credential,
    application: {
      id: 'application-1',
      status: 'ACTIVE',
      ...clearanceApplicationTemplatePayload(credential.id),
    },
    policy: {
      id: 'policy-1',
      status: 'ACTIVE',
      ...clearancePolicyPayload(credential),
    },
    flow: {
      id: 'flow-1',
      status: 'ACTIVE',
      ...clearanceFlowPayload(credential.id),
    },
  };
}

test('D-01 configuration binds one exact credential across application, flow, and policy', () => {
  const bound = requireConfigurationBinding(configuration());
  assert.equal(bound.credential.credential_type, 'PreBoardingClearanceCredential');
  assert.equal(bound.credential.issuance_protocol, 'OID4VCI_PRE_AUTH');
  assert.deepEqual(bound.credential.claims.map(({ name }) => name), [
    'traveler_id',
    'flight_number',
    'departure_airport',
    'arrival_airport',
    'boarding_group',
    'clearance_status',
    'passport_evidence_sha256',
  ]);
  assert.equal(bound.application.approval_strategy, 'MANUAL');
  assert.deepEqual(bound.flow.trigger, {
    trigger_type: 'WEBHOOK',
    config: { event_type: 'APPLICATION_APPROVED' },
  });
});

test('D-01 fresh configuration uses target-owned issuer, trust, and revocation bindings', () => {
  const issuerDid = 'did:web:beta.example:orgs:target';
  const credential = clearanceCredentialPayload(
    source,
    issuerDid,
    'target-revocation-1',
    'target-trust-1',
  );
  assert.equal(credential.issuer_did, issuerDid);
  assert.equal(credential.revocation_profile_id, 'target-revocation-1');
  assert.equal(credential.trust_profile_id, 'target-trust-1');
  assert.deepEqual(clearanceTrustProfilePayload(issuerDid).allowed_issuers, [issuerDid]);
});

test('D-01 application requires exact SHA-256 evidence and gate discloses only clearance', () => {
  const bound = requireConfigurationBinding(configuration());
  const evidenceField = bound.application.form_fields.find((field) => (
    field.field_id === 'passport_evidence_sha256'
  ));
  assert.equal(evidenceField.required, true);
  assert.equal(evidenceField.validation_pattern, '^[a-f0-9]{64}$');
  assert.deepEqual(
    bound.policy.credential_requirements[0].requested_claims,
    [{
      claim_name: 'clearance_status',
      display_name: 'Clearance status',
      description: 'A current pre-boarding clearance decision.',
      required: true,
      selective_disclosure: true,
      accept_derived: false,
      predicate_spec: null,
      constraints: [{
        claim_name: 'clearance_status',
        constraint_type: 'equals',
        value: 'CLEARED',
        description: null,
      }],
    }],
  );
  assert.equal(bound.policy.display_metadata.purpose, 'authorization');
  assert.equal(bound.policy.credential_ranking_strategy, 'FRESHEST_FIRST');
});

test('D-01 configuration rejects evidence, resource, policy, and trigger drift', () => {
  const wrongEvidence = configuration();
  wrongEvidence.application.form_fields.find((field) => (
    field.field_id === 'passport_evidence_sha256'
  )).validation_pattern = '.*';
  assert.throws(() => requireConfigurationBinding(wrongEvidence), /passport evidence contract/);

  const wrongCredential = configuration();
  wrongCredential.policy.credential_requirements[0].credential_template_id = 'credential-2';
  assert.throws(() => requireConfigurationBinding(wrongCredential), /rapid-gate contract/);

  const wrongIssuanceProtocol = configuration();
  wrongIssuanceProtocol.credential.issuance_protocol = 'OID4VCI_AUTH_CODE';
  assert.throws(() => requireConfigurationBinding(wrongIssuanceProtocol), /pre-boarding contract/);

  const excessiveDisclosure = configuration();
  excessiveDisclosure.policy.credential_requirements[0].requested_claims.push({
    claim_name: 'passport_evidence_sha256',
    constraints: [],
  });
  assert.throws(() => requireConfigurationBinding(excessiveDisclosure), /rapid-gate contract/);

  const legacyPolicy = configuration();
  legacyPolicy.policy.credential_ranking_strategy = 'first_match';
  assert.throws(() => requireConfigurationBinding(legacyPolicy), /rapid-gate contract/);

  const unsupportedPurpose = configuration();
  unsupportedPurpose.policy.display_metadata.purpose = 'travel_clearance';
  assert.throws(() => requireConfigurationBinding(unsupportedPurpose), /rapid-gate contract/);

  const weakCredentialEvidence = configuration();
  weakCredentialEvidence.credential.claims.find((claim) => (
    claim.name === 'passport_evidence_sha256'
  )).pattern = null;
  assert.throws(() => requireConfigurationBinding(weakCredentialEvidence), /pre-boarding contract/);

  const wrongTrigger = configuration();
  wrongTrigger.flow.trigger.config.event_type = 'APPLICATION_SUBMITTED';
  assert.throws(() => requireConfigurationBinding(wrongTrigger), /approval event contract/);
});

test('D-01 retains its created application ID when stored passport evidence fails validation', async () => {
  const owned = ownedRun();
  const evidenceDigest = 'a'.repeat(64);
  const page = fakePage([
    {
      ok: true,
      status: 201,
      body: application(owned, { form_data: { passport_evidence_sha256: 'b'.repeat(64) } }),
    },
  ]);

  await assert.rejects(
    () => createAndSubmitApplication(page, owned, evidenceDigest, owned.runId),
    /Stored D-01 application is not bound to the supplied passport evidence/,
  );
  assert.equal(owned.applicationId, 'passport-application/1');
  assert.deepEqual(owned.uncertainMutations, []);
  assert.deepEqual(page.requests.map(({ requestPath, requestOptions }) => [requestPath, requestOptions.method]), [
    ['/v1/me/applications', 'POST'],
  ]);
  const body = JSON.parse(page.requests[0].requestOptions.body);
  assert.deepEqual(body.integration_context, {
    evidence_type: 'marty_verifier_emrtd',
    evidence_sha256: evidenceDigest,
    demo_run_id: owned.runId,
  });
  assert.equal(body.form_data.passport_evidence_sha256, evidenceDigest);
});

test('D-01 attempts exact lock release on approval mismatch and retains unconfirmed lock outcomes', async () => {
  for (const lostRelease of [false, true]) {
    const owned = ownedRun({ applicationId: 'passport-application/1' });
    const page = fakePage([
      { ok: true, status: 200, body: application(owned, { status: 'SUBMITTED' }) },
      {
        ok: true,
        status: 200,
        body: { id: 'reviewer-lock', organization_id: owned.organizationId, applicant_id: owned.applicationId },
      },
      {
        ok: true,
        status: 200,
        body: application(owned, { status: 'APPROVED', integration_context: { demo_run_id: 'another-run' } }),
      },
      lostRelease ? new Error('Lost reviewer lock release response') : { ok: true, status: 200, body: { released: true } },
    ]);

    await assert.rejects(() => approveAndIssue(page, owned, 'a'.repeat(64)), lostRelease
      ? /Lost reviewer lock release response/
      : /Application response does not match this run/);
    const root = `/v1/organizations/${encodeURIComponent(owned.organizationId)}/applicants/passport-application%2F1`;
    assert.deepEqual(page.requests.map(({ requestPath, requestOptions }) => [requestPath, requestOptions.method || 'GET']), [
      [root, 'GET'],
      [`${root}/lock`, 'POST'],
      [`${root}/approve`, 'POST'],
      [`${root}/lock`, 'DELETE'],
    ]);
    assert.equal(owned.transactionId, undefined);
    assert.deepEqual(owned.uncertainMutations, lostRelease ? [{ operation: 'reviewer_lock' }] : []);
  }
});
