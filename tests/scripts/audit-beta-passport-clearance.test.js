'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  clearanceApplicationTemplatePayload,
  clearanceCredentialPayload,
  clearanceFlowPayload,
  clearancePolicyPayload,
  requireConfigurationBinding,
} = require('./audit-beta-passport-clearance');

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
      credential_type: null,
      value_constraint: 'CLEARED',
      predicate_spec: null,
    }],
  );
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

  const excessiveDisclosure = configuration();
  excessiveDisclosure.policy.credential_requirements[0].requested_claims.push({
    claim_name: 'passport_evidence_sha256',
    value_constraint: null,
  });
  assert.throws(() => requireConfigurationBinding(excessiveDisclosure), /rapid-gate contract/);

  const weakCredentialEvidence = configuration();
  weakCredentialEvidence.credential.claims.find((claim) => (
    claim.name === 'passport_evidence_sha256'
  )).pattern = null;
  assert.throws(() => requireConfigurationBinding(weakCredentialEvidence), /pre-boarding contract/);

  const wrongTrigger = configuration();
  wrongTrigger.flow.trigger.config.event_type = 'APPLICATION_SUBMITTED';
  assert.throws(() => requireConfigurationBinding(wrongTrigger), /approval event contract/);
});
