'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  employeeApplicationTemplatePayload,
  employeeCredentialPayload,
  employeeFlowPayload,
  employeePolicyPayload,
  requireConfigurationBinding,
} = require('./audit-beta-employee-access');

const source = {
  issuer_did: 'did:web:beta.example:orgs:issuer',
  compliance_profile_id: 'compliance-1',
  revocation_profile_id: 'revocation-1',
  trust_profile_id: 'trust-1',
  privacy_posture: 'SELECTIVE_DISCLOSURE',
  supported_formats: ['SD_JWT_VC'],
};

test('D-04 configuration uses one exact employee credential across application, flow, and policy', () => {
  const credentialPayload = employeeCredentialPayload(source);
  assert.equal(credentialPayload.credential_type, 'EmployeeAccessCredential');
  assert.deepEqual(
    credentialPayload.claims.map(({ name }) => name),
    ['employee_id', 'given_name', 'family_name', 'department', 'access_level', 'employment_status'],
  );
  assert.equal(credentialPayload.revocation_profile_id, 'revocation-1');

  const application = { id: 'application-template-1', status: 'ACTIVE', ...employeeApplicationTemplatePayload('credential-1') };
  const credential = {
    id: 'credential-1',
    status: 'ACTIVE',
    ...credentialPayload,
    trust_profile_id: 'trust-1',
    compliance_profile_id: 'compliance-1',
  };
  const policy = { id: 'policy-1', status: 'ACTIVE', ...employeePolicyPayload(credential) };
  const flow = {
    id: 'flow-1',
    status: 'ACTIVE',
    ...employeeFlowPayload('credential-1'),
  };
  assert.equal(application.approval_strategy, 'MANUAL');
  assert.deepEqual(flow.trigger, {
    trigger_type: 'WEBHOOK',
    config: { event_type: 'APPLICATION_APPROVED' },
  });
  assert.equal(policy.credential_requirements[0].credential_template_id, 'credential-1');
  assert.deepEqual(policy.credential_requirements[0].requested_claims, [{
    claim_name: 'employee_id',
    display_name: 'Employee ID',
    description: 'The employee identifier used for the access decision.',
    required: true,
    selective_disclosure: true,
    accept_derived: false,
    predicate_spec: null,
    constraints: [],
  }]);
  assert.equal(policy.credential_ranking_strategy, 'FRESHEST_FIRST');
  assert.equal(requireConfigurationBinding({ credential, application, policy, flow }).flow.id, 'flow-1');
});

test('D-04 configuration rejects drift between active release resources', () => {
  const credentialPayload = employeeCredentialPayload(source);
  assert.throws(() => requireConfigurationBinding({
    credential: { id: 'credential-1', ...credentialPayload },
    application: {
      id: 'application-template-1',
      credential_template_id: 'credential-2',
      approval_strategy: 'MANUAL',
    },
    policy: employeePolicyPayload({
      id: 'credential-1',
      trust_profile_id: 'trust-1',
      compliance_profile_id: 'compliance-1',
    }),
    flow: {
      ...employeeFlowPayload('credential-1'),
    },
  }), /wrong Credential Template/);

  assert.throws(() => requireConfigurationBinding({
    credential: { id: 'credential-1', ...credentialPayload },
    application: {
      id: 'application-template-1',
      ...employeeApplicationTemplatePayload('credential-1'),
    },
    policy: employeePolicyPayload({
      id: 'credential-1',
      trust_profile_id: 'trust-1',
      compliance_profile_id: 'compliance-1',
    }),
    flow: {
      ...employeeFlowPayload('credential-1'),
      application_template_id: 'application-template-1',
    },
  }), /exact employee Credential Template/);
});

test('D-04 configuration rejects semantic and approval-trigger drift', () => {
  const credentialPayload = employeeCredentialPayload(source);
  const credential = { id: 'credential-1', status: 'ACTIVE', ...credentialPayload };
  const application = {
    id: 'application-template-1',
    status: 'ACTIVE',
    ...employeeApplicationTemplatePayload('credential-1'),
  };
  const policy = { id: 'policy-1', status: 'ACTIVE', ...employeePolicyPayload(credential) };
  const flow = {
    id: 'flow-1',
    status: 'ACTIVE',
    ...employeeFlowPayload('credential-1'),
  };

  assert.throws(() => requireConfigurationBinding({
    credential: { ...credential, credential_type: 'GenericCredential' },
    application,
    policy,
    flow,
  }), /credential contract/);
  assert.throws(() => requireConfigurationBinding({
    credential,
    application,
    policy,
    flow: { ...flow, trigger: { trigger_type: 'WEBHOOK', config: { event_type: 'OTHER' } } },
  }), /approval event contract/);
  assert.throws(() => requireConfigurationBinding({
    credential,
    application,
    policy: { ...policy, credential_ranking_strategy: 'first_match' },
    flow,
  }), /employee access contract/);
  assert.throws(() => requireConfigurationBinding({
    credential,
    application,
    policy: {
      ...policy,
      credential_requirements: [{
        ...policy.credential_requirements[0],
        requested_claims: [{
          claim_name: 'employee_id',
          credential_type: null,
          value_constraint: null,
          predicate_spec: null,
        }],
      }],
    },
    flow,
  }), /employee access contract/);
});
