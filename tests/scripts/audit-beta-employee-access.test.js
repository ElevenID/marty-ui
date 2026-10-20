'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  approveAndIssue,
  createAndSubmitApplication,
  employeeApplicationTemplatePayload,
  employeeCredentialPayload,
  employeeFlowPayload,
  employeePolicyPayload,
  employeeTrustProfilePayload,
  requireConfigurationBinding,
} = require('./audit-beta-employee-access');
const { DEFAULT_BETA_ORGANIZATION_ID } = require('./beta-credential-contract');
const { walletSessionDriverRegressions } = require('./demo-wallet-driver-test-helpers');

walletSessionDriverRegressions('audit-beta-employee-access.js', 'D-04');

function ownedRun(extra = {}) {
  return {
    organizationId: process.env.BETA_AUDIT_ORG_ID || DEFAULT_BETA_ORGANIZATION_ID,
    applicationTemplateId: 'employee-application-template',
    credentialTemplateId: 'employee-credential-template',
    applicantId: 'employee-applicant',
    runId: 'employee-run',
    applicationId: null,
    uncertainMutations: [],
    ...extra,
  };
}

function application(owned, extra = {}) {
  return {
    id: owned.applicationId || 'employee-application/1',
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

test('D-04 configuration uses one exact employee credential across application, flow, and policy', () => {
  const credentialPayload = employeeCredentialPayload(
    source,
    'did:web:beta.example:orgs:target',
    'target-revocation-1',
    'target-trust-1',
  );
  assert.equal(credentialPayload.credential_type, 'EmployeeAccessCredential');
  assert.deepEqual(
    credentialPayload.claims.map(({ name }) => name),
    ['employee_id', 'given_name', 'family_name', 'department', 'access_level', 'employment_status'],
  );
  assert.equal(credentialPayload.issuer_did, 'did:web:beta.example:orgs:target');
  assert.equal(credentialPayload.revocation_profile_id, 'target-revocation-1');
  assert.equal(credentialPayload.trust_profile_id, 'target-trust-1');
  assert.deepEqual(
    employeeTrustProfilePayload('did:web:beta.example:orgs:target').allowed_issuers,
    ['did:web:beta.example:orgs:target'],
  );

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

test('D-04 retains its created application ID when submission fails', async () => {
  const owned = ownedRun();
  const page = fakePage([
    { ok: true, status: 201, body: application(owned) },
    { ok: false, status: 503, body: { error: 'unavailable' } },
  ]);

  await assert.rejects(
    () => createAndSubmitApplication(page, owned, 'EMP-current-run'),
    /Submit employee application failed \(HTTP 503\)/,
  );
  assert.equal(owned.applicationId, 'employee-application/1');
  assert.deepEqual(owned.uncertainMutations, []);
  assert.deepEqual(page.requests.map(({ requestPath, requestOptions }) => [requestPath, requestOptions.method]), [
    ['/v1/me/applications', 'POST'],
    ['/v1/me/applications/employee-application%2F1/submit', 'POST'],
  ]);
  const body = JSON.parse(page.requests[0].requestOptions.body);
  assert.equal(body.integration_context.demo_run_id, owned.runId);
  assert.equal(body.form_data.employee_id, 'EMP-current-run');
});

test('D-04 releases its exact reviewer lock after lost acquisition or approval failure without issuing', async () => {
  for (const lostAcquisition of [true, false]) {
    const owned = ownedRun({ applicationId: 'employee-application/1' });
    const page = fakePage([
      { ok: true, status: 200, body: application(owned, { status: 'SUBMITTED' }) },
      ...(lostAcquisition ? [new Error('Lost reviewer lock response')] : [
        {
          ok: true,
          status: 200,
          body: { id: 'reviewer-lock', organization_id: owned.organizationId, applicant_id: owned.applicationId },
        },
        { ok: false, status: 403, body: { error: 'forbidden' } },
      ]),
      { ok: true, status: 200, body: { released: true } },
    ]);

    await assert.rejects(() => approveAndIssue(page, owned), lostAcquisition
      ? /Lost reviewer lock response/
      : /Approve employee application failed \(HTTP 403\)/);
    const root = `/v1/organizations/${encodeURIComponent(owned.organizationId)}/applicants/employee-application%2F1`;
    assert.deepEqual(page.requests.map(({ requestPath, requestOptions }) => [requestPath, requestOptions.method || 'GET']), [
      [root, 'GET'],
      [`${root}/lock`, 'POST'],
      ...(lostAcquisition ? [] : [[`${root}/approve`, 'POST']]),
      [`${root}/lock`, 'DELETE'],
    ]);
    assert.equal(owned.transactionId, undefined);
    assert.deepEqual(owned.uncertainMutations, []);
  }
});
