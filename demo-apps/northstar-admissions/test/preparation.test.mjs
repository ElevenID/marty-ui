import assert from 'node:assert/strict';
import test from 'node:test';

import {
  buildApplicationTemplateRequest,
  buildApplicationRequest,
  normalizeApplicationFixture,
  prepareApplicationContext,
  selectActiveCredentialTemplate,
} from '../src/preparation.mjs';

const applicationTemplate = {
  name: 'Northstar Application',
  form_fields: [{ field_id: 'email', label: 'Email', field_type: 'EMAIL', required: true }],
};

test('application fixture defines only safe, identifier-free public setup inputs', () => {
  const fixture = normalizeApplicationFixture({
    credential_template_name: 'Marty Verified Member Badge',
    application_template: applicationTemplate,
    form_data: { email: 'learner@northstar.example' },
    integration_context: { source: 'northstar' },
  });
  assert.equal(fixture.credentialTemplateName, 'Marty Verified Member Badge');
  assert.equal(fixture.applicationTemplate.approval_strategy, 'MANUAL');
  assert.deepEqual(fixture.applicationTemplate.evidence_requirements, []);
  assert.deepEqual(fixture.applicationTemplate.required_checks, []);
  assert.throws(
    () => normalizeApplicationFixture({
      credential_template_name: 'Marty Verified Member Badge',
      application_template: applicationTemplate,
      application_template_id: 'stale-id',
      form_data: { email: 'learner@northstar.example' },
    }),
    /unsupported fields: application_template_id/,
  );
  assert.throws(
    () => normalizeApplicationFixture({
      credential_template_name: 'Marty Verified Member Badge',
      application_template: applicationTemplate,
      organization_id: 'wrong-org',
      form_data: { email: 'learner@northstar.example' },
    }),
    /unsupported fields: organization_id/,
  );
  assert.throws(
    () => normalizeApplicationFixture({
      credential_template_name: 'Marty Verified Member Badge',
      application_template: applicationTemplate,
      form_data: {},
    }),
    /missing required field email/,
  );
});

test('active credential template selection is exact, tenant-bound, and fail-closed', () => {
  const templates = [
    { id: 'template-other', organization_id: 'org-2', name: 'Marty Verified Member Badge', status: 'ACTIVE' },
    { id: 'template-1', organization_id: 'org-1', name: 'Marty Verified Member Badge', status: 'active' },
  ];
  assert.deepEqual(
    selectActiveCredentialTemplate(templates, { organizationId: 'org-1', name: 'Marty Verified Member Badge' }),
    { id: 'template-1', name: 'Marty Verified Member Badge' },
  );
  assert.throws(
    () => selectActiveCredentialTemplate([], { organizationId: 'org-1', name: 'Marty Verified Member Badge' }),
    /found 0/,
  );
  assert.throws(
    () => selectActiveCredentialTemplate(
      [{ id: 'template-1', organization_id: 'org-1', name: 'Marty Verified Member Badge', status: 'DRAFT' }],
      { organizationId: 'org-1', name: 'Marty Verified Member Badge' },
    ),
    /not active/,
  );
  assert.throws(
    () => selectActiveCredentialTemplate(
      [
        { id: 'template-1', organization_id: 'org-1', name: 'Marty Verified Member Badge', status: 'ACTIVE' },
        { id: 'template-2', organization_id: 'org-1', name: 'Marty Verified Member Badge', status: 'ACTIVE' },
      ],
      { organizationId: 'org-1', name: 'Marty Verified Member Badge' },
    ),
    /found 2/,
  );
});

test('application setup binds public identifiers only at runtime', () => {
  const fixture = normalizeApplicationFixture({
    credential_template_name: 'Marty Verified Member Badge',
    application_template: applicationTemplate,
    form_data: { email: 'learner@northstar.example' },
    integration_context: { source: 'northstar' },
  });
  const templateRequest = buildApplicationTemplateRequest(
    fixture,
    { id: 'credential-template-1', name: 'Marty Verified Member Badge' },
    'org-1',
    'run-1',
  );
  assert.equal(templateRequest.name, 'Northstar Application run-1');
  assert.equal(templateRequest.credential_template_id, 'credential-template-1');
  assert.equal(templateRequest.organization_id, 'org-1');
  const request = buildApplicationRequest(
    fixture,
    { id: 'template-1', name: templateRequest.name },
    'org-1',
  );
  assert.deepEqual(request, {
    organization_id: 'org-1',
    application_template_id: 'template-1',
    form_data: { email: 'learner@northstar.example' },
    integration_context: { source: 'northstar' },
  });
  assert.throws(
    () => buildApplicationRequest(fixture, {}, 'org-1'),
    /application template identifier is required/,
  );
});

test('application preparation uses only the public gateway and activates before submission', async () => {
  const fixture = normalizeApplicationFixture({
    credential_template_name: 'Marty Verified Member Badge',
    application_template: applicationTemplate,
    form_data: { email: 'learner@northstar.example' },
    integration_context: { source: 'northstar' },
  });
  const calls = [];
  const responses = [
    [{ id: 'credential-template-1', organization_id: 'org-1', name: 'Marty Verified Member Badge', status: 'ACTIVE' }],
    { id: 'application-template-1', status: 'DRAFT' },
    { valid: true },
    { id: 'application-template-1', status: 'ACTIVE' },
  ];
  const gateway = async (path, options) => {
    calls.push({ path, options });
    return { ok: true, status: 200, payload: responses.shift() };
  };

  const prepared = await prepareApplicationContext({
    gateway,
    organizationId: 'org-1',
    adminCookie: 'session-cookie',
    fixture,
    runId: 'run-1',
  });

  assert.deepEqual(calls.map(({ path }) => path), [
    '/v1/credential-templates?organization_id=org-1&status=active',
    '/v1/application-templates',
    '/v1/application-templates/application-template-1/validate',
    '/v1/application-templates/application-template-1/activate',
  ]);
  assert.equal(calls[1].options.body.credential_template_id, 'credential-template-1');
  assert.equal(calls[2].options.method, 'POST');
  assert.equal(calls[3].options.method, 'POST');
  assert.equal(prepared.applicationInput.application_template_id, 'application-template-1');
  assert.equal(prepared.applicationTemplate.status, 'ACTIVE');
});

test('application preparation stops before activation when public validation fails', async () => {
  const fixture = normalizeApplicationFixture({
    credential_template_name: 'Marty Verified Member Badge',
    application_template: applicationTemplate,
    form_data: { email: 'learner@northstar.example' },
  });
  const calls = [];
  const responses = [
    [{ id: 'credential-template-1', organization_id: 'org-1', name: 'Marty Verified Member Badge', status: 'ACTIVE' }],
    { id: 'application-template-1', status: 'DRAFT' },
    { valid: false },
  ];
  const gateway = async (path) => {
    calls.push(path);
    return { ok: true, status: 200, payload: responses.shift() };
  };

  await assert.rejects(
    prepareApplicationContext({
      gateway,
      organizationId: 'org-1',
      adminCookie: 'session-cookie',
      fixture,
      runId: 'run-1',
    }),
    /did not pass public validation/,
  );
  assert.equal(calls.length, 3);
});
