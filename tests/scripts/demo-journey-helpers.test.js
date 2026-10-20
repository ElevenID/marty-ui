const assert = require('node:assert/strict');
const test = require('node:test');
const vm = require('node:vm');
const {
  requireSession, selectDemoSetup, assertApplicationRecord, isClaimedApplication,
  bindOrganization, scrollIntoView, fillApplicationStep, submitApplication, approveApplication,
} = require('../e2e/e2e-flows/demo-journey-helpers');
const contract = require('../../contracts/applicant-service-behavior.json');
const migration = require('../../contracts/applicant-store-migration-behavior.json');
const mdocTemplateContract = require('../../contracts/credential-template-internal-behavior.json')
  .credential_configurations.find((template) => template.credential_format === 'MDOC');

// The released migration fixture supplies the public application identifiers
// and offer state. These doubles exercise recorder failure behavior, not a
// synthetic claim that the live application/wallet journey passed.
const application = { ...migration.input.applications[0], ...migration.expected };
const setup = {
  organizationId: application.organization_id,
  applicantId: application.applicant_id,
  template: { id: application.credential_template_id },
  applicationTemplate: { id: application.application_template_id },
};
const appPath = `/v1/organizations/${setup.organizationId}/applicants/${application.id}`;

function requestPage(body, status = 200) {
  const requests = [];
  return {
    requests,
    request: { get: async (url) => {
      requests.push(url);
      return { ok: () => status === 200, status: () => status, json: async () => body };
    } },
  };
}

test('missing and wrong-user sessions fail against the current auth endpoint', async () => {
  const failed = requestPage(null, 503);
  await assert.rejects(requireSession(failed, 'demo@example.test'), /failed \(503\)/);
  assert.deepEqual(failed.requests, ['/v1/auth/me']);
  await assert.rejects(requireSession(requestPage({ authenticated: true, user: { email: 'other@example.test' } }), 'demo@example.test'), /requires an authenticated session/);
});

test('preflight refuses missing, ambiguous, and foreign linked templates', () => {
  const organizations = [{ id: setup.organizationId }];
  const template = { ...setup.template, ...mdocTemplateContract, organization_id: setup.organizationId, status: 'ACTIVE' };
  const linked = { ...setup.applicationTemplate, organization_id: setup.organizationId, credential_template_id: template.id, status: 'ACTIVE', form_fields: [{ field_id: 'given_name', type: 'string', required: true }] };
  const options = { organizationId: setup.organizationId };
  assert.throws(() => selectDemoSetup(organizations, [], [linked], options), /active demo mDL/);
  assert.throws(() => selectDemoSetup(organizations, [template, { ...template, id: 'another' }], [linked], options), /active demo mDL/);
  assert.throws(() => selectDemoSetup(organizations, [template], [{ ...linked, organization_id: 'foreign' }], options), /active linked application template/);
  assert.throws(() => selectDemoSetup(organizations, [template], [{ ...linked, form_fields: [] }], options), /real form fields/);
  assert.equal(selectDemoSetup(organizations, [template], [linked], options).template.id, template.id);
});

test('a Locator scrolls directly and missing/failed scrolls reject', async () => {
  const calls = [];
  const locator = { waitFor: async () => calls.push('visible'), scrollIntoViewIfNeeded: async () => calls.push('scroll') };
  await scrollIntoView({ locator: () => { throw new Error('Locator was incorrectly treated as a selector'); } }, locator);
  assert.deepEqual(calls, ['visible', 'scroll']);
  await assert.rejects(scrollIntoView({}, { ...locator, scrollIntoViewIfNeeded: async () => { throw new Error('scroll failed'); } }), /scroll failed/);
});

test('explicit organization preference is restored and verified after navigation', async () => {
  const storage = new Map();
  const calls = [];
  const page = {
    evaluate: async (fn, id) => vm.runInNewContext(`(${fn.toString()})(id)`, {
      id, localStorage: { setItem: (key, value) => storage.set(key, value), getItem: (key) => storage.get(key) },
    }),
    goto: async (url) => calls.push(url),
    getByTestId: (id) => ({ waitFor: async () => calls.push(id) }),
  };
  await bindOrganization(page, setup.organizationId);
  assert.equal(storage.get('activeOrgId'), setup.organizationId);
  assert.deepEqual(calls, ['/console/org', 'console.dashboard.page']);
  page.goto = async () => storage.set('activeOrgId', 'other-org');
  await assert.rejects(bindOrganization(page, setup.organizationId), /did not select/);
});

test('required dynamic field values and failed fills cannot be silently skipped', async () => {
  const input = { evaluate: async () => ({ label: 'License Number *', required: true, value: '', type: 'text' }), fill: async () => { throw new Error('input detached'); } };
  const step = { locator: () => ({ count: async () => 1, nth: () => input }) };
  await assert.rejects(fillApplicationStep({}, step, {}), /required field "License Number \*"/);
  await assert.rejects(fillApplicationStep({}, step, { 'license number': 'synthetic-value' }), /input detached/);
});

function submissionPage(failAt, id = application.id) {
  const calls = [];
  const locator = (name) => ({
    waitFor: async () => { calls.push(name); if (name === failAt) throw new Error(`missing ${name}`); },
    locator: () => ({ check: async () => calls.push('check terms') }),
    scrollIntoViewIfNeeded: async () => {},
    click: async () => calls.push('submit click'),
    getAttribute: async () => id,
  });
  return { calls, getByTestId: locator };
}

test('submission requires its review, submit control, confirmation, and returned ID', async () => {
  for (const missing of ['review-step', 'submit-application-btn', 'application-submitted']) {
    await assert.rejects(submitApplication(submissionPage(missing)), new RegExp(`missing ${missing}`));
  }
  await assert.rejects(submitApplication(submissionPage(null, null)), /application ID is missing/);
  assert.equal(await submitApplication(submissionPage()), application.id);
});

test('approval cannot navigate or mutate without this run’s exact applicant/template/application', async () => {
  await assert.rejects(approveApplication({}, setup, null), /application ID is missing/);
  for (const field of ['id', 'organization_id', 'application_template_id', 'credential_template_id', 'applicant_id']) {
    const page = requestPage({ ...application, status: 'SUBMITTED', [field]: 'foreign' });
    page.goto = async () => assert.fail('foreign application must not be opened');
    await assert.rejects(approveApplication(page, setup, application.id), /does not match/);
    assert.deepEqual(page.requests, [appPath]);
  }
});

test('missing approval UI fails after exact read and never falls back to an API mutation', async () => {
  const page = requestPage({ ...application, status: 'SUBMITTED' });
  page.goto = async (url) => assert.equal(url, `/console/org/operate/applications/${application.id}`);
  page.getByRole = () => ({ waitFor: async () => { throw new Error('Approve unavailable'); } });
  await assert.rejects(approveApplication(page, setup, application.id), /Approve unavailable/);
  assert.deepEqual(page.requests, [appPath]);
});

test('approval requires a successful confirmation and a changed backend state', async () => {
  const page = requestPage({ ...application, status: 'SUBMITTED' });
  const calls = [];
  page.goto = async (url) => calls.push(url);
  const button = { waitFor: async () => {}, scrollIntoViewIfNeeded: async () => {}, click: async () => calls.push('click') };
  const dialog = { waitFor: async () => {}, getByRole: () => button };
  page.getByRole = (role) => role === 'dialog' ? dialog : button;
  await assert.rejects(approveApplication(page, setup, application.id), /is SUBMITTED; expected APPROVED/);
  assert.equal(calls.filter((call) => call === 'click').length, 2);
  assert.deepEqual(page.requests, [appPath, appPath]);
});

test('an offer or unrelated credential never qualifies as completed claim', () => {
  assert.ok(contract.lifecycle_statuses.includes(application.status));
  assert.ok(contract.claim_states.includes(application.claim_state));
  assert.equal(isClaimedApplication(application), false);
  assert.equal(isClaimedApplication({ ...application, status: 'CREDENTIALED' }), false);
  assert.equal(isClaimedApplication({ ...application, claim_state: 'CLAIMED' }), false);
  const claimed = { ...application, status: 'CREDENTIALED', claim_state: 'CLAIMED' };
  assertApplicationRecord(claimed, setup, application.id, ['CREDENTIALED']);
  assert.equal(isClaimedApplication(claimed), true);
  assert.throws(() => assertApplicationRecord({ ...claimed, credential_template_id: 'other' }, setup, application.id, ['CREDENTIALED']), /does not match/);
});
