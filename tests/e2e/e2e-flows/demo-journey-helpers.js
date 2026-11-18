const path = require('node:path');

const PORTRAIT_PATH = path.resolve(__dirname, '../../fixtures/test-portrait.jpg');

async function readJson(page, url) {
  const response = await page.request.get(url);
  if (!response.ok()) throw new Error(`Demo prerequisite GET ${url} failed (${response.status()})`);
  return response.json();
}

async function requireSession(page, expectedEmail) {
  const auth = await readJson(page, '/v1/auth/me');
  if (!auth?.authenticated || auth.user?.email !== expectedEmail) {
    throw new Error(`Demo requires an authenticated session for ${expectedEmail}`);
  }
  return auth.user;
}

function selectDemoSetup(organizations, templates, applicationTemplates, options = {}) {
  if (![organizations, templates, applicationTemplates].every(Array.isArray)) {
    throw new Error('Demo prerequisite collections must be arrays');
  }
  const orgs = organizations.filter((org) => options.organizationId
    ? org.id === options.organizationId
    : org.name === options.organizationName || org.display_name === options.organizationName);
  if (orgs.length !== 1) throw new Error('Select one existing demo organization with DEMO_ORGANIZATION_ID');
  const organizationId = orgs[0].id;
  const candidates = templates.filter((template) => (
    template.organization_id === organizationId
    && String(template.status).toUpperCase() === 'ACTIVE'
    && (!options.templateId || template.id === options.templateId)
    && (template.credential_type === 'drivers_license'
      || template.credential_type === 'org.iso.18013.5.1.mDL'
      || template.doctype === 'org.iso.18013.5.1.mDL')
  ));
  if (candidates.length !== 1) throw new Error('Select one active demo mDL template with DEMO_CREDENTIAL_TEMPLATE_ID');
  const template = candidates[0];
  const linked = applicationTemplates.filter((candidate) => (
    candidate.organization_id === organizationId
    && candidate.credential_template_id === template.id
    && String(candidate.status).toUpperCase() === 'ACTIVE'
    && (!template.application_template_id || candidate.id === template.application_template_id)
  ));
  if (linked.length !== 1 || !Array.isArray(linked[0].form_fields) || !linked[0].form_fields.length) {
    throw new Error('Demo requires one active linked application template with real form fields');
  }
  return { organizationId, template, applicationTemplate: linked[0] };
}

function requireApplicationId(value) {
  if (typeof value !== 'string' || !value.trim()) throw new Error('Submitted application ID is missing');
  return value;
}

function assertApplicationRecord(record, setup, applicationId, statuses) {
  requireApplicationId(applicationId);
  if (record?.id !== applicationId || record.organization_id !== setup.organizationId
      || record.application_template_id !== setup.applicationTemplate.id
      || record.credential_template_id !== setup.template.id
      || !setup.applicantId || record.applicant_id !== setup.applicantId) {
    throw new Error('Application response does not match this demo submission and organization');
  }
  if (!statuses.includes(String(record.status).toUpperCase())) {
    throw new Error(`Demo application ${applicationId} is ${record.status}; expected ${statuses.join(' or ')}`);
  }
  return record;
}

function isClaimedApplication(record) {
  return ['ISSUED', 'CREDENTIALED'].includes(String(record.status).toUpperCase())
    && record.claim_state === 'CLAIMED';
}

async function bindOrganization(page, organizationId) {
  // ConsoleProvider explicitly restores this selected-org preference before
  // backend preferences. Reload so its in-memory context follows the same ID.
  await page.evaluate((id) => localStorage.setItem('activeOrgId', id), organizationId);
  await page.goto('/console/org');
  await page.getByTestId('console.dashboard.page').waitFor({ state: 'visible' });
  const selectedId = await page.evaluate(() => localStorage.getItem('activeOrgId'));
  if (selectedId !== organizationId) throw new Error('Console did not select the demo organization');
}

async function scrollIntoView(page, selectorOrLocator) {
  const locator = typeof selectorOrLocator === 'string'
    ? page.locator(selectorOrLocator).first() : selectorOrLocator;
  await locator.waitFor({ state: 'visible' });
  await locator.scrollIntoViewIfNeeded();
}

const normaliseLabel = (label) => label.replace(/\*/g, '').trim().toLowerCase();

function demoFormValues(user, overrides = {}) {
  if (!overrides || typeof overrides !== 'object' || Array.isArray(overrides)) {
    throw new Error('DEMO_FORM_VALUES_JSON must be an object keyed by visible field label');
  }
  return Object.fromEntries(Object.entries({
    'First Name': user.firstName, 'Given Name': user.firstName,
    'Last Name': user.lastName, 'Family Name': user.lastName, Surname: user.lastName,
    'Date Of Birth': user.dateOfBirth, 'Birth Date': user.dateOfBirth, Email: user.email,
    Street: '456 Oak Avenue', 'Street Address': '456 Oak Avenue', City: 'Austin',
    State: 'Texas', Zip: '78701', 'ZIP Code': '78701', 'Postal Code': '78701',
    Country: 'USA', Nationality: user.nationality,
    ...overrides,
  }).map(([label, value]) => [normaliseLabel(label), value]));
}

// ApplicationForm renders step-N and DynamicFieldRenderer controls with labels,
// not the old first-name-input/address-step/portrait-upload-input test IDs.
async function fillApplicationStep(page, step, values) {
  const inputs = step.locator('input:not([type="hidden"]):not([type="file"]):not([aria-hidden="true"]), textarea');
  for (let index = 0; index < await inputs.count(); index += 1) {
    const input = inputs.nth(index);
    const field = await input.evaluate((element) => ({
      label: Array.from(element.labels || []).map((label) => label.textContent).join(' '),
      required: element.required, type: element.type, value: element.value,
    }));
    const value = values[normaliseLabel(field.label)];
    if (value === undefined) {
      if (field.required && (!field.value || field.type === 'checkbox')) {
        throw new Error(`Provide DEMO_FORM_VALUES_JSON for required field "${field.label}"`);
      }
      continue;
    }
    if (field.type === 'checkbox') {
      if (typeof value !== 'boolean') throw new Error(`Checkbox "${field.label}" requires a boolean demo value`);
      await input.setChecked(value);
    } else {
      await input.fill(String(value));
    }
  }

  const selects = step.getByRole('combobox');
  for (let index = 0; index < await selects.count(); index += 1) {
    const select = selects.nth(index);
    const label = await select.evaluate((element) => element.closest('.MuiFormControl-root')?.querySelector('label')?.textContent || '');
    const value = values[normaliseLabel(label)];
    if (value === undefined) throw new Error(`Provide DEMO_FORM_VALUES_JSON for selection "${label}"`);
    await select.click();
    await page.getByRole('option', { name: String(value), exact: true }).click();
  }

  const uploads = step.locator('input[type="file"]');
  for (let index = 0; index < await uploads.count(); index += 1) {
    const upload = uploads.nth(index);
    const label = await upload.evaluate((element) => element.parentElement?.querySelector('button')?.textContent || '');
    const configuredPath = values[normaliseLabel(label)];
    if (!configuredPath && !/^Upload (Portrait|Photo)$/i.test(label.trim())) {
      throw new Error(`Provide DEMO_FORM_VALUES_JSON for file field "${label}"`);
    }
    await upload.setInputFiles(configuredPath || PORTRAIT_PATH);
  }
}

async function submitApplication(page) {
  await page.getByTestId('review-step').waitFor({ state: 'visible' });
  await page.getByTestId('accept-terms-checkbox').locator('input[type="checkbox"]').check();
  const submit = page.getByTestId('submit-application-btn');
  await scrollIntoView(page, submit);
  await submit.click();
  await page.getByTestId('application-submitted').waitFor({ state: 'visible', timeout: 30000 });
  return requireApplicationId(await page.getByTestId('application-id').getAttribute('data-value'));
}

async function approveApplication(page, setup, applicationId) {
  requireApplicationId(applicationId);
  const endpoint = `/v1/organizations/${encodeURIComponent(setup.organizationId)}/applicants/${encodeURIComponent(applicationId)}`;
  assertApplicationRecord(await readJson(page, endpoint), setup, applicationId,
    ['SUBMITTED', 'UNDER_REVIEW']);
  // Never open an arbitrary pending row, or use an API mutation to conceal a
  // missing approval control. This route binds review and reviewer lock to our ID.
  await page.goto(`/console/org/operate/applications/${encodeURIComponent(applicationId)}`);
  const approve = page.getByRole('button', { name: 'Approve', exact: true });
  await scrollIntoView(page, approve);
  await approve.click();
  const dialog = page.getByRole('dialog', { name: 'Approve Application', exact: true });
  await dialog.waitFor({ state: 'visible' });
  await dialog.getByRole('button', { name: 'Confirm Approval', exact: true }).click();
  await dialog.waitFor({ state: 'hidden' });
  return assertApplicationRecord(await readJson(page, endpoint), setup, applicationId,
    ['APPROVED', 'OFFERED', 'ISSUED', 'CREDENTIALED']);
}

module.exports = {
  readJson, requireSession, selectDemoSetup, requireApplicationId, assertApplicationRecord,
  isClaimedApplication, bindOrganization, scrollIntoView, demoFormValues, fillApplicationStep,
  submitApplication, approveApplication,
};
