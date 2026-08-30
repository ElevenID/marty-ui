function plainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function requiredText(value, label) {
  const normalized = String(value || '').trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

async function expectGatewayPayload(label, promise) {
  const result = await promise;
  if (!result?.ok) {
    throw new Error(`${label} failed with HTTP ${result?.status ?? 'unknown'}: ${result?.payload?.detail || 'unknown error'}`);
  }
  return result.payload;
}

export function normalizeApplicationFixture(value) {
  const fixture = plainObject(value, 'Northstar application request');
  const allowed = new Set([
    'credential_template_name',
    'application_template',
    'form_data',
    'integration_context',
  ]);
  const unknown = Object.keys(fixture).filter((key) => !allowed.has(key));
  if (unknown.length) {
    throw new Error(`Northstar application request contains unsupported fields: ${unknown.sort().join(', ')}`);
  }
  const credentialTemplateName = String(fixture.credential_template_name || '').trim();
  if (!credentialTemplateName) {
    throw new Error('Northstar application request requires credential_template_name');
  }
  const applicationTemplate = plainObject(
    fixture.application_template,
    'Northstar application_template',
  );
  const applicationTemplateAllowed = new Set([
    'name',
    'description',
    'form_fields',
    'application_validity_days',
  ]);
  const applicationTemplateUnknown = Object.keys(applicationTemplate)
    .filter((key) => !applicationTemplateAllowed.has(key));
  if (applicationTemplateUnknown.length) {
    throw new Error(
      `Northstar application_template contains unsupported fields: ${applicationTemplateUnknown.sort().join(', ')}`,
    );
  }
  const name = String(applicationTemplate.name || '').trim();
  if (!name) throw new Error('Northstar application_template requires name');
  if (!Array.isArray(applicationTemplate.form_fields) || !applicationTemplate.form_fields.length) {
    throw new Error('Northstar application_template requires form_fields');
  }
  const formData = { ...plainObject(fixture.form_data, 'Northstar form_data') };
  const fieldIds = new Set();
  for (const field of applicationTemplate.form_fields) {
    plainObject(field, 'Northstar application form field');
    const fieldId = String(field.field_id || '').trim();
    if (!fieldId || fieldIds.has(fieldId)) {
      throw new Error('Northstar application form field identifiers must be non-empty and unique');
    }
    fieldIds.add(fieldId);
    if (field.required === true && !(fieldId in formData)) {
      throw new Error(`Northstar form_data is missing required field ${fieldId}`);
    }
  }
  const unexpectedFormFields = Object.keys(formData).filter((fieldId) => !fieldIds.has(fieldId));
  if (unexpectedFormFields.length) {
    throw new Error(`Northstar form_data contains undefined fields: ${unexpectedFormFields.sort().join(', ')}`);
  }
  return {
    credentialTemplateName,
    applicationTemplate: {
      name,
      description: applicationTemplate.description ?? null,
      form_fields: applicationTemplate.form_fields.map((field) => ({ ...field })),
      evidence_requirements: [],
      claim_collection_rules: [],
      required_checks: [],
      approval_strategy: 'MANUAL',
      application_validity_days: applicationTemplate.application_validity_days ?? 30,
      ui_config: { scenario: 'd11', partner: 'northstar-admissions' },
      notification_config: {},
    },
    formData,
    integrationContext: {
      ...plainObject(fixture.integration_context || {}, 'Northstar integration_context'),
    },
  };
}

export function selectActiveCredentialTemplate(payload, { organizationId, name }) {
  if (!Array.isArray(payload)) {
    throw new Error('Credential template listing must be a JSON array');
  }
  const tenant = requiredText(organizationId, 'Northstar organization identifier');
  const templateName = requiredText(name, 'Northstar credential template name');
  const matches = payload.filter((template) => (
    template
    && String(template.name || '').trim() === templateName
    && String(template.organization_id || '').trim() === tenant
  ));
  if (matches.length !== 1) {
    throw new Error(`Expected exactly one active public credential template named "${templateName}"; found ${matches.length}`);
  }
  const [template] = matches;
  if (String(template.status || '').toUpperCase() !== 'ACTIVE') {
    throw new Error(`Credential template "${templateName}" is not active`);
  }
  const id = String(template.id || '').trim();
  if (!id) throw new Error(`Credential template "${templateName}" has no public identifier`);
  return { id, name: templateName };
}

export function buildApplicationTemplateRequest(fixture, credentialTemplate, organizationId, runId) {
  const tenant = requiredText(organizationId, 'Northstar organization identifier');
  const credentialTemplateId = requiredText(
    credentialTemplate?.id,
    'Northstar credential template identifier',
  );
  const suffix = requiredText(runId, 'Northstar preparation run identifier');
  return {
    organization_id: tenant,
    ...fixture.applicationTemplate,
    name: `${fixture.applicationTemplate.name} ${suffix}`,
    credential_template_id: credentialTemplateId,
  };
}

export function buildApplicationRequest(fixture, template, organizationId) {
  const tenant = requiredText(organizationId, 'Northstar organization identifier');
  const applicationTemplateId = requiredText(
    template?.id,
    'Northstar application template identifier',
  );
  return {
    organization_id: tenant,
    application_template_id: applicationTemplateId,
    form_data: fixture.formData,
    integration_context: fixture.integrationContext,
  };
}

export async function prepareApplicationContext({
  gateway,
  organizationId,
  adminCookie,
  fixture,
  runId,
}) {
  if (typeof gateway !== 'function') throw new Error('Northstar gateway client is required');
  const tenant = requiredText(organizationId, 'Northstar organization identifier');
  const sessionCookie = requiredText(adminCookie, 'Northstar administrator session cookie');
  const credentialTemplates = await expectGatewayPayload('credential template listing', gateway(
    `/v1/credential-templates?organization_id=${encodeURIComponent(tenant)}&status=active`,
    { method: 'GET', sessionCookie, organizationId: tenant },
  ));
  const credentialTemplate = selectActiveCredentialTemplate(credentialTemplates, {
    organizationId: tenant,
    name: fixture.credentialTemplateName,
  });
  const draft = await expectGatewayPayload('application template creation', gateway(
    '/v1/application-templates',
    {
      method: 'POST',
      sessionCookie,
      organizationId: tenant,
      body: buildApplicationTemplateRequest(fixture, credentialTemplate, tenant, runId),
    },
  ));
  const draftId = requiredText(draft?.id, 'Northstar application template draft identifier');
  const validation = await expectGatewayPayload('application template validation', gateway(
    `/v1/application-templates/${encodeURIComponent(draftId)}/validate`,
    { method: 'POST', sessionCookie, organizationId: tenant, body: {} },
  ));
  if (validation?.valid !== true) {
    throw new Error('Northstar application template did not pass public validation');
  }
  const applicationTemplate = await expectGatewayPayload('application template activation', gateway(
    `/v1/application-templates/${encodeURIComponent(draftId)}/activate`,
    { method: 'POST', sessionCookie, organizationId: tenant, body: {} },
  ));
  if (String(applicationTemplate?.status || '').toUpperCase() !== 'ACTIVE') {
    throw new Error('Northstar application template did not become active');
  }
  return {
    applicationInput: buildApplicationRequest(fixture, applicationTemplate, tenant),
    applicationTemplate,
    credentialTemplate,
  };
}
