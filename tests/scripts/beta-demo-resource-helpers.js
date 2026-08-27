'use strict';

function compactObject(value) {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined));
}

async function browserJson(page, pathName, options = {}) {
  return page.evaluate(async ({ requestPath, requestOptions }) => {
    const response = await fetch(requestPath, {
      credentials: 'include',
      ...requestOptions,
      headers: {
        ...(requestOptions.body ? { 'Content-Type': 'application/json' } : {}),
        ...(requestOptions.headers || {}),
      },
    });
    const body = await response.json().catch(() => null);
    return { ok: response.ok, status: response.status, body };
  }, { requestPath: pathName, requestOptions: options });
}

function safeErrorDetail(body) {
  const blocked = /(?:password|secret|token|authorization|cookie|credential)/i;
  const sanitize = (value, key = '') => {
    if (blocked.test(key)) return '[REDACTED]';
    if (Array.isArray(value)) return value.slice(0, 10).map((item) => sanitize(item));
    if (value && typeof value === 'object') {
      return Object.fromEntries(
        Object.entries(value)
          .slice(0, 20)
          .map(([name, item]) => [name, sanitize(item, name)]),
      );
    }
    if (typeof value === 'string') return value.replace(/[\r\n\t]+/g, ' ').slice(0, 500);
    return value;
  };
  if (body === null || body === undefined) return '';
  const serialized = JSON.stringify(sanitize(body));
  return serialized ? `: ${serialized.slice(0, 1000)}` : '';
}

async function requireJson(page, pathName, options = {}, label = pathName) {
  const result = await browserJson(page, pathName, options);
  if (!result.ok) {
    throw new Error(`${label} failed (HTTP ${result.status})${safeErrorDetail(result.body)}`);
  }
  return result.body;
}

async function listResources(page, pathName, organizationId) {
  const separator = pathName.includes('?') ? '&' : '?';
  const body = await requireJson(
    page,
    `${pathName}${separator}organization_id=${encodeURIComponent(organizationId)}`,
  );
  if (!Array.isArray(body)) throw new Error(`${pathName} returned a malformed collection`);
  return body;
}

async function ensureActiveResource(page, {
  organizationId,
  collectionPath,
  name,
  payload,
  idempotencyKey,
  validate = false,
}) {
  const matches = (await listResources(page, collectionPath, organizationId))
    .filter((resource) => resource.name === name);
  if (matches.length > 1) throw new Error(`Multiple resources named '${name}' exist`);
  let resource = matches[0] || null;
  let created = false;
  if (!resource) {
    resource = await requireJson(page, collectionPath, {
      method: 'POST',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify(payload),
    }, `Create ${name}`);
    created = true;
  }
  if (!resource?.id) throw new Error(`${name} has no stable identifier`);
  if (String(resource.status || '').toUpperCase() === 'DRAFT') {
    if (validate) {
      await requireJson(page, `${collectionPath}/${encodeURIComponent(resource.id)}/validate`, {
        method: 'POST',
      }, `Validate ${name}`);
    }
    resource = await requireJson(page, `${collectionPath}/${encodeURIComponent(resource.id)}/activate`, {
      method: 'POST',
    }, `Activate ${name}`);
  }
  resource = await requireJson(
    page,
    `${collectionPath}/${encodeURIComponent(resource.id)}`,
    {},
    `Reload ${name}`,
  );
  if (String(resource.status || '').toUpperCase() !== 'ACTIVE') {
    throw new Error(`${name} is not active`);
  }
  return { ...resource, created };
}

async function ensureApplicantProfile(page, {
  email,
  givenName = 'Jamie',
  familyName = 'Lee',
}) {
  const current = await browserJson(page, '/v1/me/applicant-profile');
  if (current.ok) return current.body;
  if (current.status !== 404) throw new Error(`Applicant profile lookup failed (HTTP ${current.status})`);
  return requireJson(page, '/v1/me/applicant-profile', {
    method: 'PATCH',
    body: JSON.stringify({ email, given_name: givenName, family_name: familyName }),
  }, 'Create applicant profile');
}

async function findCurrentCredential(page, {
  organizationId,
  credentialTemplateId,
  startedAt,
  waitFor,
}) {
  return waitFor(() => page.evaluate(async ({ organizationId: orgId, templateId, lowerBound }) => {
    const response = await fetch(
      `/v1/issued-credentials?organization_id=${encodeURIComponent(orgId)}`,
      { credentials: 'include' },
    );
    const records = await response.json().catch(() => []);
    if (!response.ok || !Array.isArray(records)) return null;
    return records
      .filter((record) => record.credential_template_id === templateId)
      .filter((record) => new Date(record.issued_at || record.created_at || 0) >= new Date(lowerBound))
      .sort((left, right) => new Date(right.issued_at || 0) - new Date(left.issued_at || 0))[0]
      || null;
  }, { organizationId, templateId: credentialTemplateId, lowerBound: startedAt }));
}

async function cleanupApplicationCredential(page, {
  organizationId,
  applicationId,
  credentialId,
  reason,
}) {
  const result = { credentialRevoked: false, applicationWithdrawn: false };
  if (credentialId) {
    const response = await browserJson(page, `/v1/issued-credentials/${encodeURIComponent(credentialId)}/revoke`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    });
    result.credentialRevoked = response.ok;
  }
  if (applicationId) {
    const response = await browserJson(
      page,
      `/v1/organizations/${encodeURIComponent(organizationId)}/applicants/${encodeURIComponent(applicationId)}/withdraw`,
      { method: 'POST', body: JSON.stringify({ reason }) },
    );
    result.applicationWithdrawn = response.ok;
  }
  return result;
}

module.exports = {
  browserJson,
  cleanupApplicationCredential,
  compactObject,
  ensureActiveResource,
  ensureApplicantProfile,
  findCurrentCredential,
  listResources,
  requireJson,
  safeErrorDetail,
};
