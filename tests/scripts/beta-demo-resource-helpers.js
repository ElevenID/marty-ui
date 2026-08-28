'use strict';

const DEFAULT_CREDENTIAL_RANKING_STRATEGY = 'FRESHEST_FIRST';

function requestedClaim(claimName, {
  displayName = '',
  description = null,
  required = true,
  selectiveDisclosure = true,
  acceptDerived = true,
  predicateSpec = null,
  equals,
} = {}) {
  return {
    claim_name: claimName,
    display_name: displayName,
    description,
    required,
    selective_disclosure: selectiveDisclosure,
    accept_derived: acceptDerived,
    predicate_spec: predicateSpec,
    constraints: equals === undefined ? [] : [{
      claim_name: claimName,
      constraint_type: 'equals',
      value: equals,
      description: null,
    }],
  };
}

function compactObject(value) {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined));
}

function governedIssuerTrustProfilePayload({
  organizationId,
  name,
  description,
  issuerDid,
}) {
  return {
    organization_id: organizationId,
    name,
    description,
    profile_type: 'CUSTOM',
    trust_sources: [],
    allowed_algorithms: ['ES256'],
    supported_formats: ['SD_JWT_VC'],
    allowed_issuers: [issuerDid],
    denied_issuers: [],
  };
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

async function selectOrganization(page, { organizationId, consoleOrigin }) {
  const membershipsResult = await browserJson(page, '/v1/organizations/mine');
  if (!membershipsResult.ok) {
    throw new Error(
      `Organization membership lookup failed (HTTP ${membershipsResult.status})`
      + safeErrorDetail(membershipsResult.body),
    );
  }
  if (!Array.isArray(membershipsResult.body)) {
    throw new Error('Organization membership lookup returned a malformed collection');
  }
  const target = membershipsResult.body.find((membership) => (
    membership.id === organizationId && membership.membership?.has_org_console_access
  ));
  if (!target) {
    return {
      ok: false,
      membershipsStatus: membershipsResult.status,
      targetName: null,
      activeOrgId: null,
    };
  }

  await requireJson(page, '/v1/me/preferences', {
    method: 'PUT',
    body: JSON.stringify({
      last_view_mode: 'org_admin',
      last_active_org_id: organizationId,
    }),
  }, 'Persist demo organization selection');
  await page.goto(`${consoleOrigin}/console/org`, {
    waitUntil: 'domcontentloaded',
    timeout: 60_000,
  });
  await page.waitForFunction((expectedOrganizationId) => (
    localStorage.getItem('activeOrgId') === expectedOrganizationId
  ), organizationId, { timeout: 60_000 });
  return {
    ok: true,
    membershipsStatus: membershipsResult.status,
    targetName: target.display_name || target.name || null,
    activeOrgId: organizationId,
  };
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

async function resolveActiveIssuerDid(page, {
  organizationId,
  credentialFormat = 'SD_JWT_VC',
  algorithm = null,
  keyPurpose = 'vc_jwt_issuer',
}) {
  const response = await requireJson(
    page,
    `/v1/signing-keys/issuer-identities?organization_id=${encodeURIComponent(organizationId)}`,
    {},
    'Load active issuer identities',
  );
  if (!Array.isArray(response?.identities)) {
    throw new Error('Issuer identity lookup returned a malformed collection');
  }
  const matches = response.identities.filter((identity) => (
    String(identity.status || '').toLowerCase() === 'active'
    && identity.key_purpose === keyPurpose
    && identity.credential_format === credentialFormat
    && (!algorithm || identity.algorithm === algorithm)
    && typeof identity.issuer_did === 'string'
    && identity.issuer_did.length > 0
  ));
  const issuerDids = [...new Set(matches.map(({ issuer_did: issuerDid }) => issuerDid))];
  if (issuerDids.length !== 1) {
    throw new Error(
      `Expected exactly one active ${keyPurpose} issuer DID for ${credentialFormat}; found ${issuerDids.length}`,
    );
  }
  return issuerDids[0];
}

function publicVerificationKeys(issuer) {
  const keys = issuer?.metadata?.verification_keys;
  if (!Array.isArray(keys)) return [];
  const privateFields = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];
  return keys.filter((key) => (
    key && typeof key === 'object'
    && typeof key.kty === 'string'
    && key.kty.length > 0
    && privateFields.every((field) => !(field in key))
  ));
}

async function ensureGovernedIssuer(page, {
  organizationId,
  trustProfileId,
  issuerDid,
  displayName,
  idempotencyKey,
}) {
  const matches = (await listResources(page, '/v1/issuer-entities', organizationId))
    .filter((issuer) => issuer.issuer_id === issuerDid);
  if (matches.length > 1) throw new Error(`Multiple governed issuer entities exist for ${issuerDid}`);
  let issuer = matches[0] || null;
  let created = false;
  if (!issuer) {
    issuer = await requireJson(page, '/v1/issuer-entities', {
      method: 'POST',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify({
        organization_id: organizationId,
        issuer_id: issuerDid,
        issuer_type: 'ORGANIZATION',
        display_name: displayName,
        compliance_status: 'COMPLIANT',
        metadata: {},
      }),
    }, `Create governed issuer ${displayName}`);
    created = true;
  }
  if (!issuer?.id || publicVerificationKeys(issuer).length === 0) {
    throw new Error(`Governed issuer ${displayName} has no pinned public verification key`);
  }

  const relationshipPath = `/v1/trust-profiles/${encodeURIComponent(trustProfileId)}/issuers`;
  const relationships = await requireJson(page, relationshipPath, {}, 'Load trusted issuers');
  if (!Array.isArray(relationships)) throw new Error('Trusted issuer lookup returned a malformed collection');
  const matchingRelationships = relationships.filter((relationship) => relationship.issuer_id === issuer.id);
  if (matchingRelationships.length > 1) {
    throw new Error(`Multiple Trust Profile relationships exist for ${issuerDid}`);
  }
  let relationship = matchingRelationships[0] || null;
  let relationshipCreated = false;
  if (!relationship) {
    relationship = await requireJson(page, relationshipPath, {
      method: 'POST',
      headers: { 'Idempotency-Key': `${idempotencyKey}-relationship` },
      body: JSON.stringify({
        issuer_id: issuer.id,
        trust_level: 100,
        relationship_status: 'TRUSTED',
        cascade_revocation_policy: 'NOTIFY_ONLY',
        metadata: {},
      }),
    }, `Trust governed issuer ${displayName}`);
    relationshipCreated = true;
  }
  if (relationship.issuer_id !== issuer.id || relationship.relationship_status !== 'TRUSTED') {
    throw new Error(`Governed issuer ${displayName} relationship is not trusted`);
  }
  return { issuer, relationship, created, relationshipCreated };
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
  DEFAULT_CREDENTIAL_RANKING_STRATEGY,
  browserJson,
  cleanupApplicationCredential,
  compactObject,
  ensureActiveResource,
  ensureApplicantProfile,
  ensureGovernedIssuer,
  findCurrentCredential,
  governedIssuerTrustProfilePayload,
  listResources,
  requestedClaim,
  requireJson,
  resolveActiveIssuerDid,
  safeErrorDetail,
  selectOrganization,
};
