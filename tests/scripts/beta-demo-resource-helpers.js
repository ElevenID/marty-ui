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
  if (resource && resource.organization_id !== organizationId) {
    throw new Error(`${name} belongs to another organization`);
  }
  if (!resource) {
    resource = await requireJson(page, collectionPath, {
      method: 'POST',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify(payload),
    }, `Create ${name}`);
    created = true;
  }
  if (typeof resource?.id !== 'string' || !resource.id.trim()) {
    throw new Error(`${name} has no stable identifier`);
  }
  if (resource.organization_id !== organizationId) throw new Error(`${name} belongs to another organization`);
  const resourceId = resource.id;
  if (String(resource.status || '').toUpperCase() === 'DRAFT') {
    if (!created) throw new Error(`${name} is an existing draft; this run does not own its activation`);
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
    `${collectionPath}/${encodeURIComponent(resourceId)}`,
    {},
    `Reload ${name}`,
  );
  if (resource?.id !== resourceId || resource.organization_id !== organizationId) {
    throw new Error(`${name} reload does not match the owned organization resource`);
  }
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

function requireIdentifier(value, label) {
  if (typeof value !== 'string' || !value.trim()) throw new Error(`${label} is required`);
}

function requireApplicationScope(owned, requireCreated = true) {
  for (const field of ['organizationId', 'applicationTemplateId', 'credentialTemplateId', 'applicantId', 'runId']) {
    requireIdentifier(owned[field], field);
  }
  if (requireCreated) requireIdentifier(owned.applicationId, 'applicationId');
}

function requireOwnedApplication(application, owned, creating = false) {
  requireApplicationScope(owned, !creating);
  requireIdentifier(application?.id, 'Application response ID');
  if ((!creating && application.id !== owned.applicationId)
      || application.organization_id !== owned.organizationId
      || application.application_template_id !== owned.applicationTemplateId
      || application.credential_template_id !== owned.credentialTemplateId
      || application.applicant_id !== owned.applicantId
      || application.integration_context?.demo_run_id !== owned.runId) {
    throw new Error('Application response does not match this run and its organization, applicant, and templates');
  }
  return application;
}

function markApplicationMutation(owned, operation) {
  owned.uncertainMutations ||= [];
  owned.uncertainMutations.push({ operation });
}

function resolveApplicationMutation(owned, operation) {
  owned.uncertainMutations = (owned.uncertainMutations || [])
    .filter((entry) => entry.operation !== operation);
}

async function createOwnedApplication(page, owned, { formData, integrationContext = {}, label }) {
  requireApplicationScope(owned, false);
  if (owned.applicationId || owned.uncertainMutations?.some(({ operation }) => operation === 'application_creation')) {
    throw new Error('This run already created an application or has an uncertain creation outcome');
  }
  markApplicationMutation(owned, 'application_creation');
  const created = await requireJson(page, '/v1/me/applications', {
    method: 'POST',
    body: JSON.stringify({
      organization_id: owned.organizationId,
      application_template_id: owned.applicationTemplateId,
      form_data: formData,
      integration_context: { ...integrationContext, demo_run_id: owned.runId },
    }),
  }, label);
  requireOwnedApplication(created, owned, true);
  // Retain ownership before submit or scenario-specific evidence validation.
  owned.applicationId = created.id;
  resolveApplicationMutation(owned, 'application_creation');
  return created;
}

async function submitOwnedApplication(page, owned, label) {
  requireApplicationScope(owned);
  const submitted = await requireJson(page, `/v1/me/applications/${encodeURIComponent(owned.applicationId)}/submit`, {
    method: 'POST',
  }, label);
  requireOwnedApplication(submitted, owned);
  if (String(submitted.status || '').toUpperCase() !== 'SUBMITTED') {
    throw new Error('Application submission did not reach SUBMITTED');
  }
  return submitted;
}

function requireOrganizationInventory(records, organizationId, label) {
  if (!Array.isArray(records)) throw new Error(`${label} returned a malformed collection`);
  if (records.some((record) => record?.organization_id !== organizationId)) {
    throw new Error(`${label} returned data outside the requested organization`);
  }
}

function selectApplicationTransaction(records, owned) {
  for (const field of ['organizationId', 'credentialTemplateId', 'applicationId']) {
    requireIdentifier(owned[field], field);
  }
  requireOrganizationInventory(records, owned.organizationId, 'Issuance transaction inventory');
  const matches = records.filter((record) => record.application_id === owned.applicationId
    || (owned.transactionId && record.id === owned.transactionId));
  if (matches.length > 1) throw new Error('Application has multiple issuance transactions; ownership is ambiguous');
  const transaction = matches[0] || null;
  if (transaction) {
    requireIdentifier(transaction.id, 'Issuance transaction ID');
    if (transaction.application_id !== owned.applicationId
        || transaction.credential_template_id !== owned.credentialTemplateId
        || (owned.transactionId && transaction.id !== owned.transactionId)) {
      throw new Error('Issuance transaction does not match the exact application and template');
    }
  }
  return transaction;
}

async function readApplicationTransaction(page, owned) {
  return selectApplicationTransaction(
    await listResources(page, '/v1/issuance', owned.organizationId),
    owned,
  );
}

function recordApplicationTransaction(owned, transaction) {
  owned.transactionId = transaction.id;
  resolveApplicationMutation(owned, 'issuance');
}

async function issueOwnedApplication(page, owned, label, { requestIssue } = {}) {
  requireApplicationScope(owned);
  markApplicationMutation(owned, 'issuance');
  const endpoint = `/v1/organizations/${encodeURIComponent(owned.organizationId)}/applicants/${encodeURIComponent(owned.applicationId)}/issue`;
  // Console recording may dispatch this request through the real invite button.
  // Both paths retain the same application and transaction ownership checks.
  const issued = requestIssue
    ? await requestIssue(endpoint)
    : await requireJson(page, endpoint, { method: 'POST' }, label);
  requireOwnedApplication(issued, owned);
  // The applicant issue response's id identifies the application. Its internal
  // transaction ID is omitted; resolve it through the public transaction list.
  const transaction = await readApplicationTransaction(page, owned);
  if (!transaction) throw new Error('Application issuance transaction was not discoverable');
  recordApplicationTransaction(owned, transaction);
  return { issued, transaction };
}

function selectCurrentCredential(records, owned) {
  for (const field of ['organizationId', 'credentialTemplateId', 'applicationId', 'transactionId']) {
    requireIdentifier(owned[field], field);
  }
  requireOrganizationInventory(records, owned.organizationId, 'Issued credential inventory');
  const matches = records.filter((record) => record.application_id === owned.applicationId
    || record.flow_execution_id === owned.transactionId
    || (owned.credentialId && record.id === owned.credentialId));
  if (matches.length > 1) throw new Error('Application has multiple credential records; ownership is ambiguous');
  const credential = matches[0] || null;
  if (credential) {
    requireIdentifier(credential.id, 'Issued credential ID');
    if (credential.application_id !== owned.applicationId
        || credential.flow_execution_id !== owned.transactionId
        || credential.credential_template_id !== owned.credentialTemplateId
        || (owned.credentialId && credential.id !== owned.credentialId)) {
      throw new Error('Issued credential does not match the exact application, transaction, and template');
    }
  }
  return credential;
}

async function findCurrentCredential(page, { waitFor, ...owned }) {
  if (typeof waitFor !== 'function') throw new Error('Credential wait function is required');
  // Validate before polling so a missing exact identifier cannot become a
  // same-template or timestamp-based fallback.
  selectCurrentCredential([], owned);
  return waitFor(async () => selectCurrentCredential(
    await listResources(page, '/v1/issued-credentials', owned.organizationId), owned,
  ));
}

function requireOwnedTransaction(transaction, owned) {
  for (const field of ['organizationId', 'credentialTemplateId', 'transactionId']) {
    requireIdentifier(owned[field], field);
  }
  if (transaction?.id !== owned.transactionId
      || transaction.organization_id !== owned.organizationId
      || transaction.credential_template_id !== owned.credentialTemplateId
      || (transaction.application_id || null) !== (owned.applicationId || null)) {
    throw new Error('Issuance transaction does not match the exact owned organization, template, and application');
  }
  return transaction;
}

// The caller must retain this tuple from its own successful creation response;
// template names, timestamps, and an arbitrary inventory selection are not
// ownership. Application-backed callers additionally prove the run marker.
// This deliberately cancels only an offer without an issued credential. Use
// the canonical credential lifecycle cleanup for an existing credential.
async function cancelOwnedIssuanceTransaction(page, owned, reason) {
  requireOwnedTransaction({
    id: owned.transactionId, organization_id: owned.organizationId,
    credential_template_id: owned.credentialTemplateId,
    application_id: owned.applicationId || null,
  }, owned);
  requireIdentifier(reason, 'Cancellation reason');
  if (owned.credentialId) throw new Error('An owned issued credential requires credential lifecycle cleanup');
  if (owned.applicationId) {
    const applicationPath = `/v1/organizations/${encodeURIComponent(owned.organizationId)}/applicants/${encodeURIComponent(owned.applicationId)}`;
    requireOwnedApplication(await requireJson(page, applicationPath), owned);
  }
  const transactionPath = `/v1/issuance/${encodeURIComponent(owned.transactionId)}`;
  const scopedPath = `${transactionPath}?organization_id=${encodeURIComponent(owned.organizationId)}`;
  const transaction = requireOwnedTransaction(await requireJson(page, scopedPath), owned);
  const records = await listResources(page, '/v1/issued-credentials', owned.organizationId);
  requireOrganizationInventory(records, owned.organizationId, 'Issued credential inventory');
  if (records.some((record) => record.flow_execution_id === owned.transactionId
      || (owned.applicationId && record.application_id === owned.applicationId))) {
    throw new Error('An issued credential exists for this transaction; use credential lifecycle cleanup');
  }
  const status = String(transaction.status || '').toLowerCase();
  if (!['pending', 'authorized', 'failed', 'expired', 'revoked'].includes(status)) {
    throw new Error('Owned transaction is not a cancellable pending or terminal offer');
  }
  const result = {
    ok: status === 'revoked', transactionId: owned.transactionId,
    organizationId: owned.organizationId, credentialTemplateId: owned.credentialTemplateId,
    applicationId: owned.applicationId || null, status,
    scope: 'TRANSACTION_CANCELLATION_ONLY', responseStatus: null,
  };
  if (result.ok) {
    resolveApplicationMutation(owned, 'transaction_cancellation');
    return result;
  }
  if (!(owned.uncertainMutations || []).some(({ operation }) => operation === 'transaction_cancellation')) {
    markApplicationMutation(owned, 'transaction_cancellation');
  }
  const response = await browserJson(page, `${transactionPath}/revoke`, {
    method: 'POST', body: JSON.stringify({ reason }),
  }).catch(() => ({ ok: false, status: 0 }));
  result.responseStatus = response.status;
  // A lost POST response is not a reason to retry a mutation blindly. Confirm
  // the actual public state with the same ownership tuple instead.
  try {
    const readback = requireOwnedTransaction(await requireJson(page, scopedPath), owned);
    result.status = String(readback.status || '').toLowerCase();
    result.ok = result.status === 'revoked';
  } catch {
    result.status = 'unconfirmed';
  }
  if (result.ok) resolveApplicationMutation(owned, 'transaction_cancellation');
  return result;
}

async function cleanupApplicationCredential(page, owned, reason) {
  const result = {
    ok: false,
    credentialRevoked: false,
    applicationWithdrawn: false,
    pendingTransactionIds: [],
    uncertainMutations: [...(owned.uncertainMutations || [])],
    failures: [],
  };
  if (!owned.applicationId && !owned.transactionId && !owned.credentialId) {
    result.ok = result.uncertainMutations.length === 0;
    return result;
  }
  requireApplicationScope(owned);
  const applicationPath = `/v1/organizations/${encodeURIComponent(owned.organizationId)}/applicants/${encodeURIComponent(owned.applicationId)}`;
  const application = requireOwnedApplication(await requireJson(page, applicationPath), owned);
  const transaction = await readApplicationTransaction(page, owned);
  if (!transaction && (owned.transactionId || owned.credentialId)) {
    throw new Error('Cannot re-establish the tracked application issuance transaction for cleanup');
  }
  let credential = null;
  if (transaction) {
    recordApplicationTransaction(owned, transaction);
    credential = selectCurrentCredential(
      await listResources(page, '/v1/issued-credentials', owned.organizationId), owned,
    );
    if (!credential && owned.credentialId) throw new Error('Tracked credential is absent from its application transaction');
    if (credential) {
      if (!['ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED'].includes(String(credential.status).toUpperCase())) {
        throw new Error('Owned credential has an unknown lifecycle status');
      }
      owned.credentialId = credential.id;
    } else if (!['failed', 'expired', 'revoked'].includes(String(transaction.status).toLowerCase())) {
      result.pendingTransactionIds.push(transaction.id);
    }
  } else if (['OFFERED', 'CREDENTIALED'].includes(String(application.status).toUpperCase())) {
    result.failures.push({ operation: 'locate_issuance', status: 0 });
  }
  // Establish every binding before mutating any resource. A response from an
  // unrelated run must never authorize even one revoke or withdrawal.
  if (credential) {
    if (String(credential.status).toUpperCase() === 'REVOKED') {
      result.credentialRevoked = true;
    } else {
      const response = await browserJson(page, `/v1/issued-credentials/${encodeURIComponent(credential.id)}/revoke`, {
        method: 'POST', body: JSON.stringify({ reason }),
      }).catch(() => ({ ok: false, status: 0 }));
      try {
        result.credentialRevoked = response.ok
          && selectCurrentCredential([response.body], owned)?.id === credential.id
          && String(response.body.status).toUpperCase() === 'REVOKED';
      } catch { result.credentialRevoked = false; }
      if (!result.credentialRevoked) result.failures.push({ operation: 'revoke', id: credential.id, status: response.status });
    }
  }
  if (String(application.status).toUpperCase() === 'WITHDRAWN') {
    result.applicationWithdrawn = true;
  } else {
    const response = await browserJson(page, `${applicationPath}/withdraw`, {
      method: 'POST', body: JSON.stringify({ reason }),
    }).catch(() => ({ ok: false, status: 0 }));
    try {
      result.applicationWithdrawn = response.ok
        && requireOwnedApplication(response.body, owned).status === 'WITHDRAWN';
    } catch { result.applicationWithdrawn = false; }
    if (!result.applicationWithdrawn) result.failures.push({ operation: 'withdraw', id: owned.applicationId, status: response.status });
  }
  result.uncertainMutations = [...(owned.uncertainMutations || [])];
  result.ok = result.applicationWithdrawn
    && result.failures.length === 0
    && result.pendingTransactionIds.length === 0
    && result.uncertainMutations.length === 0;
  return result;
}

async function requireNoConflictingApplications(applicantPage, {
  organizationId,
  credentialTemplateId,
}) {
  requireIdentifier(organizationId, 'organizationId');
  requireIdentifier(credentialTemplateId, 'credentialTemplateId');
  const terminalStatuses = new Set(['REJECTED', 'WITHDRAWN', 'SUSPENDED']);
  let offset = 0;
  let total;
  const seen = new Set();
  do {
    const collection = await requireJson(applicantPage, `/v1/me/applications?limit=500&offset=${offset}`, {},
      'Check existing applicant applications');
    if (!Array.isArray(collection?.items) || !Number.isInteger(collection.total)
        || collection.total < 0 || collection.offset !== offset
        || (total !== undefined && total !== collection.total)
        || collection.items.length > collection.total - offset
        || (collection.items.length === 0 && offset < collection.total)) {
      throw new Error('Applicant application lookup returned a malformed or changing collection');
    }
    total = collection.total;
    for (const application of collection.items) {
      requireIdentifier(application?.id, 'Existing application ID');
      if (seen.has(application.id)) throw new Error('Applicant application listing contains duplicate records');
      seen.add(application.id);
      if (application.organization_id === organizationId
          && application.credential_template_id === credentialTemplateId
          && !terminalStatuses.has(String(application.status || '').toUpperCase())) {
        throw new Error(`Existing application ${application.id} blocks this demo; resolve it explicitly before starting a new run`);
      }
    }
    offset += collection.items.length;
  } while (offset < total);
  return { ok: true, inspected: seen.size };
}

module.exports = {
  DEFAULT_CREDENTIAL_RANKING_STRATEGY,
  browserJson,
  cancelOwnedIssuanceTransaction,
  cleanupApplicationCredential,
  compactObject,
  createOwnedApplication,
  ensureActiveResource,
  ensureApplicantProfile,
  ensureGovernedIssuer,
  findCurrentCredential,
  governedIssuerTrustProfilePayload,
  listResources,
  issueOwnedApplication,
  requestedClaim,
  requireJson,
  requireNoConflictingApplications,
  requireOwnedApplication,
  requireOwnedTransaction,
  resolveActiveIssuerDid,
  safeErrorDetail,
  selectApplicationTransaction,
  selectCurrentCredential,
  selectOrganization,
  submitOwnedApplication,
};
