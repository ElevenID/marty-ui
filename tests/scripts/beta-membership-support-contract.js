'use strict';

// D05 adapter checks only public DTO relationships and observed outcomes. The
// native issuer, test wallet, Flow verifier, and Auth service perform issuance,
// cryptographic verification, trust evaluation, and session creation.
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
const MAX_EXPIRY_WAIT_SECONDS = 180;
const MAX_OFFER_TTL_SECONDS = 120;

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}
const hash = (value) => createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');

function objectKeys(value, allowed, label) {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value), `${label} must be an object`);
  assert.ok(Object.keys(value).every((key) => allowed.includes(key)), `${label} has an unsupported field`);
}

function requiredText(value, label) {
  assert.ok(typeof value === 'string' && value.trim() === value && value.length > 0 && value.length <= 512,
    `${label} must be explicit non-empty text`);
}

function validateExpiryPrerequisite(expiry) {
  objectKeys(expiry, ['isolatedDeployment', 'mode', 'expectedServerOfferTtlSeconds', 'maximumWaitSeconds'], 'expiry');
  if (expiry.mode === 'PER_OWNED_OFFER') {
    assert.equal(expiry.isolatedDeployment, undefined, 'Per-offer lifetime does not change a deployment default');
  } else {
    assert.equal(expiry.mode, undefined, 'Unknown expiry mode');
    assert.equal(expiry.isolatedDeployment, true,
      'Expired-offer lane requires an explicitly isolated short-lived deployment');
  }
  assert.ok(Number.isInteger(expiry.expectedServerOfferTtlSeconds)
    && expiry.expectedServerOfferTtlSeconds >= 60 && expiry.expectedServerOfferTtlSeconds <= MAX_OFFER_TTL_SECONDS
    && expiry.expectedServerOfferTtlSeconds % 60 === 0,
  'Declare the server offer TTL as 60 or 120 seconds; native default is seven days');
  assert.ok(Number.isInteger(expiry.maximumWaitSeconds)
    && expiry.maximumWaitSeconds >= expiry.expectedServerOfferTtlSeconds + 5
    && expiry.maximumWaitSeconds <= MAX_EXPIRY_WAIT_SECONDS,
  'Explicit expiry maximum wait must exceed the declared TTL by five seconds and be at most 180 seconds');
  return expiry;
}

function validateFixture(fixture, lane) {
  assert.ok(['expired-offer', 'untrusted-issuer'].includes(lane), 'Explicit D05 supporting lane required');
  objectKeys(fixture, ['schemaVersion', 'kind', 'synthetic', 'authorization', 'applicant', 'trusted', 'foreign', 'login', 'expiry'], 'fixture');
  assert.equal(fixture.schemaVersion, 1);
  assert.equal(fixture.kind, 'membership-support-fixture');
  assert.equal(fixture.synthetic, true, 'Only explicitly synthetic applicant fixtures are supported');
  assert.equal(fixture.authorization, 'PREPROVISIONED_DEMO_FIXTURE', 'Preprovisioned demo fixture authorization is required');
  objectKeys(fixture.applicant, ['id', 'email', 'formData'], 'applicant');
  assert.match(fixture.applicant.id || '', UUID, 'Applicant ID must be explicit');
  requiredText(fixture.applicant.email, 'Applicant email');
  const form = fixture.applicant.formData;
  assert.ok(form && typeof form === 'object' && !Array.isArray(form) && Object.keys(form).length <= 50,
    'A bounded synthetic application form is required');
  for (const [key, value] of Object.entries(form)) {
    assert.ok(/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(key)
      && !/(password|secret|token|private.?key|authorization|cookie)/i.test(key), 'Fixture form must not contain secrets');
    assert.ok(typeof value === 'boolean' || (typeof value === 'number' && Number.isFinite(value))
      || (typeof value === 'string' && value.length <= 512), 'Synthetic form values must be bounded scalars');
  }
  if (Object.hasOwn(form, 'email')) assert.equal(form.email, fixture.applicant.email, 'Form email must match the existing applicant');
  const issuerFields = ['organizationId', 'credentialTemplateId', 'applicationTemplateId', 'trustProfileId',
    'issuerEntityId', 'issuerDid', 'credentialFormat', 'credentialConfigurationId'];
  if (lane === 'untrusted-issuer') assert.ok(fixture.foreign, 'The authorized foreign issuer fixture is required');
  for (const [label, binding] of [['trusted', fixture.trusted], ...(fixture.foreign ? [['foreign', fixture.foreign]] : [])]) {
    objectKeys(binding, issuerFields, label);
    for (const field of issuerFields.filter((key) => key.endsWith('Id') && key !== 'credentialConfigurationId')) {
      assert.match(binding[field] || '', UUID, `${label}.${field} must be an explicit UUID`);
    }
    assert.match(binding.issuerDid || '', /^did:[a-z0-9]+:\S+$/i, `${label}.issuerDid is required`);
    assert.ok(['VC_JWT', 'SD_JWT_VC'].includes(binding.credentialFormat), 'D05 supports native JWT membership credentials');
    requiredText(binding.credentialConfigurationId, `${label}.credentialConfigurationId`);
  }
  objectKeys(fixture.login, ['organizationId', 'presentationPolicyId', 'trustProfileId', 'verifierDid', 'vct'], 'login');
  for (const field of ['organizationId', 'presentationPolicyId', 'trustProfileId']) {
    assert.match(fixture.login[field] || '', UUID, `login.${field} must be explicit`);
  }
  assert.match(fixture.login.verifierDid || '', /^did:[a-z0-9]+:\S+$/i);
  requiredText(fixture.login.vct, 'Login VCT');
  assert.equal(fixture.login.organizationId, fixture.trusted.organizationId);
  if (lane === 'expired-offer' || fixture.expiry !== undefined) validateExpiryPrerequisite(fixture.expiry);
  if (lane === 'untrusted-issuer') {
    assert.notEqual(fixture.foreign.issuerDid, fixture.trusted.issuerDid, 'Foreign issuer must be distinct');
    assert.notEqual(fixture.foreign.credentialTemplateId, fixture.trusted.credentialTemplateId);
    assert.notEqual(fixture.foreign.trustProfileId, fixture.login.trustProfileId);
    assert.equal(fixture.foreign.credentialFormat, fixture.trusted.credentialFormat);
    assert.equal(fixture.foreign.credentialConfigurationId, fixture.trusted.credentialConfigurationId);
  }
  return fixture;
}

function requireScopedActive(value, id, organizationId, label) {
  assert.equal(value?.id, id, `${label} ID mismatch`);
  assert.equal(value.organization_id, organizationId, `${label} organization mismatch`);
  assert.equal(String(value.status).toUpperCase(), 'ACTIVE', `${label} must be preprovisioned ACTIVE`);
  return value;
}

function validateIssuerSetup(binding, observed, vct) {
  const { credential, application, trust, identities, issuers, relationships, revocation } = observed;
  requireScopedActive(credential, binding.credentialTemplateId, binding.organizationId, 'Credential Template');
  requireScopedActive(application, binding.applicationTemplateId, binding.organizationId, 'Application Template');
  requireScopedActive(trust, binding.trustProfileId, binding.organizationId, 'Issuer Trust Profile');
  assert.equal(application.credential_template_id, binding.credentialTemplateId);
  assert.equal(application.approval_strategy, 'MANUAL', 'D05 requires the explicit manual approval application path');
  assert.deepEqual(application.required_checks, [], 'Provision a synthetic application without external vetting prerequisites');
  assert.deepEqual(application.evidence_requirements, [], 'Provision a synthetic application without extra evidence uploads');
  assert.equal(credential.issuer_did, binding.issuerDid);
  assert.equal(credential.trust_profile_id, binding.trustProfileId);
  assert.equal(credential.vct, vct);
  assert.equal(credential.credential_payload_format, binding.credentialFormat);
  assert.ok(Array.isArray(credential.supported_formats) && credential.supported_formats.includes(binding.credentialFormat));
  const configurationId = `${credential.credential_type}${binding.credentialFormat === 'SD_JWT_VC' ? '#sd-jwt' : ''}`;
  assert.equal(binding.credentialConfigurationId, configurationId, 'Fixture must match the native format-specific configuration ID');
  assert.ok(credential.revocation_profile_id, 'A preprovisioned revocation profile is required for cleanup');
  requireScopedActive(revocation, credential.revocation_profile_id, binding.organizationId, 'Revocation Profile');
  assert.ok(Array.isArray(identities?.identities), 'Malformed issuer identity collection');
  // Native identity_projection intentionally exposes this tuple, without an
  // internal profile ID. Its collection request is organization scoped.
  const identity = identities.identities.filter((item) => item.issuer_did === binding.issuerDid
    && item.key_purpose === 'vc_jwt_issuer' && item.credential_format === binding.credentialFormat
    && item.algorithm === 'ES256' && item.status === 'active');
  assert.equal(identity.length, 1, 'Expected exact preprovisioned public issuer identity tuple');
  assert.ok(Array.isArray(issuers));
  const governed = issuers.filter((issuer) => issuer.id === binding.issuerEntityId);
  assert.equal(governed.length, 1, 'Expected exact governed issuer entity');
  assert.ok(governed[0].organization_id === binding.organizationId
    || (governed[0].organization_id === null && governed[0].is_system_issuer === true),
  'Governed issuer must belong to the declared organization or the public system catalog');
  assert.equal(governed[0].issuer_id, binding.issuerDid);
  const keys = governed[0].metadata?.verification_keys;
  assert.ok(Array.isArray(keys) && keys.length > 0 && keys.every((key) => key && typeof key.kty === 'string'
    && ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].every((name) => !Object.hasOwn(key, name))),
  'Governed issuer must contain only pinned public verification keys');
  assert.ok(Array.isArray(relationships) && relationships.every((item) => item.trust_profile_id === binding.trustProfileId));
  const relationship = relationships.filter((item) => item.issuer_id === binding.issuerEntityId);
  assert.equal(relationship.length, 1);
  assert.equal(relationship[0].relationship_status, 'TRUSTED');
  assert.ok(!(trust.denied_issuers || []).includes(binding.issuerDid), 'Issuer fixture is explicitly denied');
  return { issuerIdentitySha256: hash(identity[0]), issuerDid: binding.issuerDid, credentialTemplateId: credential.id,
    applicationTemplateId: application.id, credentialContractSha256: hash(credentialContract(credential)) };
}

function credentialContract(credential) {
  return Object.fromEntries(['credential_type', 'vct', 'claims', 'selective_disclosure_fields',
    'credential_payload_format', 'supported_formats', 'issuer_algorithm'].map((key) => [key, credential[key] ?? null]));
}

function validateLoginSetup(fixture, observed, lane) {
  const { policy, trust, relationships, issuers } = observed;
  requireScopedActive(policy, fixture.login.presentationPolicyId, fixture.login.organizationId, 'Login Presentation Policy');
  requireScopedActive(trust, fixture.login.trustProfileId, fixture.login.organizationId, 'Login Trust Profile');
  assert.equal(policy.trust_profile_id, fixture.login.trustProfileId);
  assert.ok(Array.isArray(policy.credential_requirements) && policy.credential_requirements.length === 1,
    'D05 requires one explicit membership credential requirement');
  assert.deepEqual(policy.alternative_requirements || [], [], 'Alternative login credentials are outside this negative lane');
  const requirement = policy.credential_requirements[0];
  assert.equal(requirement.credential_template_id, fixture.trusted.credentialTemplateId);
  assert.equal(requirement.required, true);
  assert.equal(requirement.credential_payload_format, fixture.trusted.credentialFormat);
  assert.ok(!requirement.trust_profile_id || requirement.trust_profile_id === fixture.login.trustProfileId);
  assert.ok(requirement.requested_claims?.some((claim) => claim.claim_name === 'email' && claim.required === true),
    'The login policy must request the existing synthetic account email');
  assert.ok(Array.isArray(issuers));
  assert.ok(Array.isArray(relationships) && relationships.every((item) => item.trust_profile_id === fixture.login.trustProfileId));
  const trusted = issuers.find((item) => item.issuer_id === fixture.trusted.issuerDid);
  assert.ok(trusted && relationships.some((item) => item.issuer_id === trusted.id && item.relationship_status === 'TRUSTED'),
    'Login must already trust the configured trusted issuer');
  assert.ok(!(trust.denied_issuers || []).includes(fixture.trusted.issuerDid));
  if (lane === 'untrusted-issuer') {
    assert.ok(!(trust.allowed_issuers || []).includes(fixture.foreign.issuerDid), 'Login explicitly allows the foreign issuer');
    const foreignIds = new Set(issuers.filter((item) => item.issuer_id === fixture.foreign.issuerDid).map((item) => item.id));
    assert.ok(!relationships.some((item) => foreignIds.has(item.issuer_id) && item.relationship_status === 'TRUSTED'),
      'Login already trusts the foreign issuer relationship');
    // External/dynamic registries and overrides require a different governed
    // fixture: their contents cannot be inferred from a negative string search.
    assert.deepEqual(trust.trust_sources, [], 'D05 untrusted fixture requires an explicit local trust profile');
    assert.deepEqual(trust.system_issuer_overrides || {}, {});
  }
  return { policyId: policy.id, trustProfileId: trust.id, trustedIssuerDid: fixture.trusted.issuerDid };
}

function expiryWindow(transaction, application, prerequisite, nowMs = Date.now()) {
  validateExpiryPrerequisite(prerequisite);
  const created = Date.parse(transaction?.created_at);
  const expires = Date.parse(transaction?.expires_at);
  const applicationExpiry = Date.parse(application?.offer_expires_at);
  assert.ok(Number.isFinite(created) && Number.isFinite(expires) && Number.isFinite(applicationExpiry),
    'Actual public transaction and application expiry timestamps are required');
  assert.equal(applicationExpiry, expires, 'Application offer expiry does not match its transaction');
  assert.ok(Math.abs((expires - created) / 1000 - prerequisite.expectedServerOfferTtlSeconds) <= 1,
    'Actual server offer TTL differs from the declared lifetime; cancel the owned transaction');
  assert.ok(expires > nowMs && expires - nowMs + 1000 <= prerequisite.maximumWaitSeconds * 1000,
    'Actual expiry is not within the explicit bounded recording window');
  return { createdAt: transaction.created_at, expiresAt: transaction.expires_at,
    serverTtlSeconds: (expires - created) / 1000, deadlineMs: nowMs + prerequisite.maximumWaitSeconds * 1000 };
}

async function awaitNaturalExpiry({ readOffer, window, now = Date.now, delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms)) }) {
  const expires = Date.parse(window.expiresAt);
  assert.ok(Number.isFinite(expires) && Number.isFinite(window.deadlineMs) && expires < window.deadlineMs);
  while (now() <= window.deadlineMs) {
    if (now() > expires) {
      const response = await readOffer();
      if (response.status === 410) return { expiredOfferHttpStatus: 410, observedAt: new Date(now()).toISOString() };
      assert.equal(response.status, 200, 'Expired offer endpoint returned an unrelated error');
    }
    const remaining = window.deadlineMs - now();
    if (remaining <= 0) break;
    await delay(Math.min(1000, remaining));
  }
  throw new Error('Server did not report natural offer expiration within the explicit maximum wait');
}

function loginInstanceBinding(details, instance, fixture, origin) {
  requiredText(details?.nonce, 'Credential login nonce');
  requiredText(details?.href, 'Credential login wallet link');
  const request = new URL(details?.dcApiRequestUrl, origin);
  const match = request.pathname.match(/^\/v1\/flows\/instances\/([0-9a-f-]{36})\/request$/i);
  assert.equal(request.origin, origin, 'Login request must target the actual service origin');
  assert.ok(match && UUID.test(match[1]), 'Login page must expose its native Flow request instance');
  assert.equal(instance?.id, match[1]);
  assert.equal(instance.organization_id, fixture.login.organizationId);
  assert.equal(instance.context_data?.presentation_policy_id, fixture.login.presentationPolicyId);
  assert.equal(instance.context_data?.trust_profile_id, fixture.login.trustProfileId);
  assert.equal(instance.context_data?.oid4vp_issuer_did, fixture.login.verifierDid);
  return { instanceId: instance.id, organizationId: instance.organization_id, presentationPolicyId: fixture.login.presentationPolicyId,
    trustProfileId: fixture.login.trustProfileId, nonceSha256: hash(details.nonce) };
}

function nativeLoginResult(result, binding, fixture, issuerDid, allowed) {
  assert.equal(result?.instance_id, binding.instanceId, 'Result belongs to a different Flow instance');
  assert.equal(String(result.status).toUpperCase(), allowed ? 'COMPLETED' : 'FAILED');
  assert.equal(result.result, allowed ? 'passed' : 'failed');
  assert.equal(result.decision, allowed ? 'allow' : 'deny');
  assert.ok(Array.isArray(result.credential_results) && result.credential_results.length === 1,
    'An exact native membership credential result is required');
  const credential = result.credential_results[0];
  assert.equal(credential.credential_template_id, fixture.trusted.credentialTemplateId);
  assert.equal(credential.issuer_did, issuerDid);
  assert.equal(credential.signature_valid, true, 'Native verifier must authenticate the actual issuer signature');
  assert.equal(credential.trust_check_passed, allowed, 'Native trust result does not match the lane');
  assert.equal(credential.satisfied, allowed);
  assert.ok(Number.isFinite(Date.parse(result.evaluation_timestamp)), 'Native evaluation timestamp is required');
  return { instanceId: binding.instanceId, issuerDid, signatureValid: true, trustCheckPassed: allowed,
    decision: result.decision, result: result.result, evaluationTimestamp: result.evaluation_timestamp,
    credentialTemplateId: credential.credential_template_id,
    scope: 'OBSERVED_NATIVE_FLOW_RESULT_NOT_INDEPENDENT_CRYPTO_VERIFICATION' };
}

function assertions(lane, checks) {
  const required = lane === 'expired-offer'
    ? ['expired_offer_gone', 'cached_code_denied', 'wallet_error_visible', 'no_credential_on_denial',
      'fresh_reissue_received', 'receipt_has_no_session', 'trusted_login_recovery']
    : ['foreign_signature_valid', 'login_trust_excludes_foreign', 'issuer_not_trusted', 'auth_failure_visible',
      'no_session_on_denial', 'trusted_login_recovery'];
  const result = Object.fromEntries([...required, 'configuration_unchanged', 'fixture_cleanup']
    .map((key) => [key, checks[key] === true]));
  result[lane === 'expired-offer' ? 'expired_offer_reissue' : 'issuer_not_trusted_no_session'] = Object.values(result).every(Boolean);
  return result;
}

module.exports = { GRANT, MAX_EXPIRY_WAIT_SECONDS, MAX_OFFER_TTL_SECONDS, assertions, awaitNaturalExpiry,
  credentialContract, expiryWindow, hash, loginInstanceBinding, nativeLoginResult, validateFixture,
  validateIssuerSetup, validateLoginSetup };
