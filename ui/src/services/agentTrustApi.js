import { resolveApiUrl } from './authApiOrigin';

// Configured first-party public Gateway. Mutations are sent once; original confirmation
// identity is retained by the caller for explicit recovery after a lost reply.
export class AgentTrustError extends Error {
  constructor(code) { super('Agent identity request could not be completed.'); this.code = code; }
}
const fail = code => { throw new AgentTrustError(code); };
const uuidPattern = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
export const isAgentTrustId = value => typeof value === 'string' && value.length === 36 && uuidPattern.test(value)
  && value !== '00000000-0000-0000-0000-000000000000';
const revision = value => Number.isSafeInteger(value) && value >= 1;
const digest = value => typeof value === 'string' && value.length === 71 && /^sha256:[a-f0-9]{64}$/.test(value);
const record = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const reference = value => typeof value === 'string' && value.length <= 1024 && !/\s/.test(value)
  && /^[A-Za-z][A-Za-z0-9+.-]*:[A-Za-z0-9\-._~:/?#\[\]@!$&'()+,;=%]+$/.test(value);
const principal = value => record(value)
  && ['USER', 'ORGANIZATION', 'SERVICE_ACCOUNT', 'MACHINE_IDENTITY', 'EXTERNAL'].includes(value.type)
  && reference(value.id);
const timestamp = value => typeof value === 'string' && !/\s/.test(value)
  && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)
  && Number.isFinite(Date.parse(value));
const scope = value => Array.isArray(value) && value.length >= 1 && value.length <= 64
  && value.every(reference) && new Set(value).size === value.length;

// Validate what the human must actually be able to review. The Gateway and
// producer still own authoritative grant validation and digest verification.
function reviewTerms(value, organizationId) {
  if (!record(value) || !principal(value.grantor) || value.grantor.type !== 'USER'
    || !isAgentTrustId(value.grantor.id.replace(/^urn:marty:user:/, '')) || !value.grantor.id.startsWith('urn:marty:user:')
    || value.subject?.type !== 'ORGANIZATION' || value.subject.id !== `urn:marty:organization:${organizationId}`
    || !principal(value.delegate) || value.binding?.method !== 'KEY' || !digest(value.binding.key_thumbprint)
    || Object.hasOwn(value.binding, 'session_ref') || Object.hasOwn(value.binding, 'establishment_evidence_ref')
    || !scope(value.actions) || !scope(value.audiences) || !scope(value.resources)
    || !timestamp(value.valid_from) || !timestamp(value.valid_until) || Date.parse(value.valid_until) <= Date.parse(value.valid_from)
    || value.subdelegation_allowed !== false || !record(value.constraints)) return false;
  const constraints = value.constraints;
  if (constraints.mode === 'EXACT_OPERATION') return reference(constraints.request_profile) && digest(constraints.request_digest)
    && !['profile', 'document_ref', 'document_digest', 'evaluator'].some(field => Object.hasOwn(constraints, field));
  if (constraints.mode === 'EXTERNAL_PROFILE') return reference(constraints.profile) && reference(constraints.document_ref)
    && digest(constraints.document_digest) && principal(constraints.evaluator)
    && !['request_profile', 'request_digest'].some(field => Object.hasOwn(constraints, field));
  return false;
}
function id(value) { if (!isAgentTrustId(value)) fail('invalid_request'); return value; }
function base(organizationId) { return `/v1/organizations/${id(organizationId)}`; }

// Public-input screening before any network dispatch. This follows the pinned
// P02 public JWK member/metadata profile; cryptographic point validation and
// the authoritative RFC 7638 fingerprint remain server responsibilities.
export function validateAgentPublicKey(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail('invalid_request');
  const ec = value.kty === 'EC' && value.crv === 'P-256';
  const ed = value.kty === 'OKP' && value.crv === 'Ed25519';
  if (!ec && !ed) fail('invalid_request');
  const required = ec ? ['kty', 'crv', 'x', 'y'] : ['kty', 'crv', 'x'];
  const allowed = new Set([...required, 'kid', 'alg', 'use', 'key_ops']);
  if (Object.keys(value).some(field => !allowed.has(field))
    || required.some(field => !Object.hasOwn(value, field) || typeof value[field] !== 'string')) fail('invalid_request');
  // A 32-byte coordinate has exactly 43 unpadded base64url characters. Its last
  // two padding bits must be zero; permissive decoding must not normalize it.
  const coordinate = text => typeof text === 'string' && text.length === 43 && /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(text);
  if (!coordinate(value.x) || (ec && !coordinate(value.y))) fail('invalid_request');
  if ((Object.hasOwn(value, 'alg') && !(ec ? ['ES256'] : ['EdDSA', 'Ed25519']).includes(value.alg))
    || (Object.hasOwn(value, 'use') && value.use !== 'sig')
    || (Object.hasOwn(value, 'kid') && (typeof value.kid !== 'string' || [...value.kid].length < 1 || [...value.kid].length > 512))
    || (Object.hasOwn(value, 'key_ops') && (!Array.isArray(value.key_ops) || value.key_ops.length !== 1 || value.key_ops[0] !== 'verify'))
    || new TextEncoder().encode(JSON.stringify(value)).length > 4096) fail('invalid_request');
  // Unknown members are rejected above, never silently stripped from a pasted
  // object that might contain private material or unrelated sensitive data.
  return { ...value, ...(Object.hasOwn(value, 'key_ops') ? { key_ops: [...value.key_ops] } : {}) };
}

async function read(response) {
  if (!/^application\/json(?:;|$)/i.test(response.headers.get('content-type') || '')) fail('invalid_response');
  if (!response.body) fail('invalid_response');
  const reader = response.body.getReader(); const chunks = []; let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read(); if (done) break;
      size += value.byteLength; if (size > 1048576) fail('invalid_response'); chunks.push(value);
    }
  } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
  const bytes = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { return fail('invalid_response'); }
}

async function request(path, method = 'GET', body) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(resolveApiUrl(path, import.meta.env.VITE_API_URL), {
      method, credentials: import.meta.env.VITE_API_URL ? 'include' : 'same-origin', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
      signal: controller.signal, headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (response.status === 401) fail('authentication_required');
    if (response.status === 403) fail('access_denied');
    if (response.status === 404) fail('not_available');
    if (response.status === 409) fail('conflict');
    if (response.status >= 400 && response.status < 500) fail('invalid_request');
    if (!response.ok) fail(method === 'GET' ? 'unavailable' : 'commit_unknown');
    return await read(response);
  } catch (error) {
    if (error instanceof AgentTrustError) throw error;
    return fail(method === 'GET' ? 'unavailable' : 'commit_unknown');
  } finally { clearTimeout(timer); }
}

function agent(value, organizationId) {
  if (!value || !isAgentTrustId(value.id) || value.organization_id !== organizationId || !revision(value.revision)
    || !['EXTERNAL', 'MANAGED'].includes(value.kind)
    || !['PROVISIONED', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'RETIRED'].includes(value.status)
    || typeof value.metadata?.display_name !== 'string' || typeof value.owner_user_id !== 'string'
    || typeof value.principal?.id !== 'string' || !Array.isArray(value.keys)) fail('invalid_response');
  return value;
}
export async function listAgentIdentities(organizationId, offset = 0) {
  if (!Number.isSafeInteger(offset) || offset < 0) fail('invalid_request');
  const result = await request(`${base(organizationId)}/agents?limit=50&offset=${offset}`);
  if (!Array.isArray(result?.items) || result.items.length > 50 || !Number.isSafeInteger(result.total) || result.total < 0) fail('invalid_response');
  result.items.forEach(value => agent(value, organizationId)); return result;
}
export async function registerAgentIdentity(organizationId, input) {
  const publicKey = validateAgentPublicKey(input?.public_key_jwk);
  return agent(await request(`${base(organizationId)}/agents`, 'POST', { ...input, public_key_jwk: publicKey }), organizationId);
}
export async function updateAgentIdentity(organizationId, identity, metadata) {
  if (!revision(identity.revision)) fail('invalid_request');
  const result = agent(await request(`${base(organizationId)}/agents/${id(identity.id)}`, 'PATCH', { ...metadata, expected_revision: identity.revision }), organizationId);
  if (result.id !== identity.id) fail('invalid_response');
  return result;
}
export async function changeAgentIdentity(organizationId, identity, action, publicKey) {
  if (!revision(identity.revision) || !['suspend', 'revoke', 'retire', 'rotate-key'].includes(action)) fail('invalid_request');
  const validatedKey = action === 'rotate-key' ? validateAgentPublicKey(publicKey) : undefined;
  const result = agent(await request(`${base(organizationId)}/agents/${id(identity.id)}/${action}`, 'POST', {
    expected_revision: identity.revision, ...(action === 'rotate-key' ? { public_key_jwk: validatedKey } : {}),
  }), organizationId);
  if (result.id !== identity.id) fail('invalid_response');
  return result;
}
export async function listAgentHistory(organizationId, agentId) {
  const result = await request(`${base(organizationId)}/agents/${id(agentId)}/history?limit=50&offset=0`);
  if (!Array.isArray(result?.items) || result.items.length > 50) fail('invalid_response');
  result.items.forEach(event => {
    if (!revision(event.revision) || typeof event.actor_user_id !== 'string' || event.snapshot?.id !== agentId) fail('invalid_response');
    agent(event.snapshot, organizationId);
  });
  return result;
}
export function validGrantReference(grant) {
  return isAgentTrustId(grant?.id) && revision(grant.revision) && digest(grant.terms_digest);
}
export async function reviewDelegation(organizationId, grant) {
  if (!validGrantReference(grant)) fail('invalid_request');
  const result = await request(`${base(organizationId)}/delegation-grants/${grant.id}/approval-reviews`, 'POST', { grant });
  if (!isAgentTrustId(result?.review_id) || result.grant?.id !== grant.id || result.grant?.revision !== grant.revision
    || result.grant?.terms_digest !== grant.terms_digest || !reviewTerms(result.terms, organizationId)
    || result.issuer?.type !== 'ORGANIZATION' || result.issuer.id !== `urn:marty:organization:${organizationId}`
    || !timestamp(result.created_at) || !timestamp(result.expires_at)
    || Date.parse(result.expires_at) <= Date.parse(result.created_at)
    || Date.parse(result.expires_at) - Date.parse(result.created_at) > 300000
    || Date.parse(result.expires_at) > Date.parse(result.terms.valid_until)
    || !Number.isSafeInteger(result.confirmation_max_age_seconds) || result.confirmation_max_age_seconds < 1
    || result.confirmation_max_age_seconds > 300) fail('invalid_response');
  return result;
}
export async function confirmDelegation(organizationId, review, confirmationId) {
  if (!validGrantReference(review?.grant)) fail('invalid_request');
  const result = await request(`${base(organizationId)}/delegation-grants/${id(review.grant.id)}/approval-reviews/${id(review.review_id)}/confirm`, 'POST', {
    confirmation_id: id(confirmationId), terms_digest: review.grant.terms_digest, decision: 'CONFIRM',
  });
  if (result?.confirmation_id !== confirmationId || result.review_id !== review.review_id
    || result.grant_id !== review.grant.id || result.terms_digest !== review.grant.terms_digest
    || typeof result.recovered !== 'boolean' || !timestamp(result.confirmed_at) || !timestamp(result.valid_until)
    || Date.parse(result.valid_until) <= Date.parse(result.confirmed_at)
    || Date.parse(result.valid_until) - Date.parse(result.confirmed_at) > 300000) fail('invalid_response');
  return result;
}
export async function withdrawDelegation(organizationId, grantId, confirmationId) {
  const result = await request(`${base(organizationId)}/delegation-grants/${id(grantId)}/approval-confirmations/${id(confirmationId)}/withdraw`, 'POST', {});
  if (result?.grant_id !== grantId || result.confirmation_id !== confirmationId
    || !timestamp(result.withdrawn_at) || typeof result.recovered !== 'boolean') fail('invalid_response');
  return result;
}

export function agentTrustErrorMessage(error) {
  return {
    authentication_required: 'Sign in to your own account again, then reload this page.',
    access_denied: 'Your current account does not have permission for this action in this organization.',
    not_available: 'This feature or record is not available in this installation.',
    conflict: 'The record changed or the review expired. Reload its current state before continuing.',
    invalid_request: 'The request could not be accepted. Check the fields and current record.',
    invalid_response: 'The response could not be verified. Reload before continuing.',
    commit_unknown: 'The reply was lost. Check the original result before starting another operation.',
  }[error?.code] || 'The service is unavailable. Try again when the connection is restored.';
}
