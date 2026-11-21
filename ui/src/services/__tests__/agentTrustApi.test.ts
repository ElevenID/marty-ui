import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { changeAgentIdentity, confirmDelegation, listAgentIdentities, registerAgentIdentity, reviewDelegation, updateAgentIdentity, withdrawDelegation } from '../agentTrustApi';

const org = 'c87326bc-7be2-4bf4-a3b6-70a36dac6394';
const otherOrg = 'ea407c6d-6ee2-4925-ab3b-9b1d9fa0453d';
const agentId = '7809b847-e9ef-4783-9667-0230d4959613';
const grant = { id: 'f2daf59c-32ae-45c8-8fef-7a4d5b43efca', revision: 1, terms_digest: `sha256:${'a'.repeat(64)}` };
const reviewId = 'fe736db7-8974-4b5e-8c94-a1e4b5d3ca56';
const confirmationId = '6bb1c0c4-cbcd-41e3-a940-0dcbce3f689c';
// Public application example keys, unrelated to any protocol-private corpus.
const publicKey = { kty: 'OKP', crv: 'Ed25519', x: 'n8dTWA2bFf1mlIs9RN_mTZPq5ojx5mpbbtmPhPsSaCU' };
const ellipticKey = { kty: 'EC', crv: 'P-256', x: 'Mr8wdupwl-l2jw8i1g1ViOXIDXEJbI-eBo2-SR9_c_g', y: 'pmqaOrU2U7bmC5SrvlxPuug_F8cFZmPkqZ9IHeu2w2E' };
const identity = { id: agentId, organization_id: org, revision: 1, kind: 'EXTERNAL', status: 'ACTIVE',
  owner_user_id: 'original-owner', metadata: { display_name: 'Inventory reader' }, principal: { id: 'urn:example:inventory' }, keys: [] };
const review = () => ({
  review_id: reviewId, grant, issuer: { type: 'ORGANIZATION', id: `urn:marty:organization:${org}` },
  created_at: '2026-11-20T22:00:00Z', expires_at: '2026-11-20T22:02:00Z', confirmation_max_age_seconds: 300,
  terms: {
    grantor: { type: 'USER', id: 'urn:marty:user:2178ac2b-9c44-4507-94b6-340302f07c12' },
    subject: { type: 'ORGANIZATION', id: `urn:marty:organization:${org}` },
    delegate: { type: 'EXTERNAL', id: 'urn:example:inventory-agent' },
    binding: { method: 'KEY', key_thumbprint: `sha256:${'b'.repeat(64)}` },
    actions: ['urn:example:inventory:read'], audiences: ['urn:example:warehouse'], resources: ['urn:example:inventory:item'],
    valid_from: '2026-11-20T22:00:00Z', valid_until: '2026-11-20T22:05:00Z', subdelegation_allowed: false,
    constraints: { mode: 'EXACT_OPERATION', request_profile: 'urn:example:inventory-read:v1', request_digest: `sha256:${'c'.repeat(64)}` },
  },
});
function response(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
}
describe('agent trust Gateway client bindings and retry policy', () => {
  const transport = vi.fn();
  beforeEach(() => { transport.mockReset(); vi.stubGlobal('fetch', transport); });
  afterEach(() => vi.unstubAllGlobals());

  it('sends an exact revision and no caller-supplied identity headers', async () => {
    transport.mockResolvedValue(response({ ...identity, revision: 2, status: 'SUSPENDED' }));
    await changeAgentIdentity(org, identity, 'suspend');
    expect(transport).toHaveBeenCalledTimes(1);
    const [path, options] = transport.mock.calls[0];
    expect(path).toBe(`/v1/organizations/${org}/agents/${agentId}/suspend`);
    expect(options).toMatchObject({ method: 'POST', credentials: 'same-origin', cache: 'no-store', redirect: 'error' });
    expect(JSON.parse(options.body)).toEqual({ expected_revision: 1 });
    expect(options.headers).toEqual({ Accept: 'application/json', 'Content-Type': 'application/json' });
  });
  it('refuses a cross-tenant directory response', async () => {
    transport.mockResolvedValue(response({ items: [{ ...identity, organization_id: otherOrg }], total: 1 }));
    await expect(listAgentIdentities(org)).rejects.toMatchObject({ code: 'invalid_response' });
  });
  it('refuses a different identity returned from a metadata update', async () => {
    transport.mockResolvedValue(response({ ...identity, id: grant.id }));
    await expect(updateAgentIdentity(org, identity, { display_name: 'Updated' })).rejects.toMatchObject({ code: 'invalid_response' });
  });
  it('does not retry a write after a transport failure or ambiguous 503', async () => {
    transport.mockRejectedValueOnce(new Error('Connection reset'));
    await expect(changeAgentIdentity(org, identity, 'suspend')).rejects.toMatchObject({ code: 'commit_unknown' });
    expect(transport).toHaveBeenCalledTimes(1);
    transport.mockResolvedValueOnce(response({}, 503));
    await expect(changeAgentIdentity(org, identity, 'suspend')).rejects.toMatchObject({ code: 'commit_unknown' });
    expect(transport).toHaveBeenCalledTimes(2);
  });
  it('retains the exact original confirmation identity and digest across explicit retry', async () => {
    const review = { review_id: reviewId, grant };
    const result = { confirmation_id: confirmationId, review_id: reviewId, grant_id: grant.id, terms_digest: grant.terms_digest,
      confirmed_at: '2026-11-20T22:00:00Z', valid_until: '2026-11-20T22:05:00Z', recovered: true };
    transport.mockRejectedValueOnce(new Error('Reply lost')).mockResolvedValueOnce(response(result));
    await expect(confirmDelegation(org, review, confirmationId)).rejects.toMatchObject({ code: 'commit_unknown' });
    expect(await confirmDelegation(org, review, confirmationId)).toEqual(result);
    expect(transport.mock.calls[0][1].body).toBe(transport.mock.calls[1][1].body);
    expect(JSON.parse(transport.mock.calls[1][1].body)).toEqual({ confirmation_id: confirmationId, terms_digest: grant.terms_digest, decision: 'CONFIRM' });
  });
  it('never accepts an approval result for a different review or terms digest', async () => {
    transport.mockResolvedValue(response({ confirmation_id: confirmationId, review_id: reviewId, grant_id: grant.id,
      terms_digest: `sha256:${'b'.repeat(64)}`, confirmed_at: '2026-11-20T22:00:00Z', valid_until: '2026-11-20T22:05:00Z', recovered: false }));
    await expect(confirmDelegation(org, { review_id: reviewId, grant }, confirmationId)).rejects.toMatchObject({ code: 'invalid_response' });
  });
  it('rejects a mismatched grant reference before showing review terms', async () => {
    transport.mockResolvedValue(response({ review_id: reviewId, grant: { ...grant, revision: 2 } }));
    await expect(reviewDelegation(org, grant)).rejects.toMatchObject({ code: 'invalid_response' });
  });
  it('requires complete bounded presentation terms before the human can review consent', async () => {
    transport.mockResolvedValueOnce(response(review()));
    expect(await reviewDelegation(org, grant)).toEqual(review());
    const original = review();
    const invalid = [
      { ...original, issuer: { ...original.issuer, id: `urn:marty:organization:${otherOrg}` } },
      { ...original, expires_at: '2026-11-20T22:06:00Z' },
      { ...original, expires_at: '2026-11-20T21:59:59Z' },
      { ...original, created_at: null },
      ...[
        { actions: [] }, { actions: [{}] }, { resources: ['urn:example:inventory:*'] },
        { audiences: ['urn:example:warehouse', 'urn:example:warehouse'] },
        { grantor: { type: 'USER', id: 'urn:example:human' } },
        { subject: { ...original.terms.subject, type: 'USER' } },
        { delegate: null }, { binding: { method: 'KEY' } },
        { binding: { ...original.terms.binding, session_ref: 'urn:example:session' } },
        { valid_until: original.terms.valid_from }, { valid_from: { value: original.terms.valid_from } },
        { constraints: null }, { constraints: { mode: 'EXACT_OPERATION' } },
        { constraints: { ...original.terms.constraints, document_ref: 'urn:example:other' } },
      ].map(terms => ({ ...original, terms: { ...original.terms, ...terms } })),
    ];
    for (const value of invalid) {
      transport.mockResolvedValueOnce(response(value));
      await expect(reviewDelegation(org, grant)).rejects.toMatchObject({ code: 'invalid_response' });
    }
  });
  it('rejects unsafe revisions and injected path identifiers before dispatch', async () => {
    await expect(reviewDelegation(org, { ...grant, revision: Number.MAX_SAFE_INTEGER + 1 })).rejects.toMatchObject({ code: 'invalid_request' });
    await expect(listAgentIdentities(`${org}/agents`)).rejects.toMatchObject({ code: 'invalid_request' });
    await expect(listAgentIdentities(`${org}\n`)).rejects.toMatchObject({ code: 'invalid_request' });
    await expect(reviewDelegation(org, { ...grant, terms_digest: `${grant.terms_digest}\n` })).rejects.toMatchObject({ code: 'invalid_request' });
    expect(transport).not.toHaveBeenCalled();
  });
  it('rejects entire JWKs containing private, unknown or incompatible members before either key write', async () => {
    for (const key of [
      { ...publicKey, d: 'private-test-material' },
      { ...publicKey, private_key: 'private-test-material' },
      { ...publicKey, extra: { seed: 'private-test-material' } },
      { ...publicKey, x5c: ['unaccepted-certificate'] },
      { ...publicKey, alg: 'ES256' },
      { ...publicKey, use: 'enc' },
      { ...publicKey, kid: null },
      { ...publicKey, key_ops: ['sign'] },
      { ...publicKey, key_ops: ['verify', 'sign'] },
      { ...publicKey, crv: 'X25519' },
      { ...publicKey, y: ellipticKey.y },
      { ...publicKey, x: `${publicKey.x}=` },
      { ...publicKey, x: `${publicKey.x}\n` },
      { ...publicKey, x: `${publicKey.x.slice(0, -1)}V` },
      { ...ellipticKey, y: null },
      { ...ellipticKey, alg: 'EdDSA' },
    ]) {
      await expect(registerAgentIdentity(org, { public_key_jwk: key })).rejects.toMatchObject({ code: 'invalid_request' });
      await expect(changeAgentIdentity(org, identity, 'rotate-key', key)).rejects.toMatchObject({ code: 'invalid_request' });
    }
    expect(transport).not.toHaveBeenCalled();
  });
  it('preserves only accepted public key profiles and compatible optional metadata', async () => {
    const ed = { ...publicKey, kid: 'application-worker', alg: 'Ed25519', use: 'sig', key_ops: ['verify'] };
    const ec = { ...ellipticKey, alg: 'ES256' };
    transport.mockResolvedValueOnce(response(identity));
    await registerAgentIdentity(org, { kind: 'EXTERNAL', public_key_jwk: ed });
    expect(JSON.parse(transport.mock.calls[0][1].body).public_key_jwk).toEqual(ed);
    transport.mockResolvedValueOnce(response({ ...identity, revision: 2 }));
    await changeAgentIdentity(org, identity, 'rotate-key', ec);
    expect(JSON.parse(transport.mock.calls[1][1].body)).toEqual({ expected_revision: 1, public_key_jwk: ec });
  });
  it('withdraws only the retained original confirmation without issuing or retrying consent', async () => {
    const result = { grant_id: grant.id, confirmation_id: confirmationId, withdrawn_at: '2026-11-20T22:04:00Z', recovered: true };
    transport.mockRejectedValueOnce(new Error('Reply lost')).mockResolvedValueOnce(response(result));
    await expect(withdrawDelegation(org, grant.id, confirmationId)).rejects.toMatchObject({ code: 'commit_unknown' });
    expect(transport).toHaveBeenCalledTimes(1);
    expect(await withdrawDelegation(org, grant.id, confirmationId)).toEqual(result);
    expect(transport.mock.calls[0][0]).toBe(transport.mock.calls[1][0]);
    expect(transport.mock.calls[1][0]).toBe(`/v1/organizations/${org}/delegation-grants/${grant.id}/approval-confirmations/${confirmationId}/withdraw`);
    expect(JSON.parse(transport.mock.calls[1][1].body)).toEqual({});
  });
});
