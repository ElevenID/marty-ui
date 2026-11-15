import { beforeEach, describe, expect, it, vi } from 'vitest';
import { get, getWithRetryConfig, post } from '../api';
import { createIssuerIdentity, getIssuerIdentityCapabilities } from '../issuerIdentitiesApi';

vi.mock('../api', () => ({ get: vi.fn(), getWithRetryConfig: vi.fn(), post: vi.fn(),
  put: vi.fn(), patch: vi.fn(), del: vi.fn() }));
const send = vi.mocked(post);
const read = vi.mocked(get);
const singleRead = vi.mocked(getWithRetryConfig);
const path = '/v1/signing-keys/issuer-identities';
const payload = { organization_id: 'org-1', issuer_did: 'did:web:issuer.example:orgs:one',
  key_purpose: 'vc_jwt_issuer', credential_format: 'SD_JWT_VC', algorithm: 'ES256' };
const created = { created: true, identity: { issuer_did: payload.issuer_did, key_purpose: payload.key_purpose,
  credential_format: payload.credential_format, algorithm: payload.algorithm, status: 'active' } };
const capabilities = { organization_id: 'org-1', managed_issuer_did_prefix: 'did:web:issuer.example:orgs:',
  basis: 'configuration', creation_options: [{ key_purpose: payload.key_purpose,
    credential_format: payload.credential_format, algorithm: payload.algorithm }] };

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

beforeEach(() => {
  send.mockReset().mockResolvedValue(created);
  read.mockReset().mockResolvedValue(capabilities);
  singleRead.mockReset().mockResolvedValue(capabilities);
});

describe('issuer create owner and public payload compatibility', () => {
  it('does not POST for an obsolete owner', async () => {
    await expect(createIssuerIdentity(payload, { isCurrent: () => false })).rejects.toMatchObject({ name: 'AbortError' });
    expect(send).not.toHaveBeenCalled();
  });

  it.each(['network error', 'success', 'ordinary error'])('checks ownership on first %s settlement', async (outcome) => {
    let current = true;
    const first = deferred<unknown>();
    send.mockReturnValueOnce(first.promise);
    const pending = createIssuerIdentity(payload, { isCurrent: () => current }).catch(error => error);
    current = false;
    if (outcome === 'success') first.resolve(created);
    else first.reject(outcome === 'network error' ? new TypeError('Failed to fetch') : new Error('Invalid identity'));
    expect(await pending).toMatchObject({ name: 'AbortError' });
    expect(send).toHaveBeenCalledTimes(1);
  });

  it.each([false, true])('retains the current same-key retry (scoped: %s)', async (scoped) => {
    send.mockRejectedValueOnce(new TypeError('Failed to fetch'));
    await expect(createIssuerIdentity(payload, scoped ? { isCurrent: () => true } : undefined)).resolves.toEqual(created);
    expect(send).toHaveBeenCalledTimes(2);
    expect(send.mock.calls[1]).toEqual(send.mock.calls[0]);
    expect(send.mock.calls[0][2]?.headers).toMatchObject({ 'Idempotency-Key': expect.any(String) });
  });

  it('checks ownership after a legitimately dispatched second attempt', async () => {
    let current = true;
    const second = deferred<unknown>();
    send.mockRejectedValueOnce(new TypeError('Failed to fetch')).mockReturnValueOnce(second.promise);
    const pending = createIssuerIdentity(payload, { isCurrent: () => current }).catch(error => error);
    await vi.waitFor(() => expect(send).toHaveBeenCalledTimes(2));
    current = false; second.resolve(created);
    expect(await pending).toMatchObject({ name: 'AbortError' });
    expect(send).toHaveBeenCalledTimes(2);
  });

  it('consumes shared helper flags, preserving native headers and the exact public body', async () => {
    const key_attestation_policy = { require_attestation: true };
    await createIssuerIdentity({ ...payload, key_attestation_policy, signing_service_id: 'private', key_reference: 'private' }, {
      isCurrent: () => true, singleAttemptReads: true, allowReadback: false,
      idempotencyKey: 'same-operation', headers: { 'X-Request-Context': 'wizard' },
    });
    expect(send).toHaveBeenCalledExactlyOnceWith(path, { ...payload, key_attestation_policy }, {
      headers: { 'X-Request-Context': 'wizard', 'Idempotency-Key': 'same-operation' },
    });
  });

  it('retains explicit retry opt-out and ordinary error identity', async () => {
    const failure = new TypeError('Failed to fetch');
    send.mockRejectedValueOnce(failure);
    await expect(createIssuerIdentity(payload, { isCurrent: () => true, retryOnNetworkAbort: false })).rejects.toBe(failure);
    expect(send).toHaveBeenCalledTimes(1);
  });
});

describe('issuer capability read ownership', () => {
  it.each([false, true])('does not dispatch an already obsolete read (single attempt: %s)', async (singleAttemptReads) => {
    await expect(getIssuerIdentityCapabilities({ organization_id: 'org-1' }, {
      isCurrent: () => false, singleAttemptReads,
    })).rejects.toMatchObject({ name: 'AbortError' });
    expect(read).not.toHaveBeenCalled(); expect(singleRead).not.toHaveBeenCalled();
  });

  it.each(['success', 'error'])('checks ownership after a single-attempt %s', async (outcome) => {
    let current = true;
    const reply = deferred<unknown>();
    singleRead.mockReturnValueOnce(reply.promise);
    const pending = getIssuerIdentityCapabilities({ organization_id: 'org-1' }, {
      isCurrent: () => current, singleAttemptReads: true,
    }).catch(error => error);
    current = false;
    if (outcome === 'success') reply.resolve(capabilities);
    else reply.reject(new TypeError('Failed to fetch'));
    expect(await pending).toMatchObject({ name: 'AbortError' });
    expect(read).not.toHaveBeenCalled(); expect(singleRead).toHaveBeenCalledTimes(1);
  });

  it.each([undefined, {}, { isCurrent: () => true }])('preserves the existing transport retry path unless explicitly opted in: %j', async (options) => {
    expect(await getIssuerIdentityCapabilities({ organization_id: ' org-1 ' }, options)).toEqual(capabilities);
    expect(read).toHaveBeenCalledExactlyOnceWith(path + '/capabilities?organization_id=org-1');
    expect(singleRead).not.toHaveBeenCalled();
  });

  it('uses the supported retry-config argument without putting scope controls on the wire', async () => {
    singleRead.mockResolvedValueOnce({ ...capabilities, service_id: 'private', creation_options: [
      { ...capabilities.creation_options[0], key_reference: 'private' },
    ] });
    expect(await getIssuerIdentityCapabilities({ organization_id: 'org-1' }, {
      isCurrent: () => true, singleAttemptReads: true, allowReadback: false,
    })).toEqual(capabilities);
    expect(singleRead).toHaveBeenCalledExactlyOnceWith(path + '/capabilities?organization_id=org-1', {}, { maxRetries: 0 });
    expect(read).not.toHaveBeenCalled();
  });

  it('surfaces the first current transient error for explicit single-attempt callers', async () => {
    const failure = new TypeError('Failed to fetch');
    singleRead.mockRejectedValueOnce(failure);
    await expect(getIssuerIdentityCapabilities({ organization_id: 'org-1' }, {
      isCurrent: () => true, singleAttemptReads: true,
    })).rejects.toBe(failure);
    expect(singleRead).toHaveBeenCalledTimes(1); expect(read).not.toHaveBeenCalled();
  });

  it('retains organization and public shape validation on the opted-in read path', async () => {
    singleRead.mockResolvedValueOnce({ ...capabilities, organization_id: 'other' });
    await expect(getIssuerIdentityCapabilities({ organization_id: 'org-1' }, { singleAttemptReads: true }))
      .rejects.toThrow(/invalid organization/);
  });
});
