import { beforeEach, describe, expect, it, vi } from 'vitest';
import { get, getWithRetryConfig, post } from '../api';
import { activateTrustProfile, addTrustProfileIssuer, createTrustProfile, listIssuerEntities, synchronizeTrustProfileRegistries } from '../presentationPolicyApi';

vi.mock('../api', () => ({ get: vi.fn(), getWithRetryConfig: vi.fn(), post: vi.fn(), patch: vi.fn(), del: vi.fn() }));
const send = vi.mocked(post);
const read = vi.mocked(get);
const readOnce = vi.mocked(getWithRetryConfig);
const profile = { id: 'profile-1', organization_id: 'org-1', status: 'ACTIVE' };
const payload = { organization_id: 'org-1', name: 'Current profile' };

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

beforeEach(() => { send.mockReset(); read.mockReset(); readOnce.mockReset(); });

describe('optional Trust Profile continuation scope', () => {
  it.each(['create', 'activate', 'registry'])('does not dispatch an obsolete %s action', async (operation) => {
    const options = { isCurrent: () => false };
    const pending = operation === 'create' ? createTrustProfile(payload, options)
      : operation === 'activate' ? activateTrustProfile('profile-1', options)
        : synchronizeTrustProfileRegistries('profile-1', options);
    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
    expect(send).not.toHaveBeenCalled(); expect(read).not.toHaveBeenCalled();
  });

  it('forwards the create scope and keeps its current same-key retry without transport-only leakage', async () => {
    send.mockRejectedValueOnce(new TypeError('Failed to fetch')).mockResolvedValueOnce({ ...profile, status: 'DRAFT' });
    await expect(createTrustProfile(payload, { isCurrent: () => true, idempotencyKey: 'fixed-key',
      singleAttemptReads: true, allowReadback: false, headers: { 'X-Context': 'wizard' } }))
      .resolves.toMatchObject({ ...profile, status: 'draft' });
    expect(send).toHaveBeenCalledTimes(2);
    expect(send.mock.calls[0]).toEqual(send.mock.calls[1]);
    expect(send.mock.calls[0][2]).toEqual({ headers: { 'X-Context': 'wizard', 'Idempotency-Key': 'fixed-key' } });
    expect(send.mock.calls[0][1]).toMatchObject(payload);
  });

  it('keeps legacy unscoped create retry behavior', async () => {
    send.mockRejectedValueOnce(new TypeError('Failed to fetch')).mockResolvedValueOnce({ ...profile, status: 'DRAFT' });
    await expect(createTrustProfile(payload)).resolves.toMatchObject({ status: 'draft' });
    expect(send).toHaveBeenCalledTimes(2);
    expect(send.mock.calls[0]).toEqual(send.mock.calls[1]);
  });

  it.each([false, true])('keeps current activation fallback for a scoped caller: %s', async (scoped) => {
    send.mockRejectedValueOnce(new TypeError('Failed to fetch'));
    read.mockResolvedValueOnce(profile);
    await expect(activateTrustProfile('profile-1', scoped ? { isCurrent: () => true } : undefined))
      .resolves.toMatchObject({ ...profile, status: 'active' });
    expect(send).toHaveBeenCalledExactlyOnceWith('/v1/trust-profiles/profile-1/activate', {});
    expect(read).toHaveBeenCalledExactlyOnceWith('/v1/trust-profiles/profile-1');
    expect(readOnce).not.toHaveBeenCalled();
  });

  it('keeps an obsolete activation rejection from dispatching its fallback GET', async () => {
    let current = true;
    const reply = deferred<unknown>(); send.mockReturnValueOnce(reply.promise);
    const pending = activateTrustProfile('profile-1', { isCurrent: () => current }).catch(error => error);
    current = false; reply.reject(new TypeError('Failed to fetch'));
    expect(await pending).toMatchObject({ name: 'AbortError' });
    expect(send).toHaveBeenCalledTimes(1); expect(read).not.toHaveBeenCalled();
  });

  it.each([false, true])('checks ownership on activation fallback settlement (rejection: %s)', async (reject) => {
    let current = true;
    const reply = deferred<unknown>();
    send.mockRejectedValueOnce(new TypeError('Failed to fetch')); read.mockReturnValueOnce(reply.promise);
    const pending = activateTrustProfile('profile-1', { isCurrent: () => current }).catch(error => error);
    await vi.waitFor(() => expect(read).toHaveBeenCalledTimes(1));
    current = false;
    if (reject) reply.reject(new Error('Readback failed')); else reply.resolve(profile);
    expect(await pending).toMatchObject({ name: 'AbortError' });
    expect(send).toHaveBeenCalledTimes(1); expect(read).toHaveBeenCalledTimes(1);
  });

  it('preserves the original activation error when the caller lacks readback permission', async () => {
    const failure = new TypeError('Failed to fetch'); send.mockRejectedValueOnce(failure);
    await expect(activateTrustProfile('profile-1', { isCurrent: () => true, allowReadback: false })).rejects.toBe(failure);
    expect(send).toHaveBeenCalledExactlyOnceWith('/v1/trust-profiles/profile-1/activate', {});
    expect(read).not.toHaveBeenCalled();
  });

  it('preserves an ordinary current activation failure without a fallback', async () => {
    const failure = new Error('Activation rejected'); send.mockRejectedValueOnce(failure);
    await expect(activateTrustProfile('profile-1', { isCurrent: () => true })).rejects.toBe(failure);
    expect(read).not.toHaveBeenCalled();
  });

  it.each([false, true])('checks registry ownership on settlement (rejection: %s)', async (reject) => {
    let current = true;
    const reply = deferred<unknown>(); send.mockReturnValueOnce(reply.promise);
    const pending = synchronizeTrustProfileRegistries('profile-1', { isCurrent: () => current }).catch(error => error);
    current = false;
    if (reject) reply.reject(new Error('Registry unavailable')); else reply.resolve({ trust_profile_id: 'profile-1', sources: [] });
    expect(await pending).toMatchObject({ name: 'AbortError' });
    expect(send).toHaveBeenCalledExactlyOnceWith('/v1/trust-profiles/profile-1/registry-sync', {});
  });

  it.each([false, true])('keeps the exact registry result for a scoped caller: %s', async (scoped) => {
    const result = { trust_profile_id: 'profile-1', sources: [{ sequence: 3 }] };
    send.mockResolvedValueOnce(result);
    await expect(synchronizeTrustProfileRegistries('profile-1', scoped ? { isCurrent: () => true } : undefined)).resolves.toBe(result);
    expect(send).toHaveBeenCalledExactlyOnceWith('/v1/trust-profiles/profile-1/registry-sync', {});
  });

  it.each([false, true])('retains native inventory retries for an isCurrent-only caller: %s', async (scoped) => {
    read.mockResolvedValueOnce([]);
    await expect(listIssuerEntities('org-1', scoped ? { isCurrent: () => true } : undefined)).resolves.toEqual([]);
    expect(read).toHaveBeenCalledExactlyOnceWith('/v1/issuer-entities', { params: { organization_id: 'org-1' } });
    expect(readOnce).not.toHaveBeenCalled();
  });

  it('uses one inventory read when explicitly requested, without forwarding helper flags or continuing after failure', async () => {
    const failure = new TypeError('Failed to fetch'); readOnce.mockRejectedValueOnce(failure);
    await expect(addTrustProfileIssuer('profile-1', 'org-1', { issuer_did: 'did:web:issuer.example' }, {
      isCurrent: () => true, singleAttemptReads: true, allowReadback: false,
    })).rejects.toBe(failure);
    expect(readOnce).toHaveBeenCalledExactlyOnceWith('/v1/issuer-entities', { params: { organization_id: 'org-1' } }, { maxRetries: 0 });
    expect(read).not.toHaveBeenCalled(); expect(send).not.toHaveBeenCalled();
  });

  it.each([false, true])('uses one activation readback when explicitly requested (failure: %s)', async (fail) => {
    const failure = new TypeError('Failed to fetch');
    send.mockRejectedValueOnce(failure);
    if (fail) readOnce.mockRejectedValueOnce(failure); else readOnce.mockResolvedValueOnce(profile);
    const pending = activateTrustProfile('profile-1', { isCurrent: () => true, singleAttemptReads: true, allowReadback: true });
    if (fail) await expect(pending).rejects.toBe(failure);
    else await expect(pending).resolves.toMatchObject({ ...profile, status: 'active' });
    expect(readOnce).toHaveBeenCalledExactlyOnceWith('/v1/trust-profiles/profile-1', {}, { maxRetries: 0 });
    expect(send).toHaveBeenCalledExactlyOnceWith('/v1/trust-profiles/profile-1/activate', {});
    expect(read).not.toHaveBeenCalled();
  });
});
