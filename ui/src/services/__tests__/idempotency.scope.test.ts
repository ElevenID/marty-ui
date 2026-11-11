import { beforeEach, describe, expect, it, vi } from 'vitest';
import { post } from '../api';
import { postWithIdempotency } from '../idempotency';

vi.mock('../api', () => ({ post: vi.fn() }));
const send = vi.mocked(post);
const path = '/v1/revocation-profiles';
const payload = { organization_id: 'org-1', name: 'Requested profile' };
const created = { id: 'created-profile', organization_id: 'org-1', status: 'DRAFT' };
const networkMessages = ['Failed to fetch', 'fetch failed'];

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

beforeEach(() => send.mockReset());

describe('idempotent POST action ownership', () => {
  it('does not dispatch an operation whose owner has already ended', async () => {
    await expect(postWithIdempotency(path, payload, { isCurrent: () => false }))
      .rejects.toMatchObject({ name: 'AbortError' });
    expect(send).not.toHaveBeenCalled();
  });

  it.each(networkMessages)('does not retry %s after the owner ends', async (message) => {
    let current = true;
    const first = deferred<unknown>();
    send.mockReturnValueOnce(first.promise).mockResolvedValueOnce(created);
    const outcome = postWithIdempotency(path, payload, { isCurrent: () => current }).catch(error => error);
    expect(send).toHaveBeenCalledTimes(1);
    current = false;
    first.reject(new TypeError(message));
    expect(await outcome).toMatchObject({ name: 'AbortError' });
    expect(send).toHaveBeenCalledTimes(1);
  });

  it('does not return a successful response to an obsolete owner', async () => {
    let current = true;
    const first = deferred<unknown>();
    send.mockReturnValueOnce(first.promise);
    const outcome = postWithIdempotency(path, payload, { isCurrent: () => current }).catch(error => error);
    current = false;
    first.resolve(created);
    expect(await outcome).toMatchObject({ name: 'AbortError' });
    expect(send).toHaveBeenCalledTimes(1);
  });

  it('replaces an obsolete validation failure with cancellation without another request', async () => {
    let current = true;
    const first = deferred<unknown>();
    send.mockReturnValueOnce(first.promise);
    const outcome = postWithIdempotency(path, payload, { isCurrent: () => current }).catch(error => error);
    current = false;
    first.reject(new Error('Name already exists'));
    expect(await outcome).toMatchObject({ name: 'AbortError' });
    expect(send).toHaveBeenCalledTimes(1);
  });

  it('checks ownership again after a retry that was legitimately dispatched', async () => {
    let current = true;
    const second = deferred<unknown>();
    send.mockRejectedValueOnce(new TypeError('Failed to fetch')).mockReturnValueOnce(second.promise);
    const outcome = postWithIdempotency(path, payload, { isCurrent: () => current }).catch(error => error);
    await vi.waitFor(() => expect(send).toHaveBeenCalledTimes(2));
    current = false;
    second.resolve(created);
    expect(await outcome).toMatchObject({ name: 'AbortError' });
    expect(send).toHaveBeenCalledTimes(2);
  });

  it.each(networkMessages)('preserves the current same-key retry for %s and excludes the callback from transport options', async (message) => {
    const isCurrent = vi.fn(() => true);
    send.mockRejectedValueOnce(new TypeError(message)).mockResolvedValueOnce(created);
    await expect(postWithIdempotency(path, payload, {
      isCurrent, idempotencyKey: 'same-operation', headers: { 'X-Request-Context': 'wizard' },
    })).resolves.toEqual(created);
    expect(send).toHaveBeenCalledTimes(2);
    for (const call of send.mock.calls) {
      expect(call).toEqual([path, payload, {
        headers: { 'X-Request-Context': 'wizard', 'Idempotency-Key': 'same-operation' },
      }]);
    }
    expect(isCurrent).toHaveBeenCalled();
  });

  it.each(networkMessages)('preserves unknown-operation evidence after retrying %s fails', async (message) => {
    const secondError = new Error('Retry failed');
    send.mockRejectedValueOnce(new TypeError(message)).mockRejectedValueOnce(secondError);
    await expect(postWithIdempotency(path, payload, {
      isCurrent: () => true, idempotencyKey: 'same-operation',
    })).rejects.toMatchObject({ message: 'Retry failed', idempotencyKey: 'same-operation', operationStatusUnknown: true });
    expect(send).toHaveBeenCalledTimes(2);
  });

  it.each([
    new Error('Name already exists'),
    new Error('fetch failed'),
    new TypeError('Invalid request URL'),
  ])('preserves an ordinary failure without retrying it: %s', async (failure) => {
    send.mockRejectedValueOnce(failure);
    await expect(postWithIdempotency(path, payload, { isCurrent: () => true })).rejects.toBe(failure);
    expect(send).toHaveBeenCalledTimes(1);
    expect(failure).not.toHaveProperty('operationStatusUnknown');
  });

  it.each(['Failed to fetch', 'fetch failed'])('keeps the automatic same-key retry for %s', async (message) => {
    send.mockRejectedValueOnce(new TypeError(message)).mockResolvedValueOnce(created);
    await expect(postWithIdempotency(path, payload)).resolves.toEqual(created);
    expect(send).toHaveBeenCalledTimes(2);
    expect(send.mock.calls[0]).toEqual(send.mock.calls[1]);
    expect(send.mock.calls[0][2]?.headers).toMatchObject({ 'Idempotency-Key': expect.any(String) });
  });

  it.each(networkMessages)('keeps explicit retry opt-out behavior for %s', async (message) => {
    const failure = new TypeError(message);
    send.mockRejectedValueOnce(failure);
    await expect(postWithIdempotency(path, payload, {
      isCurrent: () => true, retryOnNetworkAbort: false,
    })).rejects.toBe(failure);
    expect(send).toHaveBeenCalledTimes(1);
  });
});
