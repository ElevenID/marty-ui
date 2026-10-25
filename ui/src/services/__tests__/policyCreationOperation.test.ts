import { beforeEach, describe, expect, it, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import { createPolicyCreationOperation as createOperation } from '../policyCreationOperation';
import { createPresentationPolicy, getPresentationPolicy, activatePresentationPolicy } from '../presentationPolicyApi';

vi.mock('../presentationPolicyApi', () => ({
  buildPresentationPolicyPayload: ({ activate_immediately, ...data }) => data,
  createPresentationPolicy: vi.fn(), getPresentationPolicy: vi.fn(), activatePresentationPolicy: vi.fn(),
}));
const data = { organization_id: 'org-a', name: 'Policy', activate_immediately: true };
const createPolicyCreationOperation = (org: string) => createOperation(org, 'test-user');
const draft = { id: 'policy-a', organization_id: 'org-a', status: 'draft' };
beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  sessionStorage.clear();
  vi.resetAllMocks();
  vi.mocked(createPresentationPolicy).mockResolvedValue(draft);
  vi.mocked(getPresentationPolicy).mockResolvedValue(draft);
  vi.mocked(activatePresentationPolicy).mockResolvedValue({ ...draft, status: 'active' });
});
describe('template creation recovery', () => {
  it('does not replay an unresolved key for a different principal in the same organization', async () => {
    vi.mocked(createPresentationPolicy).mockRejectedValueOnce(Object.assign(new Error('lost response'), { operationStatusUnknown: true }));
    await expect(createPolicyCreationOperation('org-a').submit(data)).rejects.toThrow();
    await expect(createOperation('org-a', 'other-user').submit(data)).rejects.toThrow('previous account');
    expect(createPresentationPolicy).toHaveBeenCalledTimes(1);
  });
  it('does not replay an unresolved create outside server cache retention', async () => {
    vi.mocked(createPresentationPolicy).mockRejectedValueOnce(Object.assign(new Error('lost response'), { operationStatusUnknown: true }));
    await expect(createPolicyCreationOperation('org-a').submit(data)).rejects.toThrow();
    const key = 'marty:policy-create:v1:org-a';
    const record = JSON.parse(sessionStorage.getItem(key)!);
    record.createdAt -= 86_400_000;
    sessionStorage.setItem(key, JSON.stringify(record));
    await expect(createPolicyCreationOperation('org-a').submit(data)).rejects.toThrow('safe retry window');
    expect(createPresentationPolicy).toHaveBeenCalledTimes(1);
  });
  it('does not create a different payload while the previous request is uncertain after remount', async () => {
    vi.mocked(createPresentationPolicy).mockRejectedValueOnce(Object.assign(new Error('lost response'), { operationStatusUnknown: true }));
    await expect(createPolicyCreationOperation('org-a').submit(data)).rejects.toThrow();
    await expect(createPolicyCreationOperation('org-a').submit({ ...data, name: 'Changed' })).rejects.toThrow('already been sent');
    expect(createPresentationPolicy).toHaveBeenCalledTimes(1);
  });
  it('fails before mutation when the recovery journal cannot be written', async () => {
    const write = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('Storage unavailable'); });
    try {
      await expect(createPolicyCreationOperation('org-a').submit(data)).rejects.toThrow('Storage unavailable');
      expect(createPresentationPolicy).not.toHaveBeenCalled();
    } finally { write.mockRestore(); }
  });
  it('reuses an uncertain create key after remount without storing template content', async () => {
    vi.mocked(createPresentationPolicy).mockRejectedValueOnce(Object.assign(new Error('lost response'), { operationStatusUnknown: true }));
    await expect(createPolicyCreationOperation('org-a').submit(data)).rejects.toThrow();
    const saved = sessionStorage.getItem('marty:policy-create:v1:org-a')!;
    expect(saved).not.toContain('"name"');
    expect(saved).not.toContain('"claims"');
    await createPolicyCreationOperation('org-a').submit(data);
    const calls = vi.mocked(createPresentationPolicy).mock.calls;
    expect(calls[0][1].idempotencyKey).toBe(calls[1][1].idempotencyKey);
    expect(sessionStorage.getItem('marty:policy-create:v1:org-a')).toBeNull();
  });
  it('recovers an acknowledged draft after remount using readback and activation only', async () => {
    vi.mocked(activatePresentationPolicy).mockRejectedValueOnce(new Error('503'));
    await expect(createPolicyCreationOperation('org-a').submit(data)).rejects.toThrow();
    await createPolicyCreationOperation('org-a').submit(data);
    expect(createPresentationPolicy).toHaveBeenCalledTimes(1);
    expect(activatePresentationPolicy).toHaveBeenCalledTimes(2);
  });
  it('rejects mismatched readback IDs even when their organization matches', async () => {
    vi.mocked(getPresentationPolicy).mockResolvedValue({ ...draft, id: 'other-template' });
    const operation = createPolicyCreationOperation('org-a');
    await expect(operation.submit(data)).rejects.toThrow('ownership');
    expect(activatePresentationPolicy).not.toHaveBeenCalled();
    expect(createPresentationPolicy).toHaveBeenCalledTimes(1);
  });
  it('does not report a foreign create response as successful for a draft-only request', async () => {
    vi.mocked(createPresentationPolicy).mockResolvedValue({ ...draft, organization_id: 'org-b' });
    const operation = createPolicyCreationOperation('org-a');
    await expect(operation.submit({ ...data, activate_immediately: false })).rejects.toThrow('ownership');
    expect(getPresentationPolicy).not.toHaveBeenCalled();
    expect(activatePresentationPolicy).not.toHaveBeenCalled();
  });
  it('allows a corrected payload with a new key after a definitive validation rejection', async () => {
    const operation = createPolicyCreationOperation('org-a');
    vi.mocked(createPresentationPolicy).mockRejectedValueOnce(Object.assign(new Error('Invalid name'), { status: 422 }));
    await expect(operation.submit(data)).rejects.toThrow('Invalid name');
    await operation.submit({ ...data, name: 'Corrected' });
    const calls = vi.mocked(createPresentationPolicy).mock.calls;
    expect(calls[0][1].idempotencyKey).not.toBe(calls[1][1].idempotencyKey);
  });
  it('does not start activation after the organization changes during creation', async () => {
    let current = true;
    vi.mocked(createPresentationPolicy).mockImplementationOnce(async () => { current = false; return draft; });
    const operation = createPolicyCreationOperation('org-a');
    await expect(operation.submit(data, { isCurrent: () => current })).rejects.toThrow('scope changed');
    expect(operation.resource).toEqual(draft);
    expect(getPresentationPolicy).not.toHaveBeenCalled();
    expect(activatePresentationPolicy).not.toHaveBeenCalled();
  });
  it.each([403, 422, 503])('retains the acknowledged draft after activation %s and retries without another create', async (status) => {
    const operation = createPolicyCreationOperation('org-a');
    vi.mocked(activatePresentationPolicy).mockRejectedValueOnce(Object.assign(new Error('Activation failed'), { status }));
    await expect(operation.submit(data)).rejects.toMatchObject({ createdResource: draft });
    expect(operation.resource).toEqual(draft);
    await expect(operation.submit(data)).resolves.toMatchObject({ status: 'active' });
    expect(createPresentationPolicy).toHaveBeenCalledTimes(1);
    expect(activatePresentationPolicy).toHaveBeenCalledTimes(2);
  });
  it('reconciles an active resource after a lost activation response', async () => {
    const operation = createPolicyCreationOperation('org-a');
    vi.mocked(activatePresentationPolicy).mockRejectedValueOnce(new Error('Failed to fetch'));
    await expect(operation.submit(data)).rejects.toThrow('activation is incomplete');
    vi.mocked(getPresentationPolicy).mockResolvedValue({ ...draft, status: 'active' });
    await operation.submit(data);
    expect(createPresentationPolicy).toHaveBeenCalledTimes(1);
    expect(activatePresentationPolicy).toHaveBeenCalledTimes(1);
  });
  it('reuses the same key after an unknown creation response', async () => {
    const operation = createPolicyCreationOperation('org-a');
    vi.mocked(createPresentationPolicy).mockRejectedValueOnce(Object.assign(new Error('Failed to fetch'), { operationStatusUnknown: true }));
    await expect(operation.submit(data)).rejects.toThrow();
    await operation.submit(data);
    const calls = vi.mocked(createPresentationPolicy).mock.calls;
    expect(calls[0][1].idempotencyKey).toBe(calls[1][1].idempotencyKey);
  });
  it('does not activate a foreign resource or recreate an acknowledged draft after edits', async () => {
    const operation = createPolicyCreationOperation('org-a');
    vi.mocked(getPresentationPolicy).mockResolvedValue({ ...draft, organization_id: 'org-b' });
    await expect(operation.submit(data)).rejects.toThrow('ownership');
    await expect(operation.submit({ ...data, name: 'changed' })).rejects.toThrow('already created');
    expect(createPresentationPolicy).toHaveBeenCalledTimes(1);
    expect(activatePresentationPolicy).not.toHaveBeenCalled();
  });
});
