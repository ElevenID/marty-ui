import { beforeEach, describe, expect, it, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import { createTemplateCreationOperation } from '../templateCreationOperation';
import { createCredentialTemplate, getCredentialTemplate, activateCredentialTemplate } from '../presentationPolicyApi';

vi.mock('../presentationPolicyApi', () => ({
  buildCredentialTemplatePayload: ({ activate_immediately, ...data }) => data,
  createCredentialTemplate: vi.fn(), getCredentialTemplate: vi.fn(), activateCredentialTemplate: vi.fn(),
}));
const data = { organization_id: 'org-a', name: 'Template', activate_immediately: true };
const draft = { id: 'template-a', organization_id: 'org-a', status: 'draft' };
beforeEach(() => {
  vi.stubGlobal('crypto', webcrypto);
  sessionStorage.clear();
  vi.resetAllMocks();
  vi.mocked(createCredentialTemplate).mockResolvedValue(draft);
  vi.mocked(getCredentialTemplate).mockResolvedValue(draft);
  vi.mocked(activateCredentialTemplate).mockResolvedValue({ ...draft, status: 'active' });
});
describe('template creation recovery', () => {
  it('does not create a different payload while the previous request is uncertain after remount', async () => {
    vi.mocked(createCredentialTemplate).mockRejectedValueOnce(Object.assign(new Error('lost response'), { operationStatusUnknown: true }));
    await expect(createTemplateCreationOperation('org-a').submit(data)).rejects.toThrow();
    await expect(createTemplateCreationOperation('org-a').submit({ ...data, name: 'Changed' })).rejects.toThrow('already been sent');
    expect(createCredentialTemplate).toHaveBeenCalledTimes(1);
  });
  it('fails before mutation when the recovery journal cannot be written', async () => {
    const write = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('Storage unavailable'); });
    try {
      await expect(createTemplateCreationOperation('org-a').submit(data)).rejects.toThrow('Storage unavailable');
      expect(createCredentialTemplate).not.toHaveBeenCalled();
    } finally { write.mockRestore(); }
  });
  it('reuses an uncertain create key after remount without storing template content', async () => {
    vi.mocked(createCredentialTemplate).mockRejectedValueOnce(Object.assign(new Error('lost response'), { operationStatusUnknown: true }));
    await expect(createTemplateCreationOperation('org-a').submit(data)).rejects.toThrow();
    const saved = sessionStorage.getItem('marty:template-create:v1:org-a')!;
    expect(saved).not.toContain('"name"');
    expect(saved).not.toContain('"claims"');
    await createTemplateCreationOperation('org-a').submit(data);
    const calls = vi.mocked(createCredentialTemplate).mock.calls;
    expect(calls[0][1].idempotencyKey).toBe(calls[1][1].idempotencyKey);
    expect(sessionStorage.getItem('marty:template-create:v1:org-a')).toBeNull();
  });
  it('recovers an acknowledged draft after remount using readback and activation only', async () => {
    vi.mocked(activateCredentialTemplate).mockRejectedValueOnce(new Error('503'));
    await expect(createTemplateCreationOperation('org-a').submit(data)).rejects.toThrow();
    await createTemplateCreationOperation('org-a').submit(data);
    expect(createCredentialTemplate).toHaveBeenCalledTimes(1);
    expect(activateCredentialTemplate).toHaveBeenCalledTimes(2);
  });
  it('rejects mismatched readback IDs even when their organization matches', async () => {
    vi.mocked(getCredentialTemplate).mockResolvedValue({ ...draft, id: 'other-template' });
    const operation = createTemplateCreationOperation('org-a');
    await expect(operation.submit(data)).rejects.toThrow('ownership');
    expect(activateCredentialTemplate).not.toHaveBeenCalled();
    expect(createCredentialTemplate).toHaveBeenCalledTimes(1);
  });
  it('does not report a foreign create response as successful for a draft-only request', async () => {
    vi.mocked(createCredentialTemplate).mockResolvedValue({ ...draft, organization_id: 'org-b' });
    const operation = createTemplateCreationOperation('org-a');
    await expect(operation.submit({ ...data, activate_immediately: false })).rejects.toThrow('ownership');
    expect(getCredentialTemplate).not.toHaveBeenCalled();
    expect(activateCredentialTemplate).not.toHaveBeenCalled();
  });
  it('allows a corrected payload with a new key after a definitive validation rejection', async () => {
    const operation = createTemplateCreationOperation('org-a');
    vi.mocked(createCredentialTemplate).mockRejectedValueOnce(Object.assign(new Error('Invalid name'), { status: 422 }));
    await expect(operation.submit(data)).rejects.toThrow('Invalid name');
    await operation.submit({ ...data, name: 'Corrected' });
    const calls = vi.mocked(createCredentialTemplate).mock.calls;
    expect(calls[0][1].idempotencyKey).not.toBe(calls[1][1].idempotencyKey);
  });
  it('does not start activation after the organization changes during creation', async () => {
    let current = true;
    vi.mocked(createCredentialTemplate).mockImplementationOnce(async () => { current = false; return draft; });
    const operation = createTemplateCreationOperation('org-a');
    await expect(operation.submit(data, { isCurrent: () => current })).rejects.toThrow('scope changed');
    expect(operation.resource).toEqual(draft);
    expect(getCredentialTemplate).not.toHaveBeenCalled();
    expect(activateCredentialTemplate).not.toHaveBeenCalled();
  });
  it.each([403, 422, 503])('retains the acknowledged draft after activation %s and retries without another create', async (status) => {
    const operation = createTemplateCreationOperation('org-a');
    vi.mocked(activateCredentialTemplate).mockRejectedValueOnce(Object.assign(new Error('Activation failed'), { status }));
    await expect(operation.submit(data)).rejects.toMatchObject({ createdResource: draft });
    expect(operation.resource).toEqual(draft);
    await expect(operation.submit(data)).resolves.toMatchObject({ status: 'active' });
    expect(createCredentialTemplate).toHaveBeenCalledTimes(1);
    expect(activateCredentialTemplate).toHaveBeenCalledTimes(2);
  });
  it('reconciles an active resource after a lost activation response', async () => {
    const operation = createTemplateCreationOperation('org-a');
    vi.mocked(activateCredentialTemplate).mockRejectedValueOnce(new Error('Failed to fetch'));
    await expect(operation.submit(data)).rejects.toThrow('activation is incomplete');
    vi.mocked(getCredentialTemplate).mockResolvedValue({ ...draft, status: 'active' });
    await operation.submit(data);
    expect(createCredentialTemplate).toHaveBeenCalledTimes(1);
    expect(activateCredentialTemplate).toHaveBeenCalledTimes(1);
  });
  it('reuses the same key after an unknown creation response', async () => {
    const operation = createTemplateCreationOperation('org-a');
    vi.mocked(createCredentialTemplate).mockRejectedValueOnce(Object.assign(new Error('Failed to fetch'), { operationStatusUnknown: true }));
    await expect(operation.submit(data)).rejects.toThrow();
    await operation.submit(data);
    const calls = vi.mocked(createCredentialTemplate).mock.calls;
    expect(calls[0][1].idempotencyKey).toBe(calls[1][1].idempotencyKey);
  });
  it('does not activate a foreign resource or recreate an acknowledged draft after edits', async () => {
    const operation = createTemplateCreationOperation('org-a');
    vi.mocked(getCredentialTemplate).mockResolvedValue({ ...draft, organization_id: 'org-b' });
    await expect(operation.submit(data)).rejects.toThrow('ownership');
    await expect(operation.submit({ ...data, name: 'changed' })).rejects.toThrow('already created');
    expect(createCredentialTemplate).toHaveBeenCalledTimes(1);
    expect(activateCredentialTemplate).not.toHaveBeenCalled();
  });
});
