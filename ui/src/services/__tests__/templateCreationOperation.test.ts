import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createTemplateCreationOperation } from '../templateCreationOperation';
import { createCredentialTemplate, getCredentialTemplate, activateCredentialTemplate } from '../presentationPolicyApi';

vi.mock('../presentationPolicyApi', () => ({
  buildCredentialTemplatePayload: ({ activate_immediately, ...data }) => data,
  createCredentialTemplate: vi.fn(), getCredentialTemplate: vi.fn(), activateCredentialTemplate: vi.fn(),
}));
const data = { organization_id: 'org-a', name: 'Template', activate_immediately: true };
const draft = { id: 'template-a', organization_id: 'org-a', status: 'draft' };
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(createCredentialTemplate).mockResolvedValue(draft);
  vi.mocked(getCredentialTemplate).mockResolvedValue(draft);
  vi.mocked(activateCredentialTemplate).mockResolvedValue({ ...draft, status: 'active' });
});
describe('template creation recovery', () => {
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
  it('retains the acknowledged draft and retries activation without another create', async () => {
    const operation = createTemplateCreationOperation('org-a');
    vi.mocked(activateCredentialTemplate).mockRejectedValueOnce(new Error('503 unavailable'));
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
