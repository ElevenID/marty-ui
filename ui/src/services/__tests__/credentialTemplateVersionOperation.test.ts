import { beforeEach, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { server } from '@test/mocks/server';
import { createTemplateVersionOperation } from '../credentialTemplateVersionOperation';

const result = (overrides = {}) => ({ id: 'new-draft', organization_id: 'org-1', status: 'DRAFT', name: 'New draft', ...overrides });
beforeEach(() => { sessionStorage.clear(); vi.restoreAllMocks(); });

describe('credential-template version requests', () => {
  it('uses one scoped keyed POST and retains the acknowledged ID without inventing a version field', async () => {
    let body; let key; let organization; let calls = 0;
    server.use(http.post('*/v1/credential-templates/template-1/new-version', async ({ request }) => {
      calls += 1; body = await request.json(); key = request.headers.get('Idempotency-Key');
      organization = new URL(request.url).searchParams.get('organization_id');
      return HttpResponse.json(result());
    }));
    const operation = createTemplateVersionOperation('org-1', 'user-1', 'template-1');
    expect(await operation.create()).toMatchObject({ id: 'new-draft', status: 'draft' });
    expect(calls).toBe(1); expect(body).toEqual({}); expect(organization).toBe('org-1');
    expect(key).toMatch(/^credential-template-version:/);
    expect(createTemplateVersionOperation('org-1', 'user-1', 'template-1').read()).toMatchObject({ resourceId: 'new-draft', key });
    await expect(operation.create({ separate: true })).rejects.toThrow('Inspect the previous');
    expect(calls).toBe(1);
  });

  it.each(['network', 'server'] as const)('does not automatically replay an uncertain %s outcome or forget it on remount', async (failure) => {
    let calls = 0;
    server.use(http.post('*/v1/credential-templates/template-1/new-version', () => {
      calls += 1;
      return failure === 'network' ? HttpResponse.error() : HttpResponse.json({ detail: 'Unavailable after dispatch' }, { status: 503 });
    }));
    const first = createTemplateVersionOperation('org-1', 'user-1', 'template-1');
    await expect(first.create()).rejects.toThrow();
    expect(calls).toBe(1);
    const restored = createTemplateVersionOperation('org-1', 'user-1', 'template-1');
    expect(restored.read()).toMatchObject({ resourceId: null, key: expect.stringMatching(/^credential-template-version:/) });
    await expect(restored.create()).rejects.toThrow('Inspect the previous');
    expect(calls).toBe(1);
  });

  it.each([
    { id: 'template-1' }, { id: '../unsafe' }, { organization_id: 'org-other' }, { status: 'ACTIVE' },
  ])('preserves uncertainty for an invalid acknowledgment %j', async (override) => {
    let calls = 0;
    server.use(http.post('*/v1/credential-templates/template-1/new-version', () => { calls += 1; return HttpResponse.json(result(override)); }));
    const operation = createTemplateVersionOperation('org-1', 'user-1', 'template-1');
    await expect(operation.create()).rejects.toThrow('did not confirm a new draft');
    expect(operation.read()?.resourceId).toBeNull();
    await expect(operation.create()).rejects.toThrow('Inspect the previous');
    expect(calls).toBe(1);
  });

  it('stops before dispatch if its request reference cannot be retained', async () => {
    let calls = 0;
    server.use(http.post('*/v1/credential-templates/template-1/new-version', () => { calls += 1; return HttpResponse.json(result()); }));
    vi.spyOn(Storage.prototype, 'setItem').mockImplementationOnce(() => { throw new Error('Storage full'); });
    await expect(createTemplateVersionOperation('org-1', 'user-1', 'template-1').create()).rejects.toThrow('Storage full');
    expect(calls).toBe(0);
  });

  it('treats a successful response without a JSON receipt as uncertain', async () => {
    server.use(http.post('*/v1/credential-templates/template-1/new-version', () => new HttpResponse(null, { status: 204 })));
    const operation = createTemplateVersionOperation('org-1', 'user-1', 'template-1');
    await expect(operation.create()).rejects.toThrow('did not confirm a new draft');
    expect(operation.read()?.resourceId).toBeNull();
  });

  it('keeps a confirmed ID usable if receipt storage fails after the response', async () => {
    server.use(http.post('*/v1/credential-templates/template-1/new-version', () => HttpResponse.json(result())));
    const setItem = Storage.prototype.setItem;
    vi.spyOn(Storage.prototype, 'setItem')
      .mockImplementationOnce(function (key, value) { setItem.call(this, key, value); })
      .mockImplementationOnce(() => { throw new Error('Storage full after response'); });
    const operation = createTemplateVersionOperation('org-1', 'user-1', 'template-1');
    expect(await operation.create()).toMatchObject({ id: 'new-draft' });
    expect(operation.read()?.resourceId).toBe('new-draft');
    expect(createTemplateVersionOperation('org-1', 'user-1', 'template-1').read()?.resourceId).toBeNull();
  });

  it('does not dispatch for a departed action or reuse another account receipt', async () => {
    let calls = 0;
    server.use(http.post('*/v1/credential-templates/template-1/new-version', () => { calls += 1; return HttpResponse.json(result()); }));
    const operation = createTemplateVersionOperation('org-1', 'user-1', 'template-1');
    await expect(operation.create({ isCurrent: () => false })).rejects.toThrow('view changed');
    expect(calls).toBe(0);
    await operation.create();
    expect(createTemplateVersionOperation('org-1', 'user-2', 'template-1').read()).toBeNull();
    expect(createTemplateVersionOperation('org-2', 'user-1', 'template-1').read()).toBeNull();
  });
});
