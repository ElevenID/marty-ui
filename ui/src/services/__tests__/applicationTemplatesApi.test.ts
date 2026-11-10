import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createApplicationTemplate, getApplicationTemplate, listApplicationTemplates, updateApplicationTemplate } from '../applicationTemplatesApi';
import { get, patch, post } from '../api';

vi.mock('../api', () => ({
  get: vi.fn(),
  post: vi.fn(),
  patch: vi.fn(),
  del: vi.fn(),
}));

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

describe('applicationTemplatesApi', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('fails fast without an organization id', async () => {
    await expect(listApplicationTemplates('')).rejects.toMatchObject({ code: 'ORG_REQUIRED' });
    expect(get).not.toHaveBeenCalled();
  });

  it('includes the organization id when listing templates', async () => {
    vi.mocked(get).mockResolvedValue([]);

    await listApplicationTemplates('org-1');

    expect(get).toHaveBeenCalledWith('/v1/application-templates?organization_id=org-1');
  });

  it('fails fast before creating without an organization id', async () => {
    await expect(createApplicationTemplate({ name: 'Application' })).rejects.toMatchObject({ code: 'ORG_REQUIRED' });
    expect(post).not.toHaveBeenCalled();
  });

  it('creates templates with organization context and an idempotency key', async () => {
    vi.mocked(post).mockResolvedValue({ id: 'template-1' });

    await createApplicationTemplate({ organization_id: 'org-1', name: 'Application' });

    expect(post).toHaveBeenCalledWith(
      '/v1/application-templates',
      { organization_id: 'org-1', name: 'Application' },
      expect.objectContaining({
        headers: expect.objectContaining({
          'Idempotency-Key': expect.stringContaining('v1-application-templates'),
        }),
      })
    );
  });

  it('does not retry a failed creation after the calling editor has departed', async () => {
    let current = true;
    const first = deferred<unknown>();
    vi.mocked(post).mockReturnValueOnce(first.promise);
    const payload = { organization_id: 'org-1', name: 'Application' };

    // Keep the real create API and idempotency helper; only hold the transport.
    const outcome = createApplicationTemplate(payload, {
      isCurrent: () => current,
      idempotencyKey: 'application-editor-save',
      headers: { 'X-Request-Context': 'editor' },
    }).catch((error) => error);
    expect(post).toHaveBeenCalledTimes(1);
    expect(post).toHaveBeenCalledWith('/v1/application-templates', payload, {
      headers: { 'X-Request-Context': 'editor', 'Idempotency-Key': 'application-editor-save' },
    });

    current = false;
    first.reject(new TypeError('Failed to fetch'));

    expect(await outcome).toMatchObject({ name: 'AbortError', message: 'The view or action changed.' });
    expect(post).toHaveBeenCalledTimes(1);
  });

  it('preserves the default same-key retry for existing callers without an action owner', async () => {
    const created = { id: 'template-1', organization_id: 'org-1', status: 'DRAFT' };
    vi.mocked(post).mockRejectedValueOnce(new TypeError('Failed to fetch')).mockResolvedValueOnce(created);

    await expect(createApplicationTemplate({ organization_id: 'org-1', name: 'Application' })).resolves.toEqual(created);

    expect(post).toHaveBeenCalledTimes(2);
    expect(vi.mocked(post).mock.calls[0]).toEqual(vi.mocked(post).mock.calls[1]);
    expect(vi.mocked(post).mock.calls[0][2]?.headers).toMatchObject({ 'Idempotency-Key': expect.any(String) });
  });

  it('patches draft templates without a full-resource PUT', async () => {
    vi.mocked(patch).mockResolvedValue({ id: 'template-1', status: 'DRAFT' });

    await updateApplicationTemplate('template-1', { name: 'Updated' });

    expect(patch).toHaveBeenCalledWith('/v1/application-templates/template-1', { name: 'Updated' });
  });

  it('binds template reads to an explicit selected organization', async () => {
    await getApplicationTemplate('template-1', 'org-1');
    expect(get).toHaveBeenCalledWith('/v1/application-templates/template-1?organization_id=org-1');
  });
});
