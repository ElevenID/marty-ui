import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createApplicationTemplate, listApplicationTemplates, updateApplicationTemplate } from '../applicationTemplatesApi';
import { get, patch, post } from '../api';

vi.mock('../api', () => ({
  get: vi.fn(),
  post: vi.fn(),
  patch: vi.fn(),
  del: vi.fn(),
}));

describe('applicationTemplatesApi', () => {
  beforeEach(() => {
    vi.clearAllMocks();
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

  it('patches draft templates without a full-resource PUT', async () => {
    vi.mocked(patch).mockResolvedValue({ id: 'template-1', status: 'DRAFT' });

    await updateApplicationTemplate('template-1', { name: 'Updated' });

    expect(patch).toHaveBeenCalledWith('/v1/application-templates/template-1', { name: 'Updated' });
  });
});
