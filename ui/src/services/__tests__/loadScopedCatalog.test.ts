import { describe, it, expect, vi } from 'vitest';
import { loadScopedCatalog } from '../loadScopedCatalog';

const page = Array.from({ length: 100 }, (_, i) => ({ id: `draft-${i}` }));
describe('complete scoped catalogs', () => {
  it('finds an eligible record after the first hundred', async () => {
    const list = vi.fn().mockResolvedValueOnce(page).mockResolvedValueOnce([{ id: 'active', status: 'ACTIVE' }]);
    const result = await loadScopedCatalog(list, 'org-a');
    expect(result).toHaveLength(101);
    expect(result[100].id).toBe('active');
    expect(list).toHaveBeenLastCalledWith({ organization_id: 'org-a', limit: 100, offset: 100 });
  });
  it('reads an empty terminal page at an exact boundary', async () => {
    const list = vi.fn().mockResolvedValueOnce(page).mockResolvedValueOnce([]);
    expect(await loadScopedCatalog(list, 'org-a')).toHaveLength(100);
    expect(list).toHaveBeenCalledTimes(2);
  });
  it('rejects repeated pages and later failures without returning partial data', async () => {
    await expect(loadScopedCatalog(vi.fn().mockResolvedValue(page), 'org-a')).rejects.toThrow('did not advance');
    await expect(loadScopedCatalog(vi.fn().mockResolvedValueOnce(page).mockRejectedValueOnce(new Error('unavailable')), 'org-a')).rejects.toThrow('unavailable');
  });
  it('stops requesting pages when a former organization request is cancelled', async () => {
    const controller = new AbortController();
    const list = vi.fn(async () => { controller.abort(); return page; });
    await expect(loadScopedCatalog(list, 'org-a', { signal: controller.signal })).rejects.toMatchObject({ name: 'AbortError' });
    expect(list).toHaveBeenCalledTimes(1);
  });
});
