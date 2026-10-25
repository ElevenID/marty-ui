/** Load a complete offset-paginated catalog. Never expose a partial success. */
export async function loadScopedCatalog(listPage, organizationId, { signal, pageSize = 100 } = {}) {
  if (!organizationId) throw new Error('Select an organization before loading a catalog.');
  if (!Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > 500) throw new Error('Invalid catalog page size.');
  const items = [];
  const seen = new Set();
  const checkCancelled = () => { if (signal?.aborted) throw new DOMException('Catalog loading cancelled.', 'AbortError'); };
  for (let offset = 0; ; offset += pageSize) {
    checkCancelled();
    const page = await listPage({ organization_id: organizationId, limit: pageSize, offset });
    checkCancelled();
    if (!Array.isArray(page) || page.length > pageSize) throw new Error('Catalog returned an invalid page.');
    for (const item of page) {
      const validId = (typeof item?.id === 'string' && item.id.trim()) || (Number.isSafeInteger(item?.id) && item.id > 0);
      const id = String(item?.id);
      if (!validId || seen.has(id)) throw new Error('Catalog pagination did not advance.');
      seen.add(id);
      items.push(item);
    }
    if (page.length < pageSize) return items;
  }
}
