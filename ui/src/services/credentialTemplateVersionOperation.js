import { normalizeCredentialTemplate } from './presentationPolicyApi';
import { createIdempotencyKey, postWithIdempotency } from './idempotency';

const safeId = (value) => typeof value === 'string' && /^[A-Za-z0-9_-]{1,128}$/.test(value);

/** One explicit version request; an uncertain response must not become another POST. */
export async function createCredentialTemplateVersion(templateId, { organizationId, idempotencyKey, isCurrent } = {}) {
  if (!safeId(templateId) || typeof organizationId !== 'string' || !organizationId.trim()) {
    throw new Error('Select a credential template in the current organization.');
  }
  const result = await postWithIdempotency(
    `/v1/credential-templates/${encodeURIComponent(templateId)}/new-version`, {},
    { params: { organization_id: organizationId }, idempotencyKey, isCurrent, retryOnNetworkAbort: false },
  );
  if (!result || typeof result !== 'object' || Array.isArray(result)) {
    throw new Error('The response did not confirm a new draft. Check the template inventory before continuing.');
  }
  return normalizeCredentialTemplate(result);
}

/** Retain only public request/receipt identifiers across navigation in this tab. */
export function createTemplateVersionOperation(organizationId, principalId, templateId) {
  const journalKey = ['marty', 'template-version', 'v1', organizationId, principalId, templateId]
    .map((part) => encodeURIComponent(String(part))).join(':');
  let acknowledged = null;
  const read = () => {
    if (acknowledged) return acknowledged;
    const raw = sessionStorage.getItem(journalKey);
    if (!raw) return null;
    const record = JSON.parse(raw);
    if (record?.organizationId !== organizationId || record?.principalId !== principalId
      || record?.templateId !== templateId || typeof record.key !== 'string'
      || !record.key.startsWith('credential-template-version:') || record.key.length > 200
      || (record.resourceId !== null && (!safeId(record.resourceId) || record.resourceId === templateId))) {
      throw new Error('The previous draft-version request could not be read. Check the template inventory before continuing.');
    }
    return record;
  };
  let pending = false;
  return {
    read,
    async create({ isCurrent = () => true, separate = false } = {}) {
      if (pending) throw new Error('A draft-version request is already pending.');
      if (!principalId || !isCurrent()) throw new Error('The signed-in account or template view changed.');
      const previous = read();
      if (previous && (!separate || previous.resourceId)) {
        throw new Error('Inspect the previous draft-version request before creating another version.');
      }
      const record = { organizationId, principalId, templateId, key: createIdempotencyKey('credential-template-version'), resourceId: null };
      // A failed local write must stop before dispatch, not lose the only request reference.
      sessionStorage.setItem(journalKey, JSON.stringify(record));
      pending = true;
      try {
        const result = await createCredentialTemplateVersion(templateId, {
          organizationId, idempotencyKey: record.key, isCurrent,
        });
        if (!safeId(result?.id) || result.id === templateId || result.organization_id !== organizationId
          || String(result.status).toLowerCase() !== 'draft') {
          throw new Error('The response did not confirm a new draft in this organization. Check the template inventory before continuing.');
        }
        acknowledged = { ...record, resourceId: result.id };
        try { sessionStorage.setItem(journalKey, JSON.stringify(acknowledged)); }
        catch {
          // Keep the confirmed ID usable even if storage fills after the POST.
          // The earlier dispatch record still prevents a silent fresh request on reload.
        }
        return result;
      } finally {
        pending = false;
      }
    },
  };
}
