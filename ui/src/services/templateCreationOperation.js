import { createIdempotencyKey } from './idempotency';
import { buildCredentialTemplatePayload, createCredentialTemplate, getCredentialTemplate, activateCredentialTemplate } from './presentationPolicyApi';

// One instance belongs to one mounted, organization-scoped creation journey.
// Acknowledged creates are never repeated to recover a later activation failure.
export function createTemplateCreationOperation(organizationId, principalId) {
  let operation = null;
  let pending = null;
  const journalKey = `marty:template-create:v1:${organizationId}`;
  const persist = () => sessionStorage.setItem(journalKey, JSON.stringify({
    fingerprint: operation.fingerprint, key: operation.key,
    createdAt: operation.createdAt,
    principalId,
    resourceId: operation.resource?.organization_id === organizationId ? operation.resource.id : null,
  }));
  const complete = (resource) => { sessionStorage.removeItem(journalKey); return resource; };
  const run = async (data, isCurrent) => {
    const assertCurrent = () => { if (!isCurrent()) throw new Error('Creation scope changed. Inspect the original organization before retrying.'); };
    assertCurrent();
    if (!principalId) throw new Error('Sign in before recovering or creating a template.');
    if (data.organization_id !== organizationId) throw new Error('Template creation organization changed.');
    const payload = buildCredentialTemplatePayload(data);
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(payload)));
    const fingerprint = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
    assertCurrent();
    if (!operation) {
      const saved = sessionStorage.getItem(journalKey);
      if (saved) {
        const record = JSON.parse(saved);
        if (record.principalId !== principalId) throw new Error('A previous account has an unresolved template request in this tab. Reconcile it with that account before creating another template.');
        if (!/^[a-f0-9]{64}$/.test(record.fingerprint) || typeof record.key !== 'string'
          || !record.key.startsWith('credential-template:') || !Number.isSafeInteger(record.createdAt)
          || (record.resourceId != null && typeof record.resourceId !== 'string')) {
          throw new Error('Template request recovery data is invalid. Reconcile the previous request before creating another template.');
        }
        operation = { fingerprint: record.fingerprint, key: record.key,
          createdAt: record.createdAt,
          resource: record.resourceId ? { id: record.resourceId, organization_id: organizationId } : null,
          needsReadback: Boolean(record.resourceId) };
      }
    }
    if (operation && operation.fingerprint !== fingerprint) {
      throw new Error(operation.resource
        ? `Template ${operation.resource.id} was already created. Open that draft to edit it before activation.`
        : 'A create request has already been sent. Retry the original request before changing its configuration.');
    }
    operation ||= { fingerprint, key: createIdempotencyKey('credential-template'), resource: null, createdAt: Date.now() };
    // Current gateway cache retention is 24 hours. Never initiate a new create
    // from an unresolved journal outside that window (or after clock rollback).
    if (!operation.resource && (Date.now() < operation.createdAt || Date.now() - operation.createdAt >= 86_340_000)) {
      throw new Error('The previous template request needs reconciliation before another create. Inspect existing templates; its safe retry window has ended.');
    }
    // Persist before the mutation; reload/navigation retries retain the same key.
    persist();
    if (operation.needsReadback) {
      const restored = await getCredentialTemplate(operation.resource.id);
      assertCurrent();
      if (restored.id !== operation.resource.id || restored.organization_id !== organizationId) throw new Error('Template ownership could not be confirmed.');
      operation.resource = restored;
      operation.needsReadback = false;
    }
    if (!operation.resource) {
      try {
        operation.resource = await createCredentialTemplate({ ...data, activate_immediately: false }, { idempotencyKey: operation.key });
      } catch (error) {
        const status = error.status || error.response?.status;
        // An explicit validation/authorization rejection did not create a resource.
        if (!error.operationStatusUnknown && [400, 401, 403, 422].includes(status)) {
          sessionStorage.removeItem(journalKey);
          operation = null;
        }
        throw error;
      }
    }
    if (!operation.resource?.id) throw new Error('Template creation did not return a resource ID. Reconcile the request before continuing.');
    if (operation.resource.organization_id !== organizationId) throw new Error('Created template ownership could not be confirmed. Reconcile the request before continuing.');
    persist();
    assertCurrent();
    if (!data.activate_immediately) return complete(operation.resource);
    try {
      // Read first on every activation attempt, including retries after a lost response.
      const current = await getCredentialTemplate(operation.resource.id);
      assertCurrent();
      if (current.id !== operation.resource.id || current.organization_id !== organizationId) throw new Error('Template ownership could not be confirmed.');
      if (String(current.status).toUpperCase() === 'ACTIVE') return complete(current);
      if (String(current.status).toUpperCase() !== 'DRAFT') throw new Error('The created template is no longer a draft. Open it to inspect its state.');
      return complete(await activateCredentialTemplate(current.id));
    } catch (cause) {
      const error = new Error(`Template ${operation.resource.id} was created, but activation is incomplete. Retry activation or open the draft. ${cause.message || ''}`);
      error.createdResource = operation.resource;
      error.cause = cause;
      throw error;
    }
  };
  return {
    submit(data, { isCurrent = () => true } = {}) {
      if (pending) return pending;
      pending = run(data, isCurrent).finally(() => { pending = null; });
      return pending;
    },
    get resource() { return operation?.resource || null; },
  };
}
