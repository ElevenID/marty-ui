import { createIdempotencyKey } from './idempotency';

// One instance belongs to one mounted, organization-scoped creation journey.
// Acknowledged creates are never repeated to recover a later activation failure.
export function createResourceCreationOperation(organizationId, principalId, {
  buildPayload, create, getResource, activate, journalNamespace, keyNamespace,
  resourceName = 'template', displayName = 'Template',
}) {
  let operation = null;
  let pending = null;
  const journalKey = `marty:${journalNamespace}:v1:${organizationId}`;
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
    if (!principalId) throw new Error(`Sign in before recovering or creating a ${resourceName}.`);
    if (data.organization_id !== organizationId) throw new Error(`${displayName} creation organization changed.`);
    const payload = buildPayload(data);
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(payload)));
    const fingerprint = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
    assertCurrent();
    if (!operation) {
      const saved = sessionStorage.getItem(journalKey);
      if (saved) {
        const record = JSON.parse(saved);
        if (record.principalId !== principalId) throw new Error(`A previous account has an unresolved ${resourceName} request in this tab. Reconcile it with that account before creating another ${resourceName}.`);
        if (!/^[a-f0-9]{64}$/.test(record.fingerprint) || typeof record.key !== 'string'
          || !record.key.startsWith(`${keyNamespace}:`) || !Number.isSafeInteger(record.createdAt)
          || (record.resourceId != null && typeof record.resourceId !== 'string')) {
          throw new Error(`${displayName} request recovery data is invalid. Reconcile the previous request before creating another ${resourceName}.`);
        }
        operation = { fingerprint: record.fingerprint, key: record.key,
          createdAt: record.createdAt,
          resource: record.resourceId ? { id: record.resourceId, organization_id: organizationId } : null,
          needsReadback: Boolean(record.resourceId) };
      }
    }
    if (operation && operation.fingerprint !== fingerprint) {
      throw new Error(operation.resource
        ? `${displayName} ${operation.resource.id} was already created. Open that draft to edit it before activation.`
        : 'A create request has already been sent. Retry the original request before changing its configuration.');
    }
    operation ||= { fingerprint, key: createIdempotencyKey(keyNamespace), resource: null, createdAt: Date.now() };
    // Current gateway cache retention is 24 hours. Never initiate a new create
    // from an unresolved journal outside that window (or after clock rollback).
    if (!operation.resource && (Date.now() < operation.createdAt || Date.now() - operation.createdAt >= 86_340_000)) {
      throw new Error(`The previous ${resourceName} request needs reconciliation before another create. Inspect existing ${resourceName}s; its safe retry window has ended.`);
    }
    // Persist before the mutation; reload/navigation retries retain the same key.
    persist();
    if (operation.needsReadback) {
      const restored = await getResource(operation.resource.id);
      assertCurrent();
      if (restored.id !== operation.resource.id || restored.organization_id !== organizationId) throw new Error(`${displayName} ownership could not be confirmed.`);
      operation.resource = restored;
      operation.needsReadback = false;
    }
    if (!operation.resource) {
      try {
        operation.resource = await create({ ...data, activate_immediately: false }, { idempotencyKey: operation.key });
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
    if (!operation.resource?.id) throw new Error(`${displayName} creation did not return a resource ID. Reconcile the request before continuing.`);
    if (operation.resource.organization_id !== organizationId) throw new Error(`Created ${resourceName} ownership could not be confirmed. Reconcile the request before continuing.`);
    persist();
    assertCurrent();
    if (!data.activate_immediately) return complete(operation.resource);
    try {
      // Read first on every activation attempt, including retries after a lost response.
      const current = await getResource(operation.resource.id);
      assertCurrent();
      if (current.id !== operation.resource.id || current.organization_id !== organizationId) throw new Error(`${displayName} ownership could not be confirmed.`);
      if (String(current.status).toUpperCase() === 'ACTIVE') return complete(current);
      if (String(current.status).toUpperCase() !== 'DRAFT') throw new Error(`The created ${resourceName} is no longer a draft. Open it to inspect its state.`);
      const activated = await activate(current.id);
      if (activated.id !== current.id || activated.organization_id !== organizationId) throw new Error('Activated resource ownership could not be confirmed.');
      assertCurrent();
      return complete(activated);
    } catch (cause) {
      const error = new Error(`${displayName} ${operation.resource.id} was created, but activation is incomplete. Retry activation or open the draft. ${cause.message || ''}`);
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
