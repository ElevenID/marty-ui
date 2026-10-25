import { createIdempotencyKey } from './idempotency';
import { buildCredentialTemplatePayload, createCredentialTemplate, getCredentialTemplate, activateCredentialTemplate } from './presentationPolicyApi';

// One instance belongs to one mounted, organization-scoped creation journey.
// Acknowledged creates are never repeated to recover a later activation failure.
export function createTemplateCreationOperation(organizationId) {
  let operation = null;
  let pending = null;
  const run = async (data, isCurrent) => {
    const assertCurrent = () => { if (!isCurrent()) throw new Error('Creation scope changed. Inspect the original organization before retrying.'); };
    assertCurrent();
    if (data.organization_id !== organizationId) throw new Error('Template creation organization changed.');
    const payload = buildCredentialTemplatePayload(data);
    const fingerprint = JSON.stringify(payload);
    if (operation && operation.fingerprint !== fingerprint) {
      throw new Error(operation.resource
        ? `Template ${operation.resource.id} was already created. Open that draft to edit it before activation.`
        : 'A create request has already been sent. Retry the original request before changing its configuration.');
    }
    operation ||= { fingerprint, key: createIdempotencyKey('credential-template'), resource: null };
    if (!operation.resource) {
      try {
        operation.resource = await createCredentialTemplate({ ...data, activate_immediately: false }, { idempotencyKey: operation.key });
      } catch (error) {
        const status = error.status || error.response?.status;
        // An explicit validation/authorization rejection did not create a resource.
        if (!error.operationStatusUnknown && [400, 401, 403, 422].includes(status)) operation = null;
        throw error;
      }
    }
    if (!operation.resource?.id) throw new Error('Template creation did not return a resource ID. Reconcile the request before continuing.');
    if (operation.resource.organization_id !== organizationId) throw new Error('Created template ownership could not be confirmed. Reconcile the request before continuing.');
    assertCurrent();
    if (!data.activate_immediately) return operation.resource;
    try {
      // Read first on every activation attempt, including retries after a lost response.
      const current = await getCredentialTemplate(operation.resource.id);
      assertCurrent();
      if (current.id !== operation.resource.id || current.organization_id !== organizationId) throw new Error('Template ownership could not be confirmed.');
      if (String(current.status).toUpperCase() === 'ACTIVE') return current;
      if (String(current.status).toUpperCase() !== 'DRAFT') throw new Error('The created template is no longer a draft. Open it to inspect its state.');
      return await activateCredentialTemplate(current.id);
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
