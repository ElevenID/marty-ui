import { createResourceCreationOperation } from './resourceCreationOperation';
import { buildCredentialTemplatePayload, createCredentialTemplate, getCredentialTemplate, activateCredentialTemplate } from './presentationPolicyApi';

export function createTemplateCreationOperation(organizationId, principalId) {
  return createResourceCreationOperation(organizationId, principalId, {
    buildPayload: buildCredentialTemplatePayload, create: createCredentialTemplate,
    getResource: getCredentialTemplate, activate: activateCredentialTemplate,
    journalNamespace: 'template-create', keyNamespace: 'credential-template',
  });
}
