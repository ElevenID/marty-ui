import { createResourceCreationOperation } from './resourceCreationOperation';
import { buildPresentationPolicyPayload, createPresentationPolicy, getPresentationPolicy, activatePresentationPolicy } from './presentationPolicyApi';

export function createPolicyCreationOperation(organizationId, principalId) {
  return createResourceCreationOperation(organizationId, principalId, {
    buildPayload: buildPresentationPolicyPayload,
    create: (data, options) => createPresentationPolicy({ ...data, status: 'draft', activate_immediately: false }, options),
    getResource: getPresentationPolicy, activate: activatePresentationPolicy,
    journalNamespace: 'policy-create', keyNamespace: 'presentation-policy',
    resourceName: 'policy', displayName: 'Policy',
  });
}
