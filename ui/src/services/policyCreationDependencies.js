import { getTrustProfile, getCredentialTemplate } from './presentationPolicyApi';
import { POLICY_TEMPLATES, getTemplatesByFramework } from '../data/policyTemplates';

// Submission-time reads close the gap between selection and policy mutation.
export async function validatePolicyCreationDependencies(data, organizationId, isCurrent = () => true) {
  const assertCurrent = () => { if (!isCurrent()) throw new Error('Policy creation scope changed. Review the current organization.'); };
  assertCurrent();
  if (!organizationId || !data.selectedTrustProfile?.id || !data.selectedTemplate?.id) {
    throw new Error('Select an organization, trust profile and policy template before submitting.');
  }
  const requireOwnedActive = (resource, id, kind) => {
    if (resource?.id !== id || resource.organization_id !== organizationId || String(resource.status).toUpperCase() !== 'ACTIVE') {
      throw new Error(`${kind} is unavailable, inactive or belongs to another organization. Refresh the selection.`);
    }
  };
  const trustIds = new Set([data.selectedTrustProfile.id]);
  const templateIds = new Set();
  const selected = data.selectedTemplate;
  if (selected.id.startsWith('credential-template:')) templateIds.add(selected.id.slice('credential-template:'.length));
  for (const requirement of data.policyConfig?.credential_requirements || []) {
    if (requirement.trust_profile_id) trustIds.add(requirement.trust_profile_id);
    if (requirement.credential_template_id) templateIds.add(requirement.credential_template_id);
  }
  let selectedTrust;
  for (const id of trustIds) {
    const trust = await getTrustProfile(id);
    assertCurrent();
    requireOwnedActive(trust, id, 'Trust profile');
    if (id === data.selectedTrustProfile.id) selectedTrust = trust;
  }
  if (!selected.id.startsWith('credential-template:') && selected.id !== 'custom') {
    const options = selectedTrust.trust_framework_type ? getTemplatesByFramework(selectedTrust.trust_framework_type) : POLICY_TEMPLATES;
    if (!options.some((option) => option.id === selected.id)) throw new Error('Policy template compatibility changed. Refresh the selection.');
  }
  for (const id of templateIds) {
    const template = await getCredentialTemplate(id);
    assertCurrent();
    requireOwnedActive(template, id, 'Credential template');
  }
  assertCurrent();
}
