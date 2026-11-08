import { describe, expect, it } from 'vitest';
import { applyAutomaticTemplateConfig, automaticTemplateMatchesTrust, clearAutomaticTemplateConfig } from '../policyTemplateDefaults';

const initial = {
  name: '', purpose: '', description: '', accepted_credential_types: [], required_claims: [],
  holder_binding: 'device_key', freshness_requirements: { max_proof_age_seconds: 300 }, metadata: {},
};
const generated = {
  name: 'Automatic name', purpose: 'Automatic purpose', description: 'Automatic description',
  accepted_credential_types: ['urn:template-a'],
  required_claims: [{ claim_name: 'employee_id', credential_type: 'urn:template-a', required_value: null }],
  credential_requirements: [{ credential_template_id: 'template-a', requested_claims: [{ claim_name: 'employee_id' }] }],
  holder_binding: 'device_key', freshness_requirements: { max_proof_age_seconds: 300 },
  metadata: { credential_template_id: 'template-a', credential_template_vct: 'urn:template-a',
    credential_payload_format: 'SD_JWT_VC', template_id: 'credential-template:template-a', standard_reference: 'SD_JWT_VC' },
};

describe('automatic policy-template configuration', () => {
  it('removes the automatic credential references while preserving unrelated user changes and additions', () => {
    const selectedTemplate = { _organizationDefault: { previousConfig: initial, generatedConfig: generated } };
    const current = {
      ...generated, name: 'Edited name', purpose: 'Edited purpose',
      freshness_requirements: { max_proof_age_seconds: 42 },
      accepted_credential_types: ['urn:template-a', 'urn:manual'],
      required_claims: [
        { ...generated.required_claims[0], required_value: 'edited automatic claim' },
        { claim_name: 'manual_claim', credential_type: 'urn:manual' },
      ],
      credential_requirements: [...generated.credential_requirements, { credential_template_id: 'manual-template' }],
      metadata: { ...generated.metadata, note: 'Keep this note', standard_reference: 'User standard' },
    };
    const cleaned = clearAutomaticTemplateConfig(current, selectedTemplate);
    expect(cleaned).toMatchObject({
      name: 'Edited name', purpose: 'Edited purpose', description: '',
      freshness_requirements: { max_proof_age_seconds: 42 },
      accepted_credential_types: ['urn:manual'],
      required_claims: [{ claim_name: 'manual_claim', credential_type: 'urn:manual' }],
      credential_requirements: [{ credential_template_id: 'manual-template' }],
      metadata: { note: 'Keep this note', standard_reference: 'User standard' },
    });
    expect(cleaned.metadata).not.toHaveProperty('credential_template_id');
    expect(cleaned.metadata).not.toHaveProperty('template_id');
    expect(JSON.stringify(cleaned)).not.toContain('template-a');
  });

  it('preserves edits when an eligible automatic template is initialized again', () => {
    const before = { ...initial, name: 'User name', purpose: 'User purpose', metadata: { note: 'User note' },
      accepted_credential_types: ['urn:manual'], required_claims: [{ claim_name: 'manual_claim', credential_type: 'urn:manual' }] };
    const applied = applyAutomaticTemplateConfig(before, generated, initial);
    expect(applied).toMatchObject({ name: 'User name', purpose: 'User purpose', metadata: { note: 'User note', credential_template_id: 'template-a' } });
    expect(applied.required_claims).toEqual([...before.required_claims, ...generated.required_claims]);
    const cleaned = clearAutomaticTemplateConfig(applied, { _organizationDefault: { previousConfig: before, generatedConfig: generated } });
    expect(cleaned).toMatchObject(before);
    expect(cleaned.credential_requirements).toEqual([]);
  });

  it('rejects a formerly compatible automatic template when the same trust profile changes formats', () => {
    const template = { id: 'credential-template:template-a', _organizationDefault: { organizationId: 'org-a' },
      credentialTemplate: { id: 'template-a', organization_id: 'org-a', status: 'ACTIVE', trust_profile_id: 'trust-a', credential_payload_format: 'SD_JWT_VC' } };
    const trust = { id: 'trust-a', organization_id: 'org-a', status: 'ACTIVE', supported_formats: ['SD_JWT_VC'] };
    expect(automaticTemplateMatchesTrust(template, trust, 'org-a')).toBe(true);
    expect(automaticTemplateMatchesTrust(template, { ...trust, supported_formats: ['MDOC'] }, 'org-a')).toBe(false);
    expect(automaticTemplateMatchesTrust(template, trust, 'org-a', null)).toBe(false);
  });
});
