import { describe, expect, it } from 'vitest';
import consoleEn from '../../../../../public/locales/en/console.json';
import consoleDe from '../../../../../public/locales/de/console.json';
import consoleEs from '../../../../../public/locales/es/console.json';
import consoleFr from '../../../../../public/locales/fr/console.json';
import consoleJa from '../../../../../public/locales/ja/console.json';
import consoleNl from '../../../../../public/locales/nl/console.json';
import { clearPreviousTemplateBinding, projectTemplatePolicyClaims, TemplatePolicyClaimsError } from '../projectTemplatePolicyClaims';
import { buildPresentationPolicyPayload } from '../../../../services/presentationPolicyApi';

const role = {
  claim_name: 'role', display_name: 'Employee role', description: 'Role assigned by HR',
  required: true, selective_disclosure: false, accept_derived: false,
  constraints: [
    { claim_name: 'role', constraint_type: 'equals', value: 'guest', description: 'Configured value' },
    { claim_name: 'role', constraint_type: 'in_set', value: ['guest', 'staff'], description: 'Allowed HR roles' },
  ],
};
const department = {
  claim_name: 'department', display_name: 'Department', required: false, selective_disclosure: true,
};

function fixture(): { selectedTrustProfile: { id: string }; selectedTemplate: Record<string, any>; policyConfig: Record<string, any> } {
  const requirement = {
    credential_template_id: 'template-a', credential_payload_format: 'SD_JWT_VC',
    display_name: 'Employee', description: 'An employer credential', required: true,
    max_age_seconds: 3600, require_fresh_issuance: true,
    requested_claims: [role, department],
  };
  const config = {
    accepted_credential_types: ['urn:employee'], credential_requirements: [requirement],
    required_claims: [
      { claim_name: 'role', credential_type: 'urn:employee', required_value: 'guest', accept_predicate: false },
      { claim_name: 'department', credential_type: 'urn:employee', required_value: null, accept_predicate: false },
    ],
  };
  return structuredClone({
    selectedTrustProfile: { id: 'trust-a' },
    selectedTemplate: { id: 'credential-template:template-a', config },
    policyConfig: structuredClone(config),
  });
}

function projectionError(data: ReturnType<typeof fixture>) {
  try {
    projectTemplatePolicyClaims(data);
  } catch (error) {
    expect(error).toBeInstanceOf(TemplatePolicyClaimsError);
    return error as TemplatePolicyClaimsError;
  }
  throw new Error('Expected the template projection to reject this configuration.');
}

describe('reviewed template-backed presentation claims', () => {
  it('projects claim removal and edited equality into the actual native create payload without losing restrictions', () => {
    const data = fixture();
    data.policyConfig = { ...data.policyConfig, required_claims: [{
      ...data.policyConfig.required_claims[0], required_value: 'staff',
    }] };
    const unchangedInput = structuredClone(data);
    const requirements = projectTemplatePolicyClaims(data);
    const payload = buildPresentationPolicyPayload({
      ...data.policyConfig, organization_id: 'org-a', name: 'Staff access',
      credential_requirements: requirements,
    });
    expect(payload.credential_requirements).toEqual([{
      ...data.policyConfig.credential_requirements[0], trust_profile_id: 'trust-a',
      requested_claims: [{
        ...role,
        constraints: [{ ...role.constraints[0], value: 'staff' }, role.constraints[1]],
      }],
    }]);
    expect(payload.required_claims).toEqual([{
      claim_name: 'role', credential_type: 'urn:employee', value_constraint: 'staff', predicate_spec: null,
    }]);
    expect(data).toEqual(unchangedInput);
  });

  it('clears the editable equality while retaining other constraints and an explicit trust binding', () => {
    const data = fixture();
    data.policyConfig = {
      ...data.policyConfig,
      credential_requirements: [{ ...data.policyConfig.credential_requirements[0], trust_profile_id: 'bound-trust' }],
      required_claims: [{ ...data.policyConfig.required_claims[0], required_value: null }],
    };
    const [requirement] = projectTemplatePolicyClaims(data);
    expect(requirement.trust_profile_id).toBe('bound-trust');
    expect(requirement.requested_claims[0].constraints).toEqual([role.constraints[1]]);
    expect(requirement.requested_claims[0].selective_disclosure).toBe(false);
  });

  it('keeps optional-claim metadata and removes response-only IDs from request objects', () => {
    const data = fixture();
    data.policyConfig = {
      ...data.policyConfig,
      credential_requirements: [{ ...data.policyConfig.credential_requirements[0], id: 'requirement-record', requested_claims: [{ ...department, id: 'claim-record' }] }],
      required_claims: [data.policyConfig.required_claims[1]],
    };
    const [requirement] = projectTemplatePolicyClaims(data);
    expect(requirement).not.toHaveProperty('id');
    expect(requirement.requested_claims).toEqual([{ ...department, accept_derived: false, constraints: [] }]);
  });

  it('rejects conflicting immutable equality constraints instead of replacing them', () => {
    const data = fixture();
    data.selectedTemplate = { ...data.selectedTemplate, config: { ...data.selectedTemplate.config,
      required_claims: [{ ...data.selectedTemplate.config.required_claims[0], required_value: null }],
    } };
    data.policyConfig = { ...data.policyConfig, required_claims: [{ ...data.policyConfig.required_claims[0], required_value: 'staff' }] };
    expect(projectionError(data)).toMatchObject({
      code: 'templateValueConflict', values: { claimName: 'role' },
      message: 'The required value for “role” conflicts with a constraint from the selected template.',
    });
  });

  it.each([
    { change: 'changed type', code: 'templateTypeMismatch', values: {} },
    { change: 'additional type', code: 'templateTypeMismatch', values: {} },
    { change: 'unknown claim', code: 'templateUnknownClaim', values: { claimName: 'unknown' } },
    { change: 'duplicate claim', code: 'templateDuplicateClaim', values: { claimName: 'role' } },
    { change: 'mismatched template', code: 'templateRequirementsMismatch', values: {} },
    { change: 'multiple requirements', code: 'templateRequirementsMismatch', values: {} },
    { change: 'incomplete template', code: 'templateIncomplete', values: {} },
  ])('fails clearly for $change without weakening template restrictions', ({ change, code, values }) => {
    const data = fixture();
    if (change === 'changed type') data.policyConfig.accepted_credential_types = ['urn:other'];
    if (change === 'additional type') data.policyConfig.accepted_credential_types = ['urn:employee', 'urn:other'];
    if (change === 'unknown claim') data.policyConfig.required_claims = [{ ...data.policyConfig.required_claims[0], claim_name: 'unknown' }];
    if (change === 'duplicate claim') data.policyConfig.required_claims = [data.policyConfig.required_claims[0], data.policyConfig.required_claims[0]];
    if (change === 'mismatched template') data.selectedTemplate = { ...data.selectedTemplate, id: 'credential-template:other-template' };
    if (change === 'multiple requirements') data.policyConfig.credential_requirements = [...data.policyConfig.credential_requirements, data.policyConfig.credential_requirements[0]];
    if (change === 'incomplete template') data.selectedTemplate = { ...data.selectedTemplate, config: { ...data.selectedTemplate.config, credential_requirements: [] } };
    expect(projectionError(data)).toMatchObject({ code, values, message: expect.any(String) });
  });

  it.each(Object.entries({ en: consoleEn, de: consoleDe, es: consoleEs, fr: consoleFr, ja: consoleJa, nl: consoleNl }))('provides all projection messages in the %s locale with claim interpolation preserved', (_locale, resource) => {
    const validation = resource.wizards.presentationPolicy.claimsConfigurationStep.validation;
    for (const code of ['templateRequirementsMismatch', 'templateIncomplete', 'templateTypeMismatch', 'templateDuplicateClaim', 'templateUnknownClaim', 'templateValueConflict']) {
      expect(validation[code]).toEqual(expect.any(String));
      expect(validation[code].trim()).not.toBe('');
      if (['templateDuplicateClaim', 'templateUnknownClaim', 'templateValueConflict'].includes(code)) {
        expect(validation[code]).toContain('{{claimName}}');
      }
    }
  });

  it('leaves standards and Custom policies on their protocol-inline path', () => {
    for (const id of ['mdl-age-verification', 'custom']) {
      expect(projectTemplatePolicyClaims({
        selectedTemplate: { id }, selectedTrustProfile: { id: 'trust-a' },
        policyConfig: { required_claims: [{ claim_name: 'age_over_21' }] },
      })).toBeUndefined();
      expect(projectTemplatePolicyClaims({
        selectedTemplate: { id }, selectedTrustProfile: { id: 'trust-a' },
        policyConfig: { credential_requirements: [], required_claims: [{ claim_name: 'age_over_21' }] },
      })).toEqual([]);
    }
  });

  it('clears only the previous template binding and its unchanged metadata on an explicit selection change', () => {
    const data = fixture();
    const unrelated = { credential_template_id: 'unrelated-template', requested_claims: [{ claim_name: 'approval' }] };
    data.selectedTemplate.config.metadata = { credential_template_id: 'template-a', credential_template_vct: 'urn:employee' };
    data.policyConfig = { ...data.policyConfig,
      credential_requirements: [...data.policyConfig.credential_requirements, unrelated],
      metadata: { credential_template_id: 'template-a', credential_template_vct: 'urn:employee', template_id: data.selectedTemplate.id, purpose_note: 'Keep this note' },
    };
    const result = clearPreviousTemplateBinding(data.policyConfig, data.selectedTemplate);
    expect(result.credential_requirements).toEqual([unrelated]);
    expect(result.metadata).toEqual({ purpose_note: 'Keep this note' });
    expect(result.required_claims).toEqual(data.policyConfig.required_claims);
    expect(result.accepted_credential_types).toEqual(['urn:employee']);
  });
});
