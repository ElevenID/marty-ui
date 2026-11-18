import { describe, expect, it } from 'vitest';
import { buildCredentialTemplatePayload } from '../../../../services/presentationPolicyApi';
import { OPEN_BADGE_CLAIM_PRESET, openBadgeClaimSchemaIssue, validCredentialTemplateClaims } from '../credentialTemplateClaims';

describe('Open Badges wizard claim schema', () => {
  it('carries object criteria through the existing template write normalizer', () => {
    const payload = buildCredentialTemplatePayload({
      organization_id: 'org-test', name: 'Course completion', credential_type: 'OpenBadgeCredential',
      issuer_did: 'did:web:issuer.example.test', compliance_profile_id: 'ob3-profile',
      claims: OPEN_BADGE_CLAIM_PRESET.map((claim) => ({ ...claim })),
    });
    expect(payload.claims).toContainEqual(expect.objectContaining({
      name: 'achievement_criteria', claim_type: 'object', required: true,
    }));
    expect(payload.claims.every((claim: Record<string, unknown>) => !('type' in claim))).toBe(true);
    expect(validCredentialTemplateClaims(payload)).toBe(true);
  });

  it.each(['OpenBadgeCredential', 'open_badge', 'open_badge_v3'])('detects missing or scalar criteria for %s', (credentialType) => {
    const data = { credential_type: credentialType, claims: [{ name: 'achievement_name', type: 'string' }] };
    expect(openBadgeClaimSchemaIssue(data)).toBe('missingCriteria');
    expect(validCredentialTemplateClaims(data)).toBe(false);
    data.claims.push({ name: 'achievement_criteria', type: 'string' });
    expect(openBadgeClaimSchemaIssue(data)).toBe('criteriaObject');
  });

  it.each(['achievement', 'achievement_criteria'])('accepts the native %s representation', (name) => {
    expect(validCredentialTemplateClaims({ credential_type: 'OpenBadgeCredential', claims: [{ name, claim_type: 'object' }] })).toBe(true);
  });

  it('leaves nested values and duplicate value aliases to the native issuance owner', () => {
    expect(validCredentialTemplateClaims({ credential_type: 'OpenBadgeCredential', claims: [
      { name: 'achievement', type: 'object' }, { name: 'achievement_criteria', type: 'object' },
    ] })).toBe(true);
  });

  it('keeps non-badge templates on the existing nonempty-claims rule', () => {
    expect(validCredentialTemplateClaims({ credential_type: 'VerifiableCredential', claims: [{ name: 'employee_id', type: 'string' }] })).toBe(true);
    expect(validCredentialTemplateClaims({ credential_type: 'VerifiableCredential', claims: [] })).toBe(false);
  });
});
