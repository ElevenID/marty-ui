import { describe, expect, it } from 'vitest';
import { server } from '@test/mocks/server';
import { http, HttpResponse } from 'msw';
import { buildCredentialTemplatePatch as build, updateCredentialTemplate, buildCredentialTemplatePayload, normalizeCredentialTemplateValidityRules } from '../presentationPolicyApi';
describe('sparse credential template update', () => {
  it('sends a sparse body through the exported update adapter', async () => {
    let received;
    server.use(http.patch('*/v1/credential-templates/template-a', async ({ request }) => {
      received = await request.json();
      return HttpResponse.json({ id: 'template-a', organization_id: 'org', name: 'Renamed', status: 'ACTIVE', claims: [{ name: 'subject' }] });
    }));
    const result = await updateCredentialTemplate('template-a', { organization_id: ' org ', name: 'Renamed' });
    expect(received).toEqual({ organization_id: 'org', name: 'Renamed' });
    expect(result.claims[0].name).toBe('subject');
  });
  it('keeps metadata edits sparse without creation identity/defaults', () => {
    expect(build({ organization_id: 'org', name: 'Renamed' })).toEqual({ organization_id: 'org', name: 'Renamed' });
  });
  it('distinguishes explicit empty values from omission', () => {
    expect(build({ organization_id: 'org', claims: [], description: null, supported_formats: undefined })).toEqual({ organization_id: 'org', claims: [], description: null });
  });
  it('does not expand sparse validity rules into defaults', () => {
    expect(build({ organization_id: 'org', validity_rules: { renewable: false, not_before_offset_seconds: 0 } }).validity_rules).toEqual({ renewable: false, not_before_offset_seconds: 0 });
  });
  it.each(['issuer_key_id', 'schema_uri', 'compliance_profile_id', 'vct', 'status'])('rejects unsupported field %s', (field) => {
    expect(() => build({ organization_id: 'org', [field]: 'value' })).toThrow('Unsupported');
  });
  it('rejects nested private configuration before HTTP', () => {
    expect(() => build({ organization_id: 'org', derived_attributes: [{ parameters: { nested: [{ privateKeyJwk: {} }] } }] })).toThrow('Private custody');
  });
  it('requires organization scope', () => { expect(() => build({ name: 'Renamed' })).toThrow('organization'); });
});

describe('validity input preservation', () => {
  it('uses canonical readback days including zero even alongside legacy aliases', () => {
    const result = normalizeCredentialTemplateValidityRules({ default_validity_days: 0, ttl_seconds: 0, max_validity_days: -1, max_validity_seconds: 1, renewal_window_days: 0, reissue_within_seconds: 1, require_revalidation: false, revalidation_interval_days: null });
    expect(result).toMatchObject({ default_validity_days: 0, ttl_seconds: 0, max_validity_days: -1, max_validity_seconds: -86400, renewal_window_days: 0, reissue_within_seconds: 0, require_revalidation: false, revalidation_interval_days: null });
  });
  it('still supports seconds-only legacy readback', () => {
    expect(normalizeCredentialTemplateValidityRules({ ttl_seconds: 172800, reissue_within_seconds: 86400, renewable: false })).toMatchObject({ default_validity_days: 2, renewal_window_days: 1, renewable: false });
  });
  it.each([1, 3600, 86399, 86400, 86401, 0, -1])('forwards %s seconds for authoritative native validation', (seconds) => {
    const validity = { ttl_seconds: seconds, default_validity_days: 9, max_validity_seconds: seconds, reissue_within_seconds: seconds, not_before_offset_seconds: -900, require_revalidation: true, revalidation_interval_days: 7 };
    const payload = buildCredentialTemplatePayload({ issuer_did: 'did:web:issuer.example', compliance_profile_id: 'profile', validity_rules: validity });
    expect(payload.validity_rules).toEqual(validity);
    expect(build({ organization_id: 'org', validity_rules: validity }).validity_rules).toEqual(validity);
  });
});
