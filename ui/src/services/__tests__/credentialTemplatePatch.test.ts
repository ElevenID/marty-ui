import { describe, expect, it } from 'vitest';
import { server } from '@test/mocks/server';
import { http, HttpResponse } from 'msw';
import { buildCredentialTemplatePatch as build, updateCredentialTemplate } from '../presentationPolicyApi';
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
