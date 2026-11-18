import { describe, expect, it } from 'vitest';
import { buildOrgSettingsSaveBody, parseOrgSettingsResponse } from './orgSettingsFlow';

const response = {
  id: 'org-acme', name: 'acme', display_name: 'Acme Corp', description: 'Identity services',
  website: 'https://acme.example', contact_email: 'admin@acme.example', contact_phone: '+1 555 0100',
  visibility: 'PUBLIC', join_mechanism: 'code', requires_approval: true,
};
const profile = {
  name: 'acme', displayName: 'Acme Corp', description: 'Identity services',
  website: 'https://acme.example', contactEmail: 'admin@acme.example', contactPhone: '+1 555 0100',
  visibility: 'PUBLIC', joinMechanism: 'code', requiresApproval: true,
};

describe('organization settings public contract', () => {
  it('reads the flat public response and preserves approval and admission settings', () => {
    expect(parseOrgSettingsResponse(response, { organizationId: 'org-acme' })).toEqual(profile);
  });
  it('represents nullable contact fields as empty editable values', () => {
    const parsed = parseOrgSettingsResponse({ ...response, description: null, website: null, contact_email: null, contact_phone: null }, { organizationId: 'org-acme' });
    expect(parsed).toMatchObject({ description: '', website: '', contactEmail: '', contactPhone: '' });
  });
  it.each([
    {}, null, { ...response, id: 'other-org' }, { ...response, display_name: '' },
    { ...response, visibility: 'unknown' }, { ...response, requires_approval: null },
  ])('rejects missing, malformed, or wrong-organization data rather than creating an editable blank form', (data) => {
    expect(() => parseOrgSettingsResponse(data, { organizationId: 'org-acme' })).toThrow('selected organization');
  });
  it('includes profile edits and only the supported client fields', () => {
    expect(buildOrgSettingsSaveBody({ ...profile, name: ' acme ', displayName: ' Acme Corp ', settings: { private: true }, address: 'ignored', country: 'ignored', defaultRole: 'admin' })).toEqual({
      name: 'acme', displayName: 'Acme Corp', description: 'Identity services',
      websiteUrl: 'https://acme.example', contactEmail: 'admin@acme.example', contactPhone: '+1 555 0100',
      visibility: 'PUBLIC', joinMechanism: 'code', requiresApproval: true,
    });
  });
  it('clears optional text with null instead of an invalid empty URL or email', () => {
    expect(buildOrgSettingsSaveBody({ ...profile, description: ' ', website: '', contactEmail: '', contactPhone: '' })).toMatchObject({
      description: null, websiteUrl: null, contactEmail: null, contactPhone: null,
    });
  });
  it('refuses empty required names and private open enrollment', () => {
    expect(() => buildOrgSettingsSaveBody({ ...profile, displayName: ' ' })).toThrow('required');
    expect(() => buildOrgSettingsSaveBody({ ...profile, visibility: 'PRIVATE', joinMechanism: 'open' })).toThrow('public');
  });
  it.each(['Acme', 'two words', '-acme', 'acme-', 'x'])('rejects a changed name outside the gateway contract: %s', (name) => {
    expect(() => buildOrgSettingsSaveBody({ ...profile, name }, { originalOrg: profile })).toThrow('lowercase');
  });
  it('does not resubmit unchanged seeded names or overwrite unrelated fields', () => {
    const originalOrg = { ...profile, name: 'Marty' };
    expect(buildOrgSettingsSaveBody({ ...originalOrg, contactEmail: 'contact@example.com' }, { originalOrg })).toEqual({ contactEmail: 'contact@example.com' });
  });
  it('includes public visibility when changing to open enrollment, even if visibility is unchanged', () => {
    expect(buildOrgSettingsSaveBody({ ...profile, joinMechanism: 'open' }, { originalOrg: profile })).toEqual({ joinMechanism: 'open', visibility: 'PUBLIC' });
  });
});
