import properties from '../../../../contracts/credential-template-readback-properties.json';
import { describe, expect, it } from 'vitest';
import Ajv from 'ajv';
import { normalizeCredentialTemplate } from '../presentationPolicyApi';

const validate = new Ajv({ strict: false }).compile({ type: 'object', properties, required: Object.keys(properties), additionalProperties: false });
const stored = {
  validity_rules: { default_validity_days: 2, max_validity_days: 365, renewable: true, renewal_window_days: 0, not_before_offset_seconds: 900 },
  supported_formats: ['SD_JWT_VC'], selective_disclosure_fields: ['name'], zk_predicate_claims: ['age_over_21'],
  derived_attributes: [{ id: 'age', name: 'Age', description: null, source_claim: 'birth_date', derivation_type: 'age_over', parameters: { threshold: 21 } }],
  display_style: { background_color: '#123456', text_color: '#ffffff', logo_url: null, background_image_url: null, icon: null },
};
describe('public template configuration schema', () => {
  it('accepts persisted non-default configuration and preserves it during UI normalization', () => {
    expect(validate(stored), JSON.stringify(validate.errors)).toBe(true);
    const normalized = normalizeCredentialTemplate({ id: 'template', ...stored });
    for (const field of Object.keys(properties)) {
      if (field === 'validity_rules') expect(normalized[field]).toMatchObject(stored[field]);
      else expect(normalized[field]).toEqual(stored[field]);
    }
  });
  it('rejects undeclared display and derived-object fields', () => {
    expect(validate({ ...stored, display_style: { ...stored.display_style, key_reference: 'private' } })).toBe(false);
    expect(validate({ ...stored, derived_attributes: [{ ...stored.derived_attributes[0], issuer_profile_id: 'private' }] })).toBe(false);
  });
});
