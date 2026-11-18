import { describe, expect, it } from 'vitest';
import { buildWizardValidityRules, credentialTemplateValidity, INITIAL_TEMPLATE_VALIDITY } from '../credentialTemplateValidity';

describe('credential wizard validity contract', () => {
  it.each(['', ' ', 0, -1, 1.5, 2147483648])('rejects an invalid whole-day input (%s) before building a request', (value) => {
    for (const key of ['default_validity_days', 'max_validity_days']) {
      const rules = { ...INITIAL_TEMPLATE_VALIDITY, [key]: value };
      expect(credentialTemplateValidity(rules).errors[key]).toBe(true);
      expect(() => buildWizardValidityRules(rules)).toThrow('Invalid credential template validity settings.');
    }
  });

  it('uses native integer boundaries and preserves the native independence of maximum and default days', () => {
    for (const offset of [-2147483648, 2147483647]) {
      const rules = { default_validity_days: '2147483647', max_validity_days: '1', not_before_offset_seconds: String(offset) };
      expect(credentialTemplateValidity(rules).valid).toBe(true);
      expect(buildWizardValidityRules(rules)).toEqual({ default_validity_days: 2147483647, max_validity_days: 1, not_before_offset_seconds: offset });
    }
  });

  it.each(['', 1.5, -2147483649, 2147483648])('rejects an offset outside the native integer contract (%s)', (offset) => {
    const rules = { ...INITIAL_TEMPLATE_VALIDITY, not_before_offset_seconds: offset };
    expect(credentialTemplateValidity(rules).errors.not_before_offset_seconds).toBe(true);
    expect(() => buildWizardValidityRules(rules)).toThrow();
  });

  it('resolves native alias precedence and rounds once while preserving unrelated rules', () => {
    const rules = { default_validity_days: 9, ttl_seconds: 86401, max_validity_days: 9, max_validity_seconds: 172801,
      not_before_offset_seconds: -900, not_before_offset: 900, renewable: false, renewal_window_days: 0 };
    expect(credentialTemplateValidity(rules).values).toEqual({ default_validity_days: 2, max_validity_days: 3, not_before_offset_seconds: -900 });
    expect(buildWizardValidityRules(rules)).toEqual({ default_validity_days: 2, max_validity_days: 3,
      not_before_offset_seconds: -900, renewable: false, renewal_window_days: 0 });
  });
});
