// Match the stored i32 fields in credential-template/src/persistence.rs.
export const MAX_VALIDITY_DAYS = 2147483647;
export const MIN_VALIDITY_OFFSET = -2147483648;
export const MAX_VALIDITY_OFFSET = 2147483647;
export const SECONDS_PER_DAY = 86400;

export const INITIAL_TEMPLATE_VALIDITY = Object.freeze({
  default_validity_days: 365,
  max_validity_days: 730,
  not_before_offset_seconds: 0,
});

const numericValue = (value) => (typeof value === 'number'
  || (typeof value === 'string' && value.trim() !== '')) ? Number(value) : NaN;
const integerInRange = (value, minimum, maximum) => {
  const number = numericValue(value);
  return Number.isInteger(number) && number >= minimum && number <= maximum;
};
const daysFromSeconds = (seconds) => {
  if (seconds === '') return '';
  const number = numericValue(seconds);
  // Preserve invalid values for correction instead of displaying a valid fallback.
  return number > 0 ? Math.ceil(number / SECONDS_PER_DAY) : number / SECONDS_PER_DAY;
};

/** Resolve the native seconds aliases consistently for editing, review and creation. */
export function credentialTemplateValidity(rules = {}) {
  const values = {
    default_validity_days: rules.ttl_seconds != null
      ? daysFromSeconds(rules.ttl_seconds)
      : rules.default_validity_days ?? INITIAL_TEMPLATE_VALIDITY.default_validity_days,
    max_validity_days: rules.max_validity_seconds != null
      ? daysFromSeconds(rules.max_validity_seconds)
      : rules.max_validity_days ?? INITIAL_TEMPLATE_VALIDITY.max_validity_days,
    not_before_offset_seconds: rules.not_before_offset_seconds
      ?? rules.not_before_offset ?? INITIAL_TEMPLATE_VALIDITY.not_before_offset_seconds,
  };
  const errors = {
    default_validity_days: !integerInRange(values.default_validity_days, 1, MAX_VALIDITY_DAYS),
    max_validity_days: !integerInRange(values.max_validity_days, 1, MAX_VALIDITY_DAYS),
    not_before_offset_seconds: !integerInRange(values.not_before_offset_seconds, MIN_VALIDITY_OFFSET, MAX_VALIDITY_OFFSET),
  };
  return { values, errors, valid: !Object.values(errors).some(Boolean) };
}

/** Submit the exact reviewed whole-day values without competing seconds aliases. */
export function buildWizardValidityRules(rules = {}) {
  const { values, valid } = credentialTemplateValidity(rules);
  if (!valid) throw new Error('Invalid credential template validity settings.');
  const { ttl_seconds: _ttl, max_validity_seconds: _maximum, not_before_offset: _offset, ...preserved } = rules;
  return {
    ...preserved,
    ...Object.fromEntries(Object.entries(values).map(([key, value]) => [key, Number(value)])),
  };
}
