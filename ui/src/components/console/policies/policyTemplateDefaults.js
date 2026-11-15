import { findOrganizationDefault, matchesTrust, trustSupportsFormat } from '../organizationDefaultSelection';

const same = (left, right) => JSON.stringify(left) === JSON.stringify(right);
const has = (value, key) => Object.prototype.hasOwnProperty.call(value || {}, key);
const claimKey = (claim) => JSON.stringify([claim?.credential_type, claim?.claim_name]);
const requirementKey = (requirement) => requirement?.credential_template_id;
const ARRAY_KEYS = {
  accepted_credential_types: (value) => value,
  required_claims: claimKey,
  credential_requirements: requirementKey,
};

export function automaticTemplateMatchesTrust(selectedTemplate, trustProfile, organizationId, credentialTemplate = selectedTemplate?.credentialTemplate) {
  if (selectedTemplate?._organizationDefault?.organizationId !== organizationId) return false;
  const trust = findOrganizationDefault([trustProfile].filter(Boolean), trustProfile?.id, organizationId);
  return Boolean(trust && findOrganizationDefault([credentialTemplate].filter(Boolean), credentialTemplate?.id, organizationId,
    (template) => selectedTemplate.id === `credential-template:${template.id}`
      && matchesTrust(template, trust.id)
      && trustSupportsFormat(trust, template.credential_payload_format || template.format)));
}

/** An automatic prefill adds its requirements without replacing unrelated edits. */
export function applyAutomaticTemplateConfig(current, generated, initial) {
  const next = { ...current };
  for (const [field, value] of Object.entries(generated)) {
    if (ARRAY_KEYS[field] && Array.isArray(value)) {
      const existing = current[field] || [];
      const keyFor = ARRAY_KEYS[field];
      const keys = new Set(existing.map(keyFor));
      next[field] = [...existing, ...value.filter((item) => !keys.has(keyFor(item)))];
    } else if (field === 'metadata') {
      next.metadata = { ...value, ...current.metadata };
    } else if (current[field] == null || same(current[field], initial[field])) {
      next[field] = value;
    }
  }
  return next;
}

/** Remove the automatic template's contribution, preserving later user edits. */
export function clearAutomaticTemplateConfig(current, selectedTemplate) {
  const origin = selectedTemplate?._organizationDefault;
  if (!origin?.generatedConfig) return current;
  const generated = origin.generatedConfig;
  const previous = origin.previousConfig || {};
  const next = { ...current };

  for (const [field, value] of Object.entries(generated)) {
    if (ARRAY_KEYS[field] || field === 'metadata' || !same(current[field], value)) continue;
    if (has(previous, field)) next[field] = previous[field];
    else delete next[field];
  }

  for (const field of ['required_claims', 'credential_requirements', 'accepted_credential_types']) {
    if (!Array.isArray(current[field])) continue;
    const keyFor = ARRAY_KEYS[field];
    const generatedKeys = new Set((generated[field] || []).map(keyFor));
    const previousKeys = new Set((previous[field] || []).map(keyFor));
    next[field] = current[field].filter((item) => !generatedKeys.has(keyFor(item))
      || previousKeys.has(keyFor(item))
      || (field === 'accepted_credential_types' && next.required_claims?.some((claim) => claim.credential_type === item)));
  }

  const metadata = { ...current.metadata };
  for (const [field, value] of Object.entries(generated.metadata || {})) {
    if (!same(metadata[field], value)) continue;
    if (has(previous.metadata, field)) metadata[field] = previous.metadata[field];
    else delete metadata[field];
  }
  next.metadata = metadata;
  return next;
}
