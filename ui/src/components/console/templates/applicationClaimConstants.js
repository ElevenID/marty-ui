export function structuredClaimType(claim) {
  const type = String(claim?.claim_type || claim?.type || claim?.field_type || '').trim().toLowerCase();
  return ['object', 'array'].includes(type) ? type : null;
}

export function isConstantClaimRule(rule) {
  return rule.source === 'SYSTEM' && rule.source_config?.system_field === 'constant';
}

export function claimConstantDraft(rule, claim) {
  const source = rule.source_config || {};
  const hasValue = Object.hasOwn(source, 'value');
  const format = structuredClaimType(claim) || (hasValue && typeof source.value !== 'string') ? 'json' : 'text';
  return {
    format,
    hasValue,
    text: format === 'json'
      ? (hasValue ? JSON.stringify(source.value, null, 2) ?? '' : '')
      : (source.value ?? ''),
  };
}

function hasFiniteNumbers(value) {
  const pending = [value];
  while (pending.length > 0) {
    const current = pending.pop();
    if (typeof current === 'number' && !Number.isFinite(current)) return false;
    if (current && typeof current === 'object') {
      for (const child of Object.values(current)) pending.push(child);
    }
  }
  return true;
}

// Keep the editor's text separate from the canonical JSON value sent to the API.
// Credential contents and Open Badges criteria remain the issuance owner's policy.
export function resolveConstantClaimRule(row, claim) {
  const { rule } = row;
  if (!isConstantClaimRule(rule)) return { rule, error: '' };
  const draft = row.constantDraft || claimConstantDraft(rule, claim);
  if (!draft.hasValue) return { rule, error: 'Enter a constant value.' };
  let value = draft.text;
  if (draft.format === 'json') {
    try {
      value = JSON.parse(draft.text);
    } catch {
      return { rule, error: 'Enter valid JSON for this constant value.' };
    }
    if (!hasFiniteNumbers(value)) {
      return { rule, error: 'JSON numbers must be finite. Use text for values outside the numeric range.' };
    }
  }
  const type = structuredClaimType(claim);
  if (type === 'object' && (value === null || typeof value !== 'object' || Array.isArray(value))) {
    return { rule, error: 'This claim requires a JSON object. Choose JSON and enter an object value.' };
  }
  if (type === 'array' && !Array.isArray(value)) {
    return { rule, error: 'This claim requires a JSON array. Choose JSON and enter an array value.' };
  }
  return { rule: { ...rule, source_config: { ...rule.source_config, value } }, error: '' };
}
