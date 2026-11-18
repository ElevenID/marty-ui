function validPolicies(policies) {
  return Array.isArray(policies) && policies.every((policy) => policy && typeof policy.policy_id === 'string'
    && typeof policy.cedar_text === 'string' && ['permit', 'forbid'].includes(policy.effect));
}

export function requirePolicySet(record, organizationId, id) {
  if (!record || typeof record.id !== 'string' || !record.id || record.organization_id !== organizationId || (id && record.id !== id)) {
    throw new Error('This Policy Set is not available in the selected organization.');
  }
  if (typeof record.name !== 'string' || !['DRAFT', 'ACTIVE', 'ARCHIVED'].includes(record.status)
    || !validPolicies(record.cedar_policies)) throw new Error('The API returned an invalid Policy Set.');
  return record;
}

export function requirePolicySetList(records, organizationId) {
  if (!Array.isArray(records)) throw new Error('The API returned an invalid Policy Set list.');
  return records.map((record) => requirePolicySet(record, organizationId));
}

export function requirePolicySetTemplates(templates) {
  if (!Array.isArray(templates) || templates.some((template) => !template?.template_id || typeof template.name !== 'string'
    || typeof template.policy_type !== 'string' || !validPolicies(template.cedar_policies) || !template.cedar_policies.length)) {
    throw new Error('The API returned invalid Policy Set templates.');
  }
  // Provider presets are global definitions, not organization-owned Policy Sets.
  return templates;
}

export function requirePolicySetValidation(result) {
  if (typeof result?.valid !== 'boolean' || !Array.isArray(result.errors) || result.errors.some((error) => typeof error !== 'string')) {
    throw new Error('The API returned an invalid Policy Set validation result.');
  }
  return result;
}
