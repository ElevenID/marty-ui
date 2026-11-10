const TEMPLATE_PREFIX = 'credential-template:';
const sameValue = (left, right) => JSON.stringify(left) === JSON.stringify(right);
const withoutId = ({ id: _id, ...value }) => value;
const requiredValue = (claim) => {
  const value = claim?.value_constraint ?? claim?.required_value;
  return value === '' || value == null ? null : value;
};

/** Keep projection independent of i18n while exposing translated UI error details. */
export class TemplatePolicyClaimsError extends Error {
  constructor(code, message, values = {}) {
    super(message);
    this.name = 'TemplatePolicyClaimsError';
    this.code = code;
    this.values = values;
  }
}

/** An explicit template change removes its generated binding, retaining editable values. */
export function clearPreviousTemplateBinding(config, previousTemplate) {
  if (!previousTemplate) return config;
  const next = { ...config };
  if (previousTemplate.id?.startsWith(TEMPLATE_PREFIX) && Array.isArray(config.credential_requirements)) {
    const previousId = previousTemplate.id.slice(TEMPLATE_PREFIX.length);
    next.credential_requirements = config.credential_requirements.filter((requirement) => requirement.credential_template_id !== previousId);
  }
  const generatedMetadata = {
    ...previousTemplate.config?.metadata,
    template_id: previousTemplate.id,
    standard_reference: previousTemplate.standardReference,
  };
  next.metadata = { ...config.metadata };
  for (const [key, value] of Object.entries(generatedMetadata)) {
    if (sameValue(next.metadata[key], value)) delete next.metadata[key];
  }
  return next;
}

/** Project the reviewed claims into the native requirement that verification uses. */
export function projectTemplatePolicyClaims({ policyConfig, selectedTemplate, selectedTrustProfile }) {
  const requirements = policyConfig.credential_requirements;
  const templateId = selectedTemplate?.id?.startsWith(TEMPLATE_PREFIX)
    ? selectedTemplate.id.slice(TEMPLATE_PREFIX.length) : null;

  // Standards and Custom policies use the existing protocol-inline conversion.
  if (!templateId && (!Array.isArray(requirements) || requirements.length === 0)) return requirements;
  if (!templateId || !Array.isArray(requirements) || requirements.length !== 1
    || requirements[0].credential_template_id !== templateId
    || (policyConfig.alternative_requirements || []).length > 0) {
    throw new TemplatePolicyClaimsError('templateRequirementsMismatch', 'These requirements do not match the selected credential template. Reselect the template or start a new Custom Policy.');
  }

  const templateRequirements = selectedTemplate.config?.credential_requirements;
  const templateTypes = selectedTemplate.config?.accepted_credential_types;
  const acceptedTypes = policyConfig.accepted_credential_types;
  if (!Array.isArray(templateRequirements) || templateRequirements.length !== 1
    || templateRequirements[0].credential_template_id !== templateId
    || !Array.isArray(templateTypes) || templateTypes.length !== 1
    || requirements[0].credential_payload_format !== templateRequirements[0].credential_payload_format) {
    throw new TemplatePolicyClaimsError('templateIncomplete', 'The selected credential template is incomplete. Reselect the template before continuing.');
  }
  const boundType = templateTypes[0];
  if (!Array.isArray(acceptedTypes) || acceptedTypes.length !== 1 || acceptedTypes[0] !== boundType
    || policyConfig.required_claims.some((claim) => claim.credential_type !== boundType)) {
    throw new TemplatePolicyClaimsError('templateTypeMismatch', 'This policy is bound to the selected credential template. Use its credential type, or start a new Custom Policy to configure different types.');
  }

  const requirement = requirements[0];
  const originals = new Map((requirement.requested_claims || []).map((claim) => [claim.claim_name, claim]));
  const initialClaims = new Map((selectedTemplate.config.required_claims || []).map((claim) => [claim.claim_name, claim]));
  const names = new Set();
  const requestedClaims = policyConfig.required_claims.map((claim) => {
    if (names.has(claim.claim_name)) {
      throw new TemplatePolicyClaimsError('templateDuplicateClaim', `Request “${claim.claim_name}” only once in this policy.`, { claimName: claim.claim_name });
    }
    names.add(claim.claim_name);
    const original = originals.get(claim.claim_name);
    if (!original) {
      throw new TemplatePolicyClaimsError('templateUnknownClaim', `“${claim.claim_name}” is not a claim in the selected credential template. Select a template claim or start a new Custom Policy.`, { claimName: claim.claim_name });
    }

    const initialValue = requiredValue(initialClaims.get(claim.claim_name));
    const value = requiredValue(claim);
    // Replace only the equality represented by the editable required-value field.
    // Other constraints remain part of the selected template's restriction.
    const isEditableEquality = (constraint) => initialValue !== null
      && constraint.claim_name === claim.claim_name && constraint.constraint_type === 'equals'
      && sameValue(constraint.value, initialValue);
    const originalConstraints = (original.constraints || []).map(withoutId);
    const existingEquals = originalConstraints.filter((constraint) => !isEditableEquality(constraint)
      && constraint.claim_name === claim.claim_name && constraint.constraint_type === 'equals');
    if (value !== null && existingEquals.some((constraint) => !sameValue(constraint.value, value))) {
      throw new TemplatePolicyClaimsError('templateValueConflict', `The required value for “${claim.claim_name}” conflicts with a constraint from the selected template.`, { claimName: claim.claim_name });
    }
    const constraints = originalConstraints.flatMap((constraint) => isEditableEquality(constraint)
      ? (value === null ? [] : [{ ...constraint, value }]) : [constraint]);
    if (value !== null && !constraints.some((constraint) => constraint.claim_name === claim.claim_name
      && constraint.constraint_type === 'equals' && sameValue(constraint.value, value))) {
      constraints.push({ claim_name: claim.claim_name, constraint_type: 'equals', value });
    }
    return {
      ...withoutId(original),
      accept_derived: typeof claim.accept_predicate === 'boolean' ? claim.accept_predicate : (original.accept_derived ?? true),
      ...(Object.prototype.hasOwnProperty.call(claim, 'predicate_spec') ? { predicate_spec: claim.predicate_spec } : {}),
      constraints,
    };
  });

  return [{
    ...withoutId(requirement),
    trust_profile_id: requirement.trust_profile_id || selectedTrustProfile?.id,
    requested_claims: requestedClaims,
  }];
}
