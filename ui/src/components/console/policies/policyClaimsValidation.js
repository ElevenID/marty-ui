export const hasClaimName = (claim) => (
  typeof claim?.claim_name === 'string' && claim.claim_name.trim() !== ''
);

export const hasAcceptedClaimType = (claim, acceptedTypes = []) => (
  typeof claim?.credential_type === 'string'
  && claim.credential_type.trim() !== ''
  && acceptedTypes.includes(claim.credential_type)
);

export function isClaimsConfigurationComplete(config = {}) {
  const acceptedTypes = config.accepted_credential_types;
  return typeof config.name === 'string' && config.name.trim() !== ''
    && typeof config.purpose === 'string' && config.purpose.trim() !== ''
    && Array.isArray(acceptedTypes) && acceptedTypes.length > 0
    && acceptedTypes.every((type) => typeof type === 'string' && type.trim() !== '')
    && Array.isArray(config.required_claims) && config.required_claims.length > 0
    && config.required_claims.every((claim) => hasClaimName(claim) && hasAcceptedClaimType(claim, acceptedTypes));
}
