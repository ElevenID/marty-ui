// Claim definitions only. The issuance owner validates values and assembles the
// signed Open Badges credential; the wizard never supplies achievement evidence.
// These flat aliases match the stock credential-template catalogue and native
// issuance input. Custom templates can also use the canonical achievement object.
export const OPEN_BADGE_CLAIM_PRESET = Object.freeze([
  Object.freeze({ name: 'achievement_name', type: 'string', required: true }),
  Object.freeze({ name: 'achievement_description', type: 'string', required: false }),
  Object.freeze({ name: 'achievement_criteria', type: 'object', required: true }),
]);

export function isOpenBadgeTemplate(data) {
  const type = String(data?.credential_type || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  return ['openbadge', 'openbadgev3', 'openbadgecredential'].includes(type);
}

export function openBadgeClaimSchemaIssue(data) {
  if (!isOpenBadgeTemplate(data)) return null;
  const claims = Array.isArray(data.claims) ? data.claims : [];
  const achievement = claims.find((claim) => claim.name === 'achievement');
  const flatCriteria = claims.find((claim) => claim.name === 'achievement_criteria');
  const criteriaSources = [achievement, flatCriteria].filter(Boolean);
  if (!criteriaSources.length) return 'missingCriteria';
  // A schema-level achievement object does not tell us whether its eventual
  // value contains criteria. Native issuance owns nested-value/alias validation.
  if (!criteriaSources.some((claim) => String(claim.claim_type || claim.type || '').toLowerCase() === 'object')) return 'criteriaObject';
  return null;
}

export function validCredentialTemplateClaims(data) {
  return Array.isArray(data?.claims) && data.claims.length > 0 && !openBadgeClaimSchemaIssue(data);
}
