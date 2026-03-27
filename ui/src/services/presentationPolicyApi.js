/**
 * Presentation Policy API Service
 * 
 * Provides CRUD operations for Presentation Policies, Credential Templates, and Trust Profiles.
 * Each resource type is now managed by its own dedicated service.
 */

import { get, post, patch, del } from './api';

// Each resource type has its own service
const PRESENTATION_POLICY_BASE = '/v1/presentation-policies';
const CREDENTIAL_TEMPLATE_BASE = '/v1/credential-templates';
const TRUST_PROFILE_BASE = '/v1/trust-profiles';

const TRUST_PROFILE_FORMAT_ALIASES = {
  jwt_vc: 'VC_JWT',
  vc_jwt: 'VC_JWT',
  sd_jwt_vc: 'SD_JWT_VC',
  mdoc: 'MDOC',
  ldp_vc: 'JSON_LD',
  json_ld: 'JSON_LD',
};

const TRUST_SOURCE_TYPE_ALIASES = {
  registry: 'TRUST_LIST',
  trust_list: 'TRUST_LIST',
  allowlist: 'PINNED_ISSUER',
  pinned_issuer: 'PINNED_ISSUER',
  pinned_root: 'ROOT_CA',
  root_ca: 'ROOT_CA',
  pkd: 'PKD_URL',
  pkd_url: 'PKD_URL',
};

const SECONDS_PER_DAY = 86400;

function normalizeTrustProfileFormat(format) {
  if (!format) {
    return format;
  }

  const normalized = String(format).trim();
  return TRUST_PROFILE_FORMAT_ALIASES[normalized.toLowerCase()] || normalized.toUpperCase();
}

function normalizeTrustSourceType(sourceType) {
  if (!sourceType) {
    return 'TRUST_LIST';
  }

  const normalized = String(sourceType).trim();
  return TRUST_SOURCE_TYPE_ALIASES[normalized.toLowerCase()] || normalized.toUpperCase();
}

function normalizeTrustProfileType(profileType) {
  if (!profileType) {
    return 'CUSTOM';
  }

  return String(profileType).trim().toUpperCase();
}

function normalizeTrustedIssuer(issuer = {}) {
  return {
    ...issuer,
    did: issuer.did || issuer.issuer_did || issuer.issuer_id || '',
    issuer_did: issuer.issuer_did || issuer.did || issuer.issuer_id || '',
    country: issuer.country || issuer.metadata?.country || '—',
  };
}

function trustSourcesFromTrustedIssuers(trustedIssuers = []) {
  return trustedIssuers
    .map((issuer) => normalizeTrustedIssuer(issuer))
    .filter((issuer) => issuer.issuer_did)
    .map((issuer) => ({
      name: issuer.name || issuer.issuer_did,
      description: issuer.description || null,
      issuer_did: issuer.issuer_did,
      source_type: 'PINNED_ISSUER',
      enabled: issuer.enabled !== false,
    }));
}

function normalizeValidationRules(data = {}) {
  const rules = data.validation_rules || {};
  const minKeySize = rules.min_key_size ?? data.min_key_size ?? data.min_key_size_rsa ?? 2048;

  return {
    allowed_algorithms: data.allowed_algorithms || rules.allowed_algorithms || ['ES256', 'ES384', 'EdDSA'],
    min_key_size_rsa: data.min_key_size_rsa ?? rules.min_key_size_rsa ?? minKeySize,
    min_key_size_ec: data.min_key_size_ec ?? rules.min_key_size_ec ?? 256,
    require_key_usage: data.require_key_usage ?? rules.require_key_usage ?? true,
    max_chain_depth: data.max_chain_depth ?? rules.max_chain_depth ?? 5,
    allow_self_signed: data.allow_self_signed ?? rules.allow_self_signed ?? false,
  };
}

function buildTrustProfilePayload(data = {}) {
  const {
    framework_type,
    trusted_issuers,
    activate_immediately,
    min_key_size,
    required_credential_types,
    revocation_check_enabled,
    signature_validation_required,
    trust_anchors,
    status,
    ...rest
  } = data;

  const validation_rules = normalizeValidationRules(data);
  const trust_sources = Array.isArray(rest.trust_sources) && rest.trust_sources.length > 0
    ? rest.trust_sources.map((source) => ({
        ...source,
        source_type: normalizeTrustSourceType(source.source_type),
      }))
    : trustSourcesFromTrustedIssuers(trusted_issuers || []);

  return {
    ...rest,
    profile_type: normalizeTrustProfileType(rest.profile_type || framework_type || 'custom'),
    supported_formats: (rest.supported_formats || ['sd_jwt_vc', 'mdoc']).map(normalizeTrustProfileFormat),
    trust_sources,
    validation_rules,
    allowed_algorithms: validation_rules.allowed_algorithms,
    min_key_size_rsa: validation_rules.min_key_size_rsa,
    min_key_size_ec: validation_rules.min_key_size_ec,
    require_key_usage: validation_rules.require_key_usage,
    max_chain_depth: validation_rules.max_chain_depth,
    allow_self_signed: validation_rules.allow_self_signed,
  };
}

function normalizeTrustProfile(data = {}) {
  const trust_sources = Array.isArray(data.trust_sources) ? data.trust_sources : [];
  const trusted_issuers = Array.isArray(data.trusted_issuers) && data.trusted_issuers.length > 0
    ? data.trusted_issuers.map((issuer) => normalizeTrustedIssuer(issuer))
    : trust_sources
        .filter((source) => normalizeTrustSourceType(source.source_type) === 'PINNED_ISSUER' && source.issuer_did)
        .map((source) => normalizeTrustedIssuer({
          id: source.id,
          name: source.name || source.issuer_did,
          description: source.description,
          did: source.issuer_did,
          issuer_did: source.issuer_did,
          status: source.enabled === false ? 'inactive' : 'active',
        }));

  const validationRules = data.validation_rules || {
    allowed_algorithms: data.allowed_algorithms || [],
    min_key_size_rsa: data.min_key_size_rsa,
    min_key_size_ec: data.min_key_size_ec,
    require_key_usage: data.require_key_usage,
    max_chain_depth: data.max_chain_depth,
    allow_self_signed: data.allow_self_signed,
  };

  return {
    ...data,
    trust_sources,
    trusted_issuers,
    framework: (data.profile_type || data.framework || 'custom').toLowerCase(),
    trustedIssuers: trusted_issuers.length,
    validationRules: validationRules.allowed_algorithms?.length || 0,
    trust_anchors: trust_sources,
    revocation_strategy: data.revocation_policy?.check_mode || data.revocation_strategy || 'HARD_FAIL',
    createdAt: data.created_at || data.createdAt,
    updatedAt: data.updated_at || data.updatedAt,
  };
}

function daysFromSeconds(seconds) {
  if (seconds == null) {
    return undefined;
  }

  return Math.max(1, Math.ceil(Number(seconds) / SECONDS_PER_DAY));
}

export function normalizeCredentialTemplateValidityRules(rules = {}) {
  const ttlSeconds = rules.ttl_seconds
    ?? (rules.default_validity_days != null ? Number(rules.default_validity_days) * SECONDS_PER_DAY : undefined);
  const reissueWithinSeconds = rules.reissue_within_seconds
    ?? (rules.renewal_window_days != null ? Number(rules.renewal_window_days) * SECONDS_PER_DAY : undefined);
  const notBeforeOffsetSeconds = rules.not_before_offset_seconds
    ?? rules.not_before_offset
    ?? 0;
  const maxValiditySeconds = rules.max_validity_seconds
    ?? (rules.max_validity_days != null ? Number(rules.max_validity_days) * SECONDS_PER_DAY : undefined);

  return {
    ...rules,
    ...(ttlSeconds != null ? { ttl_seconds: ttlSeconds, default_validity_days: daysFromSeconds(ttlSeconds) } : {}),
    ...(reissueWithinSeconds != null
      ? {
          reissue_within_seconds: reissueWithinSeconds,
          renewal_window_days: daysFromSeconds(reissueWithinSeconds),
        }
      : {}),
    not_before_offset_seconds: notBeforeOffsetSeconds,
    not_before_offset: notBeforeOffsetSeconds,
    ...(maxValiditySeconds != null
      ? {
          max_validity_seconds: maxValiditySeconds,
          max_validity_days: daysFromSeconds(maxValiditySeconds),
        }
      : {}),
  };
}

export function normalizeCredentialTemplate(data = {}) {
  const claims = Array.isArray(data.claims)
    ? data.claims.map((claim) => ({
        ...claim,
        display_name: claim.display_name || claim.display?.label || claim.name,
      }))
    : [];

  return {
    ...data,
    status: data.status ? String(data.status).toLowerCase() : data.status,
    claims,
    validity_rules: normalizeCredentialTemplateValidityRules(data.validity_rules || {}),
    createdAt: data.created_at || data.createdAt,
    updatedAt: data.updated_at || data.updatedAt,
  };
}

export function buildCredentialTemplatePayload(data = {}) {
  const validityRules = data.validity_rules
    ? normalizeCredentialTemplateValidityRules(data.validity_rules)
    : undefined;

  return {
    ...data,
    ...(validityRules
      ? {
          validity_rules: {
            default_validity_days: validityRules.default_validity_days,
            max_validity_days: validityRules.max_validity_days,
            renewable: validityRules.renewable ?? true,
            renewal_window_days: validityRules.renewal_window_days,
            not_before_offset_seconds: validityRules.not_before_offset_seconds,
          },
        }
      : {}),
  };
}

/**
 * Create a new presentation policy
 */
export async function createPresentationPolicy(data) {
  return post(PRESENTATION_POLICY_BASE, data);
}

/**
 * List all presentation policies
 * @param {Object} params - Query parameters (organization_id, etc.)
 */
export async function listPresentationPolicies(params = {}) {
  return get(PRESENTATION_POLICY_BASE, { params });
}

/**
 * Get a specific presentation policy by ID
 */
export async function getPresentationPolicy(id) {
  return get(`${PRESENTATION_POLICY_BASE}/${id}`);
}

/**
 * Update a presentation policy
 */
export async function updatePresentationPolicy(id, data) {
  return patch(`${PRESENTATION_POLICY_BASE}/${id}`, data);
}

/**
 * Delete a presentation policy
 */
export async function deletePresentationPolicy(id) {
  return del(`${PRESENTATION_POLICY_BASE}/${id}`);
}

/**
 * Create a new credential template
 */
export async function createCredentialTemplate(data) {
  const result = await post(CREDENTIAL_TEMPLATE_BASE, buildCredentialTemplatePayload(data));
  return normalizeCredentialTemplate(result);
}

/**
 * List credential templates (for claim name autocomplete)
 */
export async function listCredentialTemplates(params = {}) {
  const result = await get(CREDENTIAL_TEMPLATE_BASE, { params });
  return Array.isArray(result) ? result.map((template) => normalizeCredentialTemplate(template)) : result;
}

/**
 * Get a specific credential template by ID
 */
export async function getCredentialTemplate(id) {
  const result = await get(`${CREDENTIAL_TEMPLATE_BASE}/${id}`);
  return normalizeCredentialTemplate(result);
}

/**
 * Update a credential template
 */
export async function updateCredentialTemplate(id, data) {
  const result = await patch(`${CREDENTIAL_TEMPLATE_BASE}/${id}`, buildCredentialTemplatePayload(data));
  return normalizeCredentialTemplate(result);
}

/**
 * Delete a credential template
 */
export async function deleteCredentialTemplate(id) {
  return del(`${CREDENTIAL_TEMPLATE_BASE}/${id}`);
}

/**
 * Create a new trust profile
 */
export async function createTrustProfile(data) {
  const result = await post(TRUST_PROFILE_BASE, buildTrustProfilePayload(data));
  return normalizeTrustProfile(result);
}

/**
 * List organization trust profiles
 */
export async function listTrustProfiles(params = {}) {
  const result = await get(TRUST_PROFILE_BASE, { params });
  return Array.isArray(result) ? result.map((profile) => normalizeTrustProfile(profile)) : result;
}

/**
 * Get a specific trust profile by ID
 */
export async function getTrustProfile(id) {
  const result = await get(`${TRUST_PROFILE_BASE}/${id}`);
  return normalizeTrustProfile(result);
}

/**
 * Update a trust profile
 */
export async function updateTrustProfile(id, data) {
  const result = await patch(`${TRUST_PROFILE_BASE}/${id}`, buildTrustProfilePayload(data));
  return normalizeTrustProfile(result);
}

/**
 * Delete a trust profile
 */
export async function deleteTrustProfile(id) {
  return del(`${TRUST_PROFILE_BASE}/${id}`);
}

/**
 * List trusted issuers for a trust profile.
 */
export async function listTrustProfileIssuers(profileId) {
  const result = await get(`${TRUST_PROFILE_BASE}/${profileId}/issuers`);
  return Array.isArray(result) ? result.map((issuer) => normalizeTrustedIssuer(issuer)) : result;
}

/**
 * Add a trusted issuer to a trust profile.
 */
export async function addTrustProfileIssuer(profileId, data) {
  const result = await post(`${TRUST_PROFILE_BASE}/${profileId}/issuers`, data);
  return normalizeTrustedIssuer(result);
}

/**
 * Get wallet compatibility for a trust profile
 * @param {string} id - Trust profile ID
 * @returns {Promise<Object>} Wallet compatibility data
 */
export async function getTrustProfileWalletCompatibility(id) {
  return get(`${TRUST_PROFILE_BASE}/${id}/wallet-compatibility`);
}

