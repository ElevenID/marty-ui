/**
 * Presentation Policy API Service
 * 
 * Provides CRUD operations for Presentation Policies, Credential Templates, and Trust Profiles.
 * Each resource type is now managed by its own dedicated service.
 */

import { get, getWithRetryConfig, post, patch, del } from './api';
import { isNetworkAbortLikeError, postWithIdempotency } from './idempotency';

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

const HOLDER_BINDING_PAYLOADS = {
  none: { required: false, binding_methods: [], nonce_required: false },
  device_key: { required: true, binding_methods: ['DEVICE_KEY'], nonce_required: false },
  session_nonce: { required: true, binding_methods: ['NONCE'], nonce_required: true },
  biometric: { required: true, binding_methods: ['BIOMETRIC'], nonce_required: false },
};

function resolveOrganizationId(params = {}) {
  if (typeof params === 'string') {
    return params;
  }

  if (params?.organization_id) {
    return params.organization_id;
  }

  return null;
}

function isMissingOrganizationId(organizationId) {
  return organizationId == null
    || String(organizationId).trim() === ''
    || String(organizationId).trim().toLowerCase() === 'null'
    || String(organizationId).trim().toLowerCase() === 'undefined';
}

export function requireOrganizationId(params = {}) {
  const organizationId = resolveOrganizationId(params);
  if (isMissingOrganizationId(organizationId)) {
    const error = new Error('An active organization is required before loading org-scoped credential setup artifacts.');
    error.code = 'ORG_REQUIRED';
    error.status = 400;
    throw error;
  }
  return String(organizationId).trim();
}

function requireDirectArray(value, resourceName) {
  if (!Array.isArray(value)) {
    const error = new Error(`${resourceName} service returned a malformed list response.`);
    error.code = 'MALFORMED_RESPONSE';
    throw error;
  }
  return value;
}

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

function normalizeRegistryImport(entry = {}) {
  return {
    ...entry,
    sync_enabled: entry.sync_enabled !== false,
    sync_interval_hours: Number(entry.sync_interval_hours ?? 24),
    credential_format_filter: Array.isArray(entry.credential_format_filter) ? entry.credential_format_filter : [],
  };
}

function buildTrustProfilePayload(data = {}) {
  const {
    framework_type,
    trusted_issuers,
    allow_all_issuers,
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
  const registry_imports = Array.isArray(rest.registry_imports)
    ? rest.registry_imports.map((entry) => normalizeRegistryImport(entry))
    : [];

  return {
    ...rest,
    profile_type: normalizeTrustProfileType(rest.profile_type || framework_type || 'custom'),
    supported_formats: (rest.supported_formats || ['sd_jwt_vc', 'mdoc']).map(normalizeTrustProfileFormat),
    trust_sources,
    registry_imports,
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
    status: data.status ? String(data.status).toLowerCase() : data.status,
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
  const artifactsStatus = data.artifacts_status
    || data.artifact_status
    || (data.hasArtifacts === false
      ? 'missing'
      : (data.issuer_key_id || data.issuer_certificate_chain_pem || data.remote_signing_config || data.auto_generate_artifacts)
        ? 'valid'
        : (data.issuer_did ? 'invalid' : 'missing'));
  const hasArtifacts = data.hasArtifacts ?? artifactsStatus !== 'missing';
  const artifactsValidated = data.artifactsValidated ?? artifactsStatus === 'valid';

  return {
    ...data,
    status: data.status ? String(data.status).toLowerCase() : data.status,
    artifacts_status: artifactsStatus,
    hasArtifacts,
    artifactsValidated,
    usedByFlowsCount: data.usedByFlowsCount ?? data.used_by_flows_count ?? 0,
    claims,
    validity_rules: normalizeCredentialTemplateValidityRules(data.validity_rules || {}),
    createdAt: data.created_at || data.createdAt,
    updatedAt: data.updated_at || data.updatedAt,
  };
}

function humanizeClaimName(name) {
  return String(name || '')
    .split(/[_\s-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ') || 'Claim';
}

function normalizeCredentialTemplateClaimType(claimType) {
  const normalized = String(claimType || 'string').trim().toLowerCase();
  if (normalized === 'number') {
    return 'integer';
  }
  return normalized || 'string';
}

function normalizeCredentialTemplateClaim(claim = {}) {
  const { type, display, ...rest } = claim;
  const claimType = normalizeCredentialTemplateClaimType(claim.claim_type || type);

  return {
    ...rest,
    display_name: claim.display_name || display?.label || humanizeClaimName(claim.name),
    claim_type: claimType,
    required: claim.required !== false,
    selectively_disclosable: claim.selectively_disclosable !== false,
  };
}

function normalizeHolderBindingPayload(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return {
      required: Boolean(value.required),
      binding_methods: Array.isArray(value.binding_methods)
        ? value.binding_methods.filter((method) => typeof method === 'string' && method.trim())
        : [],
      nonce_required: Boolean(value.nonce_required),
    };
  }

  const normalized = String(value || 'none').trim().toLowerCase();
  return HOLDER_BINDING_PAYLOADS[normalized] || HOLDER_BINDING_PAYLOADS.device_key;
}

function normalizeFreshnessPayload(data = {}) {
  const source = data.freshness && typeof data.freshness === 'object'
    ? data.freshness
    : (data.freshness_requirements && typeof data.freshness_requirements === 'object'
      ? data.freshness_requirements
      : null);

  if (!source) {
    return undefined;
  }

  const maxAgeSeconds = source.max_age_seconds ?? source.max_credential_age_seconds;
  const revocationGraceSeconds = source.revocation_grace_seconds ?? source.revocation_grace_period_seconds;
  const freshness = {
    require_not_revoked: Boolean(source.require_not_revoked ?? source.require_revocation_check),
  };

  if (Number.isFinite(Number(maxAgeSeconds))) {
    freshness.max_age_seconds = Number(maxAgeSeconds);
  }

  if (Number.isFinite(Number(revocationGraceSeconds))) {
    freshness.revocation_grace_seconds = Number(revocationGraceSeconds);
  }

  return freshness;
}

function normalizePresentationPolicyClaim(claim = {}) {
  const valueConstraint = claim.value_constraint ?? claim.required_value;
  return {
    claim_name: claim.claim_name || claim.name || '',
    credential_type: claim.credential_type || null,
    value_constraint: valueConstraint === '' ? null : valueConstraint,
    predicate_spec: claim.predicate_spec || null,
  };
}

function normalizePresentationPolicy(data = {}) {
  return {
    ...data,
    status: data.status ? String(data.status).toLowerCase() : data.status,
    createdAt: data.created_at || data.createdAt,
    updatedAt: data.updated_at || data.updatedAt,
  };
}

export function buildPresentationPolicyPayload(data = {}) {
  const organizationId = requireOrganizationId(data);
  const {
    activate_immediately,
    status,
    holder_binding,
    freshness_requirements,
    single_presentation,
    template_id,
    metadata,
    ...rest
  } = data;
  const displayMetadata = rest.display_metadata
    || (metadata && typeof metadata === 'object'
      ? {
          title: rest.name || '',
          description: rest.description || '',
          purpose: 'identity_verification',
          purpose_description: rest.purpose || '',
        }
      : undefined);

  return {
    ...rest,
    organization_id: organizationId,
    required_claims: Array.isArray(rest.required_claims)
      ? rest.required_claims
          .map((claim) => normalizePresentationPolicyClaim(claim))
          .filter((claim) => claim.claim_name)
      : [],
    accepted_credential_types: Array.isArray(rest.accepted_credential_types)
      ? rest.accepted_credential_types.filter((type) => typeof type === 'string' && type.trim())
      : [],
    holder_binding: normalizeHolderBindingPayload(holder_binding),
    freshness: normalizeFreshnessPayload({ ...data, freshness_requirements }),
    ...(displayMetadata ? { display_metadata: displayMetadata } : {}),
  };
}

function inferCredentialFormat(data = {}) {
  const explicitFormat = data.credential_payload_format
    || (Array.isArray(data.supported_formats) && data.supported_formats.length > 0 ? data.supported_formats[0] : null)
    || 'sd_jwt_vc';
  const normalized = String(explicitFormat).trim().toLowerCase();

  if (normalized.includes('mdoc')) {
    return 'mdoc';
  }
  if (normalized.includes('sd_jwt') || normalized.includes('sd-jwt') || normalized.includes('vc+sd-jwt')) {
    return 'sd_jwt_vc';
  }
  if (normalized.includes('jwt_vc') || normalized.includes('jwt-vc')) {
    return 'jwt_vc';
  }
  return 'sd_jwt_vc';
}

function normalizeCredentialTemplateVct(data = {}) {
  const vct = String(data.vct || '').trim();
  if (!vct || vct.includes('://') || inferCredentialFormat(data) === 'mdoc') {
    return vct;
  }

  return `https://credentials.elevenidllc.com/vct/${vct}`;
}

function normalizeCredentialTemplateComplianceProfile(data = {}) {
  if (data.compliance_profile_id || data.compliance_profile?.compliance_code || data.compliance_profile?.code) {
    return data.compliance_profile;
  }

  return {
    ...(data.compliance_profile || {}),
    compliance_code: 'CUSTOM',
    credential_format: inferCredentialFormat(data),
  };
}

function isActiveResource(resource) {
  return String(resource?.status || '').toLowerCase() === 'active';
}

export function buildCredentialTemplatePayload(data = {}) {
  const issuerProfileId = String(data.issuer_profile_id || '').trim();
  if (!issuerProfileId) {
    const error = new Error('An active issuer profile is required before creating a credential template.');
    error.code = 'ISSUER_PROFILE_REQUIRED';
    error.status = 400;
    throw error;
  }

  const validityRules = data.validity_rules
    ? normalizeCredentialTemplateValidityRules(data.validity_rules)
    : undefined;
  const claims = Array.isArray(data.claims)
    ? data.claims.map((claim) => normalizeCredentialTemplateClaim(claim))
    : [];

  return {
    ...data,
    issuer_profile_id: issuerProfileId,
    vct: normalizeCredentialTemplateVct(data),
    claims,
    compliance_profile: normalizeCredentialTemplateComplianceProfile(data),
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
  const payload = buildPresentationPolicyPayload(data);
  const shouldActivate = data?.activate_immediately === true || String(data?.status || '').toLowerCase() === 'active';
  let result = await postWithIdempotency(PRESENTATION_POLICY_BASE, payload);

  if (shouldActivate && result?.id) {
    result = await activatePresentationPolicy(result.id);
  }

  return normalizePresentationPolicy(result);
}

/**
 * List all presentation policies
 * @param {Object} params - Query parameters (organization_id, etc.)
 */
export async function listPresentationPolicies(params = {}) {
  const normalizedParams = typeof params === 'string'
    ? { organization_id: params }
    : (params || {});
  const organizationId = requireOrganizationId(normalizedParams);
  const result = await get(PRESENTATION_POLICY_BASE, {
    params: {
      ...normalizedParams,
      organization_id: organizationId,
    },
  });
  return requireDirectArray(result, 'Presentation Policy').map(normalizePresentationPolicy);
}

/**
 * Get a specific presentation policy by ID
 */
export async function getPresentationPolicy(id) {
  const result = await get(`${PRESENTATION_POLICY_BASE}/${id}`);
  return normalizePresentationPolicy(result);
}

/**
 * Update a presentation policy
 */
export async function updatePresentationPolicy(id, data) {
  const result = await patch(`${PRESENTATION_POLICY_BASE}/${id}`, buildPresentationPolicyPayload(data));
  return normalizePresentationPolicy(result);
}

/**
 * Delete a presentation policy
 */
export async function deletePresentationPolicy(id) {
  return del(`${PRESENTATION_POLICY_BASE}/${id}`);
}

/**
 * Activate a presentation policy.
 */
export async function activatePresentationPolicy(id) {
  try {
    const result = await post(`${PRESENTATION_POLICY_BASE}/${id}/activate`, {});
    return normalizePresentationPolicy(result);
  } catch (error) {
    if (!isNetworkAbortLikeError(error)) {
      throw error;
    }

    const current = await getPresentationPolicy(id);
    if (isActiveResource(current)) {
      return current;
    }
    throw error;
  }
}

/**
 * Create a new credential template
 */
export async function createCredentialTemplate(data) {
  const organizationId = requireOrganizationId(data);
  const shouldActivate = data?.activate_immediately === true || String(data?.status || '').toLowerCase() === 'active';
  const payload = buildCredentialTemplatePayload({
    ...data,
    organization_id: organizationId,
  });
  let result = await postWithIdempotency(CREDENTIAL_TEMPLATE_BASE, payload);
  if (shouldActivate && result?.id) {
    result = await activateCredentialTemplate(result.id);
  }
  return normalizeCredentialTemplate(result);
}

/**
 * Activate a credential template.
 */
export async function activateCredentialTemplate(id) {
  try {
    const result = await post(`${CREDENTIAL_TEMPLATE_BASE}/${id}/activate`, {});
    return normalizeCredentialTemplate(result);
  } catch (error) {
    if (!isNetworkAbortLikeError(error)) {
      throw error;
    }

    const current = await getCredentialTemplate(id);
    if (isActiveResource(current)) {
      return current;
    }
    throw error;
  }
}

/**
 * List credential templates (for claim name autocomplete)
 */
export async function listCredentialTemplates(params = {}) {
  const normalizedParams = typeof params === 'string'
    ? { organization_id: params }
    : (params || {});
  const organizationId = requireOrganizationId(normalizedParams);
  const result = await get(CREDENTIAL_TEMPLATE_BASE, {
    params: {
      ...normalizedParams,
      organization_id: organizationId,
    },
  });
  return requireDirectArray(result, 'Credential Template').map(normalizeCredentialTemplate);
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
  const organizationId = requireOrganizationId(data);
  const payload = buildTrustProfilePayload({
    ...data,
    organization_id: organizationId,
  });
  const result = await postWithIdempotency(TRUST_PROFILE_BASE, payload);
  return normalizeTrustProfile(result);
}

/**
 * Activate a trust profile.
 */
export async function activateTrustProfile(id) {
  try {
    const result = await post(`${TRUST_PROFILE_BASE}/${id}/activate`, {});
    return normalizeTrustProfile(result);
  } catch (error) {
    if (!isNetworkAbortLikeError(error)) {
      throw error;
    }

    const current = await getTrustProfile(id);
    if (isActiveResource(current)) {
      return current;
    }
    throw error;
  }
}

/**
 * List organization trust profiles
 */
export async function listTrustProfiles(params = {}) {
  const normalizedParams = typeof params === 'string'
    ? { organization_id: params }
    : (params || {});
  const organizationId = requireOrganizationId(normalizedParams);
  const result = await get(TRUST_PROFILE_BASE, {
    params: {
      ...normalizedParams,
      organization_id: organizationId,
    },
  });
  return requireDirectArray(result, 'Trust Profile').map(normalizeTrustProfile);
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

// ── Revocation Profile API ────────────────────────────────────────────────

const REVOCATION_PROFILE_BASE = '/v1/revocation-profiles';

/**
 * Create a revocation profile.
 * @param {Object} data - Profile data
 * @returns {Promise<Object>}
 */
export async function createRevocationProfile(data) {
  const organizationId = requireOrganizationId(data);
  return postWithIdempotency(REVOCATION_PROFILE_BASE, {
    ...data,
    organization_id: organizationId,
  });
}

/**
 * List revocation profiles for an organization.
 * @param {Object} params - Query parameters (organization_id required)
 * @returns {Promise<Array>}
 */
export async function listRevocationProfiles(params = {}, options = {}) {
  const normalizedParams = typeof params === 'string'
    ? { organization_id: params }
    : (params || {});
  const organizationId = requireOrganizationId(normalizedParams);
  const retryConfig = options.retryConfig;
  const request = retryConfig
    ? getWithRetryConfig(REVOCATION_PROFILE_BASE, {
        params: {
          ...normalizedParams,
          organization_id: organizationId,
        },
      }, retryConfig)
    : get(REVOCATION_PROFILE_BASE, {
        params: {
          ...normalizedParams,
          organization_id: organizationId,
        },
      });
  const result = await request;
  return Array.isArray(result) ? result : (result?.items ?? []);
}

/**
 * Get a revocation profile by ID.
 * @param {string} id
 * @returns {Promise<Object>}
 */
export async function getRevocationProfile(id) {
  return get(`${REVOCATION_PROFILE_BASE}/${id}`);
}

