/**
 * Presentation Policy API Service
 * 
 * Provides CRUD operations for Presentation Policies, Credential Templates, and Trust Profiles.
 * Each resource type is now managed by its own dedicated service.
 */

import { get, getWithRetryConfig, post, patch, del } from './api';
import { isNetworkAbortLikeError, postWithIdempotency } from './idempotency';
import { requireOrganizationId as requireScopedOrganizationId } from './queryUtils';

// Each resource type has its own service
const PRESENTATION_POLICY_BASE = '/v1/presentation-policies';
const CREDENTIAL_TEMPLATE_BASE = '/v1/credential-templates';
const TRUST_PROFILE_BASE = '/v1/trust-profiles';
const ISSUER_ENTITY_BASE = '/v1/issuer-entities';

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
  none: { required: false },
  credential_key: {
    required: true,
    binding_methods: ['CREDENTIAL_KEY'],
    proof_profiles: ['SD_JWT_KEY_BINDING'],
    proof_freshness: { challenge_required: true, audience_binding_required: true, replay_detection_required: true },
  },
  device_key: {
    required: true,
    binding_methods: ['DEVICE_KEY'],
    proof_profiles: ['OID4VP_VERIFIABLE_PRESENTATION', 'MDOC_DEVICE_AUTHENTICATION'],
    proof_freshness: { challenge_required: true, audience_binding_required: true, replay_detection_required: true },
  },
  session_binding: {
    required: true,
    binding_methods: ['SESSION_BINDING'],
    proof_profiles: ['OID4VP_VERIFIABLE_PRESENTATION'],
    proof_freshness: { challenge_required: true, audience_binding_required: true, replay_detection_required: true },
  },
};

export function requireOrganizationId(params = {}) {
  return requireScopedOrganizationId(typeof params === 'string' ? params : params?.organization_id || null, undefined, 'An active organization is required before loading org-scoped credential setup artifacts.');
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
    did: issuer.did || issuer.issuer_did || '',
    issuer_did: issuer.issuer_did || issuer.did || '',
    country: issuer.country || issuer.metadata?.country || '—',
  };
}

function malformedTrustIssuer(message) {
  const error = new Error(message);
  error.code = 'MALFORMED_RESPONSE';
  return error;
}

const hasIssuerIdentifier = (value) => typeof value === 'string' && value.trim().length > 0;

function linkableIssuer(entity, organizationId) {
  return entity?.organization_id === organizationId
    || (entity?.organization_id == null && entity?.is_system_issuer === true);
}

function requireIssuerEntity(entity, organizationId, expectedDid, created = false) {
  if (!hasIssuerIdentifier(entity?.id) || !hasIssuerIdentifier(entity?.issuer_id)
    || !linkableIssuer(entity, organizationId)
    || (created && entity.organization_id !== organizationId)
    || (expectedDid !== undefined && entity.issuer_id !== expectedDid)) {
    throw malformedTrustIssuer('Issuer Entity response does not match the requested identity and organization scope.');
  }
  return entity;
}

function issuerEntitiesById(entities) {
  const result = new Map();
  for (const entity of requireDirectArray(entities, 'Issuer Entity')) {
    if (!hasIssuerIdentifier(entity?.id) || result.has(entity.id)) {
      throw malformedTrustIssuer('Issuer Entity inventory contains a missing or duplicate identity.');
    }
    result.set(entity.id, entity);
  }
  return result;
}

/** The optional callback guards every dispatch and settlement, including rejection.
 * It does not cancel or roll back a request that was already dispatched.
 */
function requireCurrentTrustIssuer({ isCurrent } = {}) {
  if (isCurrent !== undefined && !isCurrent()) {
    const error = new Error('The trust profile view or action changed.');
    error.name = 'AbortError';
    throw error;
  }
}

async function runTrustIssuerRequest(operation, options) {
  requireCurrentTrustIssuer(options);
  try {
    return await operation();
  } finally {
    requireCurrentTrustIssuer(options);
  }
}

function composeTrustProfileIssuer(relationship, issuerEntity, profileId, organizationId) {
  requireIssuerEntity(issuerEntity, organizationId);
  if (!hasIssuerIdentifier(relationship?.id) || relationship.trust_profile_id !== profileId
    || relationship.issuer_id !== issuerEntity.id) {
    throw malformedTrustIssuer('Trust Profile Issuer response does not match the requested profile and issuer identity.');
  }

  return {
    ...relationship,
    issuer_entity: issuerEntity,
    name: issuerEntity.display_name,
    description: issuerEntity.description || null,
    did: issuerEntity.issuer_id,
    issuer_did: issuerEntity.issuer_id,
    issuer_type: issuerEntity.issuer_type,
    issuer_url: issuerEntity.metadata?.issuer_url || null,
    // Keep this legacy alias for existing callers. Relationship trust is the
    // separate native relationship_status field, never issuer compliance.
    status: issuerEntity.compliance_status,
    compliance_status: issuerEntity.compliance_status,
    accreditation_body: issuerEntity.accreditation_body || null,
    accreditations: Array.isArray(issuerEntity.accreditations) ? issuerEntity.accreditations : [],
    credential_template_ids: relationship.metadata?.credential_template_ids || [],
  };
}

function trustSourcesFromTrustedIssuers(trustedIssuers = []) {
  return trustedIssuers
    .map((issuer) => normalizeTrustedIssuer(issuer))
    .filter((issuer) => issuer.issuer_did)
    .map((issuer) => ({
      description: issuer.description || null,
      issuer_did: issuer.issuer_did,
      source_type: 'PINNED_ISSUER',
      ...Object.fromEntries(['organization_id', 'verification_method_ids', 'did_resolution']
        .filter((field) => issuer[field] !== undefined).map((field) => [field, issuer[field]])),
    }));
}

function normalizePublicTrustSource(source = {}) {
  const normalized = {
    source_type: normalizeTrustSourceType(source.source_type),
  };
  if (['REGISTERED_VERIFIER', 'MANAGED_FLOW_VERIFIER'].includes(normalized.source_type)) {
    const field = normalized.source_type === 'REGISTERED_VERIFIER' ? 'registered_verifier' : 'managed_flow_verifier';
    const other = field === 'registered_verifier' ? 'managed_flow_verifier' : 'registered_verifier';
    const registration = source[field];
    if (!isObject(registration) || Object.hasOwn(source, other)) {
      throw walletInput('Use only the public registration matching the verifier source type.');
    }
    validateWalletPublicKeys([registration.public_jwk], { verifier: true, requestKeyId: registration.request_key_id });
    for (const field of ['id', 'enabled', normalized.source_type === 'REGISTERED_VERIFIER' ? 'registered_verifier' : 'managed_flow_verifier']) {
      if (source[field] !== undefined) normalized[field] = source[field];
    }
  }
  if (source.url) normalized.url = String(source.url).trim();
  if (source.certificate_pem) normalized.certificate_pem = String(source.certificate_pem).trim();
  if (source.issuer_did) normalized.issuer_did = String(source.issuer_did).trim();
  for (const field of ['organization_id', 'verification_method_ids']) {
    if (source[field] !== undefined) normalized[field] = source[field];
  }
  if (source.did_resolution !== undefined) {
    normalized.did_resolution = source.did_resolution === null ? null : Object.fromEntries(
      ['resolver_type', 'allow_public_fallback', 'cache_ttl_seconds']
        .filter((field) => source.did_resolution[field] !== undefined)
        .map((field) => [field, source.did_resolution[field]])
    );
  }
  if (Array.isArray(source.purposes)) normalized.purposes = [...source.purposes];
  if (['REGISTERED_VERIFIER', 'MANAGED_FLOW_VERIFIER'].includes(normalized.source_type)
    && source.description !== undefined) normalized.description = source.description;
  else if (source.description) normalized.description = String(source.description).trim();
  if (source.registry_sync) {
    normalized.registry_sync = {
      protocol: 'MARTY_TRUST_REGISTRY_SYNC_V1',
      refresh_interval_hours: Number(source.registry_sync.refresh_interval_hours ?? 24),
    };
  }
  return normalized;
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
  const validation_rules = normalizeValidationRules(data);
  const trust_purposes = Array.isArray(data.trust_purposes) ? [...data.trust_purposes] : undefined;
  const credentialPurpose = !trust_purposes
    || trust_purposes.includes('CREDENTIAL_ISSUER');
  const supported_formats = Array.isArray(data.supported_formats)
    ? data.supported_formats.map(normalizeTrustProfileFormat)
    : (credentialPurpose ? ['SD_JWT_VC', 'MDOC'] : undefined);
  const trust_sources = Array.isArray(data.trust_sources) && data.trust_sources.length > 0
    ? data.trust_sources.map((source) => normalizePublicTrustSource(source))
    : trustSourcesFromTrustedIssuers(data.trusted_issuers || []);

  return {
    organization_id: data.organization_id,
    name: data.name,
    description: data.description,
    profile_type: normalizeTrustProfileType(data.profile_type || data.framework_type || 'custom'),
    compliance_status: data.compliance_status || 'SETUP_REQUIRED',
    ...(trust_purposes ? { trust_purposes } : {}),
    ...(supported_formats ? { supported_formats } : {}),
    ...(Array.isArray(data.trusted_assertion_formats)
      ? { trusted_assertion_formats: [...data.trusted_assertion_formats] }
      : {}),
    trust_sources,
    validation_rules,
    allowed_algorithms: validation_rules.allowed_algorithms,
    min_key_size_rsa: validation_rules.min_key_size_rsa,
    min_key_size_ec: validation_rules.min_key_size_ec,
    require_key_usage: validation_rules.require_key_usage,
    max_chain_depth: validation_rules.max_chain_depth,
    allow_self_signed: validation_rules.allow_self_signed,
    revocation_policy: data.revocation_policy,
    revocation_profile_id: data.revocation_profile_id,
    time_policy: data.time_policy,
    allowed_issuers: data.allowed_issuers,
    denied_issuers: data.denied_issuers,
    system_issuer_overrides: data.system_issuer_overrides || {},
    compatible_compliance_codes: data.compatible_compliance_codes || [],
    verification_policy_set_id: data.verification_policy_set_id,
    auto_generated: data.auto_generated || false,
  };
}

// PATCH must not inherit creation defaults: omitted security settings belong
// to the stored profile. Explicit null/false/empty values remain intentional.
function buildTrustProfilePatch(data = {}) {
  const patch = {};
  const fields = [
    'name', 'description', 'compliance_status', 'trust_purposes',
    'trusted_assertion_formats', 'revocation_policy', 'revocation_profile_id',
    'time_policy', 'allowed_issuers', 'denied_issuers', 'system_issuer_overrides',
    'compatible_compliance_codes', 'verification_policy_set_id', 'auto_generated',
  ];
  for (const field of fields) {
    if (Object.hasOwn(data, field) && data[field] !== undefined) patch[field] = data[field];
  }
  const profileType = data.profile_type ?? data.framework_type;
  if (profileType !== undefined) patch.profile_type = normalizeTrustProfileType(profileType);
  if (data.supported_formats !== undefined) {
    patch.supported_formats = data.supported_formats?.map(normalizeTrustProfileFormat) ?? null;
  }
  if (data.trust_sources !== undefined) {
    patch.trust_sources = data.trust_sources?.map(normalizePublicTrustSource) ?? null;
  } else if (data.trusted_issuers !== undefined) {
    patch.trust_sources = trustSourcesFromTrustedIssuers(data.trusted_issuers);
  }
  // Top-level rule fields merge with the current backend rules. A nested
  // replacement would fill omitted rule fields with defaults on deserialization.
  for (const field of [
    'allowed_algorithms', 'min_key_size_rsa', 'min_key_size_ec',
    'require_key_usage', 'max_chain_depth', 'allow_self_signed',
  ]) {
    const value = data[field] !== undefined ? data[field] : data.validation_rules?.[field];
    if (value !== undefined) patch[field] = value;
  }
  return patch;
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
  // This normalizes readback only. Canonical stored days are authoritative;
  // create/PATCH input aliases still pass unchanged to the native resolver.
  const ttlSeconds = rules.default_validity_days != null
    ? Number(rules.default_validity_days) * SECONDS_PER_DAY : rules.ttl_seconds;
  const reissueWithinSeconds = rules.renewal_window_days != null
    ? Number(rules.renewal_window_days) * SECONDS_PER_DAY : rules.reissue_within_seconds;
  const notBeforeOffsetSeconds = rules.not_before_offset_seconds
    ?? rules.not_before_offset
    ?? 0;
  const maxValiditySeconds = rules.max_validity_days != null
    ? Number(rules.max_validity_days) * SECONDS_PER_DAY : rules.max_validity_seconds;

  return {
    ...rules,
    ...(ttlSeconds != null ? { ttl_seconds: ttlSeconds, default_validity_days: rules.default_validity_days ?? daysFromSeconds(ttlSeconds) } : {}),
    ...(reissueWithinSeconds != null
      ? {
          reissue_within_seconds: reissueWithinSeconds,
          renewal_window_days: rules.renewal_window_days ?? daysFromSeconds(reissueWithinSeconds),
        }
      : {}),
    not_before_offset_seconds: notBeforeOffsetSeconds,
    not_before_offset: notBeforeOffsetSeconds,
    ...(maxValiditySeconds != null
      ? {
          max_validity_seconds: maxValiditySeconds,
          max_validity_days: rules.max_validity_days ?? daysFromSeconds(maxValiditySeconds),
        }
      : {}),
  };
}

export function normalizeCredentialTemplate(data = {}) {
  const {
    issuer_profile_id: _issuerProfileId,
    issuer_key_id: _issuerKeyId,
    issuer_key_algorithm: _issuerKeyAlgorithm,
    issuer_algorithm: _issuerAlgorithm,
    signing_algorithm: _signingAlgorithm,
    key_access_mode: _keyAccessMode,
    remote_signing_config: _remoteSigningConfig,
    issuer_certificate_chain_pem: _issuerCertificateChain,
    issuer_certificate_chain_configured: _issuerCertificateChainConfigured,
    auto_generate_artifacts: _autoGenerateArtifacts,
    artifacts_status: _artifactsStatus,
    artifact_status: _artifactStatus,
    hasArtifacts: _hasArtifacts,
    artifactsValidated: _artifactsValidated,
    kms_provider: _kmsProvider,
    kms_key_id: _kmsKeyId,
    signing_service_id: _signingServiceId,
    signing_key_reference: _signingKeyReference,
    ...contractData
  } = data;
  const reportedFlowCount = data.usedByFlowsCount ?? data.used_by_flows_count;
  const claims = Array.isArray(data.claims)
    ? data.claims.map((claim) => ({
        ...claim,
        display_name: claim.display_name || claim.display?.label || claim.name,
      }))
    : [];

  return {
    ...contractData,
    status: data.status ? String(data.status).toLowerCase() : data.status,
    usedByFlowsCount: Number.isSafeInteger(reportedFlowCount) && reportedFlowCount >= 0 ? reportedFlowCount : null,
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
    if (!value.required) return HOLDER_BINDING_PAYLOADS.none;
    const methods = Array.isArray(value.binding_methods)
      ? value.binding_methods
        .filter((method) => typeof method === 'string' && method.trim() && method !== 'BIOMETRIC')
        .map((method) => method === 'NONCE' ? 'SESSION_BINDING' : method)
      : [];
    return {
      required: true,
      binding_methods: methods.length ? methods : ['DEVICE_KEY'],
      proof_profiles: Array.isArray(value.proof_profiles) && value.proof_profiles.length
        ? value.proof_profiles
        : ['OID4VP_VERIFIABLE_PRESENTATION'],
      proof_freshness: value.proof_freshness || {
        challenge_required: true,
        audience_binding_required: true,
        replay_detection_required: true,
      },
    };
  }

  const normalized = String(value || 'none').trim().toLowerCase();
  if (normalized === 'session_nonce') return HOLDER_BINDING_PAYLOADS.session_binding;
  if (normalized === 'biometric') return HOLDER_BINDING_PAYLOADS.device_key;
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
    activate_immediately: _activateImmediately,
    status: _status,
    holder_binding,
    policy_revision: _policyRevision,
    freshness_requirements,
    single_presentation: _singlePresentation,
    template_id: _templateId,
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

  const configuredOrigin = String(import.meta.env.VITE_CREDENTIAL_METADATA_ORIGIN || '').trim();
  const runtimeOrigin = typeof window !== 'undefined' ? window.location.origin : '';
  const origin = (configuredOrigin || runtimeOrigin).replace(/\/+$/, '');
  if (!origin) {
    throw new Error('Credential metadata origin is unavailable.');
  }
  return `${origin}/vct/${vct}`;
}

function isActiveResource(resource) {
  return String(resource?.status || '').toLowerCase() === 'active';
}

export function buildCredentialTemplatePayload(data = {}) {
  const {
    status: _status,
    id: _id,
    created_at: _createdAt,
    updated_at: _updatedAt,
    createdAt: _createdAtAlias,
    updatedAt: _updatedAtAlias,
    usedByFlowsCount: _usedByFlowsCount,
    used_by_flows_count: _usedByFlowsCountAlias,
    activate_immediately: _activateImmediately,
    generate_artifacts_automatically: _generateArtifactsAutomatically,
    auto_generate_artifacts: _autoGenerateArtifacts,
    supported_wallet_ids: _supportedWalletIds,
    _issuer_selection: _issuerSelection,
    wallet_configs: _walletConfigs,
    compliance_profile: _embeddedComplianceProfile,
    issuer_profile_id: _issuerProfileId,
    issuer_key_id: _issuerKeyId,
    issuer_key_algorithm: _issuerKeyAlgorithm,
    issuer_algorithm: _issuerAlgorithm,
    signing_algorithm: _signingAlgorithm,
    key_access_mode: _keyAccessMode,
    remote_signing_config: _remoteSigningConfig,
    issuer_certificate_chain_pem: _issuerCertificateChain,
    issuer_certificate_chain_configured: _issuerCertificateChainConfigured,
    artifacts_status: _artifactsStatus,
    artifact_status: _artifactStatus,
    hasArtifacts: _hasArtifacts,
    artifactsValidated: _artifactsValidated,
    kms_provider: _kmsProvider,
    kms_key_id: _kmsKeyId,
    signing_service_id: _signingServiceId,
    signing_key_reference: _signingKeyReference,
    ...contractData
  } = data;
  const issuerDid = String(data.issuer_did || '').trim();
  if (!issuerDid.startsWith('did:')) {
    const error = new Error('An active issuer DID is required before creating a credential template.');
    error.code = 'ISSUER_DID_REQUIRED';
    error.status = 400;
    throw error;
  }
  const complianceProfileId = String(data.compliance_profile_id || '').trim();
  if (!complianceProfileId) {
    const error = new Error('An active compliance profile is required before creating a credential template.');
    error.code = 'COMPLIANCE_PROFILE_REQUIRED';
    error.status = 400;
    throw error;
  }

  const claims = Array.isArray(data.claims)
    ? data.claims.map((claim) => normalizeCredentialTemplateClaim(claim))
    : [];

  return {
    ...contractData,
    issuer_did: issuerDid,
    compliance_profile_id: complianceProfileId,
    vct: normalizeCredentialTemplateVct(data),
    claims,
    ...(data.validity_rules !== undefined ? { validity_rules: data.validity_rules } : {}),
  };
}

/**
 * Create a new presentation policy
 */
export async function createPresentationPolicy(data, options = {}) {
  const payload = buildPresentationPolicyPayload(data);
  const shouldActivate = data?.activate_immediately === true || String(data?.status || '').toLowerCase() === 'active';
  let result = await postWithIdempotency(PRESENTATION_POLICY_BASE, payload, options);

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
export async function getPresentationPolicy(id, scope = null) {
  const query = scope ? `?${new URLSearchParams({ organization_id: requireOrganizationId(scope) })}` : '';
  const result = await get(`${PRESENTATION_POLICY_BASE}/${encodeURIComponent(id)}${query}`);
  return normalizePresentationPolicy(result);
}

/**
 * Update a presentation policy
 */
export async function updatePresentationPolicy(id, data) {
  const organizationId = requireOrganizationId(data);
  const { organization_id: _organizationId, policy_revision: _policyRevision, freshness_requirements, ...payload } = data;
  // PATCH is a sparse update, not a new policy. Never manufacture
  // requirements or binding defaults for an unrelated metadata edit.
  if (typeof payload.holder_binding === 'string') {
    payload.holder_binding = normalizeHolderBindingPayload(payload.holder_binding);
  }
  if (freshness_requirements !== undefined && payload.freshness === undefined) {
    payload.freshness = normalizeFreshnessPayload({ freshness_requirements });
  }
  // The public gateway authenticates body scope, then removes it before
  // forwarding to the native update contract.
  const result = await patch(`${PRESENTATION_POLICY_BASE}/${encodeURIComponent(id)}`, {
    organization_id: organizationId, ...payload,
  });
  return normalizePresentationPolicy(result);
}

/**
 * Delete a presentation policy
 */
export async function deletePresentationPolicy(id) {
  return del(`${PRESENTATION_POLICY_BASE}/${id}`);
}

export async function suspendPresentationPolicy(id) {
  return normalizePresentationPolicy(await post(`${PRESENTATION_POLICY_BASE}/${encodeURIComponent(id)}/suspend`, {}));
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
export async function createCredentialTemplate(data, options = {}) {
  const organizationId = requireOrganizationId(data);
  const shouldActivate = data?.activate_immediately === true;
  const payload = buildCredentialTemplatePayload({
    ...data,
    organization_id: organizationId,
  });
  let result = await postWithIdempotency(CREDENTIAL_TEMPLATE_BASE, payload, options);
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
  const organizationId = requireOrganizationId(data);
  const result = await patch(`${CREDENTIAL_TEMPLATE_BASE}/${id}`, buildCredentialTemplatePatch(data), {
    params: { organization_id: organizationId },
  });
  return normalizeCredentialTemplate(result);
}

// Match the native sparse update contract, rather than the create contract.
export function buildCredentialTemplatePatch(data = {}) {
  const fields = new Set([
    'organization_id', 'name', 'description', 'claims', 'privacy_posture',
    'selective_disclosure_fields', 'zk_predicate_claims', 'derived_attributes',
    'display_style', 'validity_rules', 'supported_formats', 'application_template_id',
    'trust_profile_id', 'revocation_profile_id', 'issuer_did',
    'credential_payload_format', 'issuance_protocol',
    'jwt_vc_profile', 'verification_prerequisite',
  ]);
  const privateFields = new Set([
    'key_reference', 'signing_service_id', 'signing_key_reference', 'issuer_profile_id',
    'private_key', 'privatekeyjwk', 'access_token', 'auth_token', 'api_key', 'client_secret',
  ]);
  const inspect = (value, depth = 0) => {
    if (depth > 48) throw new Error('Template update exceeds the supported nesting depth.');
    if (value && typeof value === 'object') {
      for (const [key, child] of Object.entries(value)) {
        if (privateFields.has(key.toLowerCase())) throw new Error('Private custody fields are not supported in template updates.');
        inspect(child, depth + 1);
      }
    }
  };
  requireOrganizationId(data);
  const payload = {};
  for (const [field, value] of Object.entries(data)) {
    if (value === undefined) continue;
    if (!fields.has(field)) throw new Error(`Unsupported template update field: ${field}`);
    inspect(value);
    if (field !== 'organization_id') payload[field] = value;
  }
  // Preserve sparse nested validity and claim representations; the gateway
  // canonicalizes public aliases without manufacturing creation defaults.
  return payload;
}

/**
 * Delete a credential template
 */
export async function deleteCredentialTemplate(id) {
  return del(`${CREDENTIAL_TEMPLATE_BASE}/${id}`);
}

/**
 * Create a new trust profile. Scoped callers can bind each idempotent attempt
 * and its settlement to an optional isCurrent predicate.
 */
export async function createTrustProfile(data, options = {}) {
  // A shared caller-options object may also describe later helper reads. Those
  // controls are not transport options for the create request.
  const { singleAttemptReads: _singleAttemptReads, allowReadback: _allowReadback, ...createOptions } = options;
  const organizationId = requireOrganizationId(data);
  const payload = buildTrustProfilePayload({
    ...data,
    organization_id: organizationId,
  });
  const result = await postWithIdempotency(TRUST_PROFILE_BASE, payload, createOptions);
  return normalizeTrustProfile(result);
}

/**
 * Activate a trust profile. Ownership and allowReadback are helper-only options;
 * callers without options retain the existing network-failure readback.
 * singleAttemptReads opts out of lower transport retries for that readback.
 */
export async function activateTrustProfile(id, options = {}) {
  try {
    const result = await runTrustIssuerRequest(() => post(`${TRUST_PROFILE_BASE}/${id}/activate`, {}), options);
    return normalizeTrustProfile(result);
  } catch (error) {
    requireCurrentTrustIssuer(options);
    if (!isNetworkAbortLikeError(error) || options.allowReadback === false) {
      throw error;
    }

    const current = await runTrustIssuerRequest(async () => {
      if (!options.singleAttemptReads) return getTrustProfile(id);
      return normalizeTrustProfile(await getWithRetryConfig(`${TRUST_PROFILE_BASE}/${id}`, {}, { maxRetries: 0 }));
    }, options);
    if (isActiveResource(current)) {
      return current;
    }
    throw error;
  }
}

/**
 * Atomically synchronize every external registry source on a trust profile.
 */
export async function synchronizeTrustProfileRegistries(id, options = {}) {
  return runTrustIssuerRequest(() => post(`${TRUST_PROFILE_BASE}/${id}/registry-sync`, {}), options);
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
export async function getTrustProfile(id, options = {}) {
  const path = `${TRUST_PROFILE_BASE}/${encodeURIComponent(id)}`;
  const result = await runTrustIssuerRequest(() => (options.singleAttemptReads
    ? getWithRetryConfig(path, {}, { maxRetries: 0 }) : get(path)), options);
  return normalizeTrustProfile(result);
}

/**
 * Update a trust profile
 */
export async function updateTrustProfile(id, data, options = {}) {
  const result = await runTrustIssuerRequest(() => patch(`${TRUST_PROFILE_BASE}/${id}`, buildTrustProfilePatch(data)), options);
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
export async function listIssuerEntities(organizationId, options = {}) {
  const scopedOrganizationId = requireOrganizationId({ organization_id: organizationId });
  const requestOptions = { params: { organization_id: scopedOrganizationId } };
  // Opt-in callers own the whole continuation; no native retry may dispatch
  // between the outer ownership checks. Legacy reads keep their retry policy.
  const result = await runTrustIssuerRequest(() => (options.singleAttemptReads
    ? getWithRetryConfig(ISSUER_ENTITY_BASE, requestOptions, { maxRetries: 0 })
    : get(ISSUER_ENTITY_BASE, requestOptions)), options);
  return requireDirectArray(result, 'Issuer Entity');
}

export async function listTrustProfileIssuers(profileId, organizationId, options = {}) {
  const scopedOrganizationId = requireOrganizationId({ organization_id: organizationId });
  const profilePath = TRUST_PROFILE_BASE + '/' + encodeURIComponent(profileId) + '/issuers';
  const loadRelationships = async () => {
    const rows = [];
    const seen = new Set();
    // Match the native offset contract. The entity inventory is not paginated.
    const limit = 100;
    for (let offset = 0; ; offset += limit) {
      const requestOptions = { params: { offset, limit } };
      const result = await runTrustIssuerRequest(() => (options.singleAttemptReads
        ? getWithRetryConfig(profilePath, requestOptions, { maxRetries: 0 })
        : get(profilePath, requestOptions)), options);
      requireCurrentTrustIssuer(options);
      const page = requireDirectArray(result, 'Trust Profile Issuer');
      if (page.length > limit || !Number.isSafeInteger(offset)) {
        throw malformedTrustIssuer('Trust Profile Issuer pagination returned an invalid page.');
      }
      for (const relationship of page) {
        if (!hasIssuerIdentifier(relationship?.id) || relationship.trust_profile_id !== profileId
          || !hasIssuerIdentifier(relationship.issuer_id) || seen.has(relationship.id)) {
          throw malformedTrustIssuer('Trust Profile Issuer pagination did not advance within the requested profile.');
        }
        seen.add(relationship.id);
        rows.push(relationship);
      }
      if (page.length < limit) return rows;
    }
  };
  const [relationships, entities] = await Promise.all([
    loadRelationships(),
    runTrustIssuerRequest(() => listIssuerEntities(scopedOrganizationId, options), options),
  ]);
  requireCurrentTrustIssuer(options);
  const entitiesById = issuerEntitiesById(entities);
  return relationships.map((relationship) => composeTrustProfileIssuer(
    relationship, entitiesById.get(relationship.issuer_id), profileId, scopedOrganizationId,
  ));
}

/**
 * Add a trusted issuer to a trust profile. Existing three-argument callers keep
 * their API; scoped callers can supply { isCurrent } for every internal await.
 * singleAttemptReads additionally disables native inventory-read retries.
 */
export async function addTrustProfileIssuer(profileId, organizationId, data, options = {}) {
  const scopedOrganizationId = requireOrganizationId({ organization_id: organizationId });
  const issuerDid = String(data?.issuer_did || data?.did || '').trim();
  if (!issuerDid) {
    const error = new Error('An issuer DID is required before linking a trusted issuer.');
    error.code = 'ISSUER_DID_REQUIRED';
    throw error;
  }

  const entities = await runTrustIssuerRequest(() => listIssuerEntities(scopedOrganizationId, options), options);
  requireCurrentTrustIssuer(options);
  issuerEntitiesById(entities);
  // Prefer the organization's existing record, while preserving the native
  // global-system exception. Other unowned/system inventory is not linkable.
  let issuerEntity = entities.find((entity) => (
    entity.organization_id === scopedOrganizationId && entity.issuer_id === issuerDid
  )) || entities.find((entity) => (
    entity.issuer_id === issuerDid && entity.organization_id == null && entity.is_system_issuer === true
  ));
  if (!issuerEntity) {
    issuerEntity = await runTrustIssuerRequest(() => post(ISSUER_ENTITY_BASE, {
      organization_id: scopedOrganizationId,
      issuer_id: issuerDid,
      issuer_type: data.issuer_type || 'ORGANIZATION',
      display_name: data.name || issuerDid,
      description: data.description || null,
      accreditation_body: data.accreditation_body || null,
      accreditations: Array.isArray(data.accreditations) ? data.accreditations : [],
      metadata: {
        ...(data.issuer_url ? { issuer_url: data.issuer_url } : {}),
      },
    }), options);
    requireCurrentTrustIssuer(options);
    // A successful entity write may already exist even if this check fails.
    // Never use a changed owner/DID/id to dispatch the subsequent relationship.
    requireIssuerEntity(issuerEntity, scopedOrganizationId, issuerDid, true);
  } else {
    requireIssuerEntity(issuerEntity, scopedOrganizationId, issuerDid);
  }

  const relationship = await runTrustIssuerRequest(() => post(
    TRUST_PROFILE_BASE + '/' + encodeURIComponent(profileId) + '/issuers', {
      issuer_id: issuerEntity.id,
      trust_level: data.trust_level ?? 100,
      relationship_status: data.relationship_status || 'TRUSTED',
      cascade_revocation_policy: data.cascade_revocation_policy || 'NOTIFY_ONLY',
      metadata: {
        credential_template_ids: data.credential_template_ids || [],
      },
    },
  ), options);
  requireCurrentTrustIssuer(options);
  return composeTrustProfileIssuer(relationship, issuerEntity, profileId, scopedOrganizationId);
}

// These are fixed owner operations for the paired-wallet editor. The ordinary
// browser transport supplies the authenticated session; a form never supplies
// identity headers, service credentials, or a caller-selected API endpoint.
const CREDENTIAL_GRANTS = 'marty_credential_authorizations_v1';
const ISSUANCE_GRANTS = 'marty_wallet_issuance_authorizations_v1';
const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const canonicalWalletJson = (value) => Array.isArray(value) ? value.map(canonicalWalletJson)
  : isObject(value) ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalWalletJson(value[key])])) : value;
const sameWalletJson = (left, right) => JSON.stringify(canonicalWalletJson(left)) === JSON.stringify(canonicalWalletJson(right));
// Trust Profile's public serializer removes object-null properties recursively,
// while retaining null array entries. Bind the full saved metadata to that wire
// projection rather than mistaking omitted optional endpoints for a failed save.
const walletOwnerProjection = (value) => Array.isArray(value) ? value.map(walletOwnerProjection)
  : isObject(value) ? Object.fromEntries(Object.entries(value).filter(([, item]) => item !== null)
    .map(([key, item]) => [key, walletOwnerProjection(item)])) : value;
const boundedText = (value, maximum = 2048) => typeof value === 'string' && value.length > 0
  && value.length <= maximum && value.trim() === value && [...value].every((character) => {
    const point = character.codePointAt(0);
    return point >= 32 && (point < 127 || point > 159);
  });

function walletInput(message) {
  const error = new Error(message);
  error.code = 'WALLET_TRUST_INPUT';
  return error;
}

function httpsIdentifier(value, allowQuery = false) {
  try {
    const url = new URL(value);
    return boundedText(value) && !value.includes('*') && url.protocol === 'https:'
      && Boolean(url.hostname) && !url.username && !url.password && !url.hash
      && (allowQuery || !url.search);
  } catch { return false; }
}

function absoluteIdentifier(value) {
  try { return boundedText(value) && Boolean(new URL(value).protocol); } catch { return false; }
}

/** Reject private material before dispatch. Cryptographic key admission follows
 * in validateWalletSigningKeys; the runtime owner still decides current trust. */
export function validateWalletPublicKeys(keys, { verifier = false, requestKeyId } = {}) {
  if (!Array.isArray(keys) || keys.length < 1 || keys.length > 32) {
    throw walletInput('Provide between one and 32 public signing keys.');
  }
  const seen = new Set();
  for (const key of keys) {
    const allowed = ['kty', 'crv', 'x', 'y', 'kid', 'alg', 'use', 'key_ops'];
    if (!isObject(key) || Object.keys(key).some((name) => !allowed.includes(name))) {
      throw walletInput('Import public signing keys only. Private key material and unknown key fields are not accepted.');
    }
    const algorithm = key.kty === 'EC' && key.crv === 'P-256' ? 'ES256'
      : key.kty === 'OKP' && key.crv === 'Ed25519' && !verifier ? 'EdDSA' : null;
    // A 32-byte coordinate has 43 base64url characters; its final two bits are zero.
    const coordinate = (value) => typeof value === 'string'
      && /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(value);
    if (!algorithm || !coordinate(key.x) || (key.kty === 'EC' && !coordinate(key.y))
      || (key.kty === 'OKP' && key.y !== undefined)
      || (key.alg !== undefined && key.alg !== algorithm)
      || (key.kid !== undefined && (!boundedText(key.kid) || (requestKeyId && key.kid !== requestKeyId)))
      || (key.use !== undefined && key.use !== 'sig')
      || (key.key_ops !== undefined && JSON.stringify(key.key_ops) !== '["verify"]')
      || (key.use !== undefined && key.key_ops !== undefined)
      || (!verifier && key.use !== 'sig' && JSON.stringify(key.key_ops) !== '["verify"]')
      || JSON.stringify(key).length > 2048) {
      throw walletInput('Use a supported public signing key with the matching key identifier and signing or verification usage.');
    }
    const identity = JSON.stringify([key.kty, key.crv, key.x, key.y]);
    if (seen.has(identity)) throw walletInput('A public signing key was entered more than once.');
    seen.add(identity);
  }
  return keys;
}

export async function validateWalletSigningKeys(keys, options = {}) {
  validateWalletPublicKeys(keys, options);
  if (!globalThis.crypto?.subtle) throw walletInput('This browser cannot validate public signing keys. Use a browser with Web Crypto support over HTTPS.');
  for (const key of keys) {
    try {
      await globalThis.crypto.subtle.importKey('jwk', key,
        key.kty === 'EC' ? { name: 'ECDSA', namedCurve: 'P-256' } : { name: 'Ed25519' }, false, ['verify']);
    } catch {
      throw walletInput('The public signing key is invalid or is not supported by this browser. Import the key returned by its actual owner.');
    }
  }
  return keys;
}

export function buildManagedWalletVerifierSource(input, existingId) {
  const registration = input.managed_flow_verifier;
  if (!isObject(registration) || !/^[A-Za-z0-9_-]{1,128}$/.test(registration.producer_id || '')
    || !httpsIdentifier(registration.public_base_url) || registration.public_base_url.endsWith('/')
    || new URL(registration.public_base_url).href.replace(/\/$/, '') !== registration.public_base_url
    || !/^did:(web|jwk|key):[^\s?#/]+$/.test(registration.verifier_did || '')
    || !boundedText(registration.request_key_id)
    || !registration.request_key_id.startsWith(`${registration.verifier_did}#`)
    || registration.request_key_id.length === registration.verifier_did.length + 1) {
    throw walletInput('Enter the configured Flow producer, its exact HTTPS address, verifier DID and matching request key identifier.');
  }
  const wholeSecondUtc = (value) => typeof value === 'string'
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)
    && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value.replace('Z', '.000Z');
  if (!wholeSecondUtc(registration.valid_from) || !wholeSecondUtc(registration.valid_until)
    || Date.parse(registration.valid_until) <= Date.parse(registration.valid_from)) {
    throw walletInput('Enter the actual key validity as whole-second UTC times, with the end after the start.');
  }
  validateWalletPublicKeys([registration.public_jwk], { verifier: true, requestKeyId: registration.request_key_id });
  return {
    ...(existingId ? { id: existingId } : {}),
    source_type: 'MANAGED_FLOW_VERIFIER',
    purposes: ['PRESENTATION_VERIFIER'],
    enabled: input.enabled === true,
    managed_flow_verifier: registration,
  };
}

export function walletIssuerGrants(credentialTypes, issuanceAuthorizations) {
  if (!Array.isArray(credentialTypes) || credentialTypes.length < 1 || credentialTypes.length > 128
    || credentialTypes.some((vct) => !absoluteIdentifier(vct))
    || new Set(credentialTypes).size !== credentialTypes.length) {
    throw walletInput('Enter one to 128 distinct credential type identifiers, using their complete URI.');
  }
  if (!Array.isArray(issuanceAuthorizations) || issuanceAuthorizations.length > 128) {
    throw walletInput('The issuance service list is invalid.');
  }
  const seen = new Set();
  const grants = issuanceAuthorizations.map((grant) => {
    const allowed = ['credential_issuer', 'credential_configuration_id', 'format', 'vct', 'authorization_server', 'token_endpoint'];
    if (!isObject(grant) || Object.keys(grant).some((name) => !allowed.includes(name))
      || !httpsIdentifier(grant.credential_issuer) || !boundedText(grant.credential_configuration_id, 256)
      || !['dc+sd-jwt', 'vc+sd-jwt'].includes(grant.format) || !credentialTypes.includes(grant.vct)
      || ((grant.authorization_server != null || grant.token_endpoint != null)
        && (!httpsIdentifier(grant.authorization_server) || !httpsIdentifier(grant.token_endpoint, true)))) {
      throw walletInput('Each issuance service needs its exact HTTPS identifier, configuration, supported format and an accepted credential type. Authorization server and token endpoint must be supplied together.');
    }
    const normalized = Object.fromEntries(allowed.map((name) => [name, grant[name] ?? null]));
    const identity = JSON.stringify(normalized);
    if (seen.has(identity)) throw walletInput('An issuance service grant was entered more than once.');
    seen.add(identity);
    return normalized;
  });
  return {
    [CREDENTIAL_GRANTS]: credentialTypes.map((vct) => ({ format: 'SD_JWT_VC', vct })),
    [ISSUANCE_GRANTS]: grants,
  };
}

export function walletIssuerProfileSupported(profile) {
  return profile?.profile_type === 'CUSTOM' && profile.trust_sources?.length === 0
    && Array.isArray(profile.revocation_services?.enabled_methods) && profile.revocation_services.enabled_methods.length === 0
    && !profile.revocation_policy?.check_ocsp && !profile.revocation_policy?.check_crl && !profile.revocation_policy?.check_status_list
    && !profile.revocation_profile_id && !profile.verification_policy_set_id && !profile.compatible_compliance_codes?.length
    && !Object.keys(profile.system_issuer_overrides || {}).length && !Object.keys(profile.validation_rules?.extensions || {}).length
    && !profile.time_policy?.require_freshness && !profile.time_policy?.credential_freshness_hours
    && (profile.trusted_assertion_formats == null || profile.trusted_assertion_formats.includes('JWT'));
}

function requireWalletProfile(profile, profileId, organizationId) {
  if (profile?.id !== profileId || profile.organization_id !== organizationId
    || !walletIssuerProfileSupported(profile) || JSON.stringify(profile.trust_purposes) !== '["CREDENTIAL_ISSUER"]'
    || !['draft', 'active', 'suspended'].includes(profile.status)
    || (profile.allowed_issuers != null && !Array.isArray(profile.allowed_issuers))) {
    throw malformedTrustIssuer('Reload the selected organization’s dedicated wallet issuer profile before saving.');
  }
}

/** Save a reviewed issuer, its exact grants, then the profile review state.
 * Each existing object is reread and matched before writes. No write is replayed
 * after an uncertain result; callers must reload to recover partial progress. */
export async function saveWalletIssuerTrust(profileId, organizationId, input, options = {}) {
  const organization = requireOrganizationId({ organization_id: organizationId });
  const keys = await validateWalletSigningKeys(input.verification_keys);
  const grants = walletIssuerGrants(input.credential_types, input.issuance_authorizations);
  if (!boundedText(input.issuer?.issuer_id) || !boundedText(input.issuer?.display_name, 255)) {
    throw walletInput('Enter the issuer identifier and display name.');
  }
  const scopedOptions = { ...options, singleAttemptReads: true };
  const run = (operation) => runTrustIssuerRequest(operation, scopedOptions);
  const read = (path) => run(() => getWithRetryConfig(path, {}, { maxRetries: 0 }));
  const profile = normalizeTrustProfile(await read(`${TRUST_PROFILE_BASE}/${encodeURIComponent(profileId)}`));
  requireWalletProfile(profile, profileId, organization);
  if (!input.profile_updated_at || profile.updated_at !== input.profile_updated_at) {
    throw walletInput('The profile changed. Reload its latest configuration before saving.');
  }
  const relationships = await listTrustProfileIssuers(profileId, organization, scopedOptions);
  requireCurrentTrustIssuer(scopedOptions);
  let issuer = input.issuer.id ? await read(`${ISSUER_ENTITY_BASE}/${encodeURIComponent(input.issuer.id)}`) : null;
  if (issuer) {
    requireIssuerEntity(issuer, organization, input.issuer.issuer_id, true);
    if (issuer.id !== input.issuer.id || !input.issuer.updated_at || issuer.updated_at !== input.issuer.updated_at
      || issuer.revoked_at || !isObject(issuer.metadata)) {
      throw walletInput('The issuer changed or is revoked. Reload before configuring its public keys.');
    }
  }
  let relationship = issuer ? relationships.find((row) => row.issuer_id === issuer.id) : null;
  if ((relationship?.id || null) !== (input.relationship?.id || null)
    || (relationship && (relationship.updated_at !== input.relationship.updated_at || !isObject(relationship.metadata)
      || relationship.relationship_status !== 'TRUSTED' || relationship.trust_level === 0))) {
    throw walletInput('The issuer relationship changed or is not trusted. Reload and review it before saving.');
  }
  let dispatchedWrite = false;
  try {
    const existingIssuerId = issuer?.id;
    const existingRelationshipId = relationship?.id;
    const issuerBody = {
      metadata: { ...(issuer?.metadata || {}), verification_keys: keys },
      compliance_status: ['COMPLIANT', 'ACCREDITED'].includes(issuer?.compliance_status) ? issuer.compliance_status : 'COMPLIANT',
    };
    dispatchedWrite = true;
    issuer = issuer
      ? await run(() => patch(`${ISSUER_ENTITY_BASE}/${encodeURIComponent(issuer.id)}`, { organization_id: organization, ...issuerBody }))
      : await run(() => post(ISSUER_ENTITY_BASE, {
        organization_id: organization, issuer_id: input.issuer.issuer_id,
        display_name: input.issuer.display_name, issuer_type: 'ORGANIZATION', ...issuerBody,
      }));
    requireIssuerEntity(issuer, organization, input.issuer.issuer_id, true);
    if (existingIssuerId && issuer.id !== existingIssuerId) {
      throw malformedTrustIssuer('The issuer update response changed identity. Reload before continuing.');
    }
    if (!sameWalletJson(issuer.metadata, walletOwnerProjection(issuerBody.metadata)) || issuer.compliance_status !== issuerBody.compliance_status) {
      throw malformedTrustIssuer('The saved public issuer keys could not be confirmed. Reload before continuing.');
    }
    const metadata = { ...(relationship?.metadata || {}), ...grants };
    const relationshipPath = `${TRUST_PROFILE_BASE}/${encodeURIComponent(profileId)}/issuers`;
    relationship = relationship
      ? await run(() => patch(`${relationshipPath}/${encodeURIComponent(issuer.id)}`, { metadata }))
      : await run(() => post(relationshipPath, {
        issuer_id: issuer.id, trust_level: 100, relationship_status: 'TRUSTED',
        cascade_revocation_policy: 'NOTIFY_ONLY', metadata,
      }));
    const composed = composeTrustProfileIssuer(relationship, issuer, profileId, organization);
    if (existingRelationshipId && relationship.id !== existingRelationshipId) {
      throw malformedTrustIssuer('The relationship update response changed identity. Reload before continuing.');
    }
    if (!sameWalletJson(relationship.metadata, walletOwnerProjection(metadata))) {
      throw malformedTrustIssuer('The saved credential and issuance grants could not be confirmed. Reload before continuing.');
    }
    const beforeReview = normalizeTrustProfile(await read(`${TRUST_PROFILE_BASE}/${encodeURIComponent(profileId)}`));
    requireWalletProfile(beforeReview, profileId, organization);
    if (beforeReview.updated_at !== profile.updated_at) {
      throw walletInput('The profile changed while issuer settings were saved. Reload before completing its review.');
    }
    const allowed = profile.allowed_issuers == null ? null
      : [...new Set([...profile.allowed_issuers, issuer.issuer_id])];
    const updated = await updateTrustProfile(profileId, {
      compliance_status: 'COMPLIANT', allowed_issuers: allowed,
    }, scopedOptions);
    requireWalletProfile(updated, profileId, organization);
    if (updated.compliance_status !== 'COMPLIANT' || !sameWalletJson(updated.allowed_issuers ?? null, allowed)) {
      throw malformedTrustIssuer('The profile review response is incomplete. Reload to inspect the saved state.');
    }
    return { profile: updated, issuer, relationship: composed };
  } catch (error) {
    requireCurrentTrustIssuer(scopedOptions);
    if (dispatchedWrite) error.walletReloadRequired = true;
    throw error;
  }
}

// ── Revocation Profile API ────────────────────────────────────────────────

const REVOCATION_PROFILE_BASE = '/v1/revocation-profiles';

/**
 * Create a revocation profile.
 * @param {Object} data - Profile data
 * @param {Object} [options] - Request options, including an optional isCurrent predicate
 * @returns {Promise<Object>}
 */
export async function createRevocationProfile(data, options = {}) {
  const organizationId = requireOrganizationId(data);
  return postWithIdempotency(REVOCATION_PROFILE_BASE, {
    ...data,
    organization_id: organizationId,
  }, options);
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

/**
 * Activate a draft revocation profile.
 * @param {string} id
 * @returns {Promise<Object>}
 */
export async function activateRevocationProfile(id) {
  return post(`${REVOCATION_PROFILE_BASE}/${id}/activate`, {});
}

