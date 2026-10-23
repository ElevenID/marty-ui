/** Public DID identity operations. Provider configuration belongs to signingKeysApi. */
import { get, post } from './api';
import { postWithIdempotency } from './idempotency';
import { buildDefinedQueryString, requireOrganizationId, withQuery } from './queryUtils';

const BASE_PATH = '/v1/signing-keys/issuer-identities';
const organization = (params, action) => requireOrganizationId(
  typeof params === 'string' ? params : params?.organization_id || params?.organizationId,
  action,
);

export async function createIssuerIdentity(body) {
  return postWithIdempotency(BASE_PATH, {
    organization_id: organization(body, 'creating issuer identities'),
    issuer_did: body?.issuer_did,
    key_purpose: body?.key_purpose,
    credential_format: body?.credential_format,
    algorithm: body?.algorithm,
    key_attestation_policy: body?.key_attestation_policy,
  });
}

export async function listPublicIssuerIdentities(params = {}) {
  return get(withQuery(BASE_PATH, buildDefinedQueryString({
    organization_id: organization(params, 'loading issuer identities'),
    key_purpose: params?.key_purpose,
    credential_format: params?.credential_format,
    algorithm: params?.algorithm,
  })));
}

export async function getIssuerIdentityCapabilities(params = {}) {
  const organizationId = organization(params, 'loading issuer capabilities');
  const result = await get(withQuery(`${BASE_PATH}/capabilities`, buildDefinedQueryString({
    organization_id: organizationId,
  })));
  if (result?.organization_id !== organizationId
    || result?.basis !== 'configuration'
    || !Array.isArray(result?.creation_options)
    || !result.creation_options.every((option) => ['key_purpose', 'credential_format', 'algorithm']
      .every((field) => typeof option?.[field] === 'string' && option[field].trim()))
    || (result.managed_issuer_did_prefix !== null
      && (typeof result.managed_issuer_did_prefix !== 'string'
        || !result.managed_issuer_did_prefix.startsWith('did:')))) {
    throw new Error('Issuer capabilities returned invalid organization or identity data.');
  }
  return {
    organization_id: result.organization_id,
    managed_issuer_did_prefix: result.managed_issuer_did_prefix,
    basis: result.basis,
    creation_options: result.creation_options.map(({ key_purpose, credential_format, algorithm }) => ({
      key_purpose, credential_format, algorithm,
    })),
  };
}

export async function getTemplateIssuerOptions(params = {}) {
  const organizationId = organization(params, 'loading template issuer options');
  const result = await post('/v1/credential-templates/issuer-options', {
    organization_id: organizationId,
    compliance_profile_id: params.compliance_profile_id,
    ...(params.credential_payload_format ? { credential_payload_format: params.credential_payload_format } : {}),
    ...(Array.isArray(params.supported_formats) ? { supported_formats: params.supported_formats } : {}),
  });
  if (result?.organization_id !== organizationId
    || result?.compliance_profile_id !== params.compliance_profile_id
    || typeof result?.credential_payload_format !== 'string'
    || typeof result?.issuance_protocol !== 'string'
    || !Array.isArray(result?.supported_formats) || result.supported_formats.length === 0
    || !result.supported_formats.every((format) => typeof format === 'string' && format)
    || !['vct', 'doctype', 'revocation_profile', 'x509_certificate'].every((field) => typeof result?.requirements?.[field] === 'boolean')
    || !Array.isArray(result?.identities) || !result.identities.every((identity) => typeof identity?.issuer_did === 'string'
      && identity.issuer_did.startsWith('did:') && Array.isArray(identity.bindings) && identity.bindings.length > 0
      && identity.bindings.every((binding) => ['credential_format', 'key_purpose', 'algorithm'].every((field) => typeof binding?.[field] === 'string' && binding[field])))
    || !Array.isArray(result?.rejected_issuers)
    || !result.rejected_issuers.every((identity) => typeof identity?.issuer_did === 'string'
      && identity.issuer_did.startsWith('did:')
      && ['ambiguous_identity', 'incompatible_identity'].includes(identity.reason))) {
    throw new Error('Template issuer options returned invalid organization or compatibility data.');
  }
  return {
    organization_id: result.organization_id, compliance_profile_id: result.compliance_profile_id,
    credential_payload_format: result.credential_payload_format, supported_formats: result.supported_formats,
    issuance_protocol: result.issuance_protocol,
    requirements: Object.fromEntries(['vct', 'doctype', 'revocation_profile', 'x509_certificate'].map((field) => [field, result.requirements[field]])),
    identities: result.identities.map(({ issuer_did, bindings }) => ({ issuer_did,
      bindings: bindings.map(({ credential_format, key_purpose, algorithm }) => ({ credential_format, key_purpose, algorithm })) })),
    rejected_issuers: result.rejected_issuers.map(({ issuer_did, reason }) => ({ issuer_did, reason })),
  };
}

export default { createIssuerIdentity, listPublicIssuerIdentities, getIssuerIdentityCapabilities, getTemplateIssuerOptions };
