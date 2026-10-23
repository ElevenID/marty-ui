/** Public DID identity operations. Provider configuration belongs to signingKeysApi. */
import { get } from './api';
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

export default { createIssuerIdentity, listPublicIssuerIdentities, getIssuerIdentityCapabilities };
