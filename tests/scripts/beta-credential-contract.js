'use strict';

const DEFAULT_BETA_ORGANIZATION_ID = '00000000-0000-0000-0000-000000000001';
const DEFAULT_LOGIN_BADGE_TEMPLATE_ID = '50000000-0000-0000-0000-000000000040';
const DEFAULT_LOGIN_BADGE_CONFIGURATION_ID = 'open_badge';
const DEFAULT_LIFECYCLE_POLICY_ID = '50000000-0000-0000-0000-000000000002';
const DEFAULT_LIFECYCLE_SOURCE_TEMPLATE_ID = '50000000-0000-0000-0000-000000000010';

function credentialInventoryEvidence(inventory, { vct = null, configurationId = null } = {}) {
  const text = typeof inventory === 'string' ? inventory : '';
  const storedExactVct = Boolean(vct) && text.includes(vct);
  const storedExpectedConfigurationId = Boolean(configurationId) && text.includes(configurationId);
  const storedExpectedCredential = storedExactVct || storedExpectedConfigurationId;
  return {
    storedExactVct,
    storedExpectedConfigurationId,
    storedExpectedCredential,
    // Retain the established report field while allowing canonical VC-JWT,
    // which has a credential type/configuration ID rather than an SD-JWT VCT.
    storedExpectedVct: storedExpectedCredential,
  };
}

function credentialConfigurationIdForWaltid(configId) {
  if (typeof configId !== 'string' || !configId.trim()) return configId;
  const id = configId.trim();
  if (id.endsWith('#sd-jwt') || id.endsWith('#mdoc') || id.endsWith('#vds-nc')) return id;
  if (id.endsWith('#credential-manager') || id.endsWith('#apple-wallet')) {
    return `${id.split('#')[0]}#sd-jwt`;
  }
  if (id.includes('#')) return id;
  return `${id}#sd-jwt`;
}

function verificationResultEvidence(body, httpStatus = null) {
  const isObject = body !== null && typeof body === 'object' && !Array.isArray(body);
  const stringField = (name) => (
    isObject && typeof body[name] === 'string' && body[name].trim()
      ? body[name]
      : null
  );
  const stringList = (name) => (
    isObject && Array.isArray(body[name]) && body[name].every((value) => typeof value === 'string')
      ? body[name]
      : []
  );

  return {
    httpStatus,
    status: stringField('status')?.toUpperCase() || null,
    evaluation: stringField('result'),
    decision: stringField('decision'),
    decisionReason: stringField('decision_reason'),
    errorCodes: stringList('error_codes'),
    warnings: stringList('warnings'),
  };
}

function verificationSessionRequest({
  organizationId,
  presentationPolicyId,
  issuerDid,
  externalReference,
}) {
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (typeof organizationId !== 'string' || !uuid.test(organizationId)) {
    throw new TypeError('organizationId must be a UUID');
  }
  if (typeof presentationPolicyId !== 'string' || !uuid.test(presentationPolicyId)) {
    throw new TypeError('presentationPolicyId must be a UUID');
  }
  if (typeof issuerDid !== 'string' || !/^did:[a-z0-9]+:\S+$/i.test(issuerDid)) {
    throw new TypeError('issuerDid must be a DID');
  }
  if (typeof externalReference !== 'string' || !externalReference.trim()) {
    throw new TypeError('externalReference must be a non-empty string');
  }
  return {
    organization_id: organizationId,
    presentation_policy_id: presentationPolicyId,
    issuer_did: issuerDid,
    external_reference: externalReference,
  };
}

function membershipLoginBehaviorAssertions(report) {
  return {
    governed_claim: report?.badge?.offerSource === 'canonical-ui'
      && report?.badge?.loggedOut === true,
    conformant_open_badge_issuance: report?.badge?.accepted === true
      && report?.badge?.storedExpectedCredential === true,
    same_device_passwordless_login: report?.presentation?.accepted === true
      && report?.completion?.status === 'completed'
      && report?.completion?.authenticated === true,
  };
}

function credentialLifecycleBehaviorAssertions(report) {
  const suspended = report?.suspend?.verification?.result;
  const reinstated = report?.reinstate?.verification?.result;
  const revoked = report?.revoke?.verification?.result;
  return {
    renew: report?.renewal?.ok === true,
    suspend: report?.suspend?.ok === true
      && String(report?.suspend?.current?.lifecycleStatus || '').toUpperCase() === 'SUSPENDED',
    reinstate: report?.reinstate?.ok === true
      && String(report?.reinstate?.current?.lifecycleStatus || '').toUpperCase() === 'ACTIVE'
      && reinstated?.decision === 'allow',
    revoke: report?.revoke?.ok === true
      && String(report?.revoke?.current?.lifecycleStatus || '').toUpperCase() === 'REVOKED',
    suspended_and_revoked_states_denied: suspended?.decision === 'deny'
      && /suspend/i.test(suspended?.decisionReason || '')
      && revoked?.decision === 'deny'
      && /revok/i.test(revoked?.decisionReason || ''),
  };
}

module.exports = {
  DEFAULT_BETA_ORGANIZATION_ID,
  DEFAULT_LIFECYCLE_POLICY_ID,
  DEFAULT_LIFECYCLE_SOURCE_TEMPLATE_ID,
  DEFAULT_LOGIN_BADGE_CONFIGURATION_ID,
  DEFAULT_LOGIN_BADGE_TEMPLATE_ID,
  credentialConfigurationIdForWaltid,
  credentialLifecycleBehaviorAssertions,
  credentialInventoryEvidence,
  membershipLoginBehaviorAssertions,
  verificationResultEvidence,
  verificationSessionRequest,
};
