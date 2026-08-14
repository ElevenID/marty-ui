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

module.exports = {
  DEFAULT_BETA_ORGANIZATION_ID,
  DEFAULT_LIFECYCLE_POLICY_ID,
  DEFAULT_LIFECYCLE_SOURCE_TEMPLATE_ID,
  DEFAULT_LOGIN_BADGE_CONFIGURATION_ID,
  DEFAULT_LOGIN_BADGE_TEMPLATE_ID,
  credentialConfigurationIdForWaltid,
  credentialInventoryEvidence,
  verificationResultEvidence,
};
