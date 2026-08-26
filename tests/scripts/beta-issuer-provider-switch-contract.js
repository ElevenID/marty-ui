'use strict';

function providerSwitchBehaviorAssertions(report = {}) {
  const providerA = report.providerA || {};
  const providerB = report.providerB || {};
  const denied = report.unpublishedReplacement || {};
  const oldKid = providerA.credential?.kid;
  const newKid = providerB.credential?.kid;
  const issuerDid = report.identityCreation?.identity?.issuer_did;
  const publishedMethods = new Set(report.didAfterSwitch?.assertionMethodIds || []);

  return {
    create_issuer_profile: Boolean(
      report.identityCreation?.ok
      && issuerDid
      && report.identityCreation?.identity?.status === 'active',
    ),
    issue_with_provider_a: Boolean(
      providerA.issuance?.ok
      && providerA.credential?.verified
      && providerA.credential?.issuerDid === issuerDid
      && oldKid,
    ),
    switch_signing_provider: Boolean(
      report.rebind?.ok
      && report.rebind?.changed
      && report.providerBConfig?.defaultServiceId === report.providerBConfig?.serviceId
      && oldKid
      && newKid
      && oldKid !== newKid,
    ),
    verify_same_did_identity: Boolean(
      providerB.issuance?.ok
      && providerB.credential?.verified
      && providerB.credential?.issuerDid === issuerDid
      && providerA.reverifiedAfterSwitch === true
      && publishedMethods.has(oldKid)
      && publishedMethods.has(newKid),
    ),
    unpublished_signing_key_denied: Boolean(
      denied.rebindStatus === 503
      && denied.rebindOk === false
      && denied.issueAfterDenial?.ok
      && denied.credentialAfterDenial?.verified
      && denied.credentialAfterDenial?.issuerDid === issuerDid
      && denied.credentialAfterDenial?.kid === newKid,
    ),
  };
}

module.exports = { providerSwitchBehaviorAssertions };
