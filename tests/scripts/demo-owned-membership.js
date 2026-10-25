'use strict';
// Public transport and ownership orchestration; existing Rust services own
// application, issuance, trust, and credential lifecycle decisions.
const assert = require('node:assert/strict');
const {
  cleanupApplicationCredential, createOwnedApplication, ensureApplicantProfile,
  issueOwnedApplication, requireJson, requireOwnedApplication, submitOwnedApplication,
} = require('./beta-demo-resource-helpers');
const { createOwnedActiveConfiguration, retireOwnedConfiguration } = require('./demo-owned-configuration');

function createOwnedMembership(operator, inputs) {
  const owned = { organizationId: inputs.organizationId, credentialTemplateId: null,
    runId: inputs.runId, applicationId: null, transactionId: null, credentialId: null,
    applicationTemplateId: null, applicantId: null, uncertainMutations: [] };
  return {
    owned,
    async prepare(applicantPage) {
      const credential = await requireJson(operator, `/v1/credential-templates/${encodeURIComponent(inputs.credentialTemplateId)}`);
      assert.equal(credential.organization_id, owned.organizationId);
      assert.equal(credential.status, 'ACTIVE');
      assert.equal(credential.credential_type, inputs.configurationId);
      assert.equal(credential.vct, inputs.vct);
      const payload = Object.fromEntries(['organization_id', 'description', 'credential_type', 'vct', 'doctype',
        'privacy_posture', 'selective_disclosure_fields', 'zk_predicate_claims', 'derived_attributes',
        'display_style', 'validity_rules', 'supported_formats', 'trust_profile_id', 'revocation_profile_id',
        'compliance_profile_id', 'issuer_did', 'credential_payload_format', 'issuance_protocol']
        .filter(key => credential[key] !== undefined).map(key => [key, credential[key]]));
      payload.claims = credential.claims.map(claim => ({
        name: claim.name, display_name: claim.display?.label || claim.name, description: claim.description || null,
        claim_type: claim.type, required: claim.required, selectively_disclosable: claim.selectively_disclosable,
        derivable: claim.derivable || false, derived_from: claim.derived_from || null,
        pattern: claim.pattern || null, enum_values: claim.enum_values || null,
        min_value: claim.min_value ?? null, max_value: claim.max_value ?? null,
        mdoc_namespace: claim.mdoc_namespace || null, mdoc_element_identifier: claim.mdoc_element_identifier || null,
        display_icon: claim.display_icon || null,
      }));
      payload.application_template_id = null;
      const ownCredential = await createOwnedActiveConfiguration(operator, owned, {
        collectionPath: '/v1/credential-templates', name: 'First-party membership credential', payload,
      });
      owned.credentialTemplateId = ownCredential.id;
      const profile = await ensureApplicantProfile(applicantPage, { email: inputs.email });
      assert.equal(profile.email, inputs.email);
      owned.applicantId = profile.id;
      const application = await createOwnedActiveConfiguration(operator, owned, {
        collectionPath: '/v1/application-templates', name: 'First-party membership control',
        payload: { organization_id: owned.organizationId, credential_template_id: owned.credentialTemplateId,
          description: 'Run-owned membership application; shared issuer and login policy remain unchanged.',
          form_fields: credential.claims.map(claim => ({ field_id: claim.name,
            label: claim.name, field_type: 'TEXT', required: claim.required, claim_mapping: claim.name })),
          evidence_requirements: [], required_checks: [], claim_collection_rules: [],
          approval_strategy: 'MANUAL', approval_policy_set_id: null, application_validity_days: 1,
          notification_config: {}, ui_config: {} },
      });
      owned.applicationTemplateId = application.id;
      await createOwnedApplication(applicantPage, owned, { formData: {
        email: inputs.email, given_name: inputs.givenName, family_name: inputs.familyName,
        member_id: `demo-${owned.runId}`, organization_id: owned.organizationId,
        organization_name: 'ElevenID beta demo', role: 'applicant',
        achievement_name: 'Marty Verified Member', issued_at: new Date().toISOString().slice(0, 10),
      }, integrationContext: { demo_scenario: 'first-party-browser-wallet' }, label: 'Create owned membership application' });
      await submitOwnedApplication(applicantPage, owned, 'Submit owned membership application');
      const root = `/v1/organizations/${encodeURIComponent(owned.organizationId)}/applicants/${encodeURIComponent(owned.applicationId)}`;
      requireOwnedApplication(await requireJson(operator, root), owned);
      const approved = requireOwnedApplication(await requireJson(operator, `${root}/approve`, {
        method: 'POST', body: JSON.stringify({ notes: 'Authorized synthetic first-party wallet control' }),
      }), owned);
      assert.equal(approved.status, 'APPROVED');
      await issueOwnedApplication(operator, owned, 'Prepare owned membership offer for real UI claim');
      return { applicationId: owned.applicationId, organizationId: owned.organizationId };
    },
    async cleanup() {
      const application = await cleanupApplicationCredential(operator, owned,
        'Retire run-owned first-party wallet credential', { cancelPendingOffer: true });
      const configuration = await retireOwnedConfiguration(operator, owned);
      return { complete: application.ok === true && configuration.ok === true,
        application, configuration, sharedCredentialTemplateModified: false };
    },
  };
}

module.exports = { createOwnedMembership };
