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
  const owned = { organizationId: inputs.organizationId, credentialTemplateId: inputs.credentialTemplateId,
    runId: inputs.runId, applicationId: null, transactionId: null, credentialId: null,
    applicationTemplateId: null, applicantId: null, uncertainMutations: [] };
  return {
    owned,
    async prepare(applicantPage) {
      const credential = await requireJson(operator, `/v1/credential-templates/${encodeURIComponent(owned.credentialTemplateId)}`);
      assert.equal(credential.organization_id, owned.organizationId);
      assert.equal(credential.status, 'ACTIVE');
      assert.equal(credential.credential_type, inputs.configurationId);
      assert.equal(credential.vct, inputs.vct);
      const profile = await ensureApplicantProfile(applicantPage, { email: inputs.email });
      assert.equal(profile.email, inputs.email);
      owned.applicantId = profile.id;
      const application = await createOwnedActiveConfiguration(operator, owned, {
        collectionPath: '/v1/application-templates', name: 'First-party membership control',
        payload: { organization_id: owned.organizationId, credential_template_id: owned.credentialTemplateId,
          description: 'Run-owned membership application; shared issuer and login policy remain unchanged.',
          form_fields: ['email', 'given_name', 'family_name'].map(field => ({ field_id: field,
            label: field, field_type: 'TEXT', required: true, claim_mapping: field })),
          evidence_requirements: [], required_checks: [], claim_collection_rules: [],
          approval_strategy: 'MANUAL', approval_policy_set_id: null, application_validity_days: 1,
          notification_config: {}, ui_config: {} },
      });
      owned.applicationTemplateId = application.id;
      await createOwnedApplication(applicantPage, owned, { formData: {
        email: inputs.email, given_name: inputs.givenName, family_name: inputs.familyName,
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
