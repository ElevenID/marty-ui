'use strict';
// Public transport and ownership orchestration; existing Rust services own
// application, issuance, trust, and credential lifecycle decisions.
const assert = require('node:assert/strict');
const {
  cleanupApplicationCredential, createOwnedApplication, ensureApplicantProfile,
  issueOwnedApplication, requireJson, requireOwnedApplication, submitOwnedApplication,
  approvedApplicationFlowPayload,
} = require('./beta-demo-resource-helpers');
const { createOwnedActiveConfiguration, retireOwnedConfiguration } = require('./demo-owned-configuration');

function createOwnedMembership(operator, inputs) {
  const owned = { organizationId: inputs.organizationId, credentialTemplateId: null,
    runId: inputs.runId, applicationId: null, transactionId: null, credentialId: null,
    applicationTemplateId: null, applicantId: null, uncertainMutations: [] };
  const controller = {
    owned,
    async configure() {
      const credential = await requireJson(operator, `/v1/credential-templates/${encodeURIComponent(inputs.credentialTemplateId)}`);
      assert.equal(credential.organization_id, owned.organizationId);
      assert.equal(credential.status, 'ACTIVE');
      assert.equal(credential.credential_type, inputs.configurationId);
      assert.equal(credential.vct, inputs.vct);
      assert.match(inputs.sourceApplicationTemplateId || '', /^[a-f0-9-]{36}$/i);
      const applicationSource = await requireJson(operator,
        `/v1/application-templates/${encodeURIComponent(inputs.sourceApplicationTemplateId)}`);
      assert.equal(applicationSource.id, inputs.sourceApplicationTemplateId);
      assert.equal(applicationSource.organization_id, owned.organizationId);
      assert.equal(applicationSource.credential_template_id, credential.id);
      assert.equal(applicationSource.status, 'ACTIVE');
      assert.ok(applicationSource.description?.trim(), 'Membership badge requires its governed description');
      assert.ok(Array.isArray(applicationSource.form_fields) && Array.isArray(applicationSource.claim_collection_rules));
      for (const name of ['name', 'description']) assert(applicationSource.claim_collection_rules.some(rule =>
        rule.claim_name === `achievement_${name}` && rule.source === 'SYSTEM'
          && rule.source_config?.system_field === `template.${name}`), 'Preserve governed badge metadata rules');
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
      payload.supported_formats = [credential.credential_payload_format];
      // This is a new program, not a copy of the legacy seed's configuration
      // identifier into the public credential-type field.
      payload.credential_type = inputs.receiptConfigurationId;
      const ownCredential = await createOwnedActiveConfiguration(operator, owned, {
        collectionPath: '/v1/credential-templates', name: 'First-party membership credential', payload,
      });
      owned.credentialTemplateId = ownCredential.id;
      assert.equal(ownCredential.credential_type, inputs.receiptConfigurationId);
      const application = await createOwnedActiveConfiguration(operator, owned, {
        collectionPath: '/v1/application-templates', name: 'First-party membership control',
        // Preserve the production Rust-generated collection contract. System
        // claims (including badge description, role and member ID) must not be
        // recreated as applicant-entered form fields by the recorder.
        payload: { ...Object.fromEntries(['description', 'form_fields', 'evidence_requirements',
          'required_checks', 'claim_collection_rules', 'application_validity_days', 'notification_config', 'ui_config']
          .filter(key => applicationSource[key] !== undefined).map(key => [key, applicationSource[key]])),
          organization_id: owned.organizationId, credential_template_id: owned.credentialTemplateId,
          approval_strategy: 'MANUAL', approval_policy_set_id: null, application_validity_days: 1,
        },
      });
      owned.applicationTemplateId = application.id;
      const flow = await createOwnedActiveConfiguration(operator, owned, {
        collectionPath: '/v1/flows/definitions', name: 'First-party membership issuance',
        payload: approvedApplicationFlowPayload({ organizationId: owned.organizationId,
          name: 'First-party membership issuance', description: 'Issue this owned approved membership application.',
          credentialTemplateId: owned.credentialTemplateId }),
      });
      assert.equal(flow.credential_template_id, owned.credentialTemplateId);
      return { credential, ownCredential, application, flow };
    },
    async prepare(applicantPage) {
      await controller.configure();
      const profile = await ensureApplicantProfile(applicantPage, { email: inputs.email });
      assert.equal(profile.email, inputs.email);
      owned.applicantId = profile.id;
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
  return controller;
}

module.exports = { createOwnedMembership };
