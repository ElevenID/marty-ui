'use strict';
// Public transport and ownership orchestration; existing Rust services own
// application, issuance, trust, and credential lifecycle decisions.
const assert = require('node:assert/strict');
const {
  cleanupApplicationCredential, createOwnedApplication, ensureApplicantProfile,
  issueOwnedApplication, readApplicationTransaction, requireJson, requireOwnedApplication,
  submitOwnedApplication,
} = require('./beta-demo-resource-helpers');
const { createOwnedActiveConfiguration, retireOwnedConfiguration } = require('./demo-owned-configuration');

async function requireGovernedMembershipFlow(operator, owned, flowId, read = requireJson) {
  assert.match(flowId || '', /^[a-f0-9-]{36}$/i);
  const flow = await read(operator, `/v1/flows/definitions/${encodeURIComponent(flowId)}`);
  assert.equal(flow.id, flowId);
  assert.equal(flow.organization_id, owned.organizationId);
  assert.equal(flow.credential_template_id, owned.credentialTemplateId);
  assert.equal(flow.status, 'ACTIVE');
  const effectiveType = flow.flow_type === 'custom'
    ? flow.extension?.extends_flow_type : flow.flow_type;
  assert.equal(effectiveType, 'oid4vci_pre_authorized');
  assert.equal(flow.trigger?.trigger_type, 'WEBHOOK');
  assert.equal(flow.trigger?.config?.event_type, 'APPLICATION_APPROVED');
  const definitions = [];
  for (let offset = 0; offset <= 10_000; offset += 500) {
    const page = await read(operator,
      `/v1/flows/definitions?organization_id=${encodeURIComponent(owned.organizationId)}&limit=500&offset=${offset}`);
    assert.ok(Array.isArray(page), 'Flow definition inventory must be an array');
    assert.ok(page.length <= 500, 'Flow definition inventory page exceeded its limit');
    definitions.push(...page);
    if (page.length < 500) break;
    assert.ok(offset < 10_000, 'Flow definition inventory exceeded the bounded scan');
  }
  assert.equal(new Set(definitions.map(item => item.id)).size, definitions.length,
    'Flow definition inventory repeated a definition');
  const matching = definitions.filter(item => item.organization_id === owned.organizationId
    && item.credential_template_id === owned.credentialTemplateId && item.status === 'ACTIVE'
    && item.trigger?.trigger_type === 'WEBHOOK'
    && item.trigger?.config?.event_type === 'APPLICATION_APPROVED');
  assert.equal(matching.length, 1,
    'One governed membership issuance Flow must be active before issuing');
  assert.equal(matching[0]?.id, flowId);
  return flow;
}

function createOwnedMembership(operator, inputs) {
  const owned = { organizationId: inputs.organizationId, credentialTemplateId: null,
    runId: inputs.runId, applicationId: null, transactionId: null, credentialId: null,
    applicationTemplateId: null, applicantId: null, uncertainMutations: [] };
  const protectedFields = ['id', 'organization_id', 'status', 'credential_type', 'vct',
    'credential_payload_format', 'issuer_did', 'trust_profile_id', 'claims', 'supported_formats'];
  const protectedContract = template => Object.fromEntries(protectedFields.map(key => [key, template[key] ?? null]));
  let sourceContract = null, sourceFlowContract = null;
  const controller = {
    owned,
    async configure() {
      const credential = await requireJson(operator, `/v1/credential-templates/${encodeURIComponent(inputs.credentialTemplateId)}`);
      assert.equal(credential.organization_id, owned.organizationId);
      assert.equal(credential.status, 'ACTIVE');
      assert.equal(credential.credential_type, inputs.configurationId);
      assert.equal(credential.vct, inputs.vct);
      sourceContract = JSON.parse(JSON.stringify(protectedContract(credential)));
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
      // Credential login's governed policy requires this exact source template.
      // Own the application and credential, never clone or retire shared policy authority.
      owned.credentialTemplateId = credential.id;
      const flow = await requireGovernedMembershipFlow(operator, owned, inputs.sourceFlowDefinitionId);
      sourceFlowContract = { id: flow.id, organization_id: flow.organization_id,
        credential_template_id: flow.credential_template_id, status: flow.status, trigger: flow.trigger };
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
      return { credential, application, flow };
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
      // Applicant approval publishes to Notification/Event Stream. The signed
      // Flow webhook is dispatched by HttpFlowProvider::issue, not approval.
      // Refuse any unexpected prior offer before invoking that path once.
      assert.equal(await readApplicationTransaction(operator, owned), null,
        'Approval unexpectedly created an issuance transaction before the explicit issue');
      await requireGovernedMembershipFlow(operator, owned, inputs.sourceFlowDefinitionId);
      await issueOwnedApplication(operator, owned, 'Prepare owned membership offer for real UI claim');
      const issuedTransaction = await readApplicationTransaction(operator, owned);
      assert.equal(issuedTransaction?.id, owned.transactionId,
        'Explicit issue did not leave exactly one bound application transaction');
      return { applicationId: owned.applicationId, organizationId: owned.organizationId };
    },
    async cleanup() {
      let application, configuration, sharedTemplateReadback = null, sharedFlowReadback = null;
      const failures = [];
      try { application = await cleanupApplicationCredential(operator, owned,
        'Retire run-owned first-party wallet credential', { cancelPendingOffer: true }); }
      catch (error) { application = { ok: false }; failures.push({ operation: 'application',
        code: error.code || error.name, detail: String(error.stack || error.message || error) }); }
      // Configuration has an independent exact ownership ledger. A failed or
      // ambiguous application cleanup cannot leave run-owned configuration active.
      try { configuration = await retireOwnedConfiguration(operator, owned); }
      catch (error) { configuration = { ok: false }; failures.push({ operation: 'configuration',
        code: error.code || error.name, detail: String(error.stack || error.message || error) }); }
      try {
        if (sourceContract) {
          const current = await requireJson(operator,
            `/v1/credential-templates/${encodeURIComponent(inputs.credentialTemplateId)}`);
          assert.deepEqual(protectedContract(current), sourceContract,
            'Governed shared credential template changed during the owned run');
          assert.equal(current.status, 'ACTIVE');
          sharedTemplateReadback = { id: current.id, status: current.status, unchanged: true };
        }
        if (sourceFlowContract) {
          const current = await requireJson(operator,
            `/v1/flows/definitions/${encodeURIComponent(inputs.sourceFlowDefinitionId)}`);
          assert.deepEqual({ id: current.id, organization_id: current.organization_id,
            credential_template_id: current.credential_template_id, status: current.status,
            trigger: current.trigger }, sourceFlowContract,
          'Governed shared issuance Flow changed during the owned run');
          sharedFlowReadback = { id: current.id, status: current.status, unchanged: true };
        }
      } catch (error) { failures.push({ operation: 'shared_authority_readback',
        code: error.code || error.name, detail: String(error.stack || error.message || error) }); }
      return { complete: application?.ok === true && configuration?.ok === true && failures.length === 0,
        application, configuration, failures, sharedCredentialTemplateModified: false,
        sharedTemplateReadback, sharedFlowReadback };
    },
  };
  return controller;
}

module.exports = { createOwnedMembership, requireGovernedMembershipFlow };
