#!/usr/bin/env node
/* eslint-disable no-console */
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('@playwright/test');

const {
  login,
  receiveCredential,
  selectOrg,
  verify,
  waitFor,
} = require('./audit-beta-credential-lifecycle');
const {
  DEFAULT_BETA_ORGANIZATION_ID,
  DEFAULT_LIFECYCLE_SOURCE_TEMPLATE_ID,
} = require('./beta-credential-contract');
const {
  browserJson,
  cleanupApplicationCredential,
  compactObject,
  ensureActiveResource,
  ensureApplicantProfile,
  findCurrentCredential,
  requireJson,
} = require('./beta-demo-resource-helpers');
const {
  PASSPORT_EVIDENCE_SHA256,
  passportClearanceBehaviorAssertions,
  validEvidenceDigest,
} = require('./beta-passport-clearance-contract');
const { loadEnvFile, redact } = require('./verify-beta-waltid-acceptance');
const {
  VIDEO_SIZE,
  createArtifactDir,
  finalizeVideo,
  showStep,
} = require('./demo-recording');

const ROOT = path.resolve(__dirname, '..', '..');
loadEnvFile(path.join(ROOT, '.env.tunnel.beta.local'));
loadEnvFile(path.join(ROOT, '.env'));

const BETA_ORIGIN = process.env.BETA_ORIGIN || 'https://beta.elevenidllc.com';
const ORG_ID = process.env.BETA_AUDIT_ORG_ID || DEFAULT_BETA_ORGANIZATION_ID;
const SOURCE_TEMPLATE_ID = process.env.BETA_AUDIT_TEMPLATE_ID
  || DEFAULT_LIFECYCLE_SOURCE_TEMPLATE_ID;
const VERIFIER_DID = process.env.BETA_AUDIT_VERIFIER_DID || '';
const HEADLESS = process.env.HEADED !== '1';
const RECORD_VIDEO = process.env.RECORD_VIDEO === '1';
const LOCAL_BETA_PROXY = process.env.BETA_LOCAL_PROXY === '1';
const RESOURCE_NAMES = Object.freeze({
  credential: 'D-01 Pre-Boarding Clearance Credential',
  application: 'D-01 Passport Pre-Boarding Clearance',
  policy: 'D-01 Rapid Gate Clearance',
  flow: 'D-01 Pre-Boarding Credential Issuance',
});

function clearanceClaims() {
  return [
    ['traveler_id', 'Traveler ID'],
    ['flight_number', 'Flight number'],
    ['departure_airport', 'Departure airport'],
    ['arrival_airport', 'Arrival airport'],
    ['boarding_group', 'Boarding group'],
    ['clearance_status', 'Clearance status'],
    ['passport_evidence_sha256', 'Passport evidence SHA-256'],
  ].map(([name, displayName]) => ({
    name,
    display_name: displayName,
    description: null,
    claim_type: 'STRING',
    required: true,
    selectively_disclosable: true,
    derivable: false,
    derived_from: null,
    pattern: name === 'passport_evidence_sha256' ? PASSPORT_EVIDENCE_SHA256.source : null,
    enum_values: name === 'clearance_status' ? ['CLEARED'] : null,
    min_value: null,
    max_value: null,
    mdoc_namespace: null,
    mdoc_element_identifier: null,
    display_icon: null,
  }));
}

function clearanceCredentialPayload(source) {
  const claims = clearanceClaims();
  return compactObject({
    organization_id: ORG_ID,
    name: RESOURCE_NAMES.credential,
    description: 'Application-bound pre-boarding clearance issued only after D-01 passport validation.',
    credential_type: 'PreBoardingClearanceCredential',
    vct: `${BETA_ORIGIN}/credentials/pre-boarding-clearance`,
    doctype: null,
    claims,
    privacy_posture: source.privacy_posture || 'SELECTIVE_DISCLOSURE',
    selective_disclosure_fields: claims.map(({ name }) => name),
    zk_predicate_claims: [],
    derived_attributes: [],
    display_style: source.display_style || null,
    validity_rules: source.validity_rules,
    supported_formats: source.supported_formats || ['SD_JWT_VC'],
    application_template_id: null,
    trust_profile_id: source.trust_profile_id || null,
    revocation_profile_id: source.revocation_profile_id,
    compliance_profile_id: source.compliance_profile_id,
    issuer_did: source.issuer_did,
    credential_payload_format: 'w3c_vcdm_v2_sd_jwt',
    issuance_protocol: 'openid4vci_pre_authorized',
  });
}

function clearanceApplicationTemplatePayload(credentialTemplateId) {
  return {
    organization_id: ORG_ID,
    name: RESOURCE_NAMES.application,
    description: 'Manual review of a cryptographically validated passport evidence binding before clearance issuance.',
    credential_template_id: credentialTemplateId,
    form_fields: clearanceClaims().map(({ name, display_name: label }) => ({
      field_id: name,
      label,
      field_type: 'TEXT',
      required: true,
      claim_mapping: name,
      ...(name === 'passport_evidence_sha256'
        ? { validation_pattern: PASSPORT_EVIDENCE_SHA256.source }
        : {}),
      ...(name === 'clearance_status'
        ? { options: [{ label: 'Cleared', value: 'CLEARED' }] }
        : {}),
    })),
    evidence_requirements: [],
    required_checks: [],
    claim_collection_rules: [],
    approval_strategy: 'MANUAL',
    approval_policy_set_id: null,
    application_validity_days: 1,
    notification_config: {},
    ui_config: {},
  };
}

function clearancePolicyPayload(credentialTemplate) {
  const clearanceClaim = {
    claim_name: 'clearance_status',
    credential_type: null,
    value_constraint: 'CLEARED',
    predicate_spec: null,
  };
  return {
    organization_id: ORG_ID,
    name: RESOURCE_NAMES.policy,
    description: 'Disclose only clearance status and allow a currently valid D-01 pre-boarding credential.',
    purpose: 'Rapid pre-boarding gate clearance',
    display_metadata: {
      title: 'Pre-boarding clearance',
      description: 'Present a current pre-boarding clearance credential.',
      purpose: 'travel_clearance',
      purpose_description: 'Confirm that passport validation and pre-boarding review completed.',
      verifier_name: 'ElevenID LLC',
      verifier_logo_url: null,
      privacy_policy_url: null,
      terms_of_service_url: null,
    },
    required_claims: [clearanceClaim],
    accepted_credential_types: ['PreBoardingClearanceCredential'],
    trust_profile_id: credentialTemplate.trust_profile_id || null,
    holder_binding: { required: false },
    freshness: null,
    issuer_constraints: null,
    credential_ranking_strategy: 'first_match',
    credential_ranking_weights: null,
    credential_requirements: [{
      credential_template_id: credentialTemplate.id,
      display_name: RESOURCE_NAMES.credential,
      description: 'Current pre-boarding clearance credential',
      required: true,
      credential_payload_format: 'w3c_vcdm_v2_sd_jwt',
      requested_claims: [clearanceClaim],
      trust_profile_id: credentialTemplate.trust_profile_id || null,
      max_age_seconds: null,
      require_fresh_issuance: false,
    }],
    alternative_requirements: [],
    compliance_profile_id: credentialTemplate.compliance_profile_id || null,
    prefer_predicates: false,
    fallback_policy: null,
    supported_circuits: [],
  };
}

function clearanceFlowPayload(credentialTemplateId) {
  return {
    organization_id: ORG_ID,
    name: RESOURCE_NAMES.flow,
    description: 'Issue the approved D-01 pre-boarding clearance credential.',
    flow_type: 'oid4vci_pre_authorized',
    approval_strategy: 'AUTO',
    credential_template_id: credentialTemplateId,
    trigger: {
      trigger_type: 'WEBHOOK',
      config: { event_type: 'APPLICATION_APPROVED' },
    },
  };
}

function exactArray(actual, expected) {
  return Array.isArray(actual)
    && actual.length === expected.length
    && actual.every((value, index) => value === expected[index]);
}

function requireConfigurationBinding(configuration) {
  const expectedClaims = clearanceClaims().map(({ name }) => name);
  const { credential, application, policy, flow } = configuration;
  const credentialEvidence = credential.claims?.find(({ name }) => name === 'passport_evidence_sha256');
  const credentialClearance = credential.claims?.find(({ name }) => name === 'clearance_status');
  if (credential.credential_type !== 'PreBoardingClearanceCredential'
      || credential.vct !== `${BETA_ORIGIN}/credentials/pre-boarding-clearance`
      || !exactArray(credential.claims?.map(({ name }) => name), expectedClaims)
      || credentialEvidence?.pattern !== PASSPORT_EVIDENCE_SHA256.source
      || !exactArray(credentialClearance?.enum_values, ['CLEARED'])) {
    throw new Error('D-01 Credential Template has drifted from the pre-boarding contract');
  }
  const evidenceField = application.form_fields?.find(({ field_id: fieldId }) => (
    fieldId === 'passport_evidence_sha256'
  ));
  const clearanceField = application.form_fields?.find(({ field_id: fieldId }) => (
    fieldId === 'clearance_status'
  ));
  if (application.credential_template_id !== credential.id
      || application.approval_strategy !== 'MANUAL'
      || !exactArray(application.form_fields?.map(({ field_id: fieldId }) => fieldId), expectedClaims)
      || evidenceField?.validation_pattern !== PASSPORT_EVIDENCE_SHA256.source
      || clearanceField?.options?.length !== 1
      || clearanceField.options[0]?.value !== 'CLEARED') {
    throw new Error('D-01 Application Template has drifted from the passport evidence contract');
  }
  const requirement = policy.credential_requirements?.[0];
  const requested = requirement?.requested_claims?.[0];
  const required = policy.required_claims?.[0];
  if (!exactArray(policy.accepted_credential_types, ['PreBoardingClearanceCredential'])
      || policy.credential_requirements?.length !== 1
      || requirement?.credential_template_id !== credential.id
      || requirement?.requested_claims?.length !== 1
      || requested?.claim_name !== 'clearance_status'
      || requested?.value_constraint !== 'CLEARED'
      || policy.required_claims?.length !== 1
      || required?.claim_name !== 'clearance_status'
      || required?.value_constraint !== 'CLEARED') {
    throw new Error('D-01 Presentation Policy has drifted from the minimal rapid-gate contract');
  }
  if (flow.credential_template_id !== credential.id
      || flow.application_template_id
      || flow.approval_strategy !== 'AUTO'
      || flow.trigger?.trigger_type !== 'WEBHOOK'
      || flow.trigger?.config?.event_type !== 'APPLICATION_APPROVED') {
    throw new Error('D-01 issuance Flow has drifted from the approval event contract');
  }
  return configuration;
}

async function ensureConfiguration(page) {
  const source = await requireJson(
    page,
    `/v1/credential-templates/${encodeURIComponent(SOURCE_TEMPLATE_ID)}`,
    {},
    'Load D-01 source Credential Template',
  );
  if (!source.issuer_did || !source.compliance_profile_id || !source.revocation_profile_id) {
    throw new Error('D-01 source Credential Template lacks issuer, compliance, or revocation binding');
  }
  const credential = await ensureActiveResource(page, {
    organizationId: ORG_ID,
    collectionPath: '/v1/credential-templates',
    name: RESOURCE_NAMES.credential,
    payload: clearanceCredentialPayload(source),
    idempotencyKey: 'demo-d01-pre-boarding-credential-v1',
  });
  const application = await ensureActiveResource(page, {
    organizationId: ORG_ID,
    collectionPath: '/v1/application-templates',
    name: RESOURCE_NAMES.application,
    payload: clearanceApplicationTemplatePayload(credential.id),
    idempotencyKey: 'demo-d01-passport-clearance-application-v1',
    validate: true,
  });
  const policy = await ensureActiveResource(page, {
    organizationId: ORG_ID,
    collectionPath: '/v1/presentation-policies',
    name: RESOURCE_NAMES.policy,
    payload: clearancePolicyPayload(credential),
    idempotencyKey: 'demo-d01-rapid-gate-policy-v1',
  });
  const flow = await ensureActiveResource(page, {
    organizationId: ORG_ID,
    collectionPath: '/v1/flows/definitions',
    name: RESOURCE_NAMES.flow,
    payload: clearanceFlowPayload(credential.id),
    idempotencyKey: 'demo-d01-pre-boarding-issuance-flow-v1',
    validate: true,
  });
  return requireConfigurationBinding({ credential, application, policy, flow });
}

async function createAndSubmitApplication(page, applicationTemplateId, evidenceDigest, stamp) {
  const formData = {
    traveler_id: `TRAVELER-D01-${stamp}`,
    flight_number: 'MIP101',
    departure_airport: 'SLC',
    arrival_airport: 'DEN',
    boarding_group: 'A1',
    clearance_status: 'CLEARED',
    passport_evidence_sha256: evidenceDigest,
  };
  const created = await requireJson(page, '/v1/me/applications', {
    method: 'POST',
    body: JSON.stringify({
      organization_id: ORG_ID,
      application_template_id: applicationTemplateId,
      form_data: formData,
      integration_context: {
        evidence_type: 'marty_verifier_emrtd',
        evidence_sha256: evidenceDigest,
      },
    }),
  }, 'Create passport clearance application');
  if (created.form_data?.passport_evidence_sha256 !== evidenceDigest) {
    throw new Error('Stored D-01 application is not bound to the supplied passport evidence');
  }
  const submitted = await requireJson(
    page,
    `/v1/me/applications/${encodeURIComponent(created.id)}/submit`,
    { method: 'POST' },
    'Submit passport clearance application',
  );
  return { created, submitted, formData };
}

async function approveAndIssue(page, applicationId, evidenceDigest) {
  const root = `/v1/organizations/${encodeURIComponent(ORG_ID)}/applicants/${encodeURIComponent(applicationId)}`;
  const lock = await requireJson(page, `${root}/lock`, { method: 'POST' }, 'Acquire passport reviewer lock');
  const approved = await requireJson(page, `${root}/approve`, {
    method: 'POST',
    body: JSON.stringify({ notes: `D-01 passport evidence ${evidenceDigest} approved` }),
  }, 'Approve passport clearance application');
  await requireJson(page, `${root}/lock`, { method: 'DELETE' }, 'Release passport reviewer lock');
  const issued = await requireJson(page, `${root}/issue`, { method: 'POST' }, 'Issue pre-boarding credential');
  return { lock, approved, issued };
}

async function cleanup(page, applicationId, credentialId) {
  return cleanupApplicationCredential(page, {
    organizationId: ORG_ID,
    applicationId,
    credentialId,
    reason: 'D-01 release qualification cleanup',
  });
}

async function showClearanceStep(page, title, detail) {
  return showStep(page, title, detail, {
    enabled: RECORD_VIDEO,
    eyebrow: 'Passport validation to pre-boarding clearance',
  });
}

function observePage(page, report) {
  page.on('pageerror', (error) => report.pageErrors.push(redact(error.message)));
  page.on('response', (response) => {
    if (!response.url().startsWith(BETA_ORIGIN) || response.status() < 400) return;
    if (!response.url().includes('/cdn-cgi/rum')) {
      report.unexpectedResponses.push({
        status: response.status(),
        method: response.request().method(),
        url: redact(response.url()),
      });
    }
  });
}

async function main() {
  const adminEmail = process.env.TEST_VENDOR_EMAIL || process.env.TEST_ADMIN_EMAIL;
  const adminPassword = process.env.TEST_VENDOR_PASSWORD || process.env.TEST_ADMIN_PASSWORD;
  const applicantEmail = process.env.TEST_APPLICANT_EMAIL || process.env.TEST_APPLICANT1_EMAIL;
  const applicantPassword = process.env.TEST_APPLICANT_PASSWORD || process.env.TEST_APPLICANT1_PASSWORD;
  const evidenceDigest = process.env.D01_PASSPORT_EVIDENCE_SHA256 || '';
  if (!adminEmail || !adminPassword || !applicantEmail || !applicantPassword) {
    throw new Error('Missing beta administrator or applicant credentials');
  }
  if (!VERIFIER_DID) throw new Error('BETA_AUDIT_VERIFIER_DID is required');
  if (!validEvidenceDigest(evidenceDigest)) {
    throw new Error('D01_PASSPORT_EVIDENCE_SHA256 must be exactly 64 lower-case hexadecimal characters');
  }

  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '').toLowerCase();
  const startedAt = new Date(Date.now() - 5_000).toISOString();
  const artifactDir = createArtifactDir(ROOT, `beta-passport-clearance-${stamp}`);
  const report = {
    createdAt: new Date().toISOString(),
    organizationId: ORG_ID,
    passportEvidenceSha256: evidenceDigest,
    pageErrors: [],
    unexpectedResponses: [],
  };
  const browser = await chromium.launch({
    headless: HEADLESS,
    args: LOCAL_BETA_PROXY
      ? ['--host-resolver-rules=MAP beta.elevenidllc.com 127.0.0.1', '--no-proxy-server']
      : [],
  });
  let adminContext;
  let applicantContext;
  let adminPage;
  let applicationId;
  let credentialId;
  let cleanupComplete = false;
  try {
    adminContext = await browser.newContext({
      viewport: VIDEO_SIZE,
      ignoreHTTPSErrors: LOCAL_BETA_PROXY,
      ...(RECORD_VIDEO ? { recordVideo: { dir: artifactDir, size: VIDEO_SIZE } } : {}),
    });
    applicantContext = await browser.newContext({ viewport: VIDEO_SIZE, ignoreHTTPSErrors: LOCAL_BETA_PROXY });
    const page = await adminContext.newPage();
    adminPage = page;
    const walletPage = await adminContext.newPage();
    const applicantPage = await applicantContext.newPage();
    const adminVideo = page.video();
    const walletVideo = walletPage.video();
    observePage(page, report);
    observePage(applicantPage, report);
    observePage(walletPage, report);

    await login(page, adminEmail, adminPassword);
    report.orgSelection = await selectOrg(page);
    if (!report.orgSelection.ok) throw new Error(`Cannot select organization ${ORG_ID}`);
    const configuration = await ensureConfiguration(page);
    report.configuration = {
      credentialTemplateId: configuration.credential.id,
      applicationTemplateId: configuration.application.id,
      presentationPolicyId: configuration.policy.id,
      flowDefinitionId: configuration.flow.id,
      vct: configuration.credential.vct,
      allActive: [configuration.credential, configuration.application, configuration.policy, configuration.flow]
        .every((resource) => String(resource.status).toUpperCase() === 'ACTIVE'),
    };

    await login(applicantPage, applicantEmail, applicantPassword);
    await ensureApplicantProfile(applicantPage, {
      email: applicantEmail,
      givenName: process.env.TEST_APPLICANT_FIRST_NAME || 'Jamie',
      familyName: process.env.TEST_APPLICANT_LAST_NAME || 'Lee',
    });
    const application = await createAndSubmitApplication(
      applicantPage,
      configuration.application.id,
      evidenceDigest,
      stamp,
    );
    applicationId = application.created.id;
    report.application = {
      created: Boolean(applicationId),
      id: applicationId,
      travelerId: application.formData.traveler_id,
      submittedStatus: application.submitted.status,
      passportEvidenceSha256: application.created.form_data.passport_evidence_sha256,
    };

    await page.goto(`${BETA_ORIGIN}/console/org/operate/applications/${encodeURIComponent(applicationId)}`, {
      waitUntil: 'domcontentloaded',
      timeout: 60_000,
    });
    await page.getByText(application.formData.traveler_id).first().waitFor({ state: 'visible', timeout: 30_000 });
    await showClearanceStep(page, 'Passport evidence submitted', 'The application carries the exact digest of the passport result already validated by the native Rust verifier.');

    const approval = await approveAndIssue(page, applicationId, evidenceDigest);
    report.application.lockAcquired = Boolean(approval.lock?.id);
    report.application.approvedStatus = approval.approved?.status || null;
    const offerUri = approval.issued?.credential_offer_uri
      || Object.values(approval.issued?.credential_offer_uris || {})[0]
      || null;
    report.issuance = {
      issueOk: Boolean(offerUri),
      vct: configuration.credential.vct,
    };
    await page.reload({ waitUntil: 'domcontentloaded' });
    await showClearanceStep(page, 'Pre-boarding clearance approved', 'Manual review approved the evidence-bound application and the Rust issuance flow returned a real OpenID4VCI offer.');
    if (!offerUri) throw new Error('Pre-boarding issuance returned no credential offer');

    const walletReceipt = await receiveCredential(walletPage, offerUri, configuration.credential.vct);
    const walletInventory = await walletPage.locator('#credentials').innerText();
    report.issuance.walletReceived = walletReceipt.ok;
    report.issuance.walletEvidenceBound = walletInventory.includes(evidenceDigest);
    report.issuance.passportEvidenceSha256 = report.issuance.walletEvidenceBound ? evidenceDigest : null;
    const credential = await findCurrentCredential(page, {
      organizationId: ORG_ID,
      credentialTemplateId: configuration.credential.id,
      startedAt,
      waitFor,
    });
    if (!credential?.id) throw new Error('Issued pre-boarding credential was not discoverable');
    credentialId = credential.id;
    report.issuance.credentialId = credentialId;
    await showClearanceStep(page, 'Clearance credential received', 'The holder wallet accepted the credential and exposes the same passport evidence digest in its signed claims.');

    const verification = await verify(page, walletPage, 'D-01 rapid pre-boarding gate', {
      organizationId: ORG_ID,
      presentationPolicyId: configuration.policy.id,
      issuerDid: VERIFIER_DID,
    });
    report.rapidGate = {
      walletPresented: verification.wallet?.ok === true,
      result: verification.result,
    };
    await showClearanceStep(page, 'Rapid gate clearance allowed', 'A real DCQL presentation disclosed only the CLEARED status and returned an explicit allow decision.');

    report.behaviorAssertions = passportClearanceBehaviorAssertions(report);
    report.cleanup = await cleanup(page, applicationId, credentialId);
    cleanupComplete = report.cleanup.credentialRevoked && report.cleanup.applicationWithdrawn;
    report.releaseReady = Boolean(
      report.configuration.allActive
      && Object.values(report.behaviorAssertions).every((passed) => passed === true)
      && cleanupComplete
      && report.pageErrors.length === 0
      && report.unexpectedResponses.length === 0
    );
    report.finishedAt = new Date().toISOString();
    await applicantContext.close();
    applicantContext = null;
    await adminContext.close();
    adminContext = null;
    if (RECORD_VIDEO) {
      report.recordings = {
        clearance: path.relative(
          ROOT,
          await finalizeVideo(adminVideo, artifactDir, 'passport-pre-boarding-clearance-beta.webm'),
        ),
        wallet: path.relative(
          ROOT,
          await finalizeVideo(walletVideo, artifactDir, 'passport-pre-boarding-clearance-wallet.webm'),
        ),
      };
    }
    fs.writeFileSync(path.join(artifactDir, 'report.json'), JSON.stringify(report, null, 2));
    console.log(JSON.stringify(report, null, 2));
    if (!report.releaseReady) process.exitCode = 1;
  } finally {
    if (!cleanupComplete && adminPage && (applicationId || credentialId)) {
      await cleanup(adminPage, applicationId, credentialId)
        .then((result) => { report.cleanup = result; })
        .catch((error) => { report.cleanupError = redact(error.message || String(error)); });
    }
    if (applicantContext) await applicantContext.close().catch(() => {});
    if (adminContext) await adminContext.close().catch(() => {});
    await browser.close();
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.log(JSON.stringify({ error: redact(error.stack || error.message || String(error)) }, null, 2));
    process.exitCode = 1;
  });
}

module.exports = {
  clearanceApplicationTemplatePayload,
  clearanceCredentialPayload,
  clearanceFlowPayload,
  clearancePolicyPayload,
  requireConfigurationBinding,
};
