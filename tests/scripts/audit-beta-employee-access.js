#!/usr/bin/env node
/* eslint-disable no-console */
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('@playwright/test');

const {
  findCredentialRow,
  getCredentialStatus,
  login,
  performLifecycleAction,
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
  DEFAULT_CREDENTIAL_RANKING_STRATEGY,
  browserJson,
  cleanupApplicationCredential,
  compactObject,
  ensureActiveResource,
  ensureApplicantProfile,
  findCurrentCredential,
  requestedClaim,
  requireJson,
} = require('./beta-demo-resource-helpers');
const { employeeAccessBehaviorAssertions } = require('./beta-employee-access-contract');
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
  credential: 'D-04 Employee Access Credential',
  application: 'D-04 Employee Onboarding',
  policy: 'D-04 Active Employee Access',
  flow: 'D-04 Employee Credential Issuance',
});

function employeeClaims() {
  return [
    ['employee_id', 'Employee ID'],
    ['given_name', 'Given name'],
    ['family_name', 'Family name'],
    ['department', 'Department'],
    ['access_level', 'Access level'],
    ['employment_status', 'Employment status'],
  ].map(([name, displayName]) => ({
    name,
    display_name: displayName,
    description: null,
    claim_type: 'STRING',
    required: true,
    selectively_disclosable: true,
    derivable: false,
    derived_from: null,
    pattern: null,
    enum_values: null,
    min_value: null,
    max_value: null,
    mdoc_namespace: null,
    mdoc_element_identifier: null,
    display_icon: null,
  }));
}

function employeeCredentialPayload(source) {
  const claims = employeeClaims();
  return compactObject({
    organization_id: ORG_ID,
    name: RESOURCE_NAMES.credential,
    description: 'Status-aware employee credential used by the D-04 release qualification.',
    credential_type: 'EmployeeAccessCredential',
    vct: `${BETA_ORIGIN}/credentials/employee-access`,
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

function employeeApplicationTemplatePayload(credentialTemplateId) {
  return {
    organization_id: ORG_ID,
    name: RESOURCE_NAMES.application,
    description: 'Manual employee approval before access credential issuance.',
    credential_template_id: credentialTemplateId,
    form_fields: employeeClaims().map(({ name, display_name: label }) => ({
      field_id: name,
      label,
      field_type: 'TEXT',
      required: true,
      claim_mapping: name,
    })),
    evidence_requirements: [],
    required_checks: [],
    claim_collection_rules: [],
    approval_strategy: 'MANUAL',
    approval_policy_set_id: null,
    application_validity_days: 30,
    notification_config: {},
    ui_config: {},
  };
}

function employeePolicyPayload(credentialTemplate) {
  return {
    organization_id: ORG_ID,
    name: RESOURCE_NAMES.policy,
    description: 'Allow active employee credentials and enforce lifecycle status.',
    purpose: 'Employee access control',
    display_metadata: {
      title: 'Employee access',
      description: 'Present an active employee access credential.',
      purpose: 'employment_verification',
      purpose_description: 'Verify current employee access.',
      verifier_name: 'ElevenID LLC',
      verifier_logo_url: null,
      privacy_policy_url: null,
      terms_of_service_url: null,
    },
    required_claims: [{
      claim_name: 'employee_id',
      credential_type: null,
      value_constraint: null,
      predicate_spec: null,
    }],
    accepted_credential_types: ['EmployeeAccessCredential'],
    trust_profile_id: credentialTemplate.trust_profile_id || null,
    holder_binding: { required: false },
    freshness: null,
    issuer_constraints: null,
    credential_ranking_strategy: DEFAULT_CREDENTIAL_RANKING_STRATEGY,
    credential_ranking_weights: null,
    credential_requirements: [{
      credential_template_id: credentialTemplate.id,
      display_name: RESOURCE_NAMES.credential,
      description: 'Current employee access credential',
      required: true,
      credential_payload_format: 'w3c_vcdm_v2_sd_jwt',
      requested_claims: [requestedClaim('employee_id', {
        displayName: 'Employee ID',
        description: 'The employee identifier used for the access decision.',
        acceptDerived: false,
      })],
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

function employeeFlowPayload(credentialTemplateId) {
  return {
    organization_id: ORG_ID,
    name: RESOURCE_NAMES.flow,
    description: 'Issue the approved D-04 employee access credential.',
    flow_type: 'oid4vci_pre_authorized',
    approval_strategy: 'AUTO',
    credential_template_id: credentialTemplateId,
    trigger: {
      trigger_type: 'WEBHOOK',
      config: { event_type: 'APPLICATION_APPROVED' },
    },
  };
}

function requireConfigurationBinding(configuration) {
  const expectedClaims = employeeClaims().map(({ name }) => name);
  const exactArray = (actual, expected) => (
    Array.isArray(actual)
    && actual.length === expected.length
    && actual.every((value, index) => value === expected[index])
  );
  if (configuration.credential.credential_type !== 'EmployeeAccessCredential'
      || configuration.credential.vct !== `${BETA_ORIGIN}/credentials/employee-access`
      || !exactArray(configuration.credential.claims?.map(({ name }) => name), expectedClaims)) {
    throw new Error('D-04 Credential Template has drifted from the employee credential contract');
  }
  if (configuration.application.credential_template_id !== configuration.credential.id) {
    throw new Error('D-04 Application Template is bound to the wrong Credential Template');
  }
  if (configuration.flow.credential_template_id !== configuration.credential.id
      || configuration.flow.application_template_id) {
    throw new Error('D-04 issuance Flow is not bound to the exact employee Credential Template');
  }
  const requirement = configuration.policy.credential_requirements?.[0];
  const requested = requirement?.requested_claims?.[0];
  if (requirement?.credential_template_id !== configuration.credential.id) {
    throw new Error('D-04 Presentation Policy is bound to the wrong Credential Template');
  }
  if (configuration.application.approval_strategy !== 'MANUAL') {
    throw new Error('D-04 Application Template must require manual approval');
  }
  if (!exactArray(configuration.application.form_fields?.map(({ field_id: fieldId }) => fieldId), expectedClaims)) {
    throw new Error('D-04 Application Template has drifted from the employee claim contract');
  }
  if (!exactArray(configuration.policy.accepted_credential_types, ['EmployeeAccessCredential'])
      || configuration.policy.credential_ranking_strategy !== DEFAULT_CREDENTIAL_RANKING_STRATEGY
      || configuration.policy.credential_requirements?.length !== 1
      || requirement?.requested_claims?.length !== 1
      || requested?.claim_name !== 'employee_id'
      || requested?.required !== true
      || requested?.selective_disclosure !== true
      || requested?.accept_derived !== false
      || requested?.constraints?.length !== 0) {
    throw new Error('D-04 Presentation Policy has drifted from the employee access contract');
  }
  if (configuration.flow.approval_strategy !== 'AUTO'
      || configuration.flow.trigger?.trigger_type !== 'WEBHOOK'
      || configuration.flow.trigger?.config?.event_type !== 'APPLICATION_APPROVED') {
    throw new Error('D-04 issuance Flow has drifted from the approval event contract');
  }
  return configuration;
}

async function ensureConfiguration(page) {
  const source = await requireJson(
    page,
    `/v1/credential-templates/${encodeURIComponent(SOURCE_TEMPLATE_ID)}`,
    {},
    'Load D-04 source Credential Template',
  );
  if (!source.issuer_did || !source.compliance_profile_id || !source.revocation_profile_id) {
    throw new Error('D-04 source Credential Template lacks issuer, compliance, or revocation binding');
  }
  const credential = await ensureActiveResource(page, {
    organizationId: ORG_ID,
    collectionPath: '/v1/credential-templates',
    name: RESOURCE_NAMES.credential,
    payload: employeeCredentialPayload(source),
    idempotencyKey: 'demo-d04-employee-credential-v1',
  });
  const application = await ensureActiveResource(page, {
    organizationId: ORG_ID,
    collectionPath: '/v1/application-templates',
    name: RESOURCE_NAMES.application,
    payload: employeeApplicationTemplatePayload(credential.id),
    idempotencyKey: 'demo-d04-employee-application-v1',
    validate: true,
  });
  const policy = await ensureActiveResource(page, {
    organizationId: ORG_ID,
    collectionPath: '/v1/presentation-policies',
    name: RESOURCE_NAMES.policy,
    payload: employeePolicyPayload(credential),
    idempotencyKey: 'demo-d04-employee-access-policy-v1',
  });
  const flow = await ensureActiveResource(page, {
    organizationId: ORG_ID,
    collectionPath: '/v1/flows/definitions',
    name: RESOURCE_NAMES.flow,
    payload: employeeFlowPayload(credential.id),
    idempotencyKey: 'demo-d04-employee-issuance-flow-v1',
    validate: true,
  });
  return requireConfigurationBinding({ credential, application, policy, flow });
}

async function createAndSubmitApplication(page, applicationTemplateId, employeeId) {
  const formData = {
    employee_id: employeeId,
    given_name: process.env.TEST_APPLICANT_FIRST_NAME || 'Jamie',
    family_name: process.env.TEST_APPLICANT_LAST_NAME || 'Lee',
    department: 'Security Engineering',
    access_level: 'Beta Facility',
    employment_status: 'Active',
  };
  const created = await requireJson(page, '/v1/me/applications', {
    method: 'POST',
    body: JSON.stringify({
      organization_id: ORG_ID,
      application_template_id: applicationTemplateId,
      form_data: formData,
      integration_context: {},
    }),
  }, 'Create employee application');
  const submitted = await requireJson(
    page,
    `/v1/me/applications/${encodeURIComponent(created.id)}/submit`,
    { method: 'POST' },
    'Submit employee application',
  );
  return { created, submitted, formData };
}

async function approveAndIssue(page, applicationId) {
  const root = `/v1/organizations/${encodeURIComponent(ORG_ID)}/applicants/${encodeURIComponent(applicationId)}`;
  const lock = await requireJson(page, `${root}/lock`, { method: 'POST' }, 'Acquire reviewer lock');
  const approved = await requireJson(page, `${root}/approve`, {
    method: 'POST',
    body: JSON.stringify({ notes: 'D-04 release qualification approval' }),
  }, 'Approve employee application');
  await requireJson(page, `${root}/lock`, { method: 'DELETE' }, 'Release reviewer lock');
  const issued = await requireJson(page, `${root}/issue`, { method: 'POST' }, 'Issue employee credential');
  return { lock, approved, issued };
}

async function cleanup(page, applicationId, credentialId) {
  return cleanupApplicationCredential(page, {
    organizationId: ORG_ID,
    applicationId,
    credentialId,
    reason: 'D-04 release qualification cleanup',
  });
}

async function showEmployeeStep(page, title, detail) {
  return showStep(page, title, detail, {
    enabled: RECORD_VIDEO,
    eyebrow: 'Employee onboarding and status-aware access',
  });
}

async function main() {
  const adminEmail = process.env.TEST_VENDOR_EMAIL || process.env.TEST_ADMIN_EMAIL;
  const adminPassword = process.env.TEST_VENDOR_PASSWORD || process.env.TEST_ADMIN_PASSWORD;
  const applicantEmail = process.env.TEST_APPLICANT_EMAIL || process.env.TEST_APPLICANT1_EMAIL;
  const applicantPassword = process.env.TEST_APPLICANT_PASSWORD || process.env.TEST_APPLICANT1_PASSWORD;
  if (!adminEmail || !adminPassword || !applicantEmail || !applicantPassword) {
    throw new Error('Missing beta administrator or applicant credentials');
  }
  if (!VERIFIER_DID) throw new Error('BETA_AUDIT_VERIFIER_DID is required');

  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '').toLowerCase();
  const startedAt = new Date(Date.now() - 5_000).toISOString();
  const artifactDir = createArtifactDir(ROOT, `beta-employee-access-${stamp}`);
  const employeeId = `EMP-D04-${stamp}`;
  const report = {
    createdAt: new Date().toISOString(),
    organizationId: ORG_ID,
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
      employeeId,
    );
    applicationId = application.created.id;
    report.application = {
      created: Boolean(applicationId),
      id: applicationId,
      employeeId,
      submittedStatus: application.submitted.status,
    };

    await page.goto(`${BETA_ORIGIN}/console/org/operate/applications/${encodeURIComponent(applicationId)}`, {
      waitUntil: 'domcontentloaded',
      timeout: 60_000,
    });
    await page.getByText(employeeId).first().waitFor({ state: 'visible', timeout: 30_000 });
    await showEmployeeStep(page, 'Employee application submitted', 'A real applicant submitted the employee fields and the organization review queue requires a decision.');

    const approval = await approveAndIssue(page, applicationId);
    report.application.lockAcquired = Boolean(approval.lock?.id);
    report.application.approvalOk = String(approval.approved?.status || '').toUpperCase() === 'APPROVED';
    report.application.approvedStatus = approval.approved?.status || null;
    const offerUri = approval.issued?.credential_offer_uri
      || Object.values(approval.issued?.credential_offer_uris || {})[0]
      || null;
    report.issuance = {
      issueOk: Boolean(offerUri),
      vct: configuration.credential.vct,
    };
    await page.reload({ waitUntil: 'domcontentloaded' });
    await showEmployeeStep(page, 'Employee approved and credential offered', 'The reviewer lock, approval transition, and application-bound Rust issuance flow all completed.');
    if (!offerUri) throw new Error('Employee issuance returned no credential offer');

    const walletReceipt = await receiveCredential(walletPage, offerUri, configuration.credential.vct);
    report.issuance.walletReceived = walletReceipt.ok;
    const credential = await findCurrentCredential(page, {
      organizationId: ORG_ID,
      credentialTemplateId: configuration.credential.id,
      startedAt,
      waitFor,
    });
    if (!credential?.id) throw new Error('Issued employee credential was not discoverable');
    credentialId = credential.id;
    report.issuance.credentialId = credentialId;
    await showEmployeeStep(page, 'Employee credential received', 'The holder accepted the real OpenID4VCI offer for the D-04 employee credential.');

    const activeStatus = await getCredentialStatus(page, credentialId);
    const activeVerification = await verify(page, walletPage, 'D-04 active employee access', {
      organizationId: ORG_ID,
      presentationPolicyId: configuration.policy.id,
      issuerDid: VERIFIER_DID,
    });
    report.activeAccess = {
      credentialStatus: activeStatus.lifecycleStatus,
      result: activeVerification.result,
    };
    await showEmployeeStep(page, 'Active employee access allowed', 'The status-aware access policy returned an explicit allow decision for the active credential.');

    await page.goto(`${BETA_ORIGIN}/console/org/operate/issuance`, {
      waitUntil: 'domcontentloaded',
      timeout: 60_000,
    });
    const row = await findCredentialRow(page, credentialId);
    const suspended = await performLifecycleAction(
      page,
      row,
      'suspend',
      'D-04 employee access suspension qualification',
    );
    const suspendedStatus = await getCredentialStatus(page, credentialId);
    const suspendedVerification = await verify(page, walletPage, 'D-04 suspended employee access', {
      organizationId: ORG_ID,
      presentationPolicyId: configuration.policy.id,
      issuerDid: VERIFIER_DID,
    });
    report.suspension = {
      actionOk: suspended.ok,
      credentialStatus: suspendedStatus.lifecycleStatus,
      result: suspendedVerification.result,
    };
    await showEmployeeStep(page, 'Suspended employee access denied', 'The same credential now receives an explicit deny decision because its lifecycle status is suspended.');

    report.behaviorAssertions = employeeAccessBehaviorAssertions(report);
    report.cleanup = await cleanup(page, applicationId, credentialId);
    cleanupComplete = report.cleanup.credentialRevoked && report.cleanup.applicationWithdrawn;
    report.releaseReady = Boolean(
      report.configuration.allActive
      && Object.values(report.behaviorAssertions).every((passed) => passed === true)
      && report.cleanup.credentialRevoked
      && report.cleanup.applicationWithdrawn
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
        application: path.relative(
          ROOT,
          await finalizeVideo(adminVideo, artifactDir, 'employee-onboarding-secure-access.webm'),
        ),
        wallet: path.relative(
          ROOT,
          await finalizeVideo(walletVideo, artifactDir, 'employee-onboarding-secure-access-wallet.webm'),
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
  employeeApplicationTemplatePayload,
  employeeCredentialPayload,
  employeeFlowPayload,
  employeePolicyPayload,
  requireConfigurationBinding,
};
