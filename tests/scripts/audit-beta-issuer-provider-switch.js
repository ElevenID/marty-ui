#!/usr/bin/env node
/* eslint-disable no-console */
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('@playwright/test');

const {
  issueCredential,
  login,
  selectOrg,
} = require('./audit-beta-credential-lifecycle');
const {
  didWebResolutionUrl,
  receiveAndVerifyCredential,
  verificationMethodFromDidDocument,
  verifyCompactJws,
  verifyCompactJwsStructure,
} = require('./run-canvas-oss-standard-contract');
const {
  DEFAULT_BETA_ORGANIZATION_ID,
  DEFAULT_LIFECYCLE_SOURCE_TEMPLATE_ID,
} = require('./beta-credential-contract');
const {
  providerSwitchBehaviorAssertions,
} = require('./beta-issuer-provider-switch-contract');
const { loadEnvFile, redact } = require('./verify-beta-waltid-acceptance');
const {
  VIDEO_SIZE,
  createArtifactDir,
  finalizeVideo,
  showStep,
} = require('./demo-recording');
const {
  ensureGovernedIssuer,
  safeErrorDetail,
} = require('./beta-demo-resource-helpers');

const ROOT = path.resolve(__dirname, '..', '..');
loadEnvFile(path.join(ROOT, '.env.tunnel.beta.local'));
loadEnvFile(path.join(ROOT, '.env'));

const BETA_ORIGIN = process.env.BETA_ORIGIN || 'https://beta.elevenidllc.com';
const ORG_ID = process.env.BETA_AUDIT_ORG_ID || DEFAULT_BETA_ORGANIZATION_ID;
const SOURCE_TEMPLATE_ID = process.env.BETA_AUDIT_TEMPLATE_ID
  || DEFAULT_LIFECYCLE_SOURCE_TEMPLATE_ID;
const HEADLESS = process.env.HEADED !== '1';
const RECORD_VIDEO = process.env.RECORD_VIDEO === '1';
const LOCAL_BETA_PROXY = process.env.BETA_LOCAL_PROXY === '1';
const MANAGED_SERVICE_ID = 'managed-openbao-transit';
const INTERNAL_OPENBAO_ENDPOINT = 'http://openbao:8200';

async function showProviderStep(page, title, detail) {
  return showStep(page, title, detail, {
    enabled: RECORD_VIDEO,
    eyebrow: 'Stable issuer identity with pluggable KMS custody',
  });
}

async function browserJson(page, pathName, options = {}) {
  return page.evaluate(async ({ requestPath, requestOptions }) => {
    const response = await fetch(requestPath, {
      credentials: 'include',
      ...requestOptions,
      headers: {
        ...(requestOptions.body ? { 'Content-Type': 'application/json' } : {}),
        ...(requestOptions.headers || {}),
      },
    });
    const body = await response.json().catch(() => null);
    return { ok: response.ok, status: response.status, body };
  }, { requestPath: pathName, requestOptions: options });
}

async function loadSigningConfig(page) {
  const response = await browserJson(
    page,
    `/v1/signing-keys/config?organization_id=${encodeURIComponent(ORG_ID)}`,
  );
  if (!response.ok || !response.body || !Array.isArray(response.body.services)) {
    throw new Error(`Signing configuration is unavailable (HTTP ${response.status})`);
  }
  return response.body;
}

function writableConfig(config, { extraServices = [], defaultServiceId, resetDefaults = false } = {}) {
  const replacements = new Set(extraServices.map((service) => service.id));
  const services = config.services
    .filter((service) => service.id !== MANAGED_SERVICE_ID && !service.managed)
    .filter((service) => !replacements.has(service.id))
    .concat(extraServices);
  return {
    services,
    default_service_id: defaultServiceId ?? config.default_service_id,
    format_defaults: resetDefaults ? {} : (config.format_defaults || {}),
    type_defaults: resetDefaults ? {} : (config.type_defaults || {}),
    key_reference_purposes: config.key_reference_purposes || {},
  };
}

async function saveSigningConfig(page, payload) {
  const response = await browserJson(
    page,
    `/v1/signing-keys/config?organization_id=${encodeURIComponent(ORG_ID)}`,
    { method: 'PATCH', body: JSON.stringify(payload) },
  );
  if (!response.ok) {
    throw new Error(`Signing configuration update failed (HTTP ${response.status})`);
  }
  return response.body;
}

function identityRequest(issuerDid) {
  return {
    organization_id: ORG_ID,
    issuer_did: issuerDid,
    key_purpose: 'vc_jwt_issuer',
    credential_format: 'SD_JWT_VC',
    algorithm: 'ES256',
  };
}

async function createIdentity(page, issuerDid, idempotencyKey) {
  const response = await browserJson(
    page,
    `/v1/signing-keys/issuer-identities?organization_id=${encodeURIComponent(ORG_ID)}`,
    {
      method: 'POST',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: JSON.stringify(identityRequest(issuerDid)),
    },
  );
  return {
    ok: response.ok,
    status: response.status,
    created: response.body?.created === true,
    identity: response.body?.identity || null,
  };
}

async function signingKeyForIdentity(page, issuerDid) {
  const response = await browserJson(
    page,
    `/v1/signing-keys?organization_id=${encodeURIComponent(ORG_ID)}`,
  );
  const key = response.body?.keys?.find((candidate) => (
    candidate.name === issuerDid
    && candidate.service_id === MANAGED_SERVICE_ID
    && candidate.algorithm === 'ES256'
  ));
  if (!response.ok || !key?.provider_key_name) {
    throw new Error('The managed seed identity did not expose its public signing-key inventory entry');
  }
  return key.provider_key_name;
}

function transitService(id, name, keyReference) {
  return {
    id,
    name,
    description: 'Release-scoped provider-switch qualification service.',
    service_type: 'openbao-transit',
    provider: 'openbao',
    endpoint: INTERNAL_OPENBAO_ENDPOINT,
    mount: 'transit',
    namespace: '',
    region: '',
    auth_mode: 'service_token',
    auth_reference: 'Managed by Marty service stack',
    key_reference: keyReference,
    key_aliases: [keyReference],
    algorithms: ['ES256'],
    key_purposes: ['vc_jwt_issuer'],
    credential_formats: ['dc+sd-jwt'],
    status: 'configured',
  };
}

async function createTemplateVersion(page, issuerDid, stamp) {
  const result = await page.evaluate(async ({ issuer, sourceTemplateId, versionStamp }) => {
    const sourceResponse = await fetch(
      `/v1/credential-templates/${encodeURIComponent(sourceTemplateId)}`,
      { credentials: 'include' },
    );
    const source = await sourceResponse.json().catch(() => null);
    if (!sourceResponse.ok || !source?.id) {
      return { ok: false, status: sourceResponse.status, error: 'Source template unavailable' };
    }
    const versionResponse = await fetch(
      `/v1/credential-templates/${encodeURIComponent(sourceTemplateId)}/new-version`,
      { method: 'POST', credentials: 'include' },
    );
    const version = await versionResponse.json().catch(() => null);
    if (!versionResponse.ok || !version?.id) {
      return { ok: false, status: versionResponse.status, error: 'Template version creation failed' };
    }
    const patchResponse = await fetch(`/v1/credential-templates/${encodeURIComponent(version.id)}`, {
      method: 'PATCH',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: `D-02 Provider Switch ${versionStamp}`,
        issuer_did: issuer,
      }),
    });
    const patched = await patchResponse.json().catch(() => null);
    if (!patchResponse.ok) {
      return {
        ok: false,
        status: patchResponse.status,
        templateId: version.id,
        error: 'Template update failed',
        errorBody: patched,
      };
    }
    const activateResponse = await fetch(
      `/v1/credential-templates/${encodeURIComponent(version.id)}/activate`,
      { method: 'POST', credentials: 'include' },
    );
    const activated = await activateResponse.json().catch(() => null);
    return {
      ok: activateResponse.ok,
      status: activateResponse.status,
      templateId: version.id,
      template: activateResponse.ok ? activated : null,
      errorBody: activateResponse.ok ? null : activated,
    };
  }, {
    issuer: issuerDid,
    sourceTemplateId: SOURCE_TEMPLATE_ID,
    versionStamp: stamp,
  });
  return {
    ...result,
    error: result.ok
      ? null
      : `${result.error || 'Template activation failed'}${safeErrorDetail(result.errorBody)}`,
    errorBody: undefined,
  };
}

function governedIssuerRequest(sourceTemplate, issuerDid, stamp) {
  if (!sourceTemplate?.trust_profile_id) {
    throw new Error('D-02 source Credential Template lacks a Trust Profile binding');
  }
  return {
    organizationId: ORG_ID,
    trustProfileId: sourceTemplate.trust_profile_id,
    issuerDid,
    displayName: `D-02 Provider Switch Issuer ${stamp}`,
    idempotencyKey: `d02-governed-issuer-${stamp}`,
  };
}

function credentialEvidence(issued) {
  return {
    verified: true,
    issuerDid: issued.payload.iss,
    kid: issued.header.kid,
    algorithm: issued.header.alg,
    vct: issued.payload.vct,
  };
}

async function issueAndVerify(page, template) {
  const issuance = await issueCredential(page, template.id);
  if (!issuance.ok || !issuance.offerUri) {
    throw new Error(`Credential issuance failed (HTTP ${issuance.status})`);
  }
  const issued = await receiveAndVerifyCredential(issuance.offerUri, template, BETA_ORIGIN);
  return {
    issuance: {
      ok: issuance.ok,
      status: issuance.status,
      templateName: issuance.templateName,
      expectedVct: issuance.expectedVct,
    },
    credential: credentialEvidence(issued),
    issued,
  };
}

async function didDocument(issuerDid) {
  const response = await fetch(didWebResolutionUrl(issuerDid), {
    headers: { Accept: 'application/did+json, application/json' },
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error(`Issuer DID resolution failed (HTTP ${response.status})`);
  return response.json();
}

async function reverifyIssuedCredential(issued) {
  const compact = issued.credential.split('~')[0];
  const structure = verifyCompactJwsStructure(compact);
  const document = await didDocument(structure.payload.iss);
  const method = verificationMethodFromDidDocument(document, structure.header.kid);
  const verified = verifyCompactJws(compact, method.publicKeyJwk);
  return {
    verified: verified.payload.iss === structure.payload.iss,
    assertionMethodIds: (document.assertionMethod || []).map((entry) => (
      typeof entry === 'string' ? entry : entry?.id
    )).filter(Boolean),
  };
}

async function rebindThroughConsole(page, issuerDid) {
  await page.goto(`${BETA_ORIGIN}/console/org/deploy/issuer-identity`, {
    waitUntil: 'domcontentloaded',
    timeout: 60_000,
  });
  const row = page.locator('tbody tr').filter({ hasText: issuerDid }).first();
  await row.waitFor({ state: 'visible', timeout: 30_000 });
  const responsePromise = page.waitForResponse((response) => (
    new URL(response.url()).pathname === '/v1/signing-keys/issuer-identities'
    && response.request().method() === 'PATCH'
  ), { timeout: 60_000 });
  await row.getByRole('button', { name: 'Move identity to default signing service' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Move identity' }).click();
  const response = await responsePromise;
  const body = await response.json().catch(() => null);
  return {
    ok: response.ok(),
    status: response.status(),
    changed: body?.changed === true,
    identity: body?.identity || null,
  };
}

async function directRebind(page, issuerDid) {
  const response = await browserJson(
    page,
    `/v1/signing-keys/issuer-identities?organization_id=${encodeURIComponent(ORG_ID)}`,
    { method: 'PATCH', body: JSON.stringify(identityRequest(issuerDid)) },
  );
  return { ok: response.ok, status: response.status };
}

async function cleanup(page, templateId, issuerDids, governance = null) {
  const results = {
    retiredTemplate: !templateId,
    templateRetirement: templateId ? null : 'not-created',
    revokedCredentials: 0,
    removedGovernanceRelationships: 0,
    removedGovernedIssuers: 0,
    retiredIdentities: 0,
  };
  if (templateId) {
    const list = await browserJson(
      page,
      `/v1/issued-credentials?organization_id=${encodeURIComponent(ORG_ID)}`,
    );
    const credentials = Array.isArray(list.body) ? list.body : [];
    for (const credential of credentials) {
      if (credential.credential_template_id !== templateId
        || String(credential.status).toUpperCase() !== 'ACTIVE') continue;
      const revoked = await browserJson(
        page,
        `/v1/issued-credentials/${encodeURIComponent(credential.id)}/revoke`,
        { method: 'POST', body: JSON.stringify({ reason: 'D-02 release qualification cleanup' }) },
      );
      if (revoked.ok) results.revokedCredentials += 1;
    }
    const current = await browserJson(
      page,
      `/v1/credential-templates/${encodeURIComponent(templateId)}`,
    );
    const status = String(current.body?.status || '').toUpperCase();
    const retirement = status === 'DRAFT'
      ? await browserJson(page, `/v1/credential-templates/${encodeURIComponent(templateId)}`, {
        method: 'DELETE',
      })
      : await browserJson(
        page,
        `/v1/credential-templates/${encodeURIComponent(templateId)}/deprecate`,
        { method: 'POST' },
      );
    results.retiredTemplate = retirement.ok;
    results.templateRetirement = status === 'DRAFT' ? 'deleted' : 'deprecated';
  }
  if (governance?.relationshipCreated && governance.relationship?.id) {
    const removed = await browserJson(
      page,
      `/v1/trust-profiles/${encodeURIComponent(governance.trustProfileId)}`
        + `/issuers/${encodeURIComponent(governance.relationship.id)}`,
      { method: 'DELETE' },
    );
    if (removed.ok) results.removedGovernanceRelationships += 1;
  }
  if (governance?.created && governance.issuer?.id) {
    const removed = await browserJson(
      page,
      `/v1/issuer-entities/${encodeURIComponent(governance.issuer.id)}`,
      { method: 'DELETE' },
    );
    if (removed.ok) results.removedGovernedIssuers += 1;
  }
  for (const issuerDid of issuerDids) {
    const response = await browserJson(
      page,
      `/v1/signing-keys/issuer-identities?organization_id=${encodeURIComponent(ORG_ID)}`,
      { method: 'DELETE', body: JSON.stringify(identityRequest(issuerDid)) },
    );
    if (response.ok) results.retiredIdentities += 1;
  }
  return results;
}

async function main() {
  const email = process.env.TEST_VENDOR_EMAIL || process.env.TEST_ADMIN_EMAIL;
  const password = process.env.TEST_VENDOR_PASSWORD || process.env.TEST_ADMIN_PASSWORD;
  if (!email || !password) throw new Error('Missing beta operator credentials');

  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '').toLowerCase();
  const artifactDir = createArtifactDir(ROOT, `beta-issuer-provider-switch-${stamp}`);
  const issuerDid = `did:web:${new URL(BETA_ORIGIN).host}:orgs:d02-provider-switch-${stamp}`;
  const seedDid = `did:web:${new URL(BETA_ORIGIN).host}:orgs:d02-provider-seed-${stamp}`;
  const providerBId = `d02-provider-b-${stamp}`;
  const providerCId = `d02-provider-unpublished-${stamp}`;
  const report = {
    createdAt: new Date().toISOString(),
    organizationId: ORG_ID,
    issuerDid,
    sourceTemplateId: SOURCE_TEMPLATE_ID,
    pageErrors: [],
    unexpectedResponses: [],
  };
  const browser = await chromium.launch({
    headless: HEADLESS,
    args: LOCAL_BETA_PROXY
      ? ['--host-resolver-rules=MAP beta.elevenidllc.com 127.0.0.1', '--no-proxy-server']
      : [],
  });
  let context;
  let originalConfig;
  try {
    context = await browser.newContext({
      viewport: VIDEO_SIZE,
      ignoreHTTPSErrors: LOCAL_BETA_PROXY,
      ...(RECORD_VIDEO ? { recordVideo: { dir: artifactDir, size: VIDEO_SIZE } } : {}),
    });
    const page = await context.newPage();
    const video = page.video();
    page.on('pageerror', (error) => report.pageErrors.push(redact(error.message)));
    page.on('response', (response) => {
      if (!response.url().startsWith(BETA_ORIGIN) || response.status() < 400) return;
      const expectedDeniedRebind = response.status() === 503
        && response.request().method() === 'PATCH'
        && new URL(response.url()).pathname === '/v1/signing-keys/issuer-identities';
      if (!expectedDeniedRebind && !response.url().includes('/cdn-cgi/rum')) {
        report.unexpectedResponses.push({
          status: response.status(),
          method: response.request().method(),
          url: redact(response.url()),
        });
      }
    });

    await login(page, email, password);
    report.orgSelection = await selectOrg(page);
    if (!report.orgSelection.ok) throw new Error(`Cannot select organization ${ORG_ID}`);
    originalConfig = await loadSigningConfig(page);

    let templateId = null;
    let governance = null;
    let qualificationError = null;
    const createdIdentityDids = [];
    try {
      const managedConfig = await saveSigningConfig(page, writableConfig(originalConfig, {
        defaultServiceId: MANAGED_SERVICE_ID,
        resetDefaults: true,
      }));
      report.providerAConfig = {
        defaultServiceId: managedConfig.default_service_id,
        serviceId: MANAGED_SERVICE_ID,
      };

      report.identityCreation = await createIdentity(page, issuerDid, `d02-identity-${stamp}`);
      if (!report.identityCreation.ok) throw new Error(`Issuer identity creation failed (HTTP ${report.identityCreation.status})`);
      if (report.identityCreation.created) createdIdentityDids.push(issuerDid);
      report.seedIdentityCreation = await createIdentity(page, seedDid, `d02-seed-${stamp}`);
      if (!report.seedIdentityCreation.ok) {
        throw new Error(`Provider-B seed identity creation failed (HTTP ${report.seedIdentityCreation.status})`);
      }
      if (report.seedIdentityCreation.created) createdIdentityDids.push(seedDid);

      const sourceTemplate = await browserJson(
        page,
        `/v1/credential-templates/${encodeURIComponent(SOURCE_TEMPLATE_ID)}`,
      );
      if (!sourceTemplate.ok || !sourceTemplate.body?.id) {
        throw new Error(
          `D-02 source Credential Template unavailable (HTTP ${sourceTemplate.status})`
          + safeErrorDetail(sourceTemplate.body),
        );
      }
      const governanceRequest = governedIssuerRequest(sourceTemplate.body, issuerDid, stamp);
      governance = {
        ...(await ensureGovernedIssuer(page, governanceRequest)),
        trustProfileId: governanceRequest.trustProfileId,
      };
      report.governance = {
        issuerEntityId: governance.issuer.id,
        relationshipId: governance.relationship.id,
        trustProfileId: governance.trustProfileId,
        created: governance.created,
        relationshipCreated: governance.relationshipCreated,
      };

      report.template = await createTemplateVersion(page, issuerDid, stamp);
      templateId = report.template.templateId || null;
      if (!report.template.ok || !report.template.template?.id) {
        throw new Error(`D-02 template setup failed: ${report.template.error}`);
      }
      const template = report.template.template;
      report.template = { ok: true, id: template.id, name: template.name, vct: template.vct };

      await page.goto(`${BETA_ORIGIN}/console/org/deploy/issuer-identity`, {
        waitUntil: 'domcontentloaded',
        timeout: 60_000,
      });
      await page.getByText(issuerDid).first().waitFor({ state: 'visible', timeout: 30_000 });
      await showProviderStep(page, 'Stable issuer DID created', 'The public identity is active without exposing provider or key coordinates.');

      const providerA = await issueAndVerify(page, template);
      report.providerA = { issuance: providerA.issuance, credential: providerA.credential };
      await showProviderStep(page, 'Credential signed by provider A', 'The first credential verifies against the DID method published by managed custody.');

      const providerBKey = await signingKeyForIdentity(page, seedDid);
      const latestConfig = await loadSigningConfig(page);
      const providerB = transitService(providerBId, `D-02 Provider B ${stamp}`, providerBKey);
      const providerBConfig = await saveSigningConfig(page, writableConfig(latestConfig, {
        extraServices: [providerB],
        defaultServiceId: providerBId,
        resetDefaults: true,
      }));
      report.providerBConfig = {
        defaultServiceId: providerBConfig.default_service_id,
        serviceId: providerBId,
      };

      report.rebind = await rebindThroughConsole(page, issuerDid);
      if (!report.rebind.ok || !report.rebind.changed) {
        throw new Error(`Provider switch failed (HTTP ${report.rebind.status})`);
      }
      await showProviderStep(page, 'Custody moved to provider B', 'The replacement public key was published before the active provider changed.');

      const providerBResult = await issueAndVerify(page, template);
      report.providerB = {
        issuance: providerBResult.issuance,
        credential: providerBResult.credential,
      };
      const oldReverification = await reverifyIssuedCredential(providerA.issued);
      report.providerA.reverifiedAfterSwitch = oldReverification.verified;
      report.didAfterSwitch = { assertionMethodIds: oldReverification.assertionMethodIds };
      await showProviderStep(page, 'One DID, both credentials valid', 'New issuance uses provider B while the provider-A credential remains verifiable through the retained DID method.');

      const beforeFailureConfig = await loadSigningConfig(page);
      const unavailable = transitService(
        providerCId,
        `D-02 Unpublished Provider ${stamp}`,
        `d02-unpublished-key-${stamp}`,
      );
      await saveSigningConfig(page, writableConfig(beforeFailureConfig, {
        extraServices: [providerB, unavailable],
        defaultServiceId: providerCId,
        resetDefaults: true,
      }));
      const deniedRebind = await directRebind(page, issuerDid);
      const afterDenial = await issueAndVerify(page, template);
      report.unpublishedReplacement = {
        rebindOk: deniedRebind.ok,
        rebindStatus: deniedRebind.status,
        issueAfterDenial: afterDenial.issuance,
        credentialAfterDenial: afterDenial.credential,
      };
      await showProviderStep(page, 'Unpublished replacement denied', 'An unavailable replacement key cannot cut over custody; issuance continues on the last published provider-B method.');

      report.behaviorAssertions = providerSwitchBehaviorAssertions(report);
    } catch (error) {
      qualificationError = error;
      report.error = redact(error.stack || error.message || String(error));
    } finally {
      try {
        report.cleanup = await cleanup(page, templateId, createdIdentityDids, governance);
      } catch (error) {
        report.cleanupError = redact(error.stack || error.message || String(error));
      }
      if (originalConfig) {
        try {
          const restored = await saveSigningConfig(page, writableConfig(originalConfig));
          report.configRestored = {
            ok: restored.default_service_id === originalConfig.default_service_id
              && JSON.stringify(restored.format_defaults || {}) === JSON.stringify(originalConfig.format_defaults || {})
              && JSON.stringify(restored.type_defaults || {}) === JSON.stringify(originalConfig.type_defaults || {}),
            defaultServiceId: restored.default_service_id,
          };
        } catch (error) {
          report.configRestoreError = redact(error.stack || error.message || String(error));
        }
      }
    }

    report.releaseReady = Boolean(
      !qualificationError
      && Object.values(report.behaviorAssertions || {}).every((passed) => passed === true)
      && report.cleanup?.retiredTemplate
      && report.cleanup?.revokedCredentials >= 3
      && report.cleanup?.removedGovernanceRelationships === 1
      && report.cleanup?.removedGovernedIssuers === 1
      && report.cleanup?.retiredIdentities === 2
      && report.configRestored?.ok
      && report.pageErrors.length === 0
      && report.unexpectedResponses.length === 0
    );
    report.finishedAt = new Date().toISOString();
    await context.close();
    context = null;
    if (RECORD_VIDEO) {
      report.recording = path.relative(
        ROOT,
        await finalizeVideo(video, artifactDir, 'stable-issuer-identity-pluggable-kms.webm'),
      );
    }
    fs.writeFileSync(path.join(artifactDir, 'report.json'), JSON.stringify(report, null, 2));
    console.log(JSON.stringify(report, null, 2));
    if (!report.releaseReady) process.exitCode = 1;
  } finally {
    if (context) await context.close().catch(() => {});
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
  cleanup,
  credentialEvidence,
  governedIssuerRequest,
  identityRequest,
  transitService,
  writableConfig,
};
