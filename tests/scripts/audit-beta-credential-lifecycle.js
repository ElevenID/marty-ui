#!/usr/bin/env node
/* eslint-disable no-console */

const fs = require('fs');
const path = require('path');
const { chromium } = require('@playwright/test');
const { loadEnvFile, redact } = require('./verify-beta-waltid-acceptance');
const {
  VIDEO_SIZE,
  finalizeVideo,
  maskProtocolField,
  showStep,
} = require('./demo-recording');

const ROOT = path.resolve(__dirname, '..', '..');
loadEnvFile(path.join(ROOT, '.env.tunnel.beta.local'));
loadEnvFile(path.join(ROOT, '.env'));

const BETA_ORIGIN = process.env.BETA_ORIGIN || 'https://beta.elevenidllc.com';
const TEST_WALLET_ORIGIN = process.env.MARTY_TEST_WALLET_ORIGIN || 'http://127.0.0.1:8787';
const ORG_ID = process.env.BETA_AUDIT_ORG_ID || '02af5d70-04e6-40d8-80e2-3e8400d4b018';
const POLICY_ID = process.env.BETA_AUDIT_POLICY_ID || '43336aa5-4532-4a9d-95de-241ac97d5a2a';
const SOURCE_TEMPLATE_ID = process.env.BETA_AUDIT_TEMPLATE_ID || '1d9d2ea0-1a39-4fc3-99de-c786a5617f78';
const HEADLESS = process.env.HEADED !== '1';
const RECORD_VIDEO = process.env.RECORD_VIDEO === '1';

async function showLifecycleStep(page, title, detail) {
  return showStep(page, title, detail, {
    enabled: RECORD_VIDEO,
    eyebrow: 'Credential lifecycle and status-aware verification',
  });
}

async function waitFor(fn, timeoutMs = 60_000, intervalMs = 1_000) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    last = await fn();
    if (last) return last;
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error(`Timed out waiting for condition; last=${JSON.stringify(last)}`);
}

async function login(page, email, password) {
  await page.goto(`${BETA_ORIGIN}/v1/auth/login?redirect_uri=${encodeURIComponent('/console/org')}`, {
    waitUntil: 'domcontentloaded',
    timeout: 60_000,
  });
  await page.locator('#username, input[name="username"], input[type="email"]').first().fill(email);
  await page.locator('#password, input[name="password"], input[type="password"]').first().fill(password);
  await Promise.all([
    page.waitForURL((url) => url.origin === BETA_ORIGIN && url.pathname.startsWith('/console'), {
      timeout: 60_000,
    }).catch(() => {}),
    page.locator('#kc-login, button[type="submit"], input[type="submit"]').first().click(),
  ]);
  await waitFor(() => page.evaluate(async () => {
    const response = await fetch('/v1/auth/me', { credentials: 'include' });
    const body = await response.json().catch(() => null);
    return response.ok && body?.authenticated;
  }));
}

async function selectOrg(page) {
  const selection = await page.evaluate(async (organizationId) => {
    const response = await fetch('/v1/organizations/mine', { credentials: 'include' });
    const memberships = await response.json().catch(() => []);
    const target = memberships.find((item) => (
      item.id === organizationId && item.membership?.has_org_console_access
    ));
    return {
      ok: Boolean(target),
      name: target?.display_name || target?.name || null,
    };
  }, ORG_ID);
  if (!selection.ok) return selection;

  const orgButton = page.getByRole('button', {
    name: /Marty Identity Platform|Audit Production Flow|Select Organization/i,
  }).first();
  await orgButton.click({ timeout: 15_000 });
  await page.getByPlaceholder('Search organizations').fill(selection.name);
  await page.getByRole('menuitem').filter({ hasText: selection.name }).first().click();
  await waitFor(() => page.evaluate((organizationId) => (
    localStorage.getItem('activeOrgId') === organizationId
  ), ORG_ID));
  return { ...selection, activeOrgId: ORG_ID };
}

async function ensureActiveRevocationProfile(page, stamp) {
  const existing = await page.evaluate(async (organizationId) => {
    const response = await fetch(
      `/v1/revocation-profiles?organization_id=${encodeURIComponent(organizationId)}`,
      { credentials: 'include' },
    );
    const profiles = await response.json().catch(() => []);
    const active = Array.isArray(profiles)
      ? profiles.find((profile) => String(profile?.status || '').toUpperCase() === 'ACTIVE')
      : null;
    return active ? { ok: true, id: active.id, name: active.name, reused: true } : null;
  }, ORG_ID);
  if (existing) return existing;

  await page.goto(`${BETA_ORIGIN}/console/org/trust/revocation/new`, {
    waitUntil: 'domcontentloaded',
    timeout: 60_000,
  });
  await page.getByTestId('revocationWizard.name').fill(`Lifecycle Status ${stamp}`);
  const createResponsePromise = page.waitForResponse((response) => (
    response.url().endsWith('/v1/revocation-profiles')
    && response.request().method() === 'POST'
  ), { timeout: 30_000 });
  await page.getByTestId('revocationWizard.submit').click();
  const createResponse = await createResponsePromise;
  const created = await createResponse.json().catch(() => null);
  if (!createResponse.ok() || !created?.id) {
    return { ok: false, status: createResponse.status(), error: created?.detail || 'Profile creation failed' };
  }

  const activateResponsePromise = page.waitForResponse((response) => (
    response.url().endsWith(`/v1/revocation-profiles/${created.id}/activate`)
    && response.request().method() === 'POST'
  ), { timeout: 30_000 });
  await page.getByRole('button', { name: /^activate$/i }).click();
  const activateResponse = await activateResponsePromise;
  const activated = await activateResponse.json().catch(() => null);
  return {
    ok: activateResponse.ok() && String(activated?.status || '').toUpperCase() === 'ACTIVE',
    status: activateResponse.status(),
    id: created.id,
    name: created.name,
    reused: false,
    error: activateResponse.ok() ? null : activated?.detail || 'Profile activation failed',
  };
}

async function ensureLifecycleTemplate(page, revocationProfileId, stamp) {
  return page.evaluate(async ({ organizationId, sourceTemplateId, profileId, versionStamp }) => {
    const listResponse = await fetch(
      `/v1/credential-templates?organization_id=${encodeURIComponent(organizationId)}`,
      { credentials: 'include' },
    );
    const templates = await listResponse.json().catch(() => []);
    const source = Array.isArray(templates)
      ? templates.find((template) => template.id === sourceTemplateId)
      : null;
    if (!listResponse.ok || !source) {
      return { ok: false, status: listResponse.status, error: 'Source Credential Template unavailable' };
    }
    const existing = templates.find((template) => (
      template.id !== sourceTemplateId
      && template.vct === source.vct
      && template.revocation_profile_id === profileId
      && String(template.status || '').toUpperCase() === 'ACTIVE'
      && template.validity_rules?.renewable === true
      && Number(template.validity_rules?.reissue_within_seconds || 0)
        >= Number(template.validity_rules?.ttl_seconds || Number.MAX_SAFE_INTEGER)
    ));
    if (existing) return { ok: true, id: existing.id, name: existing.name, reused: true };

    const versionResponse = await fetch(
      `/v1/credential-templates/${encodeURIComponent(sourceTemplateId)}/new-version`,
      { method: 'POST', credentials: 'include' },
    );
    const version = await versionResponse.json().catch(() => null);
    if (!versionResponse.ok || !version?.id) {
      return { ok: false, status: versionResponse.status, error: version?.detail || 'Template version creation failed' };
    }
    const patchResponse = await fetch(`/v1/credential-templates/${encodeURIComponent(version.id)}`, {
      method: 'PATCH',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: `Lifecycle ${source.name} ${versionStamp}`,
        revocation_profile_id: profileId,
        validity_rules: {
          default_validity_days: 1,
          max_validity_days: 7,
          renewable: true,
          renewal_window_days: 7,
        },
      }),
    });
    const patched = await patchResponse.json().catch(() => null);
    if (!patchResponse.ok) {
      return {
        ok: false,
        status: patchResponse.status,
        error: patched?.detail || patched?.message || JSON.stringify(patched) || 'Template update failed',
      };
    }
    const activateResponse = await fetch(
      `/v1/credential-templates/${encodeURIComponent(version.id)}/activate`,
      { method: 'POST', credentials: 'include' },
    );
    const activated = await activateResponse.json().catch(() => null);
    return {
      ok: activateResponse.ok && String(activated?.status || '').toUpperCase() === 'ACTIVE',
      status: activateResponse.status,
      id: version.id,
      name: activated?.name || patched?.name,
      reused: false,
      error: activateResponse.ok ? null : activated?.detail || 'Template activation failed',
    };
  }, {
    organizationId: ORG_ID,
    sourceTemplateId: SOURCE_TEMPLATE_ID,
    profileId: revocationProfileId,
    versionStamp: stamp,
  });
}

async function cleanupLifecycleDrafts(page, sourceTemplateId, activeTemplateId) {
  return page.evaluate(async ({ organizationId, sourceId, activeId }) => {
    const listResponse = await fetch(
      `/v1/credential-templates?organization_id=${encodeURIComponent(organizationId)}`,
      { credentials: 'include' },
    );
    const templates = await listResponse.json().catch(() => []);
    const source = Array.isArray(templates)
      ? templates.find((template) => template.id === sourceId)
      : null;
    if (!listResponse.ok || !source) {
      return { ok: false, deleted: [], failures: [{ id: null, status: listResponse.status }] };
    }

    const drafts = templates.filter((template) => (
      template.id !== sourceId
      && template.id !== activeId
      && template.vct === source.vct
      && String(template.status || '').toUpperCase() === 'DRAFT'
      && (
        String(template.name || '').startsWith('Lifecycle ')
        || template.name === source.name
      )
    ));
    const results = await Promise.all(drafts.map(async (template) => {
      const response = await fetch(`/v1/credential-templates/${encodeURIComponent(template.id)}`, {
        method: 'DELETE',
        credentials: 'include',
      });
      return { id: template.id, status: response.status };
    }));
    return {
      ok: results.every((result) => result.status === 204),
      deleted: results.filter((result) => result.status === 204).map((result) => result.id),
      failures: results.filter((result) => result.status !== 204),
    };
  }, {
    organizationId: ORG_ID,
    sourceId: sourceTemplateId,
    activeId: activeTemplateId,
  });
}

async function issueCredential(page, templateId) {
  return page.evaluate(async ({ organizationId, templateId }) => {
    const templateResponse = await fetch(`/v1/credential-templates/${encodeURIComponent(templateId)}`, {
      credentials: 'include',
    });
    const template = await templateResponse.json().catch(() => null);
    if (!templateResponse.ok || !template) {
      return { ok: false, status: templateResponse.status, error: 'Credential Template unavailable' };
    }

    const claims = Object.fromEntries((template.claims || []).map((claim) => {
      const name = claim?.name || claim?.claim_name;
      const normalized = String(name || '').toLowerCase();
      const type = String(claim?.type || claim?.data_type || 'STRING').toUpperCase();
      const options = claim?.options || claim?.enum || [];
      let value;
      if (Array.isArray(options) && options.length) {
        const first = options[0];
        value = typeof first === 'object' ? first.value ?? first.label : first;
      } else if (type === 'DATE') value = '2026-07-12';
      else if (type === 'DATETIME') value = '2026-07-12T12:00:00Z';
      else if (type === 'NUMBER' || type === 'INTEGER') value = 1;
      else if (type === 'BOOLEAN') value = true;
      else if (normalized.includes('email')) value = 'lifecycle-holder@example.test';
      else if (normalized.includes('given') || normalized.includes('first')) value = 'Grace';
      else if (normalized.includes('family') || normalized.includes('last') || normalized.includes('surname')) value = 'Hopper';
      else if (normalized.includes('employee') || normalized.endsWith('_id')) value = `LIFECYCLE-${Date.now()}`;
      else if (normalized.includes('department')) value = 'Security';
      else if (normalized.includes('position') || normalized.includes('title')) value = 'Lifecycle Auditor';
      else value = `Lifecycle audit ${name || 'value'}`;
      return [name, value];
    }).filter(([name]) => Boolean(name)));

    const issuanceResponse = await fetch('/v1/issuance', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        organization_id: organizationId,
        credential_template_id: templateId,
        claims,
      }),
    });
    const body = await issuanceResponse.json().catch(() => null);
    return {
      ok: issuanceResponse.ok,
      status: issuanceResponse.status,
      templateName: template.name,
      expectedVct: template.vct,
      offerUri: body?.credential_offer_uri || body?.offer_url || null,
      error: issuanceResponse.ok ? null : body?.detail || body?.message || 'Issuance failed',
    };
  }, { organizationId: ORG_ID, templateId });
}

async function receiveCredential(walletPage, offerUri, expectedVct) {
  await walletPage.goto(TEST_WALLET_ORIGIN, { waitUntil: 'domcontentloaded', timeout: 60_000 });
  await walletPage.request.post(`${TEST_WALLET_ORIGIN}/api/reset`, { data: {} });
  await walletPage.reload({ waitUntil: 'domcontentloaded' });
  await maskProtocolField(walletPage, 'Credential offer URI', RECORD_VIDEO);
  await walletPage.getByLabel('Credential offer URI').fill(offerUri);
  const responsePromise = walletPage.waitForResponse((response) => (
    response.url() === `${TEST_WALLET_ORIGIN}/api/receive`
    && response.request().method() === 'POST'
  ), { timeout: 60_000 });
  await walletPage.getByRole('button', { name: /^receive$/i }).click();
  const response = await responsePromise;
  const body = await response.json().catch(() => null);
  await walletPage.getByRole('status').filter({ hasText: 'Credential received' }).waitFor({
    timeout: 60_000,
  }).catch(() => {});
  const inventory = await walletPage.locator('#credentials').innerText();
  return {
    ok: response.ok() && inventory.includes(expectedVct),
    status: response.status(),
    error: response.ok() ? null : body?.error || 'Wallet receipt failed',
  };
}

async function findIssuedCredential(page, templateId) {
  return waitFor(() => page.evaluate(async ({ organizationId, templateId }) => {
    const response = await fetch(
      `/v1/issued-credentials?organization_id=${encodeURIComponent(organizationId)}`,
      { credentials: 'include' },
    );
    const records = await response.json().catch(() => []);
    if (!response.ok || !Array.isArray(records)) return null;
    return records
      .filter((record) => record.credential_template_id === templateId)
      .sort((left, right) => (
        new Date(right.issued_at || 0).getTime() - new Date(left.issued_at || 0).getTime()
      ))[0] || null;
  }, { organizationId: ORG_ID, templateId }));
}

async function cleanupActiveLifecycleCredentials(page, templateId) {
  return page.evaluate(async ({ organizationId, templateId }) => {
    const listResponse = await fetch(
      `/v1/issued-credentials?organization_id=${encodeURIComponent(organizationId)}`,
      { credentials: 'include' },
    );
    const records = await listResponse.json().catch(() => []);
    if (!listResponse.ok || !Array.isArray(records)) {
      return { ok: false, status: listResponse.status, revoked: [], failures: ['list'] };
    }

    const active = records.filter((record) => (
      record.credential_template_id === templateId
      && String(record.status || '').toUpperCase() === 'ACTIVE'
    ));
    const revoked = [];
    const failures = [];
    for (const record of active) {
      const response = await fetch(
        `/v1/issued-credentials/${encodeURIComponent(record.id)}/revoke`,
        {
          method: 'POST',
          credentials: 'include',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ reason: 'Lifecycle audit fixture cleanup' }),
        },
      );
      if (response.ok) revoked.push(record.id);
      else failures.push({ id: record.id, status: response.status });
    }
    return { ok: failures.length === 0, status: listResponse.status, revoked, failures };
  }, { organizationId: ORG_ID, templateId });
}

async function performLifecycleAction(page, row, action, reason) {
  const responsePromise = page.waitForResponse((response) => (
    response.url().includes(`/v1/issued-credentials/`)
    && response.url().endsWith(`/${action}`)
    && response.request().method() === 'POST'
  ), { timeout: 30_000 });
  await row.getByRole('button', { name: new RegExp(`^${action} credential`, 'i') }).click();
  const dialog = page.getByRole('dialog', { name: new RegExp(`${action} credential`, 'i') });
  await dialog.getByRole('textbox', { name: /reason/i }).fill(reason);
  await dialog.getByRole('button', { name: new RegExp(`^${action}$`, 'i') }).click();
  const response = await responsePromise;
  const body = await response.json().catch(() => null);
  if (response.ok()) {
    await dialog.waitFor({ state: 'hidden', timeout: 30_000 });
  } else {
    await dialog.getByRole('button', { name: /cancel/i }).click().catch(() => {});
  }
  return { ok: response.ok(), status: response.status(), body };
}

async function renewCredential(page, row) {
  const responsePromise = page.waitForResponse((response) => (
    response.url().includes('/v1/issued-credentials/')
    && response.url().endsWith('/renew')
    && response.request().method() === 'POST'
  ), { timeout: 30_000 });
  await row.getByRole('button', { name: /^renew credential/i }).click();
  const response = await responsePromise;
  const body = await response.json().catch(() => null);
  return {
    ok: response.ok(),
    status: response.status(),
    offerUri: body?.credential_offer_uri || null,
    transactionId: body?.transaction_id || null,
    error: response.ok() ? null : body?.detail || 'Renewal failed',
  };
}

async function getCredentialStatus(page, credentialId) {
  return page.evaluate(async (id) => {
    const response = await fetch(`/v1/issued-credentials/${encodeURIComponent(id)}`, {
      credentials: 'include',
    });
    const body = await response.json().catch(() => null);
    return { ok: response.ok, status: response.status, lifecycleStatus: body?.status || null };
  }, credentialId);
}

async function present(walletPage, requestUri) {
  await maskProtocolField(walletPage, 'Presentation request URI', RECORD_VIDEO);
  await walletPage.getByLabel('Presentation request URI').fill(requestUri);
  const responsePromise = walletPage.waitForResponse((response) => (
    response.url() === `${TEST_WALLET_ORIGIN}/api/present`
    && response.request().method() === 'POST'
  ), { timeout: 60_000 });
  await walletPage.getByRole('button', { name: /^present$/i }).click();
  const response = await responsePromise;
  const body = await response.json().catch(() => null);
  return {
    ok: response.ok() && body?.ok === true,
    status: response.status(),
    error: response.ok() ? null : body?.error || 'Presentation failed',
  };
}

async function verify(page, walletPage, label) {
  const session = await page.evaluate(async ({ organizationId, policyId, externalReference }) => {
    const response = await fetch('/v1/flows/verify', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        organization_id: organizationId,
        presentation_policy_id: policyId,
        external_reference: externalReference,
      }),
    });
    const body = await response.json().catch(() => null);
    return {
      ok: response.ok,
      status: response.status,
      instanceId: body?.instance_id || body?.id || null,
      requestUri: body?.request_uri || null,
      error: response.ok ? null : body?.detail || body?.message || 'Session creation failed',
    };
  }, { organizationId: ORG_ID, policyId: POLICY_ID, externalReference: label });
  if (!session.ok || !session.instanceId || !session.requestUri) return { session };

  const wallet = await present(walletPage, session.requestUri);
    const result = await waitFor(() => page.evaluate(async (instanceId) => {
    const response = await fetch(`/v1/flows/instances/${encodeURIComponent(instanceId)}/result`, {
      credentials: 'include',
    });
    const body = await response.json().catch(() => null);
    if (!response.ok) return null;
    const terminal = ['COMPLETED', 'PASSED', 'VERIFIED', 'FAILED', 'EXPIRED', 'CANCELLED']
      .includes(String(body?.status || '').toUpperCase());
    return terminal ? {
      status: body.status,
      evaluation: body?.result?.evaluation_result || null,
      decision: body?.result?.decision || null,
      decisionReason: body?.result?.decision_reason || null,
    } : null;
  }, session.instanceId));
  return { session: { ...session, requestUri: '[present]' }, wallet, result };
}

async function main() {
  const email = process.env.TEST_VENDOR_EMAIL || process.env.TEST_ADMIN_EMAIL;
  const password = process.env.TEST_VENDOR_PASSWORD || process.env.TEST_ADMIN_PASSWORD;
  if (!email || !password) throw new Error('Missing beta operator credentials');

  const stamp = new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '');
  const artifactDir = process.env.DEMO_ARTIFACT_DIR
    ? path.resolve(process.env.DEMO_ARTIFACT_DIR)
    : path.join(ROOT, 'tests', 'artifacts', `beta-credential-lifecycle-${stamp}`);
  fs.mkdirSync(artifactDir, { recursive: true });
  const report = {
    createdAt: new Date().toISOString(),
    organizationId: ORG_ID,
    policyId: POLICY_ID,
    sourceTemplateId: SOURCE_TEMPLATE_ID,
    artifactDir,
    pageErrors: [],
    unexpectedResponses: [],
  };

  const browser = await chromium.launch({ headless: HEADLESS });
  try {
    const context = await browser.newContext({
      viewport: VIDEO_SIZE,
      ...(RECORD_VIDEO ? { recordVideo: { dir: artifactDir, size: VIDEO_SIZE } } : {}),
    });
    const page = await context.newPage();
    const walletPage = await context.newPage();
    const applicationVideo = page.video();
    const walletVideo = walletPage.video();
    page.on('pageerror', (error) => report.pageErrors.push(redact(error.message)));
    page.on('response', async (response) => {
      if (!response.url().startsWith(BETA_ORIGIN) || response.status() < 400) return;
      if (response.url().includes('/cdn-cgi/rum')) return;
      report.unexpectedResponses.push({
        status: response.status(),
        method: response.request().method(),
        url: redact(response.url()),
      });
    });

    await login(page, email, password);
    report.orgSelection = await selectOrg(page);
    if (!report.orgSelection.ok) throw new Error(`Cannot select organization ${ORG_ID}`);

    report.permissions = await page.evaluate(async (organizationId) => {
      const response = await fetch(
        `/v1/organizations/${encodeURIComponent(organizationId)}/members/me/permissions`,
        { credentials: 'include' },
      );
      const body = await response.json().catch(() => null);
      return {
        status: response.status,
        hasLifecyclePermission: body?.permissions?.includes('issuance:revoke') === true,
      };
    }, ORG_ID);

    report.revocationProfile = await ensureActiveRevocationProfile(page, stamp);
    if (!report.revocationProfile.ok) {
      throw new Error(`Revocation Profile setup failed: ${report.revocationProfile.error}`);
    }
    report.credentialTemplate = await ensureLifecycleTemplate(
      page,
      report.revocationProfile.id,
      stamp,
    );
    if (!report.credentialTemplate.ok) {
      throw new Error(`Credential Template setup failed: ${report.credentialTemplate.error}`);
    }
    report.templateId = report.credentialTemplate.id;
    report.draftCleanup = await cleanupLifecycleDrafts(
      page,
      SOURCE_TEMPLATE_ID,
      report.templateId,
    );
    report.credentialCleanup = await cleanupActiveLifecycleCredentials(page, report.templateId);
    if (!report.credentialCleanup.ok) {
      throw new Error(`Lifecycle credential cleanup failed: ${JSON.stringify(report.credentialCleanup.failures)}`);
    }

    report.issuance = await issueCredential(page, report.templateId);
    if (!report.issuance.ok || !report.issuance.offerUri) {
      throw new Error(`Issuance failed: ${report.issuance.error}`);
    }
    report.walletReceipt = await receiveCredential(
      walletPage,
      report.issuance.offerUri,
      report.issuance.expectedVct,
    );
    delete report.issuance.offerUri;
    if (!report.walletReceipt.ok) throw new Error(`Wallet receipt failed: ${report.walletReceipt.error}`);

    let credential = await findIssuedCredential(page, report.templateId);
    const sourceCredentialId = credential.id;

    await page.goto(`${BETA_ORIGIN}/console/org/operate/issuance`, {
      waitUntil: 'domcontentloaded',
      timeout: 60_000,
    });
    let row = page.getByRole('row').filter({ hasText: report.issuance.templateName }).first();
    await row.waitFor({ state: 'visible', timeout: 30_000 });
    await showLifecycleStep(page, 'Active credential issued', 'The issuer inventory shows the newly issued credential and its available lifecycle controls.');
    await page.screenshot({ path: path.join(artifactDir, '01-active-credential.png'), fullPage: true });

    report.renewalOffer = await renewCredential(page, row);
    if (!report.renewalOffer.ok || !report.renewalOffer.offerUri) {
      throw new Error(`Renewal failed: ${JSON.stringify(report.renewalOffer.error)}`);
    }
    report.renewalWalletReceipt = await receiveCredential(
      walletPage,
      report.renewalOffer.offerUri,
      report.issuance.expectedVct,
    );
    delete report.renewalOffer.offerUri;
    credential = await findIssuedCredential(page, report.templateId);
    const sourceAfterRenewal = await getCredentialStatus(page, sourceCredentialId);
    report.renewal = {
      ok: report.renewalWalletReceipt.ok
        && credential.renewed_from_credential_id === sourceCredentialId
        && String(sourceAfterRenewal.lifecycleStatus || '').toUpperCase() === 'REVOKED',
      sourceCredentialId,
      renewedCredentialId: credential.id,
      renewedFromCredentialId: credential.renewed_from_credential_id || null,
      sourceStatus: sourceAfterRenewal.lifecycleStatus,
    };
    await page.goto(`${BETA_ORIGIN}/console/org/operate/issuance`, {
      waitUntil: 'domcontentloaded',
      timeout: 60_000,
    });
    row = page.getByRole('row').filter({ hasText: report.issuance.templateName }).first();
    await row.waitFor({ state: 'visible', timeout: 30_000 });
    await showLifecycleStep(page, 'Credential renewed', 'The replacement credential is active and linked to its superseded predecessor.');
    await page.screenshot({ path: path.join(artifactDir, '02-renewed-credential.png'), fullPage: true });

    const statusListUris = (credential.status_list_entries || [])
      .map((entry) => entry.status_list_uri || entry.status_list_credential)
      .filter(Boolean);
    report.statusListOwnership = {
      uris: statusListUris,
      ok: statusListUris.length > 0 && statusListUris.every((uri) => (
        uri.includes(`/organizations/${ORG_ID}/`)
      )),
    };
    report.credential = {
      id: credential.id,
      status: credential.status,
      templateName: report.issuance.templateName,
    };

    report.suspend = await performLifecycleAction(page, row, 'suspend', 'Automated lifecycle suspension audit');
    report.suspend.current = await getCredentialStatus(page, credential.id);
    report.suspend.verification = await verify(page, walletPage, 'Suspended credential audit');
    await showLifecycleStep(page, 'Suspension denies verification', 'The status-aware verifier rejects the suspended credential while preserving its lifecycle history.');
    await page.screenshot({ path: path.join(artifactDir, '02-suspended-credential.png'), fullPage: true });

    report.reinstate = await performLifecycleAction(page, row, 'reinstate', 'Automated lifecycle reinstatement audit');
    report.reinstate.current = await getCredentialStatus(page, credential.id);
    report.reinstate.verification = await verify(page, walletPage, 'Reinstated credential audit');
    await showLifecycleStep(page, 'Reinstatement restores verification', 'The same canonical presentation succeeds again after the issuer reinstates the credential.');
    await page.screenshot({ path: path.join(artifactDir, '03-reinstated-credential.png'), fullPage: true });

    report.revoke = await performLifecycleAction(page, row, 'revoke', 'Automated lifecycle revocation audit');
    report.revoke.current = await getCredentialStatus(page, credential.id);
    report.revoke.verification = await verify(page, walletPage, 'Revoked credential audit');
    await showLifecycleStep(page, 'Revocation is final', 'The verifier denies the revoked credential and the issuer inventory retains a privacy-safe status history.');
    await page.screenshot({ path: path.join(artifactDir, '04-revoked-credential.png'), fullPage: true });

    report.crossOrg = await page.evaluate(async () => {
      const otherOrg = 'ffffffff-ffff-ffff-ffff-ffffffffffff';
      const response = await fetch(
        `/v1/issued-credentials?organization_id=${encodeURIComponent(otherOrg)}`,
        { credentials: 'include' },
      );
      return { status: response.status, denied: response.status === 403 };
    });
    report.unexpectedResponses = report.unexpectedResponses.filter((entry) => !(
      entry.status === 403 && entry.url.includes('organization_id=ffffffff-ffff-ffff-ffff-ffffffffffff')
    ) && !(
      entry.status === 403 && entry.url.includes('/v1/policy-sets?')
    ));

    const suspendDecision = report.suspend.verification?.result;
    const reinstateDecision = report.reinstate.verification?.result;
    const revokeDecision = report.revoke.verification?.result;
    report.releaseReady = Boolean(
      report.permissions.status === 200
      && report.permissions.hasLifecyclePermission
      && report.draftCleanup.ok
      && report.credentialCleanup.ok
      && report.renewal.ok
      && report.statusListOwnership.ok
      && report.suspend.ok
      && String(report.suspend.current.lifecycleStatus).toUpperCase() === 'SUSPENDED'
      && suspendDecision?.decision === 'deny'
      && /suspend/i.test(suspendDecision?.decisionReason || '')
      && report.reinstate.ok
      && String(report.reinstate.current.lifecycleStatus).toUpperCase() === 'ACTIVE'
      && reinstateDecision?.decision === 'allow'
      && report.revoke.ok
      && String(report.revoke.current.lifecycleStatus).toUpperCase() === 'REVOKED'
      && revokeDecision?.decision === 'deny'
      && /revok/i.test(revokeDecision?.decisionReason || '')
      && report.crossOrg.denied
      && report.pageErrors.length === 0
      && report.unexpectedResponses.length === 0
    );
    report.finishedAt = new Date().toISOString();
    await context.close();
    if (RECORD_VIDEO) {
      report.recordings = {
        application: path.relative(ROOT, await finalizeVideo(applicationVideo, artifactDir, 'credential-lifecycle-application.webm')),
        wallet: path.relative(ROOT, await finalizeVideo(walletVideo, artifactDir, 'credential-lifecycle-wallet.webm')),
      };
    }
    fs.writeFileSync(path.join(artifactDir, 'report.json'), JSON.stringify(report, null, 2));
    console.log(JSON.stringify(report, null, 2));
    if (!report.releaseReady) process.exitCode = 1;
  } finally {
    await browser.close();
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.log(JSON.stringify({ error: redact(error.stack || error.message || String(error)) }, null, 2));
    process.exitCode = 1;
  });
}
