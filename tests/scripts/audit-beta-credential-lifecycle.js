#!/usr/bin/env node
/* eslint-disable no-console */

const fs = require('fs');
const { acquireWalletSession, openIsolatedWallet, resetIsolatedWallet } = require('./demo-wallet-session');
const path = require('path');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { createDemoLiveEvidence, acknowledgeDemoInputs } = require('./demo-live-evidence');
const { spawnSync } = require('child_process');
const { chromium } = require('@playwright/test');
const { loadEnvFile, redact } = require('./verify-beta-waltid-acceptance');
const { browserJson, cancelOwnedIssuanceTransaction, selectOrganization } = require('./beta-demo-resource-helpers');
const { requireVerificationDecision } = require('./beta-demo-review-ui');
const {
  VIDEO_SIZE,
  createActionRecording,
  createArtifactDir,
  finalizeVideo,
  maskProtocolField,
  showStep,
  showVerificationResult,
} = require('./demo-recording');
const {
  DEFAULT_BETA_ORGANIZATION_ID,
  DEFAULT_LIFECYCLE_POLICY_ID,
  DEFAULT_LIFECYCLE_SOURCE_TEMPLATE_ID,
  credentialLifecycleBehaviorAssertions,
  verificationResultEvidence,
  verificationSessionRequest,
} = require('./beta-credential-contract');

const ROOT = path.resolve(__dirname, '..', '..');
loadEnvFile(path.join(ROOT, '.env.tunnel.beta.local'));
loadEnvFile(path.join(ROOT, '.env'));

const BETA_ORIGIN = process.env.BETA_ORIGIN || 'https://beta.elevenidllc.com';
const TEST_WALLET_ORIGIN = process.env.MARTY_TEST_WALLET_ORIGIN || 'http://127.0.0.1:8787';
const ORG_ID = process.env.BETA_AUDIT_ORG_ID || DEFAULT_BETA_ORGANIZATION_ID;
const POLICY_ID = process.env.BETA_AUDIT_POLICY_ID || DEFAULT_LIFECYCLE_POLICY_ID;
const SOURCE_TEMPLATE_ID = process.env.BETA_AUDIT_TEMPLATE_ID || DEFAULT_LIFECYCLE_SOURCE_TEMPLATE_ID;
const VERIFIER_DID = process.env.BETA_AUDIT_VERIFIER_DID || '';
const HEADLESS = process.env.HEADED !== '1';
const RECORD_VIDEO = process.env.RECORD_VIDEO === '1';
const LOCAL_BETA_PROXY = process.env.BETA_LOCAL_PROXY === '1';
const PRESENTATION_TEST_ID = 'LIFECYCLE-PRES-01';

// Adapted from demo-lifecycle-live-v258-20261019 (34e5e32, 4083437).
// The acknowledged fixture supplies the actual issuance claims used below.
function lifecycleFixture(stamp) {
  return {
    schemaVersion: 1,
    organizationId: ORG_ID,
    sourceTemplateId: SOURCE_TEMPLATE_ID,
    policyId: POLICY_ID,
    presentationTestId: PRESENTATION_TEST_ID,
    stamp,
    holder: {
      email: 'lifecycle-holder@example.test',
      given: 'Grace',
      family: 'Hopper',
      employeeId: `LIFECYCLE-${stamp}`,
      department: 'Security',
      position: 'Lifecycle Auditor',
      date: '2026-07-12',
      dateTime: '2026-07-12T12:00:00Z',
    },
  };
}

async function prepareLiveInputs(artifactDir, stamp, client) {
  return acknowledgeDemoInputs(artifactDir, 'lifecycle-fixture-input.json', lifecycleFixture(stamp), client);
}

async function finalizeLiveRun({ cleanup, closeBrowser, writeReport, complete, closeEvidence, successful }) {
  const failures = [];
  try {
    for (const operation of [cleanup, closeBrowser, writeReport]) {
      try {
        await operation();
      } catch (error) {
        failures.push(error);
      }
    }
    if (failures.length) throw new AggregateError(failures, 'Lifecycle finalization failed');
    // Cleanup and video finalization can invalidate an otherwise successful
    // journey. Evaluate readiness after those operations, not before them.
    const ready = typeof successful === 'function' ? await successful() : successful;
    if (ready === true) await complete();
  } finally {
    await closeEvidence();
  }
}

async function liveClient() {
  assert.equal(VERIFIER_DID, '', 'Canonical verifier identity must come from the issued credential');
  return createDemoLiveEvidence();
}

function resolveUiCandidateDist(
  root = ROOT,
  configured = process.env.MARTY_UI_CANDIDATE_DIST,
  dependencies = {},
) {
  const value = String(configured || '').trim();
  if (!value) return null;
  const expected = fs.realpathSync(path.join(root, 'ui', 'dist'));
  const candidate = fs.realpathSync(path.resolve(value));
  if (candidate !== expected) {
    throw new Error('MARTY_UI_CANDIDATE_DIST must resolve to this worktree\'s ui/dist directory');
  }
  for (const relative of ['index.html', path.join('console', 'index.html'), 'assets']) {
    if (!fs.existsSync(path.join(candidate, relative))) {
      throw new Error(`Local UI candidate is incomplete: missing ${relative}`);
    }
  }
  const sourceState = dependencies.sourceState || (() => {
    const revision = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' });
    const status = spawnSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' });
    return {
      revision: revision.status === 0 ? revision.stdout.trim() : '',
      clean: status.status === 0 && !status.stdout.trim(),
    };
  });
  const state = sourceState();
  if (!/^[0-9a-f]{40}$/.test(state.revision)) {
    throw new Error('Local UI candidate source revision could not be resolved');
  }
  if (!state.clean) {
    throw new Error('Local UI candidate requires a clean committed worktree');
  }
  return {
    absolute: candidate,
    relative: 'ui/dist',
    sourceRevision: state.revision,
  };
}

function candidateUiFileForRequest(candidate, pathname, resourceType) {
  if (!candidate || ['/v1/', '/api/', '/auth/'].some((prefix) => pathname.startsWith(prefix))) return null;
  const relative = resourceType === 'document' && (pathname === '/console' || pathname.startsWith('/console/'))
    ? path.join('console', 'index.html')
    : decodeURIComponent(pathname).replace(/^[/\\]+/, '');
  const resolved = path.resolve(candidate.absolute, relative || 'index.html');
  const relation = path.relative(candidate.absolute, resolved);
  if (!relation || (!relation.startsWith('..') && !path.isAbsolute(relation))) {
    return fs.existsSync(resolved) && fs.statSync(resolved).isFile() ? resolved : null;
  }
  return null;
}

function contentTypeFor(candidatePath) {
  const extension = path.extname(candidatePath).toLowerCase();
  return {
    '.css': 'text/css; charset=utf-8',
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.wasm': 'application/wasm',
  }[extension] || 'application/octet-stream';
}

async function installUiCandidateRoute(context, candidate) {
  if (!candidate) return;
  await context.route(`${BETA_ORIGIN}/**`, async (route) => {
    const request = route.request();
    if (request.method() !== 'GET') return route.continue();
    const candidatePath = candidateUiFileForRequest(
      candidate,
      new URL(request.url()).pathname,
      request.resourceType(),
    );
    if (!candidatePath) return route.continue();
    return route.fulfill({
      status: 200,
      contentType: contentTypeFor(candidatePath),
      headers: { 'cache-control': 'no-store' },
      body: fs.readFileSync(candidatePath),
    });
  });
}

async function showLifecycleStep(page, title, detail, stage) {
  if (!/^\d of \d$/.test(String(stage || ''))) {
    throw new TypeError('Lifecycle recording stage must use the form "1 of 5"');
  }
  return showStep(page, title, detail, {
    enabled: RECORD_VIDEO,
    eyebrow: `Credential lifecycle | Stage ${stage}`,
  });
}

async function dismissLifecycleUpdatedNotification(page) {
  const title = page.getByText('Lifecycle updated', { exact: true }).last();
  if (!await title.isVisible().catch(() => false)) return false;

  const alert = title.locator('xpath=ancestor::*[@role="alert"][1]');
  const closeButton = alert.locator('button[aria-label="Close"]');
  if (!await closeButton.isVisible().catch(() => false)) {
    throw new Error('Visible lifecycle notification has no dismiss control');
  }
  await closeButton.click();
  await title.waitFor({ state: 'hidden', timeout: 5_000 });
  if (await title.isVisible().catch(() => false)) {
    throw new Error('Lifecycle notification remains visible before verifier evidence');
  }
  return true;
}

async function requireDismissedLifecycleNotification(page) {
  if (!await dismissLifecycleUpdatedNotification(page)) {
    throw new Error('Recording requires the lifecycle notification to be visible and dismissible');
  }
}

function resolveVerificationIssuerDid(override, credential) {
  const issuerDid = String(override || credential?.issuer_did || '').trim();
  if (!/^did:[a-z0-9]+:\S+$/i.test(issuerDid)) {
    throw new Error('Verification issuer DID is absent from both the governed override and issued credential record');
  }
  return issuerDid;
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

function validateElevenIdLoginTheme(evidence) {
  if (!evidence?.stylesheet?.includes('/login/11id/css/marty.css')) {
    throw new Error('Keycloak did not load the ElevenID login theme stylesheet');
  }
  if (!evidence.appBar || evidence.brand !== 'ElevenID LLC') {
    throw new Error('Keycloak did not render the ElevenID login theme shell');
  }
  return { ...evidence, ok: true };
}

async function inspectElevenIdLoginTheme(page) {
  const evidence = await page.evaluate(() => {
    const appBar = document.querySelector('.elevenid-appbar');
    const stylesheet = Array.from(document.querySelectorAll('link[rel~="stylesheet"]'))
      .map((element) => element.href)
      .find((href) => href.includes('/login/11id/css/marty.css'));
    return {
      stylesheet: stylesheet ? new URL(stylesheet).pathname : null,
      appBar: Boolean(appBar),
      brand: document.querySelector('.elevenid-brand')?.textContent?.trim() || null,
    };
  });
  return validateElevenIdLoginTheme(evidence);
}

async function login(page, email, password) {
  await page.goto(`${BETA_ORIGIN}/v1/auth/login?redirect_uri=${encodeURIComponent('/console/org')}`, {
    waitUntil: 'domcontentloaded',
    timeout: 60_000,
  });
  const loginTheme = await inspectElevenIdLoginTheme(page);
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
  return loginTheme;
}

async function selectOrg(page) {
  const selection = await selectOrganization(page, {
    organizationId: ORG_ID,
    consoleOrigin: BETA_ORIGIN,
  });
  return {
    ...selection,
    name: selection.targetName,
  };
}

async function ensureActiveRevocationProfile(page) {
  // Revoked demo credentials still need their published status lists. Require
  // an existing service profile instead of creating an untracked profile and
  // either leaking it or deleting the status authority during cleanup.
  const source = await browserJson(page, `/v1/credential-templates/${encodeURIComponent(SOURCE_TEMPLATE_ID)}`);
  if (!source.ok || source.body?.id !== SOURCE_TEMPLATE_ID || source.body?.organization_id !== ORG_ID) {
    return { ok: false, error: 'Source template authority could not be established before status-profile selection' };
  }
  const response = await browserJson(page, `/v1/revocation-profiles?organization_id=${encodeURIComponent(ORG_ID)}`);
  if (!response.ok || !Array.isArray(response.body)) {
    return { ok: false, status: response.status, error: 'Revocation Profile lookup failed' };
  }
  const configuredId = process.env.MARTY_LIFECYCLE_REVOCATION_PROFILE_ID || source.body.revocation_profile_id;
  const active = response.body.filter((profile) => profile.organization_id === ORG_ID
    && String(profile.status || '').toUpperCase() === 'ACTIVE');
  const candidates = configuredId ? active.filter((profile) => profile.id === configuredId) : active;
  if (candidates.length !== 1) {
    return { ok: false, error: 'Select one existing active Revocation Profile with MARTY_LIFECYCLE_REVOCATION_PROFILE_ID before recording' };
  }
  return { ok: true, id: candidates[0].id, name: candidates[0].name, reused: true,
    ownership: 'REFERENCE_ONLY', provisioning: 'PREEXISTING_ACTIVE_PROFILE' };
}

function trackOwnedMutation(ownedResources, operation, recordId) {
  if (!ownedResources) return () => {};
  // A lost or malformed response does not prove the server created nothing.
  // Retain uncertainty until an exact returned ID has been recorded.
  const uncertain = { operation };
  ownedResources.uncertainMutations ||= [];
  ownedResources.uncertainMutations.push(uncertain);
  return (id) => {
    if (typeof id !== 'string' || !id.trim()) return;
    recordId(id);
    const index = ownedResources.uncertainMutations.indexOf(uncertain);
    if (index !== -1) ownedResources.uncertainMutations.splice(index, 1);
  };
}

async function ensureLifecycleTemplate(page, revocationProfileId, runId, onCreated, ownedResources) {
  if (!/^[A-Za-z0-9._-]+$/.test(runId || '') || typeof onCreated !== 'function') {
    throw new TypeError('A lifecycle run ID and created-template callback are required');
  }
  const list = await browserJson(
    page,
    `/v1/credential-templates?organization_id=${encodeURIComponent(ORG_ID)}`,
  );
  const templates = Array.isArray(list.body) ? list.body : [];
  const source = templates.find((template) => template.id === SOURCE_TEMPLATE_ID);
  if (!list.ok || !source) {
    return { ok: false, status: list.status, error: 'Source Credential Template unavailable' };
  }
  const name = `Lifecycle ${source.name} ${runId}`;
  if (templates.some((template) => template.name === name)) {
    throw new Error('Fresh lifecycle template name already exists');
  }
  const recordCreation = trackOwnedMutation(ownedResources, 'template_creation', (id) => {
    ownedResources.templateId = id;
  });
  const version = await browserJson(
    page,
    `/v1/credential-templates/${encodeURIComponent(SOURCE_TEMPLATE_ID)}/new-version`,
    { method: 'POST' },
  );
  if (!version.ok || typeof version.body?.id !== 'string' || !version.body.id) {
    return { ok: false, status: version.status, error: 'Template version creation failed' };
  }
  const id = version.body.id;
  if (templates.some((template) => template.id === id)) {
    throw new Error('Template version creation returned an existing resource');
  }
  // Retain the exact returned ID before patch/activation can fail. Existing
  // templates with similar names or the same VCT never become owned fixtures.
  recordCreation(id);
  onCreated(id);
  const patched = await browserJson(page, `/v1/credential-templates/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    body: JSON.stringify({
      name,
      revocation_profile_id: revocationProfileId,
      validity_rules: {
        default_validity_days: 1,
        max_validity_days: 7,
        renewable: true,
        renewal_window_days: 7,
      },
    }),
  });
  if (!patched.ok) {
    return { ok: false, status: patched.status, id, name, error: 'Template update failed' };
  }
  const activated = await browserJson(
    page,
    `/v1/credential-templates/${encodeURIComponent(id)}/activate`,
    { method: 'POST' },
  );
  const ok = activated.ok && String(activated.body?.status || '').toUpperCase() === 'ACTIVE';
  return {
    ok,
    status: activated.status,
    id,
    name,
    reused: false,
    error: ok ? null : 'Template activation failed',
  };
}

async function issueCredential(page, templateId, ownedResources, holder = lifecycleFixture(Date.now()).holder) {
  const templateResponse = await browserJson(page, `/v1/credential-templates/${encodeURIComponent(templateId)}`);
  if (!templateResponse.ok || !templateResponse.body) {
    return { ok: false, status: templateResponse.status, error: 'Credential Template unavailable' };
  }
  const recordIssuance = trackOwnedMutation(ownedResources, 'issuance', (id) => {
    (ownedResources.transactionIds ||= []).push(id);
  });
  const result = await page.evaluate(async ({ organizationId, templateId, template, holder }) => {
    const claims = Object.fromEntries((template.claims || []).map((claim) => {
      const name = claim?.name || claim?.claim_name;
      const normalized = String(name || '').toLowerCase();
      const type = String(claim?.type || claim?.data_type || 'STRING').toUpperCase();
      const options = claim?.options || claim?.enum || [];
      let value;
      if (Array.isArray(options) && options.length) {
        const first = options[0];
        value = typeof first === 'object' ? first.value ?? first.label : first;
      } else if (type === 'DATE') value = holder.date;
      else if (type === 'DATETIME') value = holder.dateTime;
      else if (type === 'NUMBER' || type === 'INTEGER') value = 1;
      else if (type === 'BOOLEAN') value = true;
      else if (normalized.includes('email')) value = holder.email;
      else if (normalized.includes('given') || normalized.includes('first')) value = holder.given;
      else if (normalized.includes('family') || normalized.includes('last') || normalized.includes('surname')) value = holder.family;
      else if (normalized.includes('employee') || normalized.endsWith('_id')) value = holder.employeeId;
      else if (normalized.includes('department')) value = holder.department;
      else if (normalized.includes('position') || normalized.includes('title')) value = holder.position;
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
      // Public issuance exposes the transaction as id; renewal uses transaction_id.
      transactionId: body?.id || null,
      offerUri: body?.credential_offer_uri || body?.offer_url || null,
      error: issuanceResponse.ok ? null : body?.detail || body?.message || 'Issuance failed',
    };
  }, { organizationId: ORG_ID, templateId, template: templateResponse.body, holder });
  recordIssuance(result.transactionId);
  return result;
}

async function receiveCredential(walletPage, offerUri, expectedVct) {
  await openIsolatedWallet(walletPage, TEST_WALLET_ORIGIN);
  await resetIsolatedWallet(walletPage, TEST_WALLET_ORIGIN);
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
    receipt: response.ok() ? {
      id: body?.id, vct: body?.vct, format: body?.format,
      credentialConfigurationId: body?.credential_configuration_id,
    } : null,
  };
}

function selectIssuedCredential(records, templateId, transactionId) {
  if (!Array.isArray(records) || typeof templateId !== 'string' || !templateId
    || typeof transactionId !== 'string' || !transactionId) {
    throw new TypeError('Credential inventory, template ID, and issuance transaction ID are required');
  }
  const matches = records.filter((record) => (
    record?.credential_template_id === templateId
    && record?.flow_execution_id === transactionId
  ));
  if (matches.length > 1) throw new Error('Issuance transaction produced multiple credential records');
  if (matches.length && (typeof matches[0].id !== 'string' || !matches[0].id)) {
    throw new Error('Issued credential is missing its record ID');
  }
  return matches[0] || null;
}

async function lifecycleCredentialInventory(page) {
  const response = await browserJson(
    page,
    `/v1/issued-credentials?organization_id=${encodeURIComponent(ORG_ID)}`,
  );
  if (!response.ok || !Array.isArray(response.body)) {
    throw new Error(`Lifecycle credential inventory failed (HTTP ${response.status})`);
  }
  return response.body;
}

async function findIssuedCredential(page, templateId, transactionId) {
  if (typeof templateId !== 'string' || !templateId
    || typeof transactionId !== 'string' || !transactionId) {
    throw new TypeError('Exact template and issuance transaction IDs are required');
  }
  return waitFor(async () => selectIssuedCredential(
    await lifecycleCredentialInventory(page),
    templateId,
    transactionId,
  ));
}

function selectRenewedCredential(records, templateId, sourceCredentialId) {
  if (!Array.isArray(records)) return null;
  const matches = records.filter((record) => (
    record.credential_template_id === templateId
    && record.renewed_from_credential_id === sourceCredentialId
  ));
  if (matches.length > 1) throw new Error('Renewal produced multiple successor credentials');
  return matches[0] || null;
}

async function findRenewedCredential(page, templateId, sourceCredentialId, transactionId) {
  const credential = await findIssuedCredential(page, templateId, transactionId);
  if (credential.renewed_from_credential_id !== sourceCredentialId) {
    throw new Error('Renewed credential is not linked to the exact predecessor');
  }
  return credential;
}

async function findCredentialRow(page, credentialId) {
  if (!/^[A-Za-z0-9:._-]+$/.test(credentialId)) {
    throw new Error('Credential row lookup requires a presentation-safe exact record ID');
  }
  const search = page.getByPlaceholder('Search issued credentials...');
  const row = page.locator(`tbody tr[data-credential-record-id="${credentialId}"]`);
  await row.waitFor({ state: 'visible', timeout: 30_000 });
  const reference = row.locator('[data-credential-reference]');
  await reference.waitFor({ state: 'visible', timeout: 30_000 });
  const friendlyReference = await reference.getAttribute('data-credential-reference');
  if (!friendlyReference?.trim()) {
    throw new Error('Credential row is missing its stable privacy-safe reference');
  }
  await search.fill(friendlyReference.trim());
  await row.waitFor({ state: 'visible', timeout: 30_000 });
  return row;
}

async function cleanupOwnedLifecycle(page, {
  templateId,
  transactionIds = [],
  credentialIds = [],
  uncertainMutations = [],
}) {
  const result = {
    ok: false,
    revoked: [],
    alreadyRevoked: [],
    templateRetired: false,
    cancelledTransactionIds: [],
    pendingTransactionIds: [],
    uncertainMutations: [...uncertainMutations],
    failures: [],
  };
  if (!templateId && transactionIds.length === 0 && credentialIds.length === 0) {
    return { ...result, ok: uncertainMutations.length === 0 };
  }
  if (!templateId || templateId === SOURCE_TEMPLATE_ID) {
    throw new Error('Cleanup requires the newly created lifecycle template ID');
  }
  const templatePath = `/v1/credential-templates/${encodeURIComponent(templateId)}`;
  const template = await browserJson(page, templatePath);
  if (!template.ok || template.body?.id !== templateId || template.body?.organization_id !== ORG_ID) {
    throw new Error('Cannot establish the owned lifecycle template during cleanup');
  }
  const templateStatus = String(template.body.status || '').toUpperCase();
  if (!['DRAFT', 'ACTIVE', 'DEPRECATED'].includes(templateStatus)) {
    throw new Error('Owned lifecycle template has an unknown status');
  }
  const records = transactionIds.length || credentialIds.length
    ? await lifecycleCredentialInventory(page)
    : [];
  const owned = new Map();
  const unclaimedTransactions = [];
  for (const transactionId of new Set(transactionIds)) {
    const record = selectIssuedCredential(records, templateId, transactionId);
    if (!record) {
      unclaimedTransactions.push(transactionId);
      continue;
    }
    if (record.organization_id !== ORG_ID) {
      throw new Error('Owned credential response belongs to another organization');
    }
    const status = String(record.status || '').toUpperCase();
    if (!['ACTIVE', 'SUSPENDED', 'REVOKED'].includes(status)) {
      throw new Error('Owned credential has an unknown lifecycle status');
    }
    if (owned.has(record.id)) throw new Error('Credential record is ambiguous across issuance transactions');
    owned.set(record.id, record);
  }
  if (credentialIds.some((id) => !owned.has(id))) {
    throw new Error('Tracked credential cannot be matched to an owned issuance transaction');
  }
  // Validate every candidate before mutating any resource. Same-template
  // records from other transactions never enter this explicitly owned set.
  for (const transactionId of unclaimedTransactions) {
    const cancellation = {
      organizationId: ORG_ID,
      credentialTemplateId: templateId,
      applicationId: null,
      transactionId,
      uncertainMutations: [],
    };
    const outcome = await cancelOwnedIssuanceTransaction(
      page, cancellation, 'Lifecycle audit unclaimed offer cleanup',
    ).catch(() => ({ ok: false, responseStatus: 0 }));
    if (outcome.ok) {
      result.cancelledTransactionIds.push(transactionId);
    } else {
      result.pendingTransactionIds.push(transactionId);
      result.failures.push({ id: transactionId, operation: 'cancel_transaction', status: outcome.responseStatus });
      result.uncertainMutations.push(...cancellation.uncertainMutations.map((mutation) => ({
        ...mutation, transactionId,
      })));
    }
  }
  for (const record of owned.values()) {
    if (String(record.status).toUpperCase() === 'REVOKED') {
      result.alreadyRevoked.push(record.id);
      continue;
    }
    const response = await browserJson(page, `/v1/issued-credentials/${encodeURIComponent(record.id)}/revoke`, {
      method: 'POST',
      body: JSON.stringify({ reason: 'Lifecycle audit fixture cleanup' }),
    }).catch(() => ({ ok: false, status: 0 }));
    if (response.ok && response.body?.id === record.id
      && String(response.body?.status || '').toUpperCase() === 'REVOKED') {
      result.revoked.push(record.id);
    } else {
      result.failures.push({ id: record.id, operation: 'revoke', status: response.status });
    }
  }
  if (templateStatus === 'DEPRECATED') {
    result.templateRetired = true;
  } else {
    const draft = templateStatus === 'DRAFT';
    const response = await browserJson(page, draft ? templatePath : `${templatePath}/deprecate`, {
      method: draft ? 'DELETE' : 'POST',
    }).catch(() => ({ ok: false, status: 0 }));
    result.templateRetired = response.ok && (draft
      ? response.status === 204
      : response.body?.id === templateId
        && String(response.body?.status || '').toUpperCase() === 'DEPRECATED');
    if (!result.templateRetired) {
      result.failures.push({ id: templateId, operation: draft ? 'delete' : 'deprecate', status: response.status });
    }
  }
  result.ok = result.templateRetired
    && result.failures.length === 0
    && result.pendingTransactionIds.length === 0
    && result.uncertainMutations.length === 0;
  return result;
}

// Visible business context and pauses adapted from upstream 6337485.
const LIFECYCLE_DEMO_REASONS = Object.freeze({
  renew: 'Synthetic scenario: extend the employee access period.',
  suspend: 'Synthetic scenario: temporarily suspend access during a security investigation.',
  reinstate: 'Synthetic scenario: investigation cleared; restore employee access.',
  revoke: 'Synthetic scenario: employment ended; permanently revoke employee access.',
});

function createLifecycleRecording(page, {
  enabled = RECORD_VIDEO,
  scenario = 'credential-lifecycle',
  eyebrow = 'Synthetic business scenario - ElevenID admin portal',
  pageName = 'application',
  reasons = LIFECYCLE_DEMO_REASONS,
  now,
  onEvent,
} = {}) {
  const actionReasons = { ...LIFECYCLE_DEMO_REASONS, ...reasons };
  const recording = createActionRecording({
    enabled,
    scenario,
    eyebrow,
    pageName,
    now,
    onEvent,
  });
  return {
    enabled: recording.enabled,
    evidence: recording.evidence,
    events: recording.events,
    mark: recording.mark,
    hold: (action, phase, locator, milliseconds) => recording.hold(
      page, locator, milliseconds, { action, phase },
    ),
    explain: (action, reason = actionReasons[action]) => recording.explain(page, action, reason, {
      title: `Admin action: ${action}`,
      durationMs: 3200,
    }),
  };
}

async function performLifecycleAction(page, row, action, reason, recording = null) {
  await recording?.explain(action, reason);
  const actionButton = row.getByRole('button', { name: new RegExp(`^${action} credential`, 'i') });
  await recording?.hold(action, 'button', actionButton);
  const responsePromise = page.waitForResponse((response) => (
    response.url().includes(`/v1/issued-credentials/`)
    && response.url().endsWith(`/${action}`)
    && response.request().method() === 'POST'
  ), { timeout: 30_000 });
  recording?.mark(action, 'button-click');
  await actionButton.click();
  const dialog = page.getByRole('dialog', { name: new RegExp(`${action} credential`, 'i') });
  await recording?.hold(action, 'dialog', dialog, 1800);
  await dialog.getByRole('textbox', { name: /reason/i }).fill(reason);
  await recording?.hold(action, 'reason', dialog, 3200);
  recording?.mark(action, 'confirm-click', { reason });
  await dialog.getByRole('button', { name: new RegExp(`^${action}$`, 'i') }).click();
  const response = await responsePromise;
  const body = await response.json().catch(() => null);
  if (response.ok()) {
    await dialog.waitFor({ state: 'hidden', timeout: 30_000 });
    recording?.mark(action, 'response-success', { httpStatus: response.status() });
    if (recording?.enabled) await requireDismissedLifecycleNotification(page);
    const expected = { suspend: 'suspended', reinstate: 'active', revoke: 'revoked' }[action];
    await recording?.hold(action, 'resulting-status', row.getByText(new RegExp(`^${expected}$`, 'i')), 3200);
  } else {
    await dialog.getByRole('button', { name: /cancel/i }).click().catch(() => {});
  }
  return { ok: response.ok(), status: response.status(), body };
}

function initialActiveVerificationPassed(verification) {
  return verification?.session?.ok === true
    && verification?.wallet?.ok === true
    && verification?.result?.httpStatus === 200
    && verification?.result?.decision === 'allow';
}

function requireLifecycleActionEvidence(action, evidence) {
  const expectedState = { suspend: 'SUSPENDED', reinstate: 'ACTIVE', revoke: 'REVOKED' }[action];
  if (!expectedState) throw new TypeError('A supported lifecycle action is required');
  if (evidence?.ok !== true || !Number.isInteger(evidence?.status)
    || evidence.status < 200 || evidence.status >= 300
    || evidence?.current?.ok !== true || evidence.current.status !== 200
    || String(evidence.current.lifecycleStatus || '').toUpperCase() !== expectedState) {
    throw new Error(`${action} did not reach ${expectedState} with successful current-state evidence`);
  }
  const result = requireVerificationDecision(evidence.verification, action === 'reinstate' ? 'allow' : 'deny');
  const expectedReason = { suspend: /suspend/i, revoke: /revok/i }[action];
  if (expectedReason && !expectedReason.test(result.decisionReason || '')) {
    throw new Error(`${action} verification did not corroborate the ${expectedState} denial reason`);
  }
  return result;
}

// Both rows must be visible in the deployed inventory, including in runs that
// omit video. API lineage alone does not demonstrate the administrator's UI.
async function showRenewalLineage(page, sourceCredentialId, successorId, recording) {
  const search = page.getByPlaceholder('Search issued credentials...');
  await search.fill('');
  await page.getByRole('button', { name: /^refresh$/i }).click();
  const predecessor = await findCredentialRow(page, sourceCredentialId);
  const revoked = predecessor.getByText(/^revoked$/i);
  await revoked.waitFor({ state: 'visible', timeout: 30_000 });
  await recording.hold('renew', 'predecessor-revoked-status', revoked, 3600);
  const predecessorReference = await predecessor.locator('[data-credential-reference]').getAttribute('data-credential-reference');
  await search.fill('');
  const successor = await findCredentialRow(page, successorId);
  const relationship = successor.getByText(`Renewed from ${predecessorReference}`, { exact: true });
  await relationship.waitFor({ state: 'visible', timeout: 30_000 });
  await recording.hold('renew', 'successor-link', relationship, 3600);
  return {
    row: successor,
    evidence: {
      predecessorRevokedVisible: true,
      successorLinkVisible: true,
      sourceCredentialId,
      successorId,
      predecessorReference,
    },
  };
}

async function renewCredential(page, row, ownedResources, recording = null) {
  await recording?.explain('renew');
  const button = row.getByRole('button', { name: /^renew credential/i });
  await recording?.hold('renew', 'button', button, 3200);
  const responsePromise = page.waitForResponse((response) => (
    response.url().includes('/v1/issued-credentials/')
    && response.url().endsWith('/renew')
    && response.request().method() === 'POST'
  ), { timeout: 30_000 });
  const recordRenewal = trackOwnedMutation(ownedResources, 'renewal', (id) => {
    (ownedResources.transactionIds ||= []).push(id);
  });
  recording?.mark('renew', 'button-click', { confirmationDialog: false, reasonField: false });
  await button.click();
  const response = await responsePromise;
  const body = await response.json().catch(() => null);
  recordRenewal(body?.transaction_id);
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
    submission: body?.submission || null,
  };
}

async function verify(page, walletPage, label, {
  organizationId = ORG_ID,
  presentationPolicyId = POLICY_ID,
  issuerDid = VERIFIER_DID,
  onPhase = () => {},
} = {}) {
  onPhase('session-request');
  const request = verificationSessionRequest({
    organizationId,
    presentationPolicyId,
    issuerDid,
    externalReference: label,
  });
  const session = await page.evaluate(async (payload) => {
    const response = await fetch('/v1/flows/verify', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const body = await response.json().catch(() => null);
    return {
      ok: response.ok,
      status: response.status,
      instanceId: body?.instance_id || body?.id || null,
      requestUri: body?.request_uri || null,
      diagnostic: response.ok ? undefined : body,
      error: response.ok
        ? null
        : body?.detail
          || body?.message
          || body?.error?.message
          || (typeof body?.error === 'string' ? body.error : null)
          || JSON.stringify(body)
          || 'Session creation failed',
    };
  }, request);
  const sanitizedSession = {
    ...session,
    requestUri: session.requestUri ? '[present]' : null,
    diagnostic: session.diagnostic == null
      ? undefined
      : redact(session.diagnostic).slice(0, 800),
    error: session.error == null ? null : redact(session.error).slice(0, 800),
  };
  if (!session.ok || !session.instanceId || !session.requestUri) {
    return { session: sanitizedSession };
  }

  onPhase('wallet-presentation');
  const wallet = await present(walletPage, session.requestUri);
  onPhase('verifier-result', { instanceId: session.instanceId,
    walletOk: wallet.ok === true, walletStatus: wallet.status });
  const rawResult = await waitFor(() => page.evaluate(async (instanceId) => {
    const response = await fetch(`/v1/flows/instances/${encodeURIComponent(instanceId)}/result`, {
      credentials: 'include',
    });
    const body = await response.json().catch(() => null);
    if (!response.ok) return { httpStatus: response.status, status: null, terminal: false };
    const terminal = ['COMPLETED', 'PASSED', 'VERIFIED', 'FAILED', 'EXPIRED', 'CANCELLED']
      .includes(String(body?.status || '').toUpperCase());
    return { httpStatus: response.status, status: String(body?.status || ''),
      terminal, body: terminal ? body : null };
  }, session.instanceId).then(observed => {
    onPhase('verifier-result-poll', { instanceId: session.instanceId,
      httpStatus: observed.httpStatus,
      flowStatus: ['PENDING','PROCESSING','COMPLETED','PASSED','VERIFIED','FAILED','EXPIRED','CANCELLED']
        .includes(observed.status.toUpperCase()) ? observed.status.toUpperCase() : 'OTHER' });
    return observed.terminal ? observed : null;
  }));
  const result = rawResult
    ? verificationResultEvidence(rawResult.body, rawResult.httpStatus)
    : null;
  return { session: sanitizedSession, wallet, result };
}

async function main() {
  const email = process.env.TEST_VENDOR_EMAIL || process.env.TEST_ADMIN_EMAIL;
  const password = process.env.TEST_VENDOR_PASSWORD || process.env.TEST_ADMIN_PASSWORD;
  if (!email || !password) throw new Error('Missing beta operator credentials');

  const stamp = `${new Date().toISOString().replace(/[-:]/g, '').replace(/\..+/, '')}-${randomUUID()}`;
  const artifactDir = createArtifactDir(ROOT, `beta-credential-lifecycle-${stamp}`);
  // Qualification uses the recorder's acknowledged transport. Importing the
  // engineering helpers remains possible without starting this live entry point.
  const evidence = await liveClient();
  const uiCandidate = resolveUiCandidateDist();
  const ownedResources = { templateId: null, transactionIds: [], credentialIds: [], uncertainMutations: [] };
  const report = {
    createdAt: new Date().toISOString(),
    organizationId: ORG_ID,
    policyId: POLICY_ID,
    presentationTestId: PRESENTATION_TEST_ID,
    uiCandidate: uiCandidate ? {
      mode: 'LOCAL_DIST_ENGINEERING_ONLY',
      sourceRevision: uiCandidate.sourceRevision,
      path: uiCandidate.relative,
      qualifiesAsDeployedEvidence: false,
    } : {
      mode: 'DEPLOYED_BETA',
      qualifiesAsDeployedEvidence: true,
    },
    sourceTemplateId: SOURCE_TEMPLATE_ID,
    ownedResources,
    artifactDir,
    pageErrors: [],
    unexpectedResponses: [],
  };

  let browser;
  let context;
  let page;
  let applicationVideo;
  let walletVideo;
  let walletSession;
  try {
    const input = await prepareLiveInputs(artifactDir, stamp, evidence);
    browser = await chromium.launch({
      headless: HEADLESS,
      args: LOCAL_BETA_PROXY
        ? ['--host-resolver-rules=MAP beta.elevenidllc.com 127.0.0.1', '--no-proxy-server']
        : [],
    });
    context = await browser.newContext({
      viewport: VIDEO_SIZE,
      ignoreHTTPSErrors: LOCAL_BETA_PROXY,
      ...(RECORD_VIDEO ? { recordVideo: { dir: artifactDir, size: VIDEO_SIZE } } : {}),
    });
    walletSession = await acquireWalletSession(context, { origin: TEST_WALLET_ORIGIN, runId: stamp });
    report.walletSession = walletSession.evidence;
    await installUiCandidateRoute(context, uiCandidate);
    page = await context.newPage();
    const recording = createLifecycleRecording(page, {
      onEvent: (events) => fs.writeFileSync(
        path.join(artifactDir, 'lifecycle-action-events.json'), JSON.stringify(events, null, 2),
      ),
    });
    if (recording.enabled) report.recordingActionEvidence = recording.evidence;
    recording.mark('setup', 'begin', { boundary: 'API_FIXTURE_SETUP_NOT_ADMIN_UI_DEMONSTRATION' });
    const walletPage = await context.newPage();
    evidence.bindPage(page);
    evidence.bindPage(walletPage);
    applicationVideo = page.video();
    walletVideo = walletPage.video();
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

    report.revocationProfile = await ensureActiveRevocationProfile(page, input.stamp);
    if (!report.revocationProfile.ok) {
      throw new Error(`Revocation Profile setup failed: ${report.revocationProfile.error}`);
    }
    report.credentialTemplate = await ensureLifecycleTemplate(
      page,
      report.revocationProfile.id,
      input.stamp,
      (id) => { ownedResources.templateId = id; },
      ownedResources,
    );
    if (!report.credentialTemplate.ok) {
      throw new Error(`Credential Template setup failed: ${report.credentialTemplate.error}`);
    }
    report.templateId = report.credentialTemplate.id;

    const { offerUri, ...issuance } = await issueCredential(page, report.templateId, ownedResources, input.holder);
    report.issuance = issuance;
    const hasIssuanceTransaction = typeof issuance.transactionId === 'string' && issuance.transactionId.length > 0;
    if (!issuance.ok || !offerUri || !hasIssuanceTransaction) {
      throw new Error(`Issuance failed: ${report.issuance.error}`);
    }
    report.walletReceipt = await receiveCredential(
      walletPage,
      offerUri,
      report.issuance.expectedVct,
    );
    if (!report.walletReceipt.ok) throw new Error(`Wallet receipt failed: ${report.walletReceipt.error}`);

    let credential = await findIssuedCredential(page, report.templateId, issuance.transactionId);
    ownedResources.credentialIds.push(credential.id);
    const sourceCredentialId = credential.id;
    recording.mark('setup', 'complete', {
      boundary: 'ISSUANCE_AND_WALLET_RECEIPT_PREPARED_BEFORE_ADMIN_ACTIONS',
    });

    await page.goto(`${BETA_ORIGIN}/console/org/operate/issuance`, {
      waitUntil: 'domcontentloaded',
      timeout: 60_000,
    });
    let row = await findCredentialRow(page, credential.id);
    await showLifecycleStep(page, 'Active credential issued', 'The issuer inventory shows the newly issued credential and its available lifecycle controls.', '1 of 5');
    await page.screenshot({ path: path.join(artifactDir, '01-active-credential.png'), fullPage: true });
    if (RECORD_VIDEO) await page.waitForTimeout(5_100);

    report.initialVerification = await verify(page, walletPage, `${PRESENTATION_TEST_ID}: initial active trial`, {
      issuerDid: resolveVerificationIssuerDid(VERIFIER_DID, credential),
    });
    report.initialActiveAllowed = initialActiveVerificationPassed(report.initialVerification);
    report.storyAssertions = { initial_active_access_allowed: report.initialActiveAllowed };
    recording.mark('active', 'verification-result', { passed: report.initialActiveAllowed });
    await showVerificationResult(page, report.initialVerification.result, {
      enabled: RECORD_VIDEO,
      actor: 'Marty status-aware verifier',
      testId: PRESENTATION_TEST_ID,
      evaluatedState: 'ACTIVE',
      comparison: 'Original active credential before renewal',
    });
    if (!report.initialActiveAllowed) {
      throw new Error('Initial active credential did not receive an actual allowed verifier decision');
    }

    const { offerUri: renewalOfferUri, ...renewalOffer } = await renewCredential(page, row, ownedResources, recording);
    report.renewalOffer = renewalOffer;
    const hasRenewalTransaction = typeof renewalOffer.transactionId === 'string' && renewalOffer.transactionId.length > 0;
    if (!renewalOffer.ok || !renewalOfferUri || !hasRenewalTransaction) {
      throw new Error(`Renewal failed: ${JSON.stringify(report.renewalOffer.error)}`);
    }
    report.renewalWalletReceipt = await receiveCredential(
      walletPage,
      renewalOfferUri,
      report.issuance.expectedVct,
    );
    credential = await findRenewedCredential(
      page,
      report.templateId,
      sourceCredentialId,
      renewalOffer.transactionId,
    );
    ownedResources.credentialIds.push(credential.id);
    const sourceAfterRenewal = await getCredentialStatus(page, sourceCredentialId);
    report.renewal = {
      ok: report.renewalWalletReceipt.ok
        && credential.renewed_from_credential_id === sourceCredentialId
        && sourceAfterRenewal.ok
        && String(sourceAfterRenewal.lifecycleStatus || '').toUpperCase() === 'REVOKED',
      sourceCredentialId,
      renewedCredentialId: credential.id,
      renewedFromCredentialId: credential.renewed_from_credential_id || null,
      sourceStatus: sourceAfterRenewal.lifecycleStatus,
    };
    if (!report.renewal.ok) {
      throw new Error('Renewal did not establish wallet receipt, the exact successor and a revoked predecessor');
    }
    const detailDialog = page.getByRole('dialog', { name: /issued credential details/i });
    if (await detailDialog.isVisible().catch(() => false)) {
      await detailDialog.getByRole('button', { name: /^close$/i }).click();
      await detailDialog.waitFor({ state: 'hidden', timeout: 30_000 });
    }
    const lineage = await showRenewalLineage(page, sourceCredentialId, credential.id, recording);
    report.renewalUiLineage = lineage.evidence;
    row = lineage.row;
    await showLifecycleStep(page, 'Credential renewed', 'The replacement credential is active and linked to its superseded predecessor.', '2 of 5');
    await page.screenshot({ path: path.join(artifactDir, '02-renewed-credential.png'), fullPage: true });
    await recording.hold('renew', 'replacement-active-status', row.getByText(/^active$/i), 3200);

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

    report.suspend = await performLifecycleAction(page, row, 'suspend', LIFECYCLE_DEMO_REASONS.suspend, recording);
    report.suspend.current = await getCredentialStatus(page, credential.id);
    report.suspend.verification = await verify(page, walletPage, `${PRESENTATION_TEST_ID}: suspended trial`, {
      issuerDid: resolveVerificationIssuerDid(VERIFIER_DID, credential),
    });
    requireLifecycleActionEvidence('suspend', report.suspend);
    await showLifecycleStep(page, 'Suspension denies verification', 'The status-aware verifier returns the credential\'s suspended-state denial reason.', '3 of 5');
    await showVerificationResult(page, report.suspend.verification.result, {
      enabled: RECORD_VIDEO,
      actor: 'Marty status-aware verifier',
      testId: PRESENTATION_TEST_ID,
      evaluatedState: 'SUSPENDED',
      comparison: 'Active -> suspended',
    });
    await page.screenshot({ path: path.join(artifactDir, '02-suspended-credential.png'), fullPage: true });

    report.reinstate = await performLifecycleAction(page, row, 'reinstate', LIFECYCLE_DEMO_REASONS.reinstate, recording);
    report.reinstate.current = await getCredentialStatus(page, credential.id);
    report.reinstate.verification = await verify(page, walletPage, `${PRESENTATION_TEST_ID}: reinstated trial`, {
      issuerDid: resolveVerificationIssuerDid(VERIFIER_DID, credential),
    });
    requireLifecycleActionEvidence('reinstate', report.reinstate);
    await showLifecycleStep(page, 'Reinstatement restores verification', 'The same credential fixture passes again after the issuer reinstates it.', '4 of 5');
    await showVerificationResult(page, report.reinstate.verification.result, {
      enabled: RECORD_VIDEO,
      actor: 'Marty status-aware verifier',
      testId: PRESENTATION_TEST_ID,
      evaluatedState: 'ACTIVE',
      comparison: 'Denied while suspended -> allowed after reinstatement',
    });
    await page.screenshot({ path: path.join(artifactDir, '03-reinstated-credential.png'), fullPage: true });

    report.revoke = await performLifecycleAction(page, row, 'revoke', LIFECYCLE_DEMO_REASONS.revoke, recording);
    report.revoke.current = await getCredentialStatus(page, credential.id);
    report.revoke.verification = await verify(page, walletPage, `${PRESENTATION_TEST_ID}: revoked trial`, {
      issuerDid: resolveVerificationIssuerDid(VERIFIER_DID, credential),
    });
    requireLifecycleActionEvidence('revoke', report.revoke);
    await showLifecycleStep(page, 'Revoked credential is denied', 'In this test scenario, the verifier denies the revoked credential and the issuer inventory retains the revoked state.', '5 of 5');
    await showVerificationResult(page, report.revoke.verification.result, {
      enabled: RECORD_VIDEO,
      actor: 'Marty status-aware verifier',
      testId: PRESENTATION_TEST_ID,
      evaluatedState: 'REVOKED',
      comparison: 'Active -> revoked in this test scenario',
    });
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

    report.behaviorAssertions = credentialLifecycleBehaviorAssertions(report);
    report.engineeringReady = Boolean(
      report.permissions.status === 200
      && report.permissions.hasLifecyclePermission
      && report.initialActiveAllowed
      && report.renewalUiLineage.predecessorRevokedVisible
      && report.renewalUiLineage.successorLinkVisible
      && Object.values(report.behaviorAssertions).every((passed) => passed === true)
      && report.statusListOwnership.ok
      && report.crossOrg.denied
      && report.pageErrors.length === 0
      && report.unexpectedResponses.length === 0
    );
    report.releaseReady = Boolean(report.engineeringReady && !uiCandidate);
  } catch (error) {
    report.error = redact(error.stack || error.message || String(error));
    report.engineeringReady = false;
    report.releaseReady = false;
    throw error;
  } finally {
    await finalizeLiveRun({
      cleanup: async () => {
        try {
          report.cleanup = await cleanupOwnedLifecycle(page, ownedResources);
        } catch (error) {
          report.cleanup = { ok: false, error: redact(error.message || String(error)) };
        }
        if (walletSession) {
          try {
            await walletSession.close();
          } catch (error) {
            report.cleanup.ok = false;
            report.cleanup.walletError = redact(error.message || String(error));
          }
        }
        if (!report.cleanup.ok) {
          report.engineeringReady = false;
          report.releaseReady = false;
        }
      },
      closeBrowser: async () => {
        try {
          if (context) await context.close();
          if (RECORD_VIDEO && applicationVideo && walletVideo) {
            report.recordings = {
              application: path.relative(ROOT, await finalizeVideo(applicationVideo, artifactDir, 'credential-lifecycle-application.webm')),
              wallet: path.relative(ROOT, await finalizeVideo(walletVideo, artifactDir, 'credential-lifecycle-wallet.webm')),
            };
          }
        } catch (error) {
          report.recordingError = redact(error.message || String(error));
          report.engineeringReady = false;
          report.releaseReady = false;
        } finally {
          if (browser) await browser.close().catch((error) => {
            report.browserError = redact(error.message || String(error));
            report.engineeringReady = false;
            report.releaseReady = false;
          });
        }
      },
      writeReport: () => {
        report.finishedAt = new Date().toISOString();
        fs.writeFileSync(path.join(artifactDir, 'report.json'), JSON.stringify(report, null, 2));
        console.log(JSON.stringify(report, null, 2));
        if (uiCandidate ? !report.engineeringReady : !report.releaseReady) process.exitCode = 1;
      },
      successful: () => report.releaseReady === true,
      complete: () => evidence.complete(),
      closeEvidence: () => evidence.close(),
    });
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.log(JSON.stringify({ error: redact(error.stack || error.message || String(error)) }, null, 2));
    process.exitCode = 1;
  });
}

module.exports = {
  candidateUiFileForRequest,
  cleanupOwnedLifecycle,
  createLifecycleRecording,
  dismissLifecycleUpdatedNotification,
  requireDismissedLifecycleNotification,
  requireLifecycleActionEvidence,
  ensureActiveRevocationProfile,
  ensureLifecycleTemplate,
  findCredentialRow,
  findIssuedCredential,
  findRenewedCredential,
  finalizeLiveRun,
  getCredentialStatus,
  initialActiveVerificationPassed,
  issueCredential,
  inspectElevenIdLoginTheme,
  login,
  LIFECYCLE_DEMO_REASONS,
  performLifecycleAction,
  prepareLiveInputs,
  receiveCredential,
  renewCredential,
  resolveUiCandidateDist,
  resolveVerificationIssuerDid,
  selectIssuedCredential,
  selectRenewedCredential,
  selectOrg,
  showRenewalLineage,
  verify,
  validateElevenIdLoginTheme,
  waitFor,
};
