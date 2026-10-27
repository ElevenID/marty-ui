'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const {
  candidateUiFileForRequest,
  cleanupOwnedLifecycle,
  createLifecycleRecording,
  dismissLifecycleUpdatedNotification,
  ensureLifecycleTemplate,
  ensureActiveRevocationProfile,
  acquireLifecycleWalletAfterSource,
  findCredentialRow,
  findIssuedCredential,
  findRenewedCredential,
  finalizeLiveRun,
  initialActiveVerificationPassed,
  issueCredential,
  LIFECYCLE_DEMO_REASONS,
  performLifecycleAction,
  prepareLiveInputs,
  receiveCredential,
  renewCredential,
  requireDismissedLifecycleNotification,
  requireLifecycleActionEvidence,
  resolveUiCandidateDist,
  resolveVerificationIssuerDid,
  selectIssuedCredential,
  selectRenewedCredential,
  showRenewalLineage,
  verify,
} = require('./audit-beta-credential-lifecycle');
const {
  DEFAULT_BETA_ORGANIZATION_ID,
  DEFAULT_LIFECYCLE_SOURCE_TEMPLATE_ID,
} = require('./beta-credential-contract');

const organizationId = process.env.BETA_AUDIT_ORG_ID || DEFAULT_BETA_ORGANIZATION_ID;
const sourceTemplateId = process.env.BETA_AUDIT_TEMPLATE_ID || DEFAULT_LIFECYCLE_SOURCE_TEMPLATE_ID;
const templateListPath = `/v1/credential-templates?organization_id=${encodeURIComponent(organizationId)}`;
const credentialListPath = `/v1/issued-credentials?organization_id=${encodeURIComponent(organizationId)}`;
const sourceTemplate = { id: sourceTemplateId, organization_id: organizationId, name: 'Employee', status: 'ACTIVE' };

test('stale or foreign lifecycle source fails before acquiring a wallet session or mutating a fixture',async()=>{
  for(const source of [{ok:false,status:404,body:null},{ok:true,status:200,body:{...sourceTemplate,organization_id:'foreign'}}]){
    let acquired=0,reads=0;const page={evaluate:async()=>{reads++;return source;}};
    let profile;await assert.rejects(acquireLifecycleWalletAfterSource(page,{},'source-only',p=>{profile=p;},async()=>{acquired++;}),/Source template authority/);
    assert.equal(reads,1);assert.equal(acquired,0);assert.equal(profile.ok,false);
  }
});
test('wallet acquisition follows both exact source and active status-profile authority reads',async()=>{
  const order=[],profile={id:'status-profile',organization_id:organizationId,status:'ACTIVE'};
  const page={evaluate:async()=>{order.push('READ');return order.length===1
    ?{ok:true,status:200,body:{...sourceTemplate,revocation_profile_id:profile.id}}
    :{ok:true,status:200,body:[profile]};}};
  const session={evidence:{closed:false}};let observed;
  assert.equal(await acquireLifecycleWalletAfterSource(page,{},'source-only',p=>{observed=p;},async()=>{order.push('WALLET_ACQUIRE');return session;}),session);
  assert.deepEqual(order,['READ','READ','WALLET_ACQUIRE']);assert.equal(observed.ok,true);
});
const ownedTemplate = { id: 'run-template', organization_id: organizationId, name: 'Lifecycle Employee run', status: 'ACTIVE' };

// Execute the real browser callbacks against a scripted local fetch. Checking
// every request also proves that no extra cleanup mutation was attempted.
function scriptedBrowser(responses) {
  const requests = [];
  return {
    requests,
    async evaluate(callback, argument) {
      const result = await vm.runInNewContext(`(${callback.toString()})(argument)`, {
        argument,
        fetch: async (requestPath, options = {}) => {
          const response = responses[requests.length];
          requests.push({ path: requestPath, method: options.method || 'GET', options });
          if (!response) throw new Error(`Unexpected request to ${requestPath}`);
          if (response.observe) response.observe(options);
          if (response.error) throw response.error;
          const status = response.status || 200;
          return {
            ok: status >= 200 && status < 300,
            status,
            json: async () => {
              if (response.jsonError) throw response.jsonError;
              return response.body ?? null;
            },
          };
        },
      });
      return JSON.parse(JSON.stringify(result));
    },
    assertDone() {
      assert.deepEqual(
        requests.map(({ path: requestPath, method }) => ({ path: requestPath, method })),
        responses.map(({ path: requestPath, method = 'GET' }) => ({ path: requestPath, method })),
      );
    },
  };
}

function credential(id, transactionId, status = 'ACTIVE', extra = {}) {
  return {
    id,
    organization_id: organizationId,
    credential_template_id: ownedTemplate.id,
    flow_execution_id: transactionId,
    status,
    ...extra,
  };
}

test('recording flow dismisses lifecycle feedback before presenting verifier evidence', async () => {
  const calls = [];
  const closeButton = {
    isVisible: async () => true,
    click: async () => calls.push('click'),
  };
  const alert = {
    locator: (selector) => {
      assert.equal(selector, 'button[aria-label="Close"]');
      return closeButton;
    },
    waitFor: async (options) => calls.push(`wait:${options.state}`),
  };
  const title = {
    isVisible: async () => calls.length === 0,
    locator: (selector) => {
      assert.equal(selector, 'xpath=ancestor::*[@role="alert"][1]');
      return alert;
    },
    waitFor: async (options) => calls.push(`wait:${options.state}`),
  };
  const page = {
    getByText: (text, options) => {
      assert.equal(text, 'Lifecycle updated');
      assert.equal(options.exact, true);
      return { last: () => title };
    },
  };

  assert.equal(await dismissLifecycleUpdatedNotification(page), true);
  assert.deepEqual(calls, ['click', 'wait:hidden']);
});

test('recording flow fails closed when lifecycle feedback is missing', async () => {
  const page = {
    getByText: () => ({
      last: () => ({ isVisible: async () => false }),
    }),
  };

  assert.equal(await dismissLifecycleUpdatedNotification(page), false);
  await assert.rejects(
    requireDismissedLifecycleNotification(page),
    /requires the lifecycle notification to be visible and dismissible/,
  );
});

test('credential row selection uses the exact record id and its stable display reference', async () => {
  const calls = [];
  const reference = {
    waitFor: async (options) => calls.push(['reference.waitFor', options]),
    getAttribute: async (name) => {
      calls.push(['reference.getAttribute', name]);
      return 'Credential ABC-123';
    },
  };
  const row = {
    waitFor: async (options) => calls.push(['row.waitFor', options]),
    locator: (selector) => {
      calls.push(['row.locator', selector]);
      return reference;
    },
  };
  const page = {
    getByPlaceholder: (label) => {
      calls.push(['page.getByPlaceholder', label]);
      return {
        fill: async (value) => calls.push(['search.fill', value]),
      };
    },
    locator: (selector) => {
      calls.push(['page.locator', selector]);
      return row;
    },
  };

  assert.equal(await findCredentialRow(page, 'issued-rec-1'), row);
  assert.deepEqual(calls, [
    ['page.getByPlaceholder', 'Search issued credentials...'],
    ['page.locator', 'tbody tr[data-credential-record-id="issued-rec-1"]'],
    ['row.waitFor', { state: 'visible', timeout: 30_000 }],
    ['row.locator', '[data-credential-reference]'],
    ['reference.waitFor', { state: 'visible', timeout: 30_000 }],
    ['reference.getAttribute', 'data-credential-reference'],
    ['search.fill', 'Credential ABC-123'],
    ['row.waitFor', { state: 'visible', timeout: 30_000 }],
  ]);
  await assert.rejects(() => findCredentialRow(page, 'unsafe id'), /presentation-safe exact record ID/);
});

test('local UI candidate is exact, committed, and never intercepts API routes', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'marty-ui-candidate-'));
  const dist = path.join(root, 'ui', 'dist');
  fs.mkdirSync(path.join(dist, 'console'), { recursive: true });
  fs.mkdirSync(path.join(dist, 'assets'), { recursive: true });
  fs.writeFileSync(path.join(dist, 'index.html'), 'public');
  fs.writeFileSync(path.join(dist, 'console', 'index.html'), 'console');
  fs.writeFileSync(path.join(dist, 'assets', 'app.js'), 'app');
  try {
    const candidate = resolveUiCandidateDist(root, dist, {
      sourceState: () => ({ revision: 'a'.repeat(40), clean: true }),
    });
    assert.deepEqual(candidate, {
      absolute: fs.realpathSync(dist),
      relative: 'ui/dist',
      sourceRevision: 'a'.repeat(40),
    });
    assert.equal(
      candidateUiFileForRequest(candidate, '/console/org/operate/issuance', 'document'),
      path.join(fs.realpathSync(dist), 'console', 'index.html'),
    );
    assert.equal(
      candidateUiFileForRequest(candidate, '/assets/app.js', 'script'),
      path.join(fs.realpathSync(dist), 'assets', 'app.js'),
    );
    assert.equal(candidateUiFileForRequest(candidate, '/v1/auth/me', 'fetch'), null);
    assert.equal(candidateUiFileForRequest(candidate, '/../outside', 'script'), null);
    assert.throws(
      () => resolveUiCandidateDist(root, dist, {
        sourceState: () => ({ revision: 'a'.repeat(40), clean: false }),
      }),
      /clean committed worktree/,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('verification issuer identity is bound to the issued credential unless explicitly overridden', () => {
  assert.equal(
    resolveVerificationIssuerDid('', { issuer_did: 'did:web:beta.elevenidllc.com:orgs:demo' }),
    'did:web:beta.elevenidllc.com:orgs:demo',
  );
  assert.equal(
    resolveVerificationIssuerDid('did:web:reviewed.example', { issuer_did: 'did:web:ignored.example' }),
    'did:web:reviewed.example',
  );
  assert.throws(() => resolveVerificationIssuerDid('', {}), /absent/);
});

test('renewal waits for the one successor linked to the exact predecessor', () => {
  const records = [
    { id: 'source', credential_template_id: 'template', renewed_from_credential_id: null },
    { id: 'unrelated', credential_template_id: 'other', renewed_from_credential_id: 'source' },
    { id: 'successor', credential_template_id: 'template', renewed_from_credential_id: 'source' },
  ];
  assert.equal(selectRenewedCredential(records, 'template', 'source').id, 'successor');
  assert.equal(selectRenewedCredential(records.slice(0, 2), 'template', 'source'), null);
  assert.throws(
    () => selectRenewedCredential([...records, { ...records[2], id: 'duplicate' }], 'template', 'source'),
    /multiple successor/,
  );
});

test('each lifecycle run creates and names its own template instead of reusing shared fixtures', async () => {
  const templates = [
    sourceTemplate,
    { ...sourceTemplate, id: 'shared-template', name: 'Lifecycle Employee' },
    { ...sourceTemplate, id: 'unrelated-draft', status: 'DRAFT' },
  ];
  for (const runId of ['run-a', 'run-b']) {
    const owned = { templateId: null, uncertainMutations: [] };
    let createdId;
    let ownedAtPatch;
    let pendingAtCreation;
    const id = `template-${runId}`;
    const page = scriptedBrowser([
      { path: templateListPath, body: templates },
      { path: `/v1/credential-templates/${sourceTemplateId}/new-version`, method: 'POST', body: { id }, observe: () => { pendingAtCreation = owned.uncertainMutations.map(({ operation }) => operation); } },
      { path: `/v1/credential-templates/${id}`, method: 'PATCH', body: { id }, observe: () => { ownedAtPatch = createdId; } },
      { path: `/v1/credential-templates/${id}/activate`, method: 'POST', body: { id, status: 'ACTIVE' } },
    ]);
    const result = await ensureLifecycleTemplate(page, 'revocation-profile', runId, (value) => { createdId = value; }, owned);
    assert.equal(result.ok, true);
    assert.equal(result.reused, false);
    assert.equal(result.id, id);
    assert.equal(ownedAtPatch, id);
    assert.equal(owned.templateId, id);
    assert.deepEqual(pendingAtCreation, ['template_creation']);
    assert.deepEqual(owned.uncertainMutations, []);
    const patch = JSON.parse(page.requests[2].options.body);
    assert.equal(patch.name, `Lifecycle Employee ${runId}`);
    assert.equal(patch.revocation_profile_id, 'revocation-profile');
    page.assertDone();
    templates.push({ ...sourceTemplate, id, name: result.name });
  }
});

test('failed template patch or activation still cleans only the draft created by this run', async () => {
  for (const failedStep of ['patch', 'activate']) {
    let templateId;
    const templatePath = `/v1/credential-templates/${ownedTemplate.id}`;
    const responses = [
      { path: templateListPath, body: [sourceTemplate, { ...sourceTemplate, id: 'prior-draft', status: 'DRAFT' }] },
      { path: `/v1/credential-templates/${sourceTemplateId}/new-version`, method: 'POST', body: ownedTemplate },
      { path: templatePath, method: 'PATCH', status: failedStep === 'patch' ? 503 : 200, body: ownedTemplate },
      ...(failedStep === 'activate' ? [{ path: `${templatePath}/activate`, method: 'POST', status: 503 }] : []),
      { path: templatePath, body: { ...ownedTemplate, status: 'DRAFT' } },
      { path: templatePath, method: 'DELETE', status: 204 },
    ];
    const page = scriptedBrowser(responses);
    const setup = await ensureLifecycleTemplate(page, 'profile', failedStep, (id) => { templateId = id; });
    assert.equal(setup.ok, false);
    assert.equal(templateId, ownedTemplate.id);
    const cleanup = await cleanupOwnedLifecycle(page, { templateId });
    assert.equal(cleanup.ok, true);
    assert.equal(cleanup.templateRetired, true);
    assert.deepEqual(cleanup.revoked, []);
    page.assertDone();
  }
});

test('template setup rejects collisions and returned pre-existing IDs before claiming ownership', async () => {
  const collision = scriptedBrowser([
    { path: templateListPath, body: [sourceTemplate, { id: 'old', name: 'Lifecycle Employee same-run' }] },
  ]);
  await assert.rejects(
    ensureLifecycleTemplate(collision, 'profile', 'same-run', () => assert.fail('must not own an existing template')),
    /name already exists/,
  );
  collision.assertDone();

  const existing = scriptedBrowser([
    { path: templateListPath, body: [sourceTemplate] },
    { path: `/v1/credential-templates/${sourceTemplateId}/new-version`, method: 'POST', body: sourceTemplate },
  ]);
  await assert.rejects(
    ensureLifecycleTemplate(existing, 'profile', 'fresh-run', () => assert.fail('must not own the source template')),
    /existing resource/,
  );
  existing.assertDone();
});

test('issuance retains the canonical public id for exact transaction correlation', async () => {
  const owned = { templateId: ownedTemplate.id, transactionIds: [], uncertainMutations: [] };
  let pendingAtIssuance;
  const contract = JSON.parse(fs.readFileSync(
    path.join(__dirname, '..', '..', 'contracts', 'gateway-issuance-response-projection.json'),
    'utf8',
  ));
  const response = {
    ...contract.cases.find((entry) => entry.name === 'issuance_initiation_hides_redemption_and_custody').expected,
    organization_id: organizationId,
    credential_template_id: ownedTemplate.id,
  };
  assert.equal(Object.hasOwn(response, 'transaction_id'), false);
  const page = scriptedBrowser([
    { path: `/v1/credential-templates/${ownedTemplate.id}`, body: { ...ownedTemplate, vct: 'urn:example:employee', claims: [] } },
    { path: '/v1/issuance', method: 'POST', status: 201, body: response, observe: () => { pendingAtIssuance = owned.uncertainMutations.map(({ operation }) => operation); } },
  ]);
  const result = await issueCredential(page, ownedTemplate.id, owned);
  assert.equal(result.ok, true);
  assert.equal(result.transactionId, response.id);
  assert.equal(result.offerUri, response.credential_offer_uri);
  assert.deepEqual(pendingAtIssuance, ['issuance']);
  assert.deepEqual(owned.transactionIds, [response.id]);
  assert.deepEqual(owned.uncertainMutations, []);
  assert.equal(JSON.parse(page.requests[1].options.body).credential_template_id, ownedTemplate.id);
  page.assertDone();
});

test('lost or malformed template creation responses leave cleanup incomplete without guessing ownership', async () => {
  for (const failure of [
    { body: {} },
    { jsonError: new Error('Synthetic malformed JSON') },
    { error: new Error('Synthetic response lost') },
  ]) {
    const owned = { templateId: null, transactionIds: [], credentialIds: [], uncertainMutations: [] };
    const page = scriptedBrowser([
      { path: templateListPath, body: [sourceTemplate] },
      { path: `/v1/credential-templates/${sourceTemplateId}/new-version`, method: 'POST', status: 201, ...failure },
    ]);
    const setup = ensureLifecycleTemplate(page, 'profile', 'uncertain-run', (id) => { owned.templateId = id; }, owned);
    if (failure.error) await assert.rejects(setup, /response lost/);
    else assert.equal((await setup).ok, false);
    const cleanup = await cleanupOwnedLifecycle(page, owned);
    assert.equal(owned.templateId, null);
    assert.equal(cleanup.ok, false);
    assert.deepEqual(cleanup.uncertainMutations, [{ operation: 'template_creation' }]);
    assert.deepEqual(cleanup.revoked, []);
    page.assertDone();
  }
});

test('read-only setup failures do not imply a resource mutation', async () => {
  const owned = { templateId: null, transactionIds: [], credentialIds: [], uncertainMutations: [] };
  const page = scriptedBrowser([
    { path: templateListPath, status: 503 },
    { path: `/v1/credential-templates/${ownedTemplate.id}`, status: 404 },
  ]);
  assert.equal((await ensureLifecycleTemplate(page, 'profile', 'read-failure', () => {}, owned)).ok, false);
  assert.equal((await issueCredential(page, ownedTemplate.id, owned)).ok, false);
  assert.deepEqual(owned.uncertainMutations, []);
  assert.equal((await cleanupOwnedLifecycle(page, owned)).ok, true);
  page.assertDone();
});

test('lost or malformed issuance responses preserve uncertainty while retiring only the known template', async () => {
  for (const failure of [
    { body: { credential_offer_uri: 'openid-credential-offer://synthetic' } },
    { jsonError: new Error('Synthetic malformed JSON') },
    { error: new Error('Synthetic response lost') },
  ]) {
    const owned = { templateId: ownedTemplate.id, transactionIds: [], credentialIds: [], uncertainMutations: [] };
    const page = scriptedBrowser([
      { path: `/v1/credential-templates/${ownedTemplate.id}`, body: { ...ownedTemplate, claims: [] } },
      { path: '/v1/issuance', method: 'POST', status: 201, ...failure },
      { path: `/v1/credential-templates/${ownedTemplate.id}`, body: ownedTemplate },
      { path: `/v1/credential-templates/${ownedTemplate.id}/deprecate`, method: 'POST', body: { ...ownedTemplate, status: 'DEPRECATED' } },
    ]);
    const issuance = issueCredential(page, ownedTemplate.id, owned);
    if (failure.error) await assert.rejects(issuance, /response lost/);
    else assert.equal((await issuance).transactionId, null);
    const cleanup = await cleanupOwnedLifecycle(page, owned);
    assert.equal(cleanup.ok, false);
    assert.equal(cleanup.templateRetired, true);
    assert.deepEqual(cleanup.uncertainMutations, [{ operation: 'issuance' }]);
    assert.deepEqual(owned.transactionIds, []);
    assert.deepEqual(cleanup.revoked, []);
    page.assertDone();
  }
});

test('renewal uncertainty clears only after its exact transaction ID is recorded', async () => {
  for (const body of [{}, { transaction_id: 'renewal-transaction' }]) {
    const owned = { templateId: ownedTemplate.id, transactionIds: [], uncertainMutations: [] };
    let pendingAtClick;
    const page = {
      waitForResponse: async () => ({ ok: () => true, status: () => 200, json: async () => body }),
    };
    const row = {
      getByRole: () => ({ click: async () => { pendingAtClick = owned.uncertainMutations.map(({ operation }) => operation); } }),
    };
    await renewCredential(page, row, owned);
    assert.deepEqual(pendingAtClick, ['renewal']);
    assert.deepEqual(owned.transactionIds, body.transaction_id ? [body.transaction_id] : []);
    assert.deepEqual(owned.uncertainMutations, body.transaction_id ? [] : [{ operation: 'renewal' }]);
  }
});

test('issued-record selection ignores newer concurrent records and rejects transaction ambiguity', () => {
  const ours = credential('ours', 'run-transaction', 'ACTIVE', { created_at: '2026-01-01T00:00:00Z' });
  const records = [
    ours,
    credential('newer-unrelated', 'other-transaction', 'ACTIVE', { created_at: '2099-01-01T00:00:00Z' }),
    credential('other-template', 'run-transaction', 'ACTIVE', { credential_template_id: 'other-template' }),
  ];
  assert.equal(selectIssuedCredential(records, ownedTemplate.id, 'run-transaction'), ours);
  assert.equal(selectIssuedCredential(records, ownedTemplate.id, 'absent-transaction'), null);
  assert.throws(() => selectIssuedCredential(records, ownedTemplate.id, null), /transaction ID/);
  assert.throws(
    () => selectIssuedCredential([...records, { ...ours, id: 'duplicate' }], ownedTemplate.id, 'run-transaction'),
    /multiple credential records/,
  );
});

test('renewal requires the exact transaction and predecessor, and failed inventory is not success', async () => {
  const successor = credential('successor', 'renewal-transaction', 'ACTIVE', { renewed_from_credential_id: 'source' });
  const records = [successor, { ...successor, id: 'other-successor', flow_execution_id: 'other-renewal' }];
  const page = scriptedBrowser([
    { path: credentialListPath, body: records },
    { path: credentialListPath, body: [{ ...successor, renewed_from_credential_id: 'unrelated-source' }] },
    { path: credentialListPath, status: 503, body: [] },
  ]);
  assert.equal((await findRenewedCredential(page, ownedTemplate.id, 'source', 'renewal-transaction')).id, 'successor');
  await assert.rejects(
    findRenewedCredential(page, ownedTemplate.id, 'source', 'renewal-transaction'),
    /exact predecessor/,
  );
  await assert.rejects(findIssuedCredential(page, ownedTemplate.id, 'renewal-transaction'), /HTTP 503/);
  page.assertDone();
});

test('cleanup revokes only this run including a receipt that failed before recording its credential ID', async () => {
  const records = [
    credential('ours-active', 'tx-active'),
    credential('ours-suspended', 'tx-suspended', 'SUSPENDED'),
    credential('ours-revoked', 'tx-revoked', 'REVOKED'),
    credential('unrelated-same-template', 'unrelated-transaction'),
    credential('unrelated-other-template', 'tx-active', 'ACTIVE', { credential_template_id: 'other-template' }),
  ];
  const page = scriptedBrowser([
    { path: `/v1/credential-templates/${ownedTemplate.id}`, body: ownedTemplate },
    { path: credentialListPath, body: records },
    { path: '/v1/issued-credentials/ours-active/revoke', method: 'POST', body: { id: 'ours-active', status: 'REVOKED' } },
    { path: '/v1/issued-credentials/ours-suspended/revoke', method: 'POST', body: { id: 'ours-suspended', status: 'REVOKED' } },
    { path: `/v1/credential-templates/${ownedTemplate.id}/deprecate`, method: 'POST', body: { ...ownedTemplate, status: 'DEPRECATED' } },
  ]);
  const cleanup = await cleanupOwnedLifecycle(page, {
    templateId: ownedTemplate.id,
    transactionIds: ['tx-active', 'tx-suspended', 'tx-revoked'],
    credentialIds: ['ours-active', 'ours-revoked'],
  });
  assert.equal(cleanup.ok, true);
  assert.deepEqual(cleanup.revoked, ['ours-active', 'ours-suspended']);
  assert.deepEqual(cleanup.alreadyRevoked, ['ours-revoked']);
  assert.equal(cleanup.templateRetired, true);
  page.assertDone();
});

test('cleanup validates every ownership link and organization before any mutation', async () => {
  const ours = credential('ours', 'run-transaction');
  for (const scenario of [
    { records: [ours, { ...ours, id: 'duplicate' }], message: /multiple credential records/ },
    { records: [{ ...ours, organization_id: 'other-organization' }], message: /another organization/ },
    { records: [ours], credentialIds: ['unrelated'], message: /cannot be matched/ },
    { records: [{ ...ours, status: 'UNKNOWN' }], message: /unknown lifecycle status/ },
  ]) {
    const page = scriptedBrowser([
      { path: `/v1/credential-templates/${ownedTemplate.id}`, body: ownedTemplate },
      { path: credentialListPath, body: scenario.records },
    ]);
    await assert.rejects(cleanupOwnedLifecycle(page, {
      templateId: ownedTemplate.id,
      transactionIds: ['run-transaction'],
      credentialIds: scenario.credentialIds || ['ours'],
    }), scenario.message);
    page.assertDone();
  }

  const foreignTemplate = scriptedBrowser([
    { path: `/v1/credential-templates/${ownedTemplate.id}`, body: { ...ownedTemplate, organization_id: 'other-organization' } },
  ]);
  await assert.rejects(cleanupOwnedLifecycle(foreignTemplate, { templateId: ownedTemplate.id }), /Cannot establish/);
  foreignTemplate.assertDone();

  const noResources = scriptedBrowser([]);
  assert.equal((await cleanupOwnedLifecycle(noResources, { templateId: null })).ok, true);
  await assert.rejects(cleanupOwnedLifecycle(noResources, { templateId: sourceTemplateId }), /newly created/);
  noResources.assertDone();
});

test('an unreadable unclaimed transaction stays incomplete without touching a concurrent credential', async () => {
  const page = scriptedBrowser([
    { path: `/v1/credential-templates/${ownedTemplate.id}`, body: ownedTemplate },
    { path: credentialListPath, body: [credential('concurrent', 'other-transaction')] },
    { path: `/v1/issuance/unclaimed-transaction?organization_id=${encodeURIComponent(organizationId)}`, status: 503 },
    { path: `/v1/credential-templates/${ownedTemplate.id}/deprecate`, method: 'POST', body: { ...ownedTemplate, status: 'DEPRECATED' } },
  ]);
  const cleanup = await cleanupOwnedLifecycle(page, { templateId: ownedTemplate.id, transactionIds: ['unclaimed-transaction'] });
  assert.equal(cleanup.ok, false);
  assert.equal(cleanup.templateRetired, true);
  assert.deepEqual(cleanup.revoked, []);
  assert.deepEqual(cleanup.pendingTransactionIds, ['unclaimed-transaction']);
  page.assertDone();
});

test('cleanup cancels an exact owned unclaimed offer and confirms public state after a lost response', async () => {
  const transactionId = 'unclaimed-transaction';
  const transactionPath = `/v1/issuance/${transactionId}?organization_id=${encodeURIComponent(organizationId)}`;
  const transaction = {
    id: transactionId, organization_id: organizationId,
    credential_template_id: ownedTemplate.id, application_id: null, status: 'pending',
  };
  const records = [credential('concurrent', 'other-transaction')];
  const page = scriptedBrowser([
    { path: `/v1/credential-templates/${ownedTemplate.id}`, body: ownedTemplate },
    { path: credentialListPath, body: records },
    { path: transactionPath, body: transaction },
    { path: credentialListPath, body: records },
    { path: `/v1/issuance/${transactionId}/revoke`, method: 'POST', error: new Error('Synthetic lost response') },
    { path: transactionPath, body: { ...transaction, status: 'revoked' } },
    { path: `/v1/credential-templates/${ownedTemplate.id}/deprecate`, method: 'POST', body: { ...ownedTemplate, status: 'DEPRECATED' } },
  ]);
  const cleanup = await cleanupOwnedLifecycle(page, { templateId: ownedTemplate.id, transactionIds: [transactionId] });
  assert.equal(cleanup.ok, true);
  assert.deepEqual(cleanup.cancelledTransactionIds, [transactionId]);
  assert.deepEqual(cleanup.pendingTransactionIds, []);
  assert.deepEqual(cleanup.uncertainMutations, []);
  assert.deepEqual(cleanup.revoked, []);
  page.assertDone();
});

test('unconfirmed transaction cancellation prevents lifecycle cleanup success', async () => {
  const transactionId = 'unconfirmed-transaction';
  const transactionPath = `/v1/issuance/${transactionId}?organization_id=${encodeURIComponent(organizationId)}`;
  const transaction = {
    id: transactionId, organization_id: organizationId,
    credential_template_id: ownedTemplate.id, application_id: null, status: 'pending',
  };
  const page = scriptedBrowser([
    { path: `/v1/credential-templates/${ownedTemplate.id}`, body: ownedTemplate },
    { path: credentialListPath, body: [] },
    { path: transactionPath, body: transaction },
    { path: credentialListPath, body: [] },
    { path: `/v1/issuance/${transactionId}/revoke`, method: 'POST', status: 503 },
    { path: transactionPath, status: 503 },
    { path: `/v1/credential-templates/${ownedTemplate.id}/deprecate`, method: 'POST', body: { ...ownedTemplate, status: 'DEPRECATED' } },
  ]);
  const cleanup = await cleanupOwnedLifecycle(page, { templateId: ownedTemplate.id, transactionIds: [transactionId] });
  assert.equal(cleanup.ok, false);
  assert.deepEqual(cleanup.cancelledTransactionIds, []);
  assert.deepEqual(cleanup.pendingTransactionIds, [transactionId]);
  assert.deepEqual(cleanup.uncertainMutations, [{ operation: 'transaction_cancellation', transactionId }]);
  page.assertDone();
});

test('cleanup records revoke failures and still attempts to retire only the owned template', async () => {
  for (const failure of [{ status: 503 }, { error: new Error('Synthetic network failure') }]) {
    const page = scriptedBrowser([
      { path: `/v1/credential-templates/${ownedTemplate.id}`, body: ownedTemplate },
      { path: credentialListPath, body: [credential('ours', 'run-transaction')] },
      { path: '/v1/issued-credentials/ours/revoke', method: 'POST', ...failure },
      { path: `/v1/credential-templates/${ownedTemplate.id}/deprecate`, method: 'POST', body: { ...ownedTemplate, status: 'DEPRECATED' } },
    ]);
    const cleanup = await cleanupOwnedLifecycle(page, {
      templateId: ownedTemplate.id,
      transactionIds: ['run-transaction'],
      credentialIds: ['ours'],
    });
    assert.equal(cleanup.ok, false);
    assert.equal(cleanup.templateRetired, true);
    assert.deepEqual(cleanup.revoked, []);
    assert.deepEqual(cleanup.failures, [{ id: 'ours', operation: 'revoke', status: failure.status || 0 }]);
    page.assertDone();
  }
});

test('COMPLETE follows cleanup, browser close and report writing; finalization failures still close evidence', async () => {
  for (const failing of [null, 'cleanup', 'closeBrowser', 'writeReport', 'complete']) {
    const calls = [];
    const operations = Object.fromEntries(
      ['cleanup', 'closeBrowser', 'writeReport', 'complete', 'closeEvidence'].map((name) => [name, async () => {
        calls.push(name);
        if (name === failing) throw new Error(`Synthetic ${name} failure`);
      }]),
    );
    const pending = finalizeLiveRun({ ...operations, successful: () => true });
    if (failing) await assert.rejects(pending, /finalization failed|Synthetic complete failure/);
    else await pending;
    assert.deepEqual(calls, [
      'cleanup', 'closeBrowser', 'writeReport',
      ...(!failing || failing === 'complete' ? ['complete'] : []),
      'closeEvidence',
    ]);
  }
});

test('cleanup uncertainty invalidates live completion even when the journey was previously ready', async () => {
  const report = { releaseReady: true };
  const owned = { templateId: null, transactionIds: [], uncertainMutations: [{ operation: 'template_creation' }] };
  const calls = [];
  await finalizeLiveRun({
    cleanup: async () => {
      report.cleanup = await cleanupOwnedLifecycle({}, owned);
      report.releaseReady &&= report.cleanup.ok;
    },
    closeBrowser: async () => calls.push('closed'),
    writeReport: async () => calls.push(`reported:${report.releaseReady}`),
    successful: () => report.releaseReady,
    complete: async () => assert.fail('Uncertain creation must not complete live evidence'),
    closeEvidence: async () => calls.push('evidence-closed'),
  });
  assert.deepEqual(report.cleanup.uncertainMutations, [{ operation: 'template_creation' }]);
  assert.deepEqual(calls, ['closed', 'reported:false', 'evidence-closed']);
});

test('a wallet without an acquired run session cannot navigate, reset or receive a credential', async () => {
  const calls = [];
  const walletPage = {
    context: () => ({}),
    goto: async () => calls.push('navigate'),
    request: { post: async () => { calls.push('reset'); return { ok: () => false }; } },
    reload: async () => assert.fail('Must not continue with a stale wallet'),
  };
  await assert.rejects(receiveCredential(walletPage, 'fixture-offer', 'urn:example:employee'), /run-owned Rust wallet session/);
  assert.deepEqual(calls, []);
});

test('lifecycle status authority is read-only and must be active, tenant-owned and unambiguous', async () => {
  const profilePath = `/v1/revocation-profiles?organization_id=${encodeURIComponent(organizationId)}`;
  const profile = { id: 'active-profile', organization_id: organizationId, name: 'Status authority', status: 'ACTIVE' };
  for (const profiles of [[], [profile, { ...profile, id: 'another-profile' }],
    [{ ...profile, organization_id: 'foreign-org' }], [{ ...profile, status: 'DRAFT' }]]) {
    const page = scriptedBrowser([
      { path: `/v1/credential-templates/${sourceTemplateId}`, body: sourceTemplate },
      { path: profilePath, body: profiles },
    ]);
    assert.equal((await ensureActiveRevocationProfile(page)).ok, false);
    page.assertDone();
    assert.ok(page.requests.every((request) => request.method === 'GET'));
  }
  const page = scriptedBrowser([
    { path: `/v1/credential-templates/${sourceTemplateId}`, body: { ...sourceTemplate, revocation_profile_id: profile.id } },
    { path: profilePath, body: [profile, { ...profile, id: 'unrelated-profile' }] },
  ]);
  const selected = await ensureActiveRevocationProfile(page);
  assert.equal(selected.id, profile.id);
  assert.equal(selected.reused, true);
  assert.equal(selected.ownership, 'REFERENCE_ONLY');
  page.assertDone();
});

test('acknowledged and sealed fixture values become actual issuance claims while retaining transaction ownership', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'lifecycle-live-'));
  const calls = [];
  try {
    const input = await prepareLiveInputs(directory, 'unit-run-01', {
      readFixture: async (file) => { calls.push('read-ack'); return fs.readFileSync(path.join(directory, file)); },
      seal: async () => calls.push('seal-ack'),
    });
    const claims = [
      { name: 'email' }, { name: 'given_name' }, { name: 'family_name' },
      { name: 'employee_id' }, { name: 'department' }, { name: 'position' },
      { name: 'issued_date', type: 'DATE' }, { name: 'issued_at', type: 'DATETIME' },
    ];
    const owned = { templateId: ownedTemplate.id, transactionIds: [], uncertainMutations: [] };
    const page = scriptedBrowser([
      { path: `/v1/credential-templates/${ownedTemplate.id}`, body: { ...ownedTemplate, claims, vct: 'urn:example:employee' } },
      { path: '/v1/issuance', method: 'POST', status: 201,
        body: { id: 'acknowledged-fixture-transaction', credential_offer_uri: 'fixture-offer' },
        observe: () => calls.push('issuance'),
      },
    ]);
    await issueCredential(page, ownedTemplate.id, owned, input.holder);
    const issued = JSON.parse(page.requests[1].options.body);
    assert.deepEqual(calls, ['read-ack', 'seal-ack', 'issuance']);
    assert.equal(issued.organization_id, input.organizationId);
    assert.equal(issued.credential_template_id, owned.templateId);
    assert.deepEqual(issued.claims, {
      email: input.holder.email,
      given_name: input.holder.given,
      family_name: input.holder.family,
      employee_id: 'LIFECYCLE-unit-run-01',
      department: input.holder.department,
      position: input.holder.position,
      issued_date: input.holder.date,
      issued_at: input.holder.dateTime,
    });
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(directory, 'lifecycle-fixture-input.json'))), input);
    assert.deepEqual(owned.transactionIds, ['acknowledged-fixture-transaction']);
    assert.deepEqual(owned.uncertainMutations, []);
    page.assertDone();
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('fixture ACK rejection or changed input cannot seal, and prior attempt inputs are not overwritten', async () => {
  for (const changed of [false, true]) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'lifecycle-live-failed-'));
    try {
      await assert.rejects(prepareLiveInputs(directory, 'unit-run', {
        readFixture: async (file) => {
          if (!changed) throw new Error('Fixture ACK rejected');
          const input = JSON.parse(fs.readFileSync(path.join(directory, file)));
          input.holder.employeeId = 'OTHER-RUN';
          return Buffer.from(JSON.stringify(input));
        },
        seal: async () => assert.fail('Rejected fixture must not be sealed'),
      }), /ACK rejected|differs from actual demo inputs/);
      const before = fs.readFileSync(path.join(directory, 'lifecycle-fixture-input.json'));
      await assert.rejects(prepareLiveInputs(directory, 'different-run', {}), { code: 'EEXIST' });
      assert.deepEqual(fs.readFileSync(path.join(directory, 'lifecycle-fixture-input.json')), before);
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  }
});

test('lifecycle landmarks use monotonic observation time; disabled recording still requires visible real controls', async () => {
  let now = 1000;
  const calls = [];
  const page = { waitForTimeout: async (ms) => { now += ms; calls.push(`hold:${ms}`); } };
  const locator = {
    waitFor: async ({ state }) => calls.push(state),
    scrollIntoViewIfNeeded: async () => calls.push('scroll'),
    boundingBox: async () => ({ x: 100, y: 200, width: 150, height: 40 }),
  };
  const recording = createLifecycleRecording(page, { enabled: true, now: () => now });
  await recording.hold('suspend', 'reason', locator, 3200);
  assert.equal(recording.evidence.videoFrameAlignmentEstablished, false);
  assert.equal(recording.evidence.editorMustAlignToSourceFrames, true);
  assert.equal(recording.evidence.pointerTimingBasis, 'DRIVER_LANDMARKS_NOT_OS_CLICK_TELEMETRY');
  assert.deepEqual(recording.events.map(({ action, phase, elapsedSeconds }) => ({ action, phase, elapsedSeconds })), [
    { action: 'suspend', phase: 'reason-visible', elapsedSeconds: 0 },
    { action: 'suspend', phase: 'reason-hold-end', elapsedSeconds: 3.2 },
  ]);
  assert.deepEqual(recording.events[0].bounds, { x: 100, y: 200, width: 150, height: 40 });
  const disabled = createLifecycleRecording(page, { enabled: false });
  await disabled.hold('suspend', 'reason', locator);
  await disabled.explain('suspend');
  disabled.mark('suspend', 'confirm');
  assert.deepEqual(disabled.events, []);
  assert.deepEqual(calls, ['visible', 'scroll', 'hold:3200', 'visible', 'scroll']);
  await assert.rejects(disabled.hold('suspend', 'reason', {
    waitFor: async () => { throw new Error('Real reason field missing'); },
  }), /Real reason field missing/);
});

test('lifecycle reasons are entered in the real dialog before confirmation and the resulting status is shown', async () => {
  for (const [action, state] of [['suspend', 'suspended'], ['reinstate', 'active'], ['revoke', 'revoked']]) {
    const calls = [];
    const reason = LIFECYCLE_DEMO_REASONS[action];
    const dialog = {
      getByRole: (role, { name }) => {
        if (role === 'textbox') {
          assert.ok(name.test('Reason'));
          return { fill: async (value) => calls.push(['reason', value]) };
        }
        assert.ok(name.test(action));
        return { click: async () => calls.push('confirm') };
      },
      waitFor: async ({ state: visibility }) => { assert.equal(visibility, 'hidden'); calls.push('dialog-hidden'); },
    };
    const row = {
      getByRole: (role, { name }) => {
        assert.equal(role, 'button');
        assert.ok(name.test(`${action} credential CRD-ours`));
        return { click: async () => calls.push('open-dialog') };
      },
      getByText: (pattern) => { assert.ok(pattern.test(state)); return { actualStatus: state }; },
    };
    const page = {
      waitForResponse: () => Promise.resolve({ ok: () => true, status: () => 200, json: async () => ({ status: state }) }),
      getByRole: (role) => { assert.equal(role, 'dialog'); return dialog; },
    };
    const recording = {
      explain: async (actualAction, actualReason) => {
        assert.equal(actualAction, action);
        assert.equal(actualReason, reason);
        calls.push('explain');
      },
      hold: async (_action, phase, target) => calls.push(['hold', phase, target.actualStatus || null]),
      mark: (_action, phase) => calls.push(phase),
    };
    assert.equal((await performLifecycleAction(page, row, action, reason, recording)).ok, true);
    assert.deepEqual(calls, [
      'explain', ['hold', 'button', null], 'button-click', 'open-dialog',
      ['hold', 'dialog', null], ['reason', reason], ['hold', 'reason', null],
      'confirm-click', 'confirm', 'dialog-hidden', 'response-success', ['hold', 'resulting-status', state],
    ]);
    assert.match(reason, /^Synthetic scenario:/);
  }
});

test('renewal presents its real direct button and preserves ownership before dispatch without inventing a dialog', async () => {
  const calls = [];
  const owned = { templateId: ownedTemplate.id, transactionIds: [], uncertainMutations: [] };
  const page = {
    waitForResponse: () => Promise.resolve({ ok: () => true, status: () => 200,
      json: async () => ({ credential_offer_uri: 'fixture-offer', transaction_id: 'renewal-transaction' }) }),
  };
  const row = { getByRole: () => ({ click: async () => {
    assert.deepEqual(owned.uncertainMutations, [{ operation: 'renewal' }]);
    calls.push('click');
  } }) };
  const recording = {
    explain: async () => calls.push('explain'),
    hold: async () => { assert.deepEqual(owned.uncertainMutations, []); calls.push('hold'); },
    mark: (_action, phase, detail) => calls.push([phase, detail]),
  };
  assert.equal((await renewCredential(page, row, owned, recording)).ok, true);
  assert.deepEqual(calls, ['explain', 'hold', ['button-click', { confirmationDialog: false, reasonField: false }], 'click']);
  assert.deepEqual(owned.transactionIds, ['renewal-transaction']);
  assert.deepEqual(owned.uncertainMutations, []);
});

test('a missing renewal control fails before claiming that a mutation was dispatched even without recording', async () => {
  const owned = { transactionIds: [], uncertainMutations: [] };
  const page = { waitForResponse: () => assert.fail('Must locate the control before waiting for a mutation') };
  const row = { getByRole: () => ({ waitFor: async () => { throw new Error('Renew button is unavailable'); } }) };
  await assert.rejects(
    renewCredential(page, row, owned, createLifecycleRecording(page, { enabled: false })),
    /Renew button is unavailable/,
  );
  assert.deepEqual(owned, { transactionIds: [], uncertainMutations: [] });
});

test('initial access requires actual successful session, wallet presentation and allowed verifier evidence', () => {
  const evidence = { session: { ok: true }, wallet: { ok: true }, result: { httpStatus: 200, decision: 'allow' } };
  assert.equal(initialActiveVerificationPassed(evidence), true);
  for (const invalid of [null, {}, { ...evidence, session: { ok: false } }, { ...evidence, wallet: { ok: false } },
    { ...evidence, result: { httpStatus: 200, decision: 'deny' } },
    { ...evidence, result: { httpStatus: 500, decision: 'allow' } },
    { ...evidence, result: { decision: 'allow' } }]) {
    assert.equal(initialActiveVerificationPassed(invalid), false);
  }
});

test('renewal shows exact predecessor and successor UI rows and rejects a missing revoked state or lineage link', async () => {
  const run = async (missing = null) => {
    const calls = [];
    const row = (id) => ({
      waitFor: async () => calls.push(`row:${id}`),
      locator: (selector) => {
        assert.equal(selector, '[data-credential-reference]');
        return { waitFor: async () => {}, getAttribute: async () => `CRD-${id}` };
      },
      getByText: (text, options) => {
        if (id === 'old') assert.ok(text.test('revoked'));
        else { assert.equal(text, 'Renewed from CRD-old'); assert.equal(options.exact, true); }
        return {
          waitFor: async () => {
            if (id === missing) throw new Error(`UI ${id === 'old' ? 'revoked state' : 'renewal link'} absent`);
            calls.push(`visible:${id}`);
          },
          scrollIntoViewIfNeeded: async () => calls.push(`scroll:${id}`),
        };
      },
    });
    const rows = { old: row('old'), new: row('new') };
    const page = {
      getByPlaceholder: () => ({ fill: async (value) => calls.push(`search:${value}`) }),
      getByRole: () => ({ click: async () => calls.push('refresh') }),
      locator: (selector) => {
        const id = /^tbody tr\[data-credential-record-id="(old|new)"\]$/.exec(selector)?.[1];
        assert.ok(id, 'Must select only exact source and successor IDs');
        return rows[id];
      },
    };
    const result = await showRenewalLineage(page, 'old', 'new', createLifecycleRecording(page, { enabled: false }));
    assert.equal(result.row, rows.new);
    assert.deepEqual(result.evidence, {
      predecessorRevokedVisible: true, successorLinkVisible: true,
      sourceCredentialId: 'old', successorId: 'new', predecessorReference: 'CRD-old',
    });
    assert.ok(calls.indexOf('scroll:old') < calls.indexOf('row:new'));
    assert.ok(calls.includes('search:CRD-old') && calls.includes('search:CRD-new'));
  };
  await run();
  await assert.rejects(run('old'), /UI revoked state absent/);
  await assert.rejects(run('new'), /UI renewal link absent/);
});

test('shared lifecycle cues identify the current scenario and use its configured or actual dialog reason', async () => {
  const overlays = [];
  const page = {
    evaluate: async (_callback, payload) => { if (payload) overlays.push(payload); },
    waitForTimeout: async () => {},
  };
  const recording = createLifecycleRecording(page, {
    enabled: true,
    scenario: 'employee-access',
    pageName: 'reviewer',
    eyebrow: 'Employee access scenario',
    reasons: { suspend: 'Synthetic scenario: employee changed role.' },
  });
  await recording.explain('suspend');
  await recording.explain('suspend', 'Synthetic scenario: security review requires temporary suspension.');
  assert.equal(recording.evidence.scenario, 'employee-access');
  assert.equal(recording.evidence.pageName, 'reviewer');
  assert.deepEqual(overlays.map(({ title, detail, eyebrowText }) => ({ title, detail, eyebrowText })), [
    { title: 'Admin action: suspend', detail: 'Synthetic scenario: employee changed role.', eyebrowText: 'Employee access scenario' },
    { title: 'Admin action: suspend', detail: 'Synthetic scenario: security review requires temporary suspension.', eyebrowText: 'Employee access scenario' },
  ]);
  assert.deepEqual(recording.events.map(({ reason }) => reason), overlays.map(({ detail }) => detail));
});

test('each lifecycle stage requires its action, current state and completed verifier decision before success narration', () => {
  for (const [action, state, decision, reason] of [
    ['suspend', 'SUSPENDED', 'deny', 'Credential is suspended'],
    ['reinstate', 'ACTIVE', 'allow', 'Policy satisfied'],
    ['revoke', 'REVOKED', 'deny', 'Credential is revoked'],
  ]) {
    const evidence = {
      ok: true,
      status: 200,
      current: { ok: true, status: 200, lifecycleStatus: state },
      verification: { session: { ok: true }, wallet: { ok: true }, result: { httpStatus: 200, decision, decisionReason: reason,
        status: decision === 'allow' ? 'COMPLETED' : 'FAILED',
        evaluation: decision === 'allow' ? 'passed' : 'failed' } },
    };
    assert.equal(requireLifecycleActionEvidence(action, evidence), evidence.verification.result);
    const invalid = [
      null,
      { ...evidence, ok: false },
      { ...evidence, status: 503 },
      { ...evidence, current: { ...evidence.current, ok: false } },
      { ...evidence, current: { ...evidence.current, status: 503 } },
      { ...evidence, current: { ...evidence.current, lifecycleStatus: 'DRAFT' } },
      { ...evidence, verification: { ...evidence.verification, session: { ok: false } } },
      { ...evidence, verification: { ...evidence.verification, wallet: { ok: false } } },
      { ...evidence, verification: { ...evidence.verification, result: { ...evidence.verification.result, httpStatus: 500 } } },
      { ...evidence, verification: { ...evidence.verification, result: { ...evidence.verification.result, decision: decision === 'allow' ? 'deny' : 'allow' } } },
      { ...evidence, verification: { ...evidence.verification, result: { ...evidence.verification.result, status: 'IN_PROGRESS' } } },
      { ...evidence, verification: { ...evidence.verification, result: { ...evidence.verification.result, evaluation: undefined } } },
    ];
    if (decision === 'deny') {
      invalid.push(
        { ...evidence, verification: { ...evidence.verification, result: { ...evidence.verification.result, decisionReason: 'Issuer is untrusted' } } },
        { ...evidence, verification: { ...evidence.verification, result: { ...evidence.verification.result, decisionReason: undefined } } },
      );
    }
    for (const failure of invalid) {
      assert.throws(() => requireLifecycleActionEvidence(action, failure), /current-state evidence|completed wallet presentation|denial reason/);
    }
  }
});


function verificationBrowserFixture(walletStatus,walletBody,polls=[]){
 const request={path:'/v1/flows/verify',method:'POST',status:201,body:{instance_id:'SOURCE_ONLY_INSTANCE',request_uri:'openid4vp://SOURCE_ONLY_REQUEST'}};
 const page=scriptedBrowser([request,...polls.map(p=>({path:'/v1/flows/instances/SOURCE_ONLY_INSTANCE/result',...p}))]);let clicks=0;
 const walletPage={getByLabel:()=>({fill:async()=>{},evaluate:async()=>{}}),getByRole:()=>({click:async()=>{clicks++;}}),
  waitForResponse:async predicate=>{const response={url:()=>`${process.env.MARTY_TEST_WALLET_ORIGIN||'http://127.0.0.1:8787'}/api/present`,request:()=>({method:()=> 'POST'}),ok:()=>walletStatus>=200&&walletStatus<300,status:()=>walletStatus,json:async()=>walletBody};assert(predicate(response));return response;}};
 return {page,walletPage,get clicks(){return clicks;},run:options=>verify(page,walletPage,'SOURCE_ONLY_VERIFY',{issuerDid:'did:example:source-only',resultTimeoutMs:10,resultIntervalMs:0,...options})};
}

test('verification retains a rejected wallet response and does not poll a presentation that was never submitted',async()=>{
 const f=verificationBrowserFixture(422,{ok:false,error:'SD-JWT error: issuer verification failed eyJzb3VyY2Vfb25seSI6dHJ1ZX0.payload.signature Bearer SOURCE_ONLY_SECRET'});const r=await f.run();
 assert.equal(r.wallet.ok,false);assert.equal(r.wallet.status,422);assert.equal(r.wallet.errorClass,'SD-JWT error');assert(r.wallet.errorIndicators.includes('issuer verification failed'));assert(!r.wallet.error.includes('SOURCE_ONLY_SECRET'));assert(!r.wallet.error.includes('eyJzb3VyY2V'));assert.match(r.wallet.errorSha256,/^[a-f0-9]{64}$/);
 assert.equal(r.result,null);assert.equal(r.diagnostic.outcome,'REJECTED_BEFORE_SUBMISSION');assert.equal(r.session.requestUri,'[present]');assert.equal(initialActiveVerificationPassed(r),false);assert.equal(f.page.requests.length,1);assert.equal(f.clicks,1);
});

test('submitted verifier denial still requires its real terminal result and successful presentation preserves ALLOW',async()=>{
 for(const denied of [false,true]){
  const f=verificationBrowserFixture(denied?400:200,denied?{ok:false,error:'Verifier rejected presentation',submission:{submitted:true,verifier_http_status:400,verifier_error:'invalid_presentation'}}:{ok:true},[{status:200,body:{status:denied?'FAILED':'COMPLETED',result:denied?'failed':'passed',decision:denied?'deny':'allow'}}]);
  const r=await f.run();assert.equal(r.result.decision,denied?'deny':'allow');require('./beta-demo-review-ui').requireVerificationDecision(r,denied?'deny':'allow');assert.equal(initialActiveVerificationPassed(r),!denied);assert.equal(f.page.requests.length,2);
 }
});

test('pending409 timeout and poll transport failure retain wallet/session evidence without inventing a verifier decision',async()=>{
 for(const transport of [false,true]){
  const f=verificationBrowserFixture(200,{ok:true},transport?[{error:Error('SOURCE_ONLY_POLL_TRANSPORT')}]:Array.from({length:200},()=>({status:409,body:{status:'PENDING'}})));
  const r=await f.run();assert.equal(r.wallet.ok,true);assert.equal(r.session.ok,true);assert.equal(r.result,null);assert.equal(initialActiveVerificationPassed(r),false);assert.equal(r.diagnostic.outcome,transport?'POLL_FAILED':'POLL_TIMEOUT');
  if(!transport){assert(r.diagnostic.pollCount>0);assert.equal(r.diagnostic.lastHttpStatus,409);}
  assert.throws(()=>require('./beta-demo-review-ui').requireVerificationDecision(r,'allow'));assert.throws(()=>require('./beta-demo-review-ui').requireVerificationDecision(r,'deny'));
 }
});

test('wallet control transport failure retains the created session and refuses result polling',async()=>{
 const f=verificationBrowserFixture(200,{ok:true});f.walletPage.getByRole=()=>({click:async()=>{throw Error('SOURCE_ONLY_CLICK_FAILED');}});const r=await f.run();
 assert.equal(r.session.ok,true);assert.equal(r.wallet,null);assert.equal(r.result,null);assert.equal(r.diagnostic.outcome,'TRANSPORT_FAILED');assert.equal(f.page.requests.length,1);
});


test('HTTP200 body failure retains sanitized reason and only whitelisted submission metadata',async()=>{
 const secret='SOURCE_ONLY_BODY_SECRET',f=verificationBrowserFixture(200,{ok:false,error:'JWT error: Bearer '+secret,
  submission:{submitted:false,verifier_http_status:'400',verifier_error:'https://'+secret,token:secret,claims:{secret}}});const r=await f.run();
 assert.equal(r.wallet.ok,false);assert.equal(r.wallet.status,200);assert.equal(r.wallet.errorClass,'JWT error');assert(r.wallet.error.includes('[redacted]'));assert(!JSON.stringify(r).includes(secret));
 assert.deepEqual(r.wallet.submission,{submitted:false,verifier_http_status:null,verifier_error:null});assert.equal(r.diagnostic.outcome,'REJECTED_BEFORE_SUBMISSION');assert.equal(r.result,null);assert.equal(f.page.requests.length,1);
});
