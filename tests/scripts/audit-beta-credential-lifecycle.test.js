'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

test('live fixture ACK and seal precede use of actual registered issuance inputs',async()=>{
  const {prepareLiveInputs,issueCredential}=require('./audit-beta-credential-lifecycle');
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'lifecycle-live-'));const events=[];
  try {
    const input=await prepareLiveInputs(directory,'unit-reset-01',{
      readFixture:async file=>{events.push('read-ack');return fs.readFileSync(path.join(directory,file));},
      seal:async()=>events.push('seal-ack'),
    });
    let issuance;
    const page={evaluate:async(fn,args)=>{
      const vm=require('node:vm');
      return vm.runInNewContext(`(${fn.toString()})(args)`,{args,fetch:async(url,options)=>{
        if(url.startsWith('/v1/credential-templates/'))return {ok:true,json:async()=>({name:'Synthetic',claims:[{name:'email'},{name:'employee_id'}]})};
        events.push('issuance');issuance=JSON.parse(options.body);return {ok:true,status:200,json:async()=>({credential_offer_uri:'unit-offer'})};
      }});
    }};
    await issueCredential(page,'unit-template',input.holder);
    assert.deepEqual(events,['read-ack','seal-ack','issuance']);
    assert.equal(issuance.claims.email,input.holder.email);assert.equal(issuance.claims.employee_id,'LIFECYCLE-unit-reset-01');
    assert.equal(JSON.parse(fs.readFileSync(path.join(directory,'lifecycle-fixture-input.json'))).holder.employeeId,issuance.claims.employee_id);
  }finally{fs.rmSync(directory,{recursive:true,force:true});}
});

test('live fixture rejection cannot seal and existing inputs are never overwritten',async()=>{
  const {prepareLiveInputs}=require('./audit-beta-credential-lifecycle');
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'lifecycle-live-fail-'));let sealed=false;
  try {
    await assert.rejects(prepareLiveInputs(directory,'unit',{readFixture:async()=>{throw Error('ACK rejected');},seal:async()=>{sealed=true;}}),/ACK rejected/);
    assert.equal(sealed,false);
    const before=fs.readFileSync(path.join(directory,'lifecycle-fixture-input.json'));
    await assert.rejects(prepareLiveInputs(directory,'different',{}),{code:'EEXIST'});
    assert.deepEqual(fs.readFileSync(path.join(directory,'lifecycle-fixture-input.json')),before);
  }finally{fs.rmSync(directory,{recursive:true,force:true});}
});

const {
  candidateUiFileForRequest,
  createLifecycleRecording,
  initialActiveVerificationPassed,
  showRenewalLineage,
  LIFECYCLE_DEMO_REASONS,
  performLifecycleAction,
  renewCredential,
  dismissLifecycleUpdatedNotification,
  findCredentialRow,
  requireDismissedLifecycleNotification,
  resolveUiCandidateDist,
  resolveVerificationIssuerDid,
  selectRenewedCredential,
} = require('./audit-beta-credential-lifecycle');

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


test('recording cadence records monotonic observation boundaries and stays inert outside recordings', async () => {
  let clock = 1000;
  const calls = [];
  const page = {waitForTimeout: async ms => {calls.push(ms); clock += ms;}};
  const locator = {waitFor: async () => calls.push('visible'), scrollIntoViewIfNeeded: async () => calls.push('scroll')};
  const recording = createLifecycleRecording(page, {enabled: true, now: () => clock});
  await recording.hold('suspend', 'reason', locator, 3200);
  assert.deepEqual(calls, ['visible', 'scroll', 3200]);
  assert.deepEqual(recording.evidence.events.map(e => [e.phase, e.elapsedSeconds]),
    [['reason-visible', 0], ['reason-hold-end', 3.2]]);
  assert.equal(recording.evidence.videoFrameAlignmentEstablished, false);
  assert.equal(recording.evidence.editorMustAlignToSourceFrames, true);
  const disabled = createLifecycleRecording({}, {enabled: false});
  await disabled.hold('suspend', 'reason', null);
  await disabled.explain('suspend');
  disabled.mark('suspend', 'confirm');
  assert.deepEqual(disabled.evidence.events, []);
});

test('lifecycle recording shows the real dialog reason before confirm and waits for the actual resulting status', async () => {
  for (const [action, state] of [['suspend', 'suspended'], ['reinstate', 'active'], ['revoke', 'revoked']]) {
    const calls = [];
    const reason = LIFECYCLE_DEMO_REASONS[action];
    const dialog = {
      getByRole: (role) => role === 'textbox'
        ? {fill: async value => calls.push(['fill', value])}
        : {click: async () => calls.push('confirm')},
      waitFor: async () => calls.push('dialog-hidden'),
    };
    const row = {
      getByRole: () => ({click: async () => calls.push('open-dialog')}),
      getByText: pattern => {assert.ok(pattern.test(state)); return {actualStatus: state};},
    };
    const page = {
      waitForResponse: () => Promise.resolve({ok: () => true, status: () => 200, json: async () => ({status: state})}),
      getByRole: () => dialog,
    };
    const recording = {explain: async () => calls.push('explain'),
      hold: async (_action, phase, target) => calls.push(['hold', phase, target.actualStatus || null]),
      mark: (_action, phase) => calls.push(phase)};
    const result = await performLifecycleAction(page, row, action, reason, recording);
    assert.equal(result.ok, true);
    assert.deepEqual(calls, ['explain', ['hold', 'button', null], 'button-click', 'open-dialog',
      ['hold', 'dialog', null], ['fill', reason], ['hold', 'reason', null], 'confirm-click', 'confirm',
      'dialog-hidden', 'response-success', ['hold', 'resulting-status', state]]);
    assert.match(reason, /^Synthetic scenario:/);
  }
});

test('renewal uses the real direct button without inventing a dialog or reason field', async () => {
  const calls = [];
  const page = {waitForResponse: () => Promise.resolve({ok: () => true, status: () => 200,
    json: async () => ({credential_offer_uri: 'fixture-offer', transaction_id: 'fixture'})})};
  const row = {getByRole: () => ({click: async () => calls.push('click')})};
  const recording = {explain: async () => calls.push('explain'), hold: async () => calls.push('hold'),
    mark: (_action, phase, detail) => calls.push([phase, detail])};
  assert.equal((await renewCredential(page, row, recording)).ok, true);
  assert.deepEqual(calls, ['explain', 'hold', ['button-click', {confirmationDialog: false, reasonField: false}], 'click']);
});


test('initial active evidence requires actual session, wallet and allowed verifier result', () => {
  const evidence = {session: {ok: true}, wallet: {ok: true}, result: {httpStatus: 200, decision: 'allow'}};
  assert.equal(initialActiveVerificationPassed(evidence), true);
  for (const invalid of [null, {}, {...evidence, wallet: {ok: false}},
    {...evidence, session: {ok: false}}, {...evidence, result: {httpStatus: 200, decision: 'deny'}},
    {...evidence, result: {httpStatus: 500, decision: 'allow'}}]) {
    assert.equal(initialActiveVerificationPassed(invalid), false);
  }
});

test('renewal lineage selects actual predecessor and successor rows and fails if the UI link is absent', async () => {
  const run = async (missingLink = false) => {
    const calls = [];
    const row = (id) => ({
      waitFor: async () => calls.push(`row:${id}`),
      locator: () => ({waitFor: async () => {}, getAttribute: async () => `CRD-${id}`}),
      getByText: text => ({waitFor: async () => {
        calls.push(`text:${id}:${text}`);
        if (id === 'new' && missingLink) throw new Error('UI renewal link absent');
      }}),
    });
    const page = {
      getByPlaceholder: () => ({fill: async value => calls.push(`search:${value}`)}),
      getByRole: () => ({click: async () => calls.push('refresh')}),
      locator: selector => row(selector.includes('"old"') ? 'old' : 'new'),
    };
    const result = await showRenewalLineage(page, 'old', 'new', {hold: async (_a, phase) => calls.push(phase)});
    assert.equal(result.evidence.predecessorRevokedVisible, true);
    assert.equal(result.evidence.successorLinkVisible, true);
    assert.ok(calls.includes('text:old:/^revoked$/i'));
    assert.ok(calls.includes('text:new:Renewed from CRD-old'));
    assert.ok(calls.indexOf('predecessor-revoked-status') < calls.indexOf('successor-link'));
  };
  await run();
  await assert.rejects(run(true), /UI renewal link absent/);
});
