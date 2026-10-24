const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');
const {
  REQUIRED_CHECKPOINTS, createRunReport, runCanvasJourney, finishRunReport,
  tryShowLearnerIdentity, tryShowCredentialTemplateDestinations, tryShowCanvasAdmin,
  tryShowConsoleVerification,
} = require('./record-canvas-employer-demo');

// Inject checkpoint outcomes to test control flow, not to qualify a real
// Canvas/provider/wallet run. Every actual checkpoint remains required.
for (const failing of REQUIRED_CHECKPOINTS) {
  test(`Canvas stops and records failure when ${failing} returns false`, async () => {
    const visited = [];
    const report = createRunReport();
    const actions = Object.fromEntries(REQUIRED_CHECKPOINTS.map((name) => [name, async () => {
      visited.push(name);
      return name !== failing;
    }]));
    let failure;
    try {
      await runCanvasJourney({}, report, actions);
      assert.fail('A false checkpoint must reject');
    } catch (error) {
      failure = error;
    }
    finishRunReport(report, failure);
    assert.match(failure.message, new RegExp(`did not complete: ${failing}`));
    assert.deepEqual(visited, REQUIRED_CHECKPOINTS.slice(0, REQUIRED_CHECKPOINTS.indexOf(failing) + 1));
    assert.equal(report.checkpoints.at(-1).status, 'FAILED');
    assert.equal(report.status, 'FAILED');
    assert.equal(report.completed_at, null);
    assert.equal(report.qualifies_as_real_oss_portability, false);
  });
}

test('undefined checkpoint results and narration alone cannot complete a Canvas run', async () => {
  const report = createRunReport();
  await assert.rejects(runCanvasJourney({}, report, { canvas_lti_launch: async () => undefined }), /did not complete/);
  finishRunReport(report);
  assert.equal(report.status, 'FAILED');
  assert.equal(report.completed_at, null);
});

test('a completed set of walkthrough checkpoints remains excluded from OSS qualification', async () => {
  const report = createRunReport();
  await runCanvasJourney({}, report, Object.fromEntries(REQUIRED_CHECKPOINTS.map((name) => [name, async () => true])));
  finishRunReport(report);
  assert.equal(report.status, 'COMPLETED');
  assert.ok(report.completed_at);
  assert.equal(report.scope, 'LEGACY_CANVAS_SANDBOX_WALKTHROUGH');
  assert.equal(report.qualifies_as_real_oss_portability, false);
});

function pageMissing(target) {
  const narration = [];
  const locator = (name) => ({
    first() { return this; },
    async waitFor() { if (name === target) throw new Error(`missing ${target}`); },
    async scrollIntoViewIfNeeded() {},
    async click() {},
    async count() { return 1; },
    getByText(text) { return locator(text); },
    getByTestId(id) { return locator(id); },
    getByRole(_role, { name }) { return locator(String(name)); },
  });
  return {
    narration,
    goto: async () => {},
    url: () => 'http://localhost/console',
    waitForTimeout: async () => {},
    evaluate: async (_fn, step) => { if (step) narration.push(step.title); },
    getByText: (text) => locator(text),
    getByTestId: (id) => locator(id),
    getByRole: (_role, { name } = {}) => locator(String(name)),
  };
}

test('My Identity header alone cannot pass without the named badge', async () => {
  const page = pageMissing('Interoperable Credentials Foundations Badge');
  await assert.rejects(tryShowLearnerIdentity(page), /missing Interoperable/);
  assert.equal(page.narration.includes('Learner sees the badge in My Identity'), false);
});

test('template destination and admin readiness controls are required before positive narration', async () => {
  const destinationPage = pageMissing('/destinations/i');
  await assert.rejects(tryShowCredentialTemplateDestinations(destinationPage), /missing \/destinations\/i/);
  assert.equal(destinationPage.narration.includes('Credential template owns destinations'), false);
  const adminPage = pageMissing('canvas-readiness');
  await assert.rejects(tryShowCanvasAdmin(adminPage), /missing canvas-readiness/);
  assert.equal(adminPage.narration.includes('Canvas platform and program bindings are managed'), false);
});

test('verification setup cannot pass with a missing action or missing policy dialog', async () => {
  await assert.rejects(tryShowConsoleVerification(pageMissing('/new verification/i')), /missing \/new verification\/i/);
  const page = pageMissing('Select Policy');
  await assert.rejects(tryShowConsoleVerification(page), /missing Select Policy/);
  assert.equal(page.narration.includes('Verification setup starts from policy'), false);
});

// Execute main with a local, non-browser session double and in-memory artifact
// writes to exercise failure reporting/finalization without opening a site.
function loadRecorder({ env = {}, browser, existingStorage = false } = {}) {
  const operations = [];
  const reports = [];
  const source = fs.readFileSync(path.join(__dirname, 'record-canvas-employer-demo.js'), 'utf8');
  const fakeFs = {
    existsSync: (name) => existingStorage && name === 'state.json',
    readFileSync: () => { throw new Error('Unexpected artifact read'); },
    rmSync: (name) => operations.push(`remove:${name}`),
    mkdirSync: (name) => operations.push(`mkdir:${name}`),
    writeFileSync: (_name, text) => reports.push(JSON.parse(text)),
  };
  const module = { exports: {} };
  const requireDouble = (name) => {
    if (name === 'fs') return fakeFs;
    if (name === 'path') return path;
    if (name === '@playwright/test') return { chromium: { launch: async () => {
      operations.push('launch');
      if (!browser) throw new Error('browser launch failed');
      return browser;
    } } };
    throw new Error(`Unexpected import ${name}`);
  };
  let clock = 0;
  class FastDate extends Date { static now() { clock += 31000; return clock; } }
  vm.runInNewContext(source, {
    require: requireDouble, module, __dirname, URL, Date: FastDate,
    process: { env }, console: { log() {}, error() {} },
  });
  return { api: module.exports, operations, reports };
}

test('refused fallback configuration leaves earlier artifacts untouched', async () => {
  const harness = loadRecorder();
  await assert.rejects(harness.api.main(), /built-in fallback URL/);
  assert.deepEqual(harness.operations, []);
  assert.deepEqual(harness.reports, []);
});

test('browser setup failure writes a failed run without a completion timestamp', async () => {
  const harness = loadRecorder({ env: { CANVAS_DEMO_ALLOW_FALLBACK_URLS: '1' } });
  await assert.rejects(harness.api.main(), /browser launch failed/);
  assert.equal(harness.reports.length, 1);
  assert.equal(harness.reports[0].status, 'FAILED');
  assert.equal(harness.reports[0].completed_at, null);
  assert.equal(harness.reports[0].video, null);
});

test('business failure survives finalization errors and every session close is attempted', async () => {
  const closed = [];
  const page = {
    goto: async () => { throw new Error('Canvas login failed'); },
    video: () => null,
    close: async () => { closed.push('page'); throw new Error('page close failed'); },
  };
  const context = { newPage: async () => page, close: async () => closed.push('context') };
  const browser = { newContext: async () => context, close: async () => closed.push('browser') };
  const harness = loadRecorder({ env: { CANVAS_DEMO_ALLOW_FALLBACK_URLS: '1' }, browser });
  await assert.rejects(harness.api.main(), /Canvas login failed/);
  assert.deepEqual(closed, ['page', 'context', 'browser']);
  const report = harness.reports[0];
  assert.equal(report.status, 'FAILED');
  assert.equal(report.failure, 'Canvas login failed');
  assert.equal(report.completed_at, null);
  assert.equal(report.checkpoints[0].status, 'FAILED');
  assert.equal(report.finalization_errors[0].operation, 'page_close');
});

test('provided storage state must still authenticate the configured admin', async () => {
  const harness = loadRecorder({ env: {
    CANVAS_DEMO_USE_STORAGE_STATE: '1', CANVAS_DEMO_CONSOLE_STORAGE_STATE: 'state.json',
  }, existingStorage: true });
  const page = {
    goto: async () => {}, url: () => 'https://beta.elevenidllc.com/console/org',
    evaluate: async () => ({ authenticated: true, user: { email: 'wrong@example.test' } }),
    waitForTimeout: async () => {},
  };
  assert.equal(await harness.api.signIntoDemoAdmin(page, page.url()), false);
});
