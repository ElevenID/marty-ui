'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createBoundedBrowserResource } = require('./audit-beta-canvas-capture');

const nextTurn = () => new Promise(resolve => setImmediate(resolve));

test('hung learner context is attributed and a late context is retired', async () => {
  let resolveCreation;
  const creation = new Promise(resolve => { resolveCreation = resolve; });
  const stages = [];
  const closed = [];
  const pending = createBoundedBrowserResource({ stage: 'learner-context-create',
    create: () => creation, retire: context => { closed.push(context); return context.close(); },
    setStage: stage => stages.push(stage), timeoutMs: 5 });
  await assert.rejects(pending, error => error.code === 'canvas_browser_resource_create_timeout');
  const context = { close: async () => { closed.push('closed'); } };
  resolveCreation(context);
  await nextTurn();
  assert.deepEqual(stages, ['learner-context-create']);
  assert.deepEqual(closed, [context, 'closed']);
});

test('late page retirement failure does not replace the original timeout', async () => {
  let resolveCreation;
  const creation = new Promise(resolve => { resolveCreation = resolve; });
  let stage;
  const pending = createBoundedBrowserResource({ stage: 'wallet-page-create',
    create: () => creation, retire: () => Promise.reject(new Error('late close failed')),
    setStage: value => { stage = value; }, timeoutMs: 5 });
  const timeout = await pending.catch(error => error);
  assert.equal(timeout.code, 'canvas_browser_resource_create_timeout');
  resolveCreation({});
  await nextTurn();
  assert.equal(stage, 'wallet-page-create');
  assert.equal(timeout.code, 'canvas_browser_resource_create_timeout');
});

test('an immediate creation failure retains its original error and stage', async () => {
  const original = new Error('creation refused');
  let stage, retired = false;
  await assert.rejects(createBoundedBrowserResource({ stage: 'admin-page-create',
    create: () => Promise.reject(original), retire: () => { retired = true; },
    setStage: value => { stage = value; }, timeoutMs: 50 }), error => error === original);
  assert.equal(stage, 'admin-page-create');
  assert.equal(retired, false);
});

test('a timely admin context remains owned by normal capture cleanup', async () => {
  const context = { close: async () => { throw new Error('must not close early'); } };
  let stage, retired = false;
  const actual = await createBoundedBrowserResource({ stage: 'admin-context-create',
    create: () => context, retire: () => { retired = true; },
    setStage: value => { stage = value; }, timeoutMs: 50 });
  assert.equal(actual, context);
  assert.equal(stage, 'admin-context-create');
  assert.equal(retired, false);
});
