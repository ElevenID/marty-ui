'use strict';
// Transport/ownership orchestration only; Rust owns resource lifecycle rules.
const assert = require('node:assert/strict');
const { ensureActiveResource, requireJson, browserJson } = require('./beta-demo-resource-helpers');

const retirement = Object.freeze({
  '/v1/credential-templates': { action: '/deprecate', method: 'POST', inactive: ['DEPRECATED', 'DRAFT'] },
  '/v1/application-templates': { action: '/deprecate', method: 'POST', inactive: ['DEPRECATED', 'DRAFT'] },
  '/v1/presentation-policies': { action: '/suspend', method: 'POST', inactive: ['SUSPENDED', 'DRAFT', 'ARCHIVED'] },
  // Updating a flow resets it to DRAFT in the production Rust mutation path.
  // Remove its trigger and retain its definition/history rather than deleting it.
  '/v1/flows/definitions': { action: '', method: 'PATCH', inactive: ['DRAFT', 'ARCHIVED'] },
});

async function createOwnedActiveConfiguration(page, owned, options) {
  assert.ok(owned.runId && owned.organizationId && retirement[options.collectionPath]);
  const name = `${options.name} [${owned.runId}]`;
  const pending = { collectionPath: options.collectionPath, name };
  owned.configuration ||= [];
  owned.pendingConfigurationCreations ||= [];
  return ensureActiveResource(page, { ...options, organizationId: owned.organizationId,
    name, payload: { ...options.payload, name }, requireCreated: true,
    idempotencyKey: `demo-${owned.runId}-${options.collectionPath.replace(/\W/g, '-')}`,
    onCreating: () => { owned.pendingConfigurationCreations.push(pending); },
    onCreated: resource => {
      assert.equal(resource.name, name);
      owned.configuration.push({ ...pending, id: resource.id, organizationId: owned.organizationId });
      owned.pendingConfigurationCreations = owned.pendingConfigurationCreations.filter(item => item !== pending);
    } });
}

async function retireOwnedConfiguration(page, owned) {
  assert.equal(owned.pendingConfigurationCreations?.length || 0, 0,
    'A configuration creation outcome is uncertain; retain inputs for reconciliation');
  const resources = [...(owned.configuration || [])].reverse();
  const bindings = [];
  const ids = new Set();
  function bound(resource, actual) {
    assert.ok(retirement[resource.collectionPath] && resource.id && !resource.id.includes('/'));
    assert.equal(resource.organizationId, owned.organizationId);
    assert.ok(resource.name.endsWith(` [${owned.runId}]`));
    assert.equal(actual.id, resource.id);
    assert.equal(actual.organization_id, owned.organizationId);
    assert.equal(actual.name, resource.name);
    return actual;
  }
  // Prove every creation tuple before the first mutation; names alone never
  // authorize retirement of shared or prior-attempt configuration.
  for (const resource of resources) {
    const path = `${resource.collectionPath}/${encodeURIComponent(resource.id)}`;
    assert.ok(!ids.has(path), 'Duplicate owned configuration');
    ids.add(path);
    const current = bound(resource, await requireJson(page, path));
    bindings.push({ resource, path, current, rule: retirement[resource.collectionPath] });
  }
  const retired = [];
  for (const { resource, path, current, rule } of bindings) {
    if (!rule.inactive.includes(String(current.status).toUpperCase())) {
      await browserJson(page, path + rule.action, { method: rule.method,
        ...(rule.method === 'PATCH' ? { body: JSON.stringify({ organization_id: owned.organizationId, trigger: null }) } : {})
      }).catch(() => null);
    }
    const actual = bound(resource, await requireJson(page, path));
    assert.ok(rule.inactive.includes(String(actual.status).toUpperCase()),
      'Owned configuration retirement is not confirmed');
    retired.push({ id: resource.id, collectionPath: resource.collectionPath, status: actual.status });
  }
  return { ok: true, retired, historyPreserved: true };
}

module.exports = { createOwnedActiveConfiguration, retireOwnedConfiguration };
