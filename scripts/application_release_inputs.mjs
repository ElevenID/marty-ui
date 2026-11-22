// Producer-only bridge to the existing source/package/runtime validators.
// This reviewed script is never taken from, or executed by, release consumers.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, mkdtempSync, openSync, readSync, realpathSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  applicationSourceTestPolicy, parseApplicationSourceJson, planApplicationSourceExport, restoreApplicationSourcePackage,
  validateApplicationSourceBaseline, validateApplicationSourceProducerReceipt,
} from '../ui/scripts/export-application-source.mjs';
import {
  compareApplicationPackageOutput, validateApplicationPackageBaseline,
} from '../ui/scripts/application-package-consumer.mjs';
import { validateApplicationRuntimeContext, verifyApplicationBrowserResult } from '../ui/scripts/application-runtime-context.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url)).replace(/\/$/, '');
const FILES = Object.freeze({
  archive: 'application-source-package.zip', manifest: 'application-source-origin.json',
  producer_report: 'application-source-package.json', baseline_report: 'application-profile-source-closure.json',
  consumer: 'application-package-consumer.json', context: 'application-runtime-context.json',
});
const hash = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const identity = (bytes) => ({ bytes: bytes.length, sha256: hash(bytes) });

function read(filename, maximum = 8 * 1024 * 1024) {
  assert.ok(path.isAbsolute(filename) && realpathSync(filename) === filename, 'Input paths must be ordinary absolute paths');
  const stat = lstatSync(filename);
  assert.ok(stat.isFile() && stat.size > 0 && stat.size <= maximum, 'Input must be a bounded regular file');
  const fd = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const opened = fstatSync(fd);
    assert.ok(opened.isFile() && opened.size > 0 && opened.size <= maximum
      && opened.dev === stat.dev && opened.ino === stat.ino && opened.size === stat.size,
    'Input changed before its bounded read');
    const bytes = Buffer.alloc(opened.size + 1);
    let length = 0;
    while (length < bytes.length) {
      const count = readSync(fd, bytes, length, bytes.length - length, null);
      if (!count) break;
      length += count;
    }
    const after = fstatSync(fd);
    assert.ok(length === opened.size && after.size === opened.size && after.mtimeMs === opened.mtimeMs
      && after.ctimeMs === opened.ctimeMs && after.mode === opened.mode, 'Input changed during its bounded read');
    return bytes.subarray(0, length);
  } finally { closeSync(fd); }
}

/** Reuse the existing selected-profile and output validators, then bind the
 * consumer's completed ordinary commands to their original immutable inputs. */
export function validateApplicationReleaseConsumer(consumer, { manifest, baseline, snapshots, verified }) {
  assert.equal(consumer.schema, 'marty.application-source-package-consumer/v1');
  assert.equal(consumer.status, 'passed');
  assert.equal(consumer.fixture, false);
  assert.deepEqual(consumer.source, manifest.source);
  assert.equal(consumer.source_inventory_sha256, manifest.source_inventory_sha256);
  for (const name of ['archive', 'manifest', 'producer_report', 'baseline_report']) {
    assert.deepEqual({ bytes: consumer.inputs[name]?.bytes, sha256: consumer.inputs[name]?.sha256 }, identity(snapshots[name]));
  }
  assert.deepEqual(consumer.baseline, validateApplicationPackageBaseline(baseline, manifest));
  assert.deepEqual(consumer.output_comparison, compareApplicationPackageOutput(consumer.output, baseline));
  assert.deepEqual(consumer.runtime_context, { ...verified.manifest, path: verified.root, manifest_sha256: verified.manifest_sha256 });
  assert.deepEqual(consumer.runtime_context.output_inventory, consumer.output);
  assert.deepEqual(consumer.runtime_context.resource_result, consumer.resources);
  assert.equal(consumer.runtime_comparison.payload_records_identical, true);
  assert.equal(consumer.runtime_comparison.consumer_manifest_sha256, verified.manifest_sha256);
  assert.equal(consumer.runtime_comparison.baseline_manifest_sha256, baseline.runtime_context.manifest_sha256);
  assert.equal(consumer.runtime_comparison.payload_inventory_sha256, consumer.baseline.runtime_payload_sha256);
  assert.equal(consumer.runtime_comparison.payload_files, verified.manifest.context_inventory.length);
  assert.deepEqual(consumer.runtime_context.context_inventory, baseline.runtime_context.context_inventory);
  assert.deepEqual(consumer.preservation, { pinned_inputs_unchanged: true, restored_source_unchanged: true });
  assert.deepEqual(consumer.cleanup, { process_group_cleanup_completed: true, source_removed: true, cache_removed: true,
    runtime_adapter_removed: true, temporary_removed: true, runtime_context_removed: false });
  const passed = ['source_package_verified', 'restored_source_preserved', 'independent_dependency_installation',
    'application_build_completed', 'application_tests_completed', 'sdk_wasm_initialized_in_node', 'sdk_wasm_output_bound',
    'application_output_checked', 'public_assets_preserved', 'application_resource_smoke_completed',
    'runtime_context_prepared', 'runtime_payload_identical'];
  const pending = ['source_extraction_complete', 'package_graph_minimized', 'container_runtime_tested',
    'browser_startup_observed', 'host_deployment_tested', 'oidc_journey_tested', 'signed_release_produced', 'published', 'activated'];
  assert.deepEqual(consumer.qualification, Object.fromEntries([...passed.map((key) => [key, true]), ...pending.map((key) => [key, false])]));
  assert.deepEqual(consumer.commands.map((item) => item.stage), ['npm-version', 'npm-ci', 'dependency-inspection', 'npm-build', 'npm-test', 'resource-smoke']);
  assert.ok(consumer.commands.every((item) => item.status === 0 && item.signal === null && item.process_group_cleanup_completed === true));
  assert.equal(consumer.environment?.effective_source_sha, manifest.source.commit);
  assert.equal(consumer.environment?.identity_authority, 'verified-external-producer-and-same-source-baseline');
  assert.equal(consumer.environment?.npm_configuration, 'explicit-empty-user-and-global');
  assert.equal(consumer.environment?.cache_mode, 'new-temporary-cache');
  assert.equal(consumer.tests?.test_count, applicationSourceTestPolicy(manifest).assertions,
    'Release consumer did not complete every assertion in the approved source test profile');
  assert.deepEqual([...consumer.tests.completed_files].sort(), [...manifest.test_profile.files].sort());
  assert.equal(consumer.dependency_install?.sdk?.initialized_in_node, true);
  assert.equal(consumer.dependency_install?.postinstall?.verified, true);
  const { emitted_wasm: _emitted, ...baselineSdk } = baseline.dependency_install.sdk;
  assert.deepEqual(consumer.dependency_install.sdk, baselineSdk);
  assert.deepEqual(consumer.dependency_install.removed_website_dependencies, baseline.dependency_install.removed_website_dependencies);
}

export async function verifyApplicationReleaseInputs({ sourceSha, assets, context, browserReport }) {
  assert.match(sourceSha || '', /^[0-9a-f]{40}$/);
  const snapshots = Object.fromEntries(Object.entries(FILES).map(([name, filename]) =>
    [name, read(path.join(assets, filename), name === 'archive' ? 128 * 1024 * 1024 : undefined)]));
  const manifest = parseApplicationSourceJson(snapshots.manifest);
  const baseline = parseApplicationSourceJson(snapshots.baseline_report);
  const producer = parseApplicationSourceJson(snapshots.producer_report);
  const consumer = parseApplicationSourceJson(snapshots.consumer);
  const prepared = await planApplicationSourceExport({ repositoryRoot: ROOT });
  assert.equal(prepared.manifest.fixture, false);
  assert.equal(prepared.manifest.source.commit, sourceSha);
  assert.deepEqual(prepared.manifestBytes, snapshots.manifest, 'Source manifest differs from the clean current checkout');
  validateApplicationSourceBaseline(baseline, { plan: prepared.plan });
  validateApplicationSourceProducerReceipt(producer, { manifest,
    archiveSha256: hash(snapshots.archive), manifestSha256: hash(snapshots.manifest), baselineReportSha256: hash(snapshots.baseline_report) });
  assert.equal(producer.fixture, false);
  const verified = validateApplicationRuntimeContext(context);
  assert.equal(verified.manifest.source_commit, sourceSha);
  assert.equal(verified.manifest.exact_committed_source, true);
  assert.equal(verified.manifest.effective_source_sha, sourceSha);
  assert.equal(hash(snapshots.context), verified.manifest_sha256);
  assert.deepEqual(parseApplicationSourceJson(snapshots.context), verified.manifest);
  validateApplicationReleaseConsumer(consumer, { manifest, baseline, snapshots, verified });
  const browserBytes = browserReport ? read(browserReport) : null;
  if (browserBytes) {
    const browser = parseApplicationSourceJson(browserBytes);
    assert.equal(browser.fixture, false);
    assert.equal(browser.status, 'passed');
    // Replay the actual runtime/browser validator against the unchanged source
    // bytes. This checks routes, Retry, WASM, CSP and the negative control; it
    // does not launch a browser or trust a caller-selected validator.
    await verifyApplicationBrowserResult(browser, { origin: browser.origin, root: verified.root,
      manifest: verified.manifest, contextSha: verified.manifest_sha256, channel: 'chrome' });
  }

  // Restore through the existing safe archive validator. No package command or
  // archive-selected code executes; the temporary source is removed immediately.
  const temporary = mkdtempSync(path.join(os.tmpdir(), 'application-release-source-'));
  try {
    const restored = restoreApplicationSourcePackage({ archivePath: path.join(assets, FILES.archive),
      manifestPath: path.join(assets, FILES.manifest), expectedArchiveSha256: hash(snapshots.archive),
      expectedManifestSha256: hash(snapshots.manifest), destination: path.join(temporary, 'source') });
    assert.deepEqual(restored.manifest, manifest);
  } finally { rmSync(temporary, { recursive: true, force: true }); }

  for (const [name, filename] of Object.entries(FILES)) assert.deepEqual(
    read(path.join(assets, filename), name === 'archive' ? 128 * 1024 * 1024 : undefined), snapshots[name], 'Release input changed during validation');
  assert.equal(validateApplicationRuntimeContext(context).manifest_sha256, verified.manifest_sha256);
  if (browserBytes) assert.deepEqual(read(browserReport), browserBytes, 'Browser evidence changed during validation');
  assert.deepEqual((await planApplicationSourceExport({ repositoryRoot: ROOT })).manifestBytes, snapshots.manifest);
  const wasm = consumer.output.files.find((item) => item.path === verified.manifest.sdk_wasm);
  const sdk = consumer.dependency_install.sdk;
  assert.ok(wasm && wasm.bytes === sdk.wasm.bytes && wasm.sha256 === sdk.wasm.sha256);
  const file = ({ path: name, bytes, sha256 }) => ({ path: name, bytes, sha256 });
  return { schema: 'marty.application-release-inputs/v1', source: manifest.source,
    inputs: Object.fromEntries(Object.entries(FILES).map(([name, filename]) => [filename, identity(snapshots[name])])),
    source_inventory_sha256: manifest.source_inventory_sha256,
    dependency_lock_sha256: manifest.files.find((item) => item.path === 'ui/package-lock.json').sha256,
    route_contract: manifest.route_contract,
    runtime_context: { manifest_sha256: verified.manifest_sha256,
      payload_sha256: consumer.runtime_comparison.payload_inventory_sha256, source_sha: sourceSha },
    output: { inventory_sha256: consumer.output.inventory_sha256, file_count: consumer.output.files.length,
      total_bytes: consumer.output.files.reduce((total, item) => total + item.bytes, 0) },
    sdk: { name: sdk.name, version: sdk.version, resolved: sdk.resolved, integrity: sdk.integrity,
      wasm: file(sdk.wasm), emitted_wasm: file(wasm) } };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    assert.ok([6, 8].includes(args.length) && args[0] === '--source-sha' && args[2] === '--assets' && args[4] === '--context'
      && (args.length === 6 || args[6] === '--browser-report'),
      'Usage: application_release_inputs.mjs --source-sha SHA --assets ABS_DIR --context ABS_DIR [--browser-report ABS_FILE]');
    process.stdout.write(`${JSON.stringify(await verifyApplicationReleaseInputs({ sourceSha: args[1], assets: args[3], context: args[5],
      browserReport: args[7] }))}\n`);
  } catch (error) { process.stderr.write(`Application release inputs failed: ${error.message}\n`); process.exitCode = 1; }
}
