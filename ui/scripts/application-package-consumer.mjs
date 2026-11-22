import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmodSync, closeSync, constants, existsSync, fstatSync, lstatSync, mkdirSync, mkdtempSync,
  openSync, readSync, realpathSync, rmSync, writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson } from './web-surface-contract.mjs';
import { applicationSourceTestPolicy } from './export-application-source.mjs';
import { APPLICATION_RETAINED_PUBLIC_FILES } from './application-public-assets.mjs';
import { applicationInstallationEnvironment, runOwnedInstallCommand } from './application-dependency-install.mjs';
import {
  applicationBuildEnvironment, verifyApplicationClosureOutput,
  verifyApplicationTestResult, verifyApplicationResourceResult,
} from './application-source-closure.mjs';
import {
  APPLICATION_RUNTIME_BASE_IMAGE, APPLICATION_RUNTIME_INPUTS,
  createApplicationRuntimeContext, validateApplicationRuntimeContext,
} from './application-runtime-context.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const SELF = fileURLToPath(import.meta.url);
const EXPECTED_OUTPUT_FILES = 88;
const EXPECTED_CONTEXT_FILES = 92;
const PROFILE_INPUTS = ['ui/package.json', 'ui/package-lock.json'];
const FALSE_QUALIFICATION = Object.freeze({
  source_package_verified: false, restored_source_preserved: false,
  independent_dependency_installation: false, application_build_completed: false, application_tests_completed: false,
  sdk_wasm_initialized_in_node: false, sdk_wasm_output_bound: false, application_output_checked: false,
  public_assets_preserved: false, application_resource_smoke_completed: false, runtime_context_prepared: false,
  runtime_payload_identical: false, source_extraction_complete: false, package_graph_minimized: false,
  container_runtime_tested: false, browser_startup_observed: false, host_deployment_tested: false,
  oidc_journey_tested: false, signed_release_produced: false, published: false, activated: false,
});

function require(condition, message) { if (!condition) throw new Error(message); }
function digest(bytes) { return `sha256:${createHash('sha256').update(bytes).digest('hex')}`; }
function identity(value) { return digest(canonicalJson(value)); }
function within(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!path.isAbsolute(relative) && relative !== '..' && !relative.startsWith(`..${path.sep}`));
}
function ordinaryDirectory(value) {
  require(typeof value === 'string' && path.isAbsolute(value), 'Consumer paths must be absolute');
  const resolved = path.resolve(value);
  require(lstatSync(resolved).isDirectory() && realpathSync(resolved) === resolved,
    'Consumer directory must have ordinary parents');
  return resolved;
}
function readFile(filename, maxBytes = 8 * 1024 * 1024) {
  require(typeof filename === 'string' && path.isAbsolute(filename), 'Consumer input paths must be absolute');
  const absolute = path.resolve(filename);
  ordinaryDirectory(path.dirname(absolute));
  require(lstatSync(absolute).isFile() && !lstatSync(absolute).isSymbolicLink(), 'Consumer input must be a regular file');
  const fd = openSync(absolute, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const metadata = fstatSync(fd);
    require(metadata.isFile() && metadata.size <= maxBytes, 'Consumer input exceeds its byte bound');
    const buffer = Buffer.alloc(metadata.size + 1);
    let length = 0;
    while (length < buffer.length) {
      const count = readSync(fd, buffer, length, buffer.length - length, null);
      if (!count) break;
      length += count;
    }
    require(length === metadata.size, 'Consumer input changed while reading');
    const bytes = buffer.subarray(0, length);
    return { bytes, record: { path: absolute, bytes: length, sha256: digest(bytes), mode: metadata.mode & 0o777 } };
  } finally { closeSync(fd); }
}
function newDestination(value, { json = false } = {}) {
  require(typeof value === 'string' && path.isAbsolute(value), 'Consumer destinations must be absolute');
  const result = path.resolve(value);
  ordinaryDirectory(path.dirname(result));
  require(!within(ROOT, result), 'Consumer destinations must be outside the diagnostic checkout');
  require(!json || path.extname(result) === '.json', 'Consumer report must be JSON');
  require(!existsSync(result), 'Consumer destination already exists');
  try { lstatSync(result); throw new Error('Consumer destination already exists'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  return result;
}
function reportMessages(error) {
  const pending = [error];
  const messages = [];
  for (let count = 0; pending.length && count < 16 && messages.length < 8; count++) {
    const current = pending.shift();
    if (current instanceof AggregateError) pending.push(...current.errors.slice(0, 8));
    else messages.push(String(current?.message || current).replace(/[^\x20-\x7e]/g, ' ').slice(0, 1200));
  }
  return messages;
}

export function validateApplicationPackageBaseline(baseline, manifest) {
  const testPolicy = applicationSourceTestPolicy(manifest);
  require(baseline?.schema === 'marty.application-source-closure-rehearsal/v5' && baseline.status === 'passed'
    && baseline.fixture !== true
    && baseline.plan?.schema === 'marty.application-source-closure-plan/v5', 'Consumer requires a passed v5 application baseline');
  const source = baseline.plan.source;
  require(source?.commit === manifest.source.commit && source.working_tree_dirty === false
    && Array.isArray(source.git_status) && source.git_status.length === 0
    && Array.isArray(source.files) && new Set(source.files.map((row) => row.path)).size === source.files.length
    && source.input_inventory_sha256 === identity(source.files), 'Consumer baseline source identity differs');
  require(baseline.build?.dependency_mode === 'fresh-npm-ci' && baseline.build.dependency_profile === 'application'
    && baseline.build.effective_source_sha === source.commit
    && baseline.dependency_install?.status === 'passed' && baseline.dependency_install.mode === 'fresh-npm-ci'
    && baseline.dependency_install.dependency_profile === 'application'
    && baseline.dependency_install.independent_dependency_installation === true,
  'Consumer baseline did not independently install the application profile');
  for (const key of ['application_build_completed', 'application_tests_completed', 'omitted_sources_absent',
    'application_output_checked', 'source_checkout_unchanged', 'public_assets_preserved',
    'application_resource_smoke_completed', 'locale_fallback_observed', 'runtime_context_prepared',
    'sdk_wasm_initialized_in_node', 'sdk_wasm_output_bound', 'independent_dependency_installation']) {
    require(baseline.qualification?.[key] === true, `Consumer baseline did not qualify ${key}`);
  }
  assert.deepEqual(baseline.plan.route_contract, manifest.route_contract, 'Consumer route contract differs');
  assert.deepEqual(baseline.plan.test_profile, manifest.test_profile, 'Consumer selected test contract differs');
  require(baseline.tests?.result?.test_count === testPolicy.assertions, 'Consumer requires every assertion in the approved source test profile');
  assert.deepEqual([...baseline.tests.result.completed_files].sort(), [...testPolicy.test_profile.files].sort(), 'Baseline selected tests are incomplete');
  require(baseline.plan.dependency_profile?.name === 'application' && baseline.dependency_profile?.name === 'application'
    && baseline.dependency_profile.output_identical_to_full_profile === true
    && baseline.dependency_profile.baseline_comparison?.output_files_identical === true
    && baseline.dependency_profile.baseline_comparison.public_resources_identical === true,
  'Consumer baseline omitted the full-profile comparison');
  assert.deepEqual(manifest.substitutions, baseline.plan.dependency_profile.substitutions, 'Consumer profile substitutions differ');
  assert.deepEqual(manifest.substitutions.map((row) => row.path), PROFILE_INPUTS, 'Consumer substitutions exceed the reviewed package inputs');
  const originals = new Map(source.files.map((row) => [row.path, row]));
  const producerOnlyInputs = [];
  for (const row of manifest.files) {
    const original = originals.get(row.source);
    if (original) require(row.bytes === original.bytes && row.sha256 === original.sha256,
      `Consumer package differs from the same-source baseline: ${row.path}`);
    else {
      require(['LICENSE', 'docs/restructuring/application-package-README.md'].includes(row.source),
        `Consumer source is absent from its producer baseline: ${row.source}`);
      producerOnlyInputs.push({ path: row.path, source: row.source, bytes: row.bytes, sha256: row.sha256,
        mode: row.mode, git_mode: row.git_mode, blob_oid: row.blob_oid });
    }
  }
  const selectedLock = manifest.files.find((row) => row.path === 'ui/package-lock.json');
  require(selectedLock && baseline.build.package_lock_sha256 === selectedLock.sha256, 'Consumer baseline selected lock differs');
  require(baseline.output?.files?.length === EXPECTED_OUTPUT_FILES
    && baseline.output.inventory_sha256 === identity(baseline.output.files), 'Consumer baseline output inventory is invalid');
  assert.deepEqual(baseline.output.public_resources.map((row) => row.path), [...APPLICATION_RETAINED_PUBLIC_FILES], 'Baseline public resource set differs');
  assert.deepEqual(baseline.resources?.result?.public_resources, baseline.output.public_resources, 'Baseline resource proof differs');
  const context = baseline.runtime_context;
  require(context?.schema === 'marty.application-runtime-context/v1' && context.source_commit === source.commit
    && context.effective_source_sha === source.commit && context.exact_committed_source === true
    && context.base_image === APPLICATION_RUNTIME_BASE_IMAGE, 'Consumer baseline runtime identity differs');
  const { path: _path, manifest_sha256: manifestSha256, ...rawContext } = context;
  require(manifestSha256 === digest(`${JSON.stringify(rawContext, null, 2)}\n`), 'Consumer baseline context digest is invalid');
  assert.deepEqual(context.output_inventory, baseline.output, 'Baseline runtime output differs');
  assert.deepEqual(context.resource_result, baseline.resources.result, 'Baseline runtime resource proof differs');
  require(context.source_inputs?.length === APPLICATION_RUNTIME_INPUTS.length, 'Baseline runtime recipe is incomplete');
  const currentRecipe = APPLICATION_RUNTIME_INPUTS.map((input) => {
    const original = originals.get(input.path);
    require(original, 'Baseline runtime source is missing');
    return { ...input, bytes: original.bytes, sha256: original.sha256,
      source_mode: 0o600, packaged_mode: input.mode };
  });
  assert.deepEqual(context.source_inputs, currentRecipe, 'Baseline runtime source inputs differ');
  const payload = [...baseline.output.files.map((row) => ({ ...row, path: `html/${row.path}`, mode: 0o644 })),
    ...currentRecipe.map((row) => ({ path: row.target, bytes: row.bytes, sha256: row.sha256, mode: row.packaged_mode }))]
    .sort((a, b) => a.path.localeCompare(b.path, 'en'));
  require(payload.length === EXPECTED_CONTEXT_FILES, 'Baseline runtime payload count differs');
  assert.deepEqual(context.context_inventory, payload, 'Baseline runtime payload inventory differs');
  return { source_commit: source.commit, source_inventory_sha256: source.input_inventory_sha256,
    output_inventory_sha256: baseline.output.inventory_sha256, context_manifest_sha256: manifestSha256,
    runtime_payload_sha256: identity(payload), producer_only_source_inputs: producerOnlyInputs };
}

export function compareApplicationPackageOutput(output, baseline) {
  require(output?.files?.length === EXPECTED_OUTPUT_FILES && output.inventory_sha256 === identity(output.files),
    'Consumer output inventory is invalid');
  const publicPaths = new Set(APPLICATION_RETAINED_PUBLIC_FILES);
  require(publicPaths.size === 54, 'Consumer public mode contract changed');
  const transformations = [];
  const expected = baseline.output.files.map((row) => {
    if (publicPaths.has(row.path)) {
      require(row.mode === 0o600, 'Baseline public source mode changed');
      transformations.push({ path: row.path, baseline_mode: 0o600, consumer_mode: 0o644 });
      return { ...row, mode: 0o644 };
    }
    require(row.mode === 0o644, 'Unexpected nonpublic baseline output mode');
    return row;
  });
  require(transformations.length === 54, 'Consumer public mode transformation set is incomplete');
  assert.deepEqual(output.files, expected, 'Consumer output bytes, paths or permitted modes differ from the profile baseline');
  assert.deepEqual(output.public_resources, baseline.output.public_resources, 'Consumer public bytes differ');
  return { output_files: output.files.length, public_resources: publicPaths.size,
    paths_bytes_hashes_identical: true, mode_transformations: transformations,
    baseline_inventory_sha256: baseline.output.inventory_sha256, consumer_inventory_sha256: output.inventory_sha256 };
}

function stageRuntimeSource(restored, temporary, manifest) {
  const destination = path.join(temporary, 'runtime-source');
  mkdirSync(destination, { mode: 0o700 });
  const files = new Map(manifest.files.map((row) => [row.path, row]));
  const identities = [];
  for (const input of APPLICATION_RUNTIME_INPUTS) {
    const external = input.path === 'ui/scripts/application-runtime.Dockerfile';
    require(external || files.has(input.path), 'Consumer package omitted a runtime source input');
    const selected = readFile(path.join(external ? ROOT : restored, input.path));
    const reviewed = readFile(path.join(ROOT, input.path));
    require(selected.record.sha256 === reviewed.record.sha256 && selected.record.bytes === reviewed.record.bytes,
      'Consumer runtime recipe or hook differs from the reviewed source');
    if (!external) {
      const expected = files.get(input.path);
      require(selected.record.sha256 === expected.sha256 && selected.record.mode === expected.mode, 'Consumer runtime source changed');
    }
    const target = path.join(destination, input.path);
    mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
    writeFileSync(target, selected.bytes, { flag: 'wx', mode: 0o644 });
    chmodSync(target, 0o644);
    identities.push({ path: input.path, source: external ? 'external-reviewed-diagnostic-recipe' : 'verified-source-package',
      bytes: selected.record.bytes, sha256: selected.record.sha256, source_mode: selected.record.mode, staged_mode: 0o644 });
  }
  return { root: destination, inputs: identities };
}

function defaultCommand(command, args, options) { return runOwnedInstallCommand(command, args, options); }

export async function consumeApplicationSourcePackage({ archivePath, manifestPath, producerReportPath,
  baselineReportPath, reportPath, runtimeContextDirectory }, { packageApi, command = defaultCommand } = {}) {
  const reportDestination = newDestination(reportPath, { json: true });
  const contextDestination = newDestination(runtimeContextDirectory);
  require(!within(contextDestination, reportDestination), 'Consumer report must be outside its runtime context');
  const injected = Boolean(packageApi) || command !== defaultCommand;
  const report = { schema: 'marty.application-source-package-consumer/v1', status: 'failed', fixture: injected,
    inputs: {}, commands: [], qualification: { ...FALSE_QUALIFICATION },
    cleanup: { process_group_cleanup_completed: true, source_removed: false, cache_removed: false,
      runtime_adapter_removed: false, temporary_removed: false, runtime_context_removed: false },
    process_ownership: 'existing-linux-process-group-timeout-and-cleanup',
    kernel_descendant_reaping_claimed: false };
  let api;
  let manifest;
  let baseline;
  let temporary;
  let restored;
  let ownedContext = false;
  let phase = 'input-verification';
  let failure;
  let sourcePreserved = false;
  let inputsPreserved = false;
  const snapshots = [];
  const checkInputs = () => {
    for (const snapshot of snapshots) assert.deepEqual(readFile(snapshot.record.path, snapshot.maximum).record,
      snapshot.record, 'Consumer archive, manifest, receipt or baseline changed');
  };
  const checkSource = () => {
    if (restored) api.validateApplicationSourceInventory({ destination: restored, manifest, allowGenerated: true });
  };
  const run = async (stage, executable, args, env, timeout) => {
    phase = stage;
    checkInputs();
    checkSource();
    const stdoutFile = path.join(temporary, `${stage}.stdout`);
    const stderrFile = path.join(temporary, `${stage}.stderr`);
    const observation = { stage, command: [executable, ...args], timeout_ms: timeout,
      status: null, signal: null, process_group_cleanup_completed: false };
    report.commands.push(observation);
    let result;
    let commandFailure;
    try {
      result = await command(executable, args, { cwd: path.join(restored, 'ui'), env, timeout, stdoutFile, stderrFile, stage });
      observation.process_group_cleanup_completed = true;
      observation.status = result.status;
      observation.signal = result.signal || null;
      if (result.error) throw result.error;
      require(result.status === 0, `Consumer ${stage} failed with exit code ${result.status}`);
    } catch (error) {
      commandFailure = error;
      if (!observation.process_group_cleanup_completed) report.cleanup.process_group_cleanup_completed = false;
    } finally {
      try { checkInputs(); checkSource(); } catch (error) {
        commandFailure = new AggregateError([...(commandFailure ? [commandFailure] : []), error], 'Consumer command or source preservation failed');
      }
    }
    if (commandFailure) throw commandFailure;
    return { stdoutFile, stderrFile };
  };
  try {
    require(process.platform === 'linux', 'Consumer qualification uses the reviewed Linux process boundary');
    api = packageApi || await import('./export-application-source.mjs');
    for (const [name, filename, maximum] of [['archive', archivePath, 128 * 1024 * 1024],
      ['manifest', manifestPath, 8 * 1024 * 1024], ['producer_report', producerReportPath, 8 * 1024 * 1024],
      ['baseline_report', baselineReportPath, 8 * 1024 * 1024]]) {
      require(path.resolve(filename) !== reportDestination && !within(contextDestination, path.resolve(filename)),
        'Consumer outputs overlap a pinned input');
      const snapshot = readFile(filename, maximum);
      snapshots.push({ ...snapshot, maximum });
      report.inputs[name] = snapshot.record;
    }
    manifest = api.parseApplicationSourceJson(snapshots[1].bytes);
    api.validateApplicationSourcePackageManifest(manifest);
    const producer = api.parseApplicationSourceJson(snapshots[2].bytes);
    baseline = api.parseApplicationSourceJson(snapshots[3].bytes);
    api.validateApplicationSourceProducerReceipt(producer, {
      archiveSha256: report.inputs.archive.sha256, manifestSha256: report.inputs.manifest.sha256, manifest,
      baselineReportSha256: report.inputs.baseline_report.sha256,
    });
    for (const [name, key] of [['archive', 'archive'], ['manifest', 'manifest'], ['baseline_report', 'baseline_report']]) {
      require(producer[name]?.bytes === report.inputs[key].bytes, `Consumer producer ${name} byte count differs`);
    }
    report.fixture ||= manifest.fixture === true || producer.fixture === true;
    report.baseline = validateApplicationPackageBaseline(baseline, manifest);
    report.source = manifest.source;
    report.source_inventory_sha256 = manifest.source_inventory_sha256;
    ordinaryDirectory(os.tmpdir());
    require(!within(ROOT, realpathSync(os.tmpdir())), 'Consumer temporary state must be outside the diagnostic checkout');
    temporary = mkdtempSync(path.join(os.tmpdir(), 'marty-application-package-consumer-'));
    phase = 'restore';
    const restoredResult = await api.restoreApplicationSourcePackage({ archivePath, manifestPath,
      expectedArchiveSha256: report.inputs.archive.sha256, expectedManifestSha256: report.inputs.manifest.sha256,
      destination: path.join(temporary, 'source') });
    restored = ordinaryDirectory(restoredResult.root);
    require(restored === path.join(temporary, 'source'), 'Consumer restore returned an unowned directory');
    assert.deepEqual(restoredResult.manifest, manifest, 'Consumer restored a different source manifest');
    require(restoredResult.archive_sha256 === report.inputs.archive.sha256
      && restoredResult.manifest_sha256 === report.inputs.manifest.sha256
      && restoredResult.source_inventory_sha256 === manifest.source_inventory_sha256, 'Consumer restore identity differs');
    api.validateApplicationSourceInventory({ destination: restored, manifest, allowGenerated: false });
    const cache = path.join(temporary, 'npm-cache');
    mkdirSync(cache, { mode: 0o700 });
    const userConfig = path.join(temporary, 'npm-user-config');
    const globalConfig = path.join(temporary, 'npm-global-config');
    for (const filename of [userConfig, globalConfig]) writeFileSync(filename, '', { flag: 'wx', mode: 0o600 });
    const npmConfiguration = { npm_config_cache: cache, npm_config_userconfig: userConfig, npm_config_globalconfig: globalConfig,
      npm_config_include: 'dev', npm_config_ignore_scripts: 'false', npm_config_audit: 'false', npm_config_fund: 'false',
      npm_config_package_lock: 'true', npm_config_install_strategy: 'hoisted', npm_config_legacy_peer_deps: 'false',
      npm_config_install_links: 'false', npm_config_registry: 'https://registry.npmjs.org' };
    const installEnvironment = { ...applicationInstallationEnvironment(), ...npmConfiguration };
    // This is the only exact-source marker injection. All external pins,
    // producer/baseline identities and the restored inventory are verified first.
    const buildEnvironment = { ...applicationBuildEnvironment(manifest.source.commit), ...npmConfiguration };
    const version = await run('npm-version', 'npm', ['--version'], installEnvironment, 30_000);
    const npmVersion = readFile(version.stdoutFile, 64 * 1024).bytes.toString('utf8').trim();
    require(/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(npmVersion), 'Consumer npm version is invalid');
    report.environment = { node_version: process.version, npm_version: npmVersion, npm_configuration: 'explicit-empty-user-and-global',
      cache_mode: 'new-temporary-cache', browser_download_skipped: true, effective_source_sha: manifest.source.commit,
      identity_authority: 'verified-external-producer-and-same-source-baseline' };
    await run('npm-ci', 'npm', ['ci'], installEnvironment, 8 * 60_000);
    const inspected = await run('dependency-inspection', process.execPath,
      [fileURLToPath(new URL('./application-dependency-install.mjs', import.meta.url)), '--inspect-installed', path.join(restored, 'ui'), 'application'],
      installEnvironment, 30_000);
    report.dependency_install = api.parseApplicationSourceJson(readFile(inspected.stdoutFile, 2 * 1024 * 1024).bytes);
    const installed = report.dependency_install;
    require(installed.postinstall?.verified === true && installed.postinstall.prerender_selected === false
      && installed.sdk?.initialized_in_node === true && installed.sdk.browser_execution_observed === false,
    'Consumer dependency inspection did not prove its lifecycle patch and SDK initialization');
    for (const key of ['bytes', 'sha256']) require(installed.sdk.wasm?.[key] === baseline.dependency_install.sdk.wasm[key],
      'Consumer installed a different SDK WASM');
    await run('npm-build', 'npm', ['run', 'build'], buildEnvironment, 20 * 60_000);
    await run('npm-test', 'npm', ['test', '--', '--reporter=json', '--outputFile', path.join(temporary, 'application-tests.json')],
      buildEnvironment, 20 * 60_000);
    readFile(path.join(temporary, 'application-tests.json'));
    report.tests = verifyApplicationTestResult(temporary, restored, manifest);
    require(report.tests.test_count === applicationSourceTestPolicy(manifest).assertions, 'Consumer did not complete all approved selected assertions');
    phase = 'output-comparison';
    report.output = verifyApplicationClosureOutput(restored, baseline.plan);
    report.output_comparison = compareApplicationPackageOutput(report.output, baseline);
    const wasm = report.output.files.filter((row) => /^assets\/marty_api_client_bg[-.A-Za-z0-9_]*\.wasm$/.test(row.path));
    require(wasm.length === 1 && wasm[0].bytes === installed.sdk.wasm.bytes && wasm[0].sha256 === installed.sdk.wasm.sha256,
      'Consumer emitted a different SDK WASM');
    await run('resource-smoke', process.execPath, [fileURLToPath(new URL('./application-resource-smoke.mjs', import.meta.url)),
      '--dist', path.join(restored, 'ui/dist-application'), '--report', path.join(temporary, 'application-resources.json'),
      '--dependency-root', path.join(restored, 'ui')], buildEnvironment, 60_000);
    readFile(path.join(temporary, 'application-resources.json'));
    report.resources = verifyApplicationResourceResult(temporary, restored, report.output);
    assert.deepEqual(verifyApplicationClosureOutput(restored, baseline.plan), report.output, 'Consumer resource probe changed its output');
    phase = 'runtime-context';
    const adapter = stageRuntimeSource(restored, temporary, manifest);
    report.runtime_source_adapter = adapter.inputs;
    report.runtime_context = createApplicationRuntimeContext({ sourceRoot: adapter.root,
      outputRoot: path.join(restored, 'ui/dist-application'), destination: contextDestination,
      sourceCommit: manifest.source.commit, outputInventory: report.output, resourceResult: report.resources });
    ownedContext = true;
    require(validateApplicationRuntimeContext(contextDestination).manifest_sha256 === report.runtime_context.manifest_sha256,
      'Consumer runtime context changed during validation');
    assert.deepEqual(report.runtime_context.context_inventory, baseline.runtime_context.context_inventory,
      'Consumer normalized runtime payload differs from the profile baseline');
    report.runtime_comparison = { payload_files: EXPECTED_CONTEXT_FILES,
      payload_inventory_sha256: identity(report.runtime_context.context_inventory), payload_records_identical: true,
      baseline_manifest_sha256: baseline.runtime_context.manifest_sha256, consumer_manifest_sha256: report.runtime_context.manifest_sha256 };
    checkInputs();
    checkSource();
    sourcePreserved = true;
    inputsPreserved = true;
    report.status = report.fixture ? 'fixture-passed' : 'passed';
  } catch (error) { failure = error; }
  finally {
    const errors = [];
    try { checkInputs(); inputsPreserved = snapshots.length === 4; } catch (error) { inputsPreserved = false; errors.push(error); }
    try { checkSource(); sourcePreserved = Boolean(restored); } catch (error) { sourcePreserved = false; errors.push(error); }
    if (temporary && report.cleanup.process_group_cleanup_completed) {
      for (const [name, key] of [['source', 'source_removed'], ['npm-cache', 'cache_removed'], ['runtime-source', 'runtime_adapter_removed']]) {
        try { rmSync(path.join(temporary, name), { recursive: true, force: true }); report.cleanup[key] = !existsSync(path.join(temporary, name)); }
        catch (error) { errors.push(error); }
      }
      try { rmSync(temporary, { recursive: true, force: true }); report.cleanup.temporary_removed = !existsSync(temporary); }
      catch (error) { errors.push(error); }
    } else if (temporary) report.retained_diagnostic_directory = temporary;
    if (errors.length) failure = new AggregateError([...(failure ? [failure] : []), ...errors], 'Consumer verification or cleanup failed');
    if (!failure && ['passed', 'fixture-passed'].includes(report.status)
      && (!inputsPreserved || !sourcePreserved || !report.cleanup.temporary_removed)) {
      failure = new Error('Consumer success requires complete source preservation and temporary cleanup');
    }
    if (ownedContext && !failure) {
      try {
        const finalContext = validateApplicationRuntimeContext(contextDestination);
        require(finalContext.manifest_sha256 === report.runtime_context.manifest_sha256,
          'Consumer runtime context changed after source verification and cleanup');
        assert.deepEqual(finalContext.manifest.context_inventory, baseline.runtime_context.context_inventory,
          'Consumer runtime payload changed after source verification and cleanup');
      } catch (error) { phase = 'runtime-context-final-verification'; failure = error; }
    }
    if (ownedContext && (failure || report.fixture)) {
      try { rmSync(contextDestination, { recursive: true, force: true }); report.cleanup.runtime_context_removed = !existsSync(contextDestination); }
      catch (error) { failure = new AggregateError([...(failure ? [failure] : []), error], 'Consumer runtime cleanup failed'); }
    }
    report.preservation = { pinned_inputs_unchanged: inputsPreserved, restored_source_unchanged: sourcePreserved };
    if (failure) {
      report.status = 'failed';
      report.failure = { phase, messages: reportMessages(failure) };
    }
    if (report.status === 'passed') {
      for (const key of ['source_package_verified', 'restored_source_preserved', 'independent_dependency_installation',
        'application_build_completed', 'application_tests_completed', 'sdk_wasm_initialized_in_node', 'sdk_wasm_output_bound',
        'application_output_checked', 'public_assets_preserved', 'application_resource_smoke_completed',
        'runtime_context_prepared', 'runtime_payload_identical']) report.qualification[key] = true;
    } else {
      report.qualification = { ...FALSE_QUALIFICATION };
      if (report.runtime_context) report.runtime_context = { ...report.runtime_context,
        qualification: Object.fromEntries(Object.keys(report.runtime_context.qualification).map((key) => [key, false])), retained: false };
    }
    writeFileSync(reportDestination, `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  }
  return report;
}

function cli(args) {
  const names = new Map([['--archive', 'archivePath'], ['--manifest', 'manifestPath'], ['--producer-report', 'producerReportPath'],
    ['--baseline-report', 'baselineReportPath'], ['--report', 'reportPath'], ['--runtime-context', 'runtimeContextDirectory']]);
  const options = {};
  while (args.length) {
    const key = names.get(args.shift());
    const value = args.shift();
    require(key && !Object.hasOwn(options, key) && value && !value.startsWith('--'), 'Unknown, duplicate or incomplete consumer option');
    options[key] = value;
  }
  require(Object.keys(options).length === names.size, 'Consumer requires all six explicit package, evidence and output paths');
  return options;
}
if (process.argv[1] && path.resolve(process.argv[1]) === SELF) {
  try {
    const result = await consumeApplicationSourcePackage(cli(process.argv.slice(2)));
    console.log(JSON.stringify({ status: result.status, fixture: result.fixture, source_commit: result.source?.commit,
      output_files: result.output?.files.length, tests: result.tests?.test_count, cleanup: result.cleanup,
      ...(result.failure ? { failure: result.failure } : {}) }));
    if (result.status !== 'passed') process.exitCode = 1;
  } catch (error) {
    console.error(`Application package consumer failed: ${error.message}`);
    process.exitCode = 1;
  }
}
