import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync,
  readdirSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { canonicalJson } from './web-surface-contract.mjs';
import { validateApplicationReleaseConsumer } from '../../scripts/application_release_inputs.mjs';
import { APPLICATION_TEST_CONFIG } from './application-test-profile.mjs';
import {
  APPLICATION_LOCALE_NAMESPACES, APPLICATION_RETAINED_PUBLIC_FILES, APPLICATION_RESOURCE_MIME_TYPES,
} from './application-public-assets.mjs';
import { APPLICATION_RUNTIME_INPUTS, createApplicationRuntimeContext } from './application-runtime-context.mjs';
import { verifyApplicationClosureOutput } from './application-source-closure.mjs';
import {
  compareApplicationPackageOutput, consumeApplicationSourcePackage, validateApplicationPackageBaseline,
} from './application-package-consumer.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const COMMIT = 'a'.repeat(40);
const SDK = 'assets/marty_api_client_bg-fixture.wasm';
const digest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const identity = (value) => digest(canonicalJson(value));
const json = (value) => `${JSON.stringify(value, null, 2)}\n`;
const byteRecord = ({ path: name, bytes, sha256 }) => ({ path: name, bytes, sha256 });

function write(root, name, bytes, mode = 0o644) {
  const filename = path.join(root, name);
  mkdirSync(path.dirname(filename), { recursive: true });
  writeFileSync(filename, bytes);
  chmodSync(filename, mode);
}
function record(name, bytes, mode = 0o644) {
  return { path: name, bytes: bytes.length, sha256: digest(bytes), mode };
}
function allFiles(root, prefix = '') {
  return readdirSync(path.join(root, prefix), { withFileTypes: true }).flatMap((entry) => {
    const name = prefix ? `${prefix}/${entry.name}` : entry.name;
    assert.equal(entry.isSymbolicLink(), false, 'fixture source link');
    if (name === 'ui/node_modules' || name === 'ui/dist-application') {
      assert.ok(entry.isDirectory(), 'fixture generated root must be ordinary');
      return [];
    }
    return entry.isDirectory() ? allFiles(root, name) : [name];
  }).sort();
}

// Only package transport and commands are simulated. Source preservation, the
// selected test/result parsers, output comparison and actual closed runtime
// construction use the production consumer. All injected executions must stay
// nonqualifying and remove their context, even when every assertion passes.
function fixture(t, { beforeCommand, afterCommand, afterInventory, historical = false } = {}) {
  const profile = {
    current: ['contracts/application-source-export.json', 414],
    'before-managed-wallet-setup': ['contracts/application-source-export-history/before-managed-wallet-setup-v1.json', 392],
    initial: ['contracts/application-source-export-history/initial-v1.json', 296],
    'before-delegation-ux-states': ['contracts/application-source-export-history/before-delegation-ux-states-v1.json', 321],
    'before-static-auth-origins': ['contracts/application-source-export-history/before-static-auth-origins-v1.json', 321],
    'main-delegation-ux-states': ['contracts/application-source-export-history/main-delegation-ux-states-v1.json', 323],
    'before-full-console-transport': ['contracts/application-source-export-history/before-full-console-transport-v1.json', 383],
    'before-main-ux-integration': ['contracts/application-source-export-history/before-main-ux-integration-v1.json', 390],
  }[historical === true ? 'initial' : historical || 'current'];
  assert.ok(profile, 'Unknown fixture source profile');
  const [contractPath, assertionCount] = profile;
  const contractBytes = readFileSync(path.join(ROOT, contractPath));
  const sourceContract = JSON.parse(contractBytes);
  const selectedTests = sourceContract.test_profile.files;
  const temporary = mkdtempSync(path.join(os.tmpdir(), 'marty-package-consumer-test-'));
  t.after(() => rmSync(temporary, { recursive: true, force: true }));
  const sourceBytes = new Map();
  const sourceFiles = new Map();
  const selected = [];
  function select(source, destination = source) {
    const bytes = readFileSync(path.join(ROOT, source));
    sourceBytes.set(destination, bytes);
    sourceFiles.set(source, record(source, bytes));
    selected.push({ ...record(destination, bytes), source, git_mode: '100644',
      blob_oid: createHash('sha1').update(Buffer.from(`blob ${bytes.length}\0`)).update(bytes).digest('hex') });
  }
  for (const name of APPLICATION_RETAINED_PUBLIC_FILES) select(`ui/public/${name}`);
  for (const input of APPLICATION_RUNTIME_INPUTS) {
    if (input.path !== 'ui/scripts/application-runtime.Dockerfile') select(input.path);
    else sourceFiles.set(input.path, record(input.path, readFileSync(path.join(ROOT, input.path))));
  }
  for (const name of ['package.json', 'package-lock.json']) select(`ui/profiles/application/${name}`, `ui/${name}`);
  const routeContract = { version: 1, sha256: `sha256:${'b'.repeat(64)}` };
  const testProfile = structuredClone(sourceContract.test_profile);
  assert.equal(testProfile.config, APPLICATION_TEST_CONFIG);
  const substitutions = ['ui/package.json', 'ui/package-lock.json'].map((name) => ({ path: name,
    baseline: record(name, readFileSync(path.join(ROOT, name))),
    selected: sourceFiles.get(`ui/profiles/application/${path.basename(name)}`) }));
  const manifest = { fixture: true, contract: { sha256: digest(contractBytes) }, source: { commit: COMMIT, tree: 'c'.repeat(40), working_tree_dirty: false },
    files: selected, route_contract: routeContract, test_profile: testProfile, substitutions,
    source_inventory_sha256: identity(selected) };
  const plan = { schema: 'marty.application-source-closure-plan/v5',
    source: { commit: COMMIT, working_tree_dirty: false, git_status: [], files: [...sourceFiles.values()] },
    route_contract: routeContract, test_profile: testProfile, dependency_profile: { name: 'application', substitutions } };
  plan.source.input_inventory_sha256 = identity(plan.source.files);
  const baselineRoot = path.join(temporary, 'baseline');
  const outputBytes = new Map(APPLICATION_RETAINED_PUBLIC_FILES.map((name) => [name, sourceBytes.get(`ui/public/${name}`)]));
  outputBytes.set('index.html', Buffer.from('<!doctype html><html><body>Public application</body></html>\n'));
  outputBytes.set('console/index.html', Buffer.from('<!doctype html><html><body>Console application</body></html>\n'));
  outputBytes.set('marty-web-routes.json', Buffer.from(json({ schema: 'marty.application-web-compatibility/v1',
    surface: 'application', source_sha: COMMIT, route_contract: routeContract })));
  outputBytes.set(SDK, Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]));
  for (let index = 0; index < 30; index++) outputBytes.set(`assets/chunk-${String(index).padStart(2, '0')}.js`, Buffer.from(`export const n = ${index};\n`));
  for (const [name, bytes] of outputBytes) write(baselineRoot, `ui/dist-application/${name}`, bytes,
    APPLICATION_RETAINED_PUBLIC_FILES.includes(name) ? 0o600 : 0o644);
  const output = verifyApplicationClosureOutput(baselineRoot, plan);
  const en = JSON.parse(outputBytes.get('locales/en/common.json'));
  const de = JSON.parse(outputBytes.get('locales/de/common.json'));
  const resources = { schema: 'marty.application-resource-smoke/v1', status: 'passed',
    public_resources: output.public_resources,
    served_resources: output.files.filter((row) => row.path !== 'marty-web-routes.json').map((row) => ({
      ...byteRecord(row), status: 200, content_type: APPLICATION_RESOURCE_MIME_TYPES[path.extname(row.path)][0],
    })), preview: { host: '127.0.0.1', port: 12345, closed: true },
    qualification: { resources_served: true, locale_fallback_observed: true, browser_startup_observed: false,
      host_deployment_tested: false, oidc_journey_tested: false },
    locale_probe: { language: 'de', fallback_language: 'en', key: 'common.login', resolved_language: 'en',
      fallback_value: en.common.login, localized_key: 'actions.cancel', localized_language: 'de', localized_value: de.actions.cancel,
      requests: ['de', 'en'].flatMap((language) => APPLICATION_LOCALE_NAMESPACES.map((namespace) => `/locales/${language}/${namespace}.json`)) } };
  for (const input of APPLICATION_RUNTIME_INPUTS) write(baselineRoot, input.path, readFileSync(path.join(ROOT, input.path)), 0o600);
  const context = createApplicationRuntimeContext({ sourceRoot: baselineRoot, outputRoot: path.join(baselineRoot, 'ui/dist-application'),
    sourceCommit: COMMIT, destination: path.join(temporary, 'baseline-context'), outputInventory: output, resourceResult: resources });
  const baseline = { schema: 'marty.application-source-closure-rehearsal/v5', status: 'passed', plan,
    build: { dependency_mode: 'fresh-npm-ci', dependency_profile: 'application', effective_source_sha: COMMIT,
      package_lock_sha256: selected.find((row) => row.path === 'ui/package-lock.json').sha256 },
    dependency_install: { status: 'passed', mode: 'fresh-npm-ci', dependency_profile: 'application',
      independent_dependency_installation: true, sdk: { wasm: byteRecord(record(SDK, outputBytes.get(SDK))) } },
    dependency_profile: { name: 'application', output_identical_to_full_profile: true,
      baseline_comparison: { output_files_identical: true, public_resources_identical: true } },
    qualification: Object.fromEntries(['application_build_completed', 'application_tests_completed', 'omitted_sources_absent',
      'application_output_checked', 'source_checkout_unchanged', 'public_assets_preserved', 'application_resource_smoke_completed',
      'locale_fallback_observed', 'runtime_context_prepared', 'sdk_wasm_initialized_in_node', 'sdk_wasm_output_bound',
      'independent_dependency_installation'].map((name) => [name, true])),
    tests: { result: { test_count: assertionCount, completed_files: [...selectedTests].sort() } },
    output, resources: { result: resources }, runtime_context: context };
  const options = { archivePath: path.join(temporary, 'source.zip'), manifestPath: path.join(temporary, 'manifest.json'),
    baselineReportPath: path.join(temporary, 'baseline.json'), producerReportPath: path.join(temporary, 'producer.json'),
    reportPath: path.join(temporary, 'consumer.json'), runtimeContextDirectory: path.join(temporary, 'consumer-context') };
  writeFileSync(options.archivePath, 'fixture archive bytes');
  writeFileSync(options.manifestPath, json(manifest));
  writeFileSync(options.baselineReportPath, json(baseline));
  const producer = { fixture: true };
  for (const [key, filename] of [['archive', options.archivePath], ['manifest', options.manifestPath], ['baseline_report', options.baselineReportPath]]) {
    const bytes = readFileSync(filename); producer[key] = { bytes: bytes.length, sha256: digest(bytes) };
  }
  writeFileSync(options.producerReportPath, json(producer));
  let restoredRoot;
  const calls = [];
  const packageApi = {
    parseApplicationSourceJson: (bytes) => JSON.parse(bytes),
    validateApplicationSourcePackageManifest: (value) => assert.deepEqual(value, manifest),
    validateApplicationSourceProducerReceipt: (value, pins) => {
      for (const [key, pin] of [['archive', 'archiveSha256'], ['manifest', 'manifestSha256'], ['baseline_report', 'baselineReportSha256']]) {
        assert.equal(value[key].sha256, pins[pin], `fixture receipt ${key} pin`);
      }
    },
    restoreApplicationSourcePackage: ({ destination, expectedArchiveSha256, expectedManifestSha256 }) => {
      restoredRoot = destination;
      assert.equal(existsSync(destination), false);
      for (const [name, bytes] of sourceBytes) write(destination, name, bytes);
      return { root: destination, manifest, archive_sha256: expectedArchiveSha256,
        manifest_sha256: expectedManifestSha256, source_inventory_sha256: manifest.source_inventory_sha256 };
    },
    validateApplicationSourceInventory: ({ destination, allowGenerated }) => {
      assert.equal(destination, restoredRoot);
      assert.deepEqual(allFiles(destination), [...sourceBytes.keys()].sort(), 'fixture source membership changed');
      for (const [name, bytes] of sourceBytes) {
        assert.equal(digest(readFileSync(path.join(destination, name))), digest(bytes), `fixture source bytes changed: ${name}`);
        assert.equal(lstatSync(path.join(destination, name)).mode & 0o777, 0o644, 'fixture source mode changed');
      }
      if (!allowGenerated) assert.equal(existsSync(path.join(destination, 'ui/node_modules')), false);
      afterInventory?.({ destination, options, calls });
    },
  };
  const command = async (executable, args, options) => {
    calls.push({ executable, args, ...options });
    beforeCommand?.({ executable, args, options, calls, restoredRoot });
    writeFileSync(options.stdoutFile, options.stage === 'npm-version' ? '11.9.0\n' : '');
    writeFileSync(options.stderrFile, '');
    if (options.stage === 'npm-ci') mkdirSync(path.join(options.cwd, 'node_modules'));
    if (options.stage === 'dependency-inspection') writeFileSync(options.stdoutFile, json({
      postinstall: { verified: true, prerender_selected: false },
      sdk: { initialized_in_node: true, browser_execution_observed: false, wasm: baseline.dependency_install.sdk.wasm },
    }));
    if (options.stage === 'npm-build') for (const [name, bytes] of outputBytes) write(restoredRoot, `ui/dist-application/${name}`, bytes);
    if (options.stage === 'npm-test') writeFileSync(args.at(-1), json({ success: true,
      numTotalTests: assertionCount, numPassedTests: assertionCount, numFailedTests: 0, numPendingTests: 0, numTodoTests: 0,
      testResults: selectedTests.map((name, index) => ({ name: path.join(options.cwd, name), status: 'passed',
        assertionResults: Array.from({ length: index === 0 ? assertionCount - 12 * (selectedTests.length - 1) : 12 }, () => ({ status: 'passed' })) })) }));
    if (options.stage === 'resource-smoke') writeFileSync(args[args.indexOf('--report') + 1], json(resources));
    return afterCommand?.({ executable, args, options, calls, restoredRoot }) || { status: 0, signal: null };
  };
  return { temporary, manifest, baseline, outputBytes, sourceBytes, options, packageApi, command, calls,
    restoredRoot: () => restoredRoot, run: () => consumeApplicationSourcePackage(options, { packageApi, command }) };
}

test('restored fixture exercises ordinary commands, exact byte output and runtime normalization without qualification', async (t) => {
  const input = fixture(t);
  const result = await input.run();
  assert.equal(result.status, 'fixture-passed', JSON.stringify(result.failure));
  assert.equal(result.fixture, true);
  assert.ok(Object.values(result.qualification).every((value) => value === false));
  assert.equal(result.tests.test_count, 414);
  assert.equal(result.output_comparison.output_files, 88);
  assert.equal(result.output_comparison.mode_transformations.length, 54);
  assert.equal(result.runtime_comparison.payload_files, 92);
  assert.equal(result.runtime_comparison.payload_records_identical, true);
  assert.notEqual(result.runtime_comparison.baseline_manifest_sha256, result.runtime_comparison.consumer_manifest_sha256);
  assert.deepEqual(result.preservation, { pinned_inputs_unchanged: true, restored_source_unchanged: true });
  assert.ok(Object.values(result.cleanup).every((value) => value === true));
  assert.equal(existsSync(input.restoredRoot()), false);
  assert.equal(existsSync(input.options.runtimeContextDirectory), false);
  assert.deepEqual(input.calls.map((call) => [call.stage, call.executable, ...call.args.slice(0, call.stage.startsWith('npm-') ? 2 : 0)]), [
    ['npm-version', 'npm', '--version'], ['npm-ci', 'npm', 'ci'], ['dependency-inspection', process.execPath],
    ['npm-build', 'npm', 'run', 'build'], ['npm-test', 'npm', 'test', '--'], ['resource-smoke', process.execPath],
  ]);
  const install = input.calls.find((call) => call.stage === 'npm-ci');
  assert.equal(install.env.PUPPETEER_SKIP_DOWNLOAD, 'true');
  assert.equal(install.env.npm_config_ignore_scripts, 'false');
  assert.equal(install.env.npm_config_registry, 'https://registry.npmjs.org');
  assert.equal(install.env.MARTY_UI_SHA, undefined);
  const build = input.calls.find((call) => call.stage === 'npm-build');
  assert.equal(build.env.MARTY_UI_SHA, COMMIT);
  assert.equal(build.env.npm_config_cache, install.env.npm_config_cache);
  assert.equal(result.kernel_descendant_reaping_claimed, false);
});

test('consumer baseline refuses fixtures, dirty sources, duplicate inventory and incomplete selected test evidence', (t) => {
  const input = fixture(t);
  validateApplicationPackageBaseline(input.baseline, input.manifest);
  for (const change of [
    (value) => { value.fixture = true; },
    (value) => { value.plan.source.working_tree_dirty = true; },
    (value) => { value.plan.source.files.push(value.plan.source.files[0]); value.plan.source.input_inventory_sha256 = identity(value.plan.source.files); },
    (value) => { value.tests.result.completed_files[0] = value.tests.result.completed_files[1]; },
    (value) => { value.tests.result.test_count--; },
    (value) => { value.dependency_profile.baseline_comparison.public_resources_identical = false; },
    (value) => { value.runtime_context.manifest_sha256 = `sha256:${'0'.repeat(64)}`; },
  ]) {
    const changed = structuredClone(input.baseline); change(changed);
    assert.throws(() => validateApplicationPackageBaseline(changed, input.manifest));
  }
});

test('the approved historical package keeps its original 24-file, 296-assertion consumer policy', async (t) => {
  const input = fixture(t, { historical: true });
  const result = await input.run();
  assert.equal(result.status, 'fixture-passed', JSON.stringify(result.failure));
  assert.equal(result.tests.completed_files.length, 24);
  assert.equal(result.tests.test_count, 296);
  assert.ok(Object.values(result.qualification).every((value) => value === false));
  const arbitrary = structuredClone(input.manifest);
  arbitrary.test_profile.files.pop();
  assert.throws(() => validateApplicationPackageBaseline(input.baseline, arbitrary), /roster changed/);
  arbitrary.test_profile = input.manifest.test_profile;
  arbitrary.contract.sha256 = `sha256:${'0'.repeat(64)}`;
  assert.throws(() => validateApplicationPackageBaseline(input.baseline, arbitrary), /unapproved source contract/);
});

test('release input validation keeps exact current and historical test profiles', async (t) => {
  const current = fixture(t);
  const previous = fixture(t, { historical: 'before-delegation-ux-states' });
  const historical = fixture(t, { historical: true });
  const predecessor = fixture(t, { historical: 'before-static-auth-origins' });
  const beforeConsole = fixture(t, { historical: 'before-full-console-transport' });
  const mainUx = fixture(t, { historical: 'main-delegation-ux-states' });
  const nativeAuth = fixture(t, { historical: 'before-main-ux-integration' });
  const beforeWallet = fixture(t, { historical: 'before-managed-wallet-setup' });
  assert.deepEqual(beforeWallet.manifest.test_profile.files, nativeAuth.manifest.test_profile.files);
  assert.deepEqual(mainUx.manifest.test_profile.files, previous.manifest.test_profile.files);
  assert.deepEqual(previous.manifest.test_profile, predecessor.manifest.test_profile);
  assert.equal(current.manifest.test_profile.assertions, 414);
  assert.equal(beforeWallet.manifest.test_profile.assertions, 392);
  assert.equal(mainUx.manifest.test_profile.assertions, 323);
  assert.equal(nativeAuth.manifest.test_profile.assertions, undefined);
  assert.equal(previous.manifest.test_profile.assertions, undefined);
  assert.deepEqual(current.manifest.test_profile.files.filter((name) => !historical.manifest.test_profile.files.includes(name)), [
    'src/components/console/agents/AgentTrustPages.test.tsx',
    'src/components/console/trust/__tests__/WalletTrustProfiles.owner.test.tsx',
    'src/services/__tests__/agentTrustApi.test.ts',
    'src/services/__tests__/walletTrustConfiguration.test.ts',
    'src/services/__tests__/authApiOrigin.test.ts',
    'src/services/__tests__/consoleApiOrigin.test.ts',
    'src/services/__tests__/identityProviderApi.test.ts',
    'src/services/__tests__/associationConsent.test.ts',
  ]);
  assert.ok(historical.manifest.test_profile.files.every((name) => current.manifest.test_profile.files.includes(name)));
  assert.equal(predecessor.manifest.test_profile.files.length, 26);
  assert.equal(beforeConsole.manifest.test_profile.files.length, 29);
  assert.equal(beforeWallet.manifest.test_profile.files.length, 30);
  assert.equal(current.manifest.test_profile.files.length, 32);
  assert.deepEqual(current.manifest.test_profile.files.filter((name) => !beforeWallet.manifest.test_profile.files.includes(name)), [
    'src/components/console/trust/__tests__/WalletTrustProfiles.owner.test.tsx',
    'src/services/__tests__/walletTrustConfiguration.test.ts',
  ]);
  assert.deepEqual(current.manifest.test_profile.files.filter((name) => !beforeConsole.manifest.test_profile.files.includes(name)), [
    'src/components/console/trust/__tests__/WalletTrustProfiles.owner.test.tsx',
    'src/services/__tests__/walletTrustConfiguration.test.ts',
    'src/services/__tests__/consoleApiOrigin.test.ts',
  ]);
  // The current owner-configuration suite has its own exact policy. Every
  // historical package keeps its original inventory and assertion count.
  const profiles = [[current, 414], [beforeWallet, 392], [nativeAuth, 390], [beforeConsole, 383], [mainUx, 323],
    [previous, 321], [predecessor, 321], [historical, 296]];
  for (const [input, assertions] of profiles) {
    const otherAssertions = [...new Set(profiles.map(([, count]) => count))].filter((count) => count !== assertions);
    const report = await input.run();
    assert.equal(report.status, 'fixture-passed', JSON.stringify(report.failure));
    assert.equal(report.fixture, true);
    assert.ok(Object.values(report.qualification).every((value) => value === false));
    // Construct inert validator arguments in memory. The injected execution and
    // its persisted report remain nonqualifying; no production receipt is made.
    const consumer = structuredClone(report);
    consumer.status = 'passed';
    consumer.fixture = false;
    consumer.cleanup.runtime_context_removed = false;
    for (const name of ['source_package_verified', 'restored_source_preserved', 'independent_dependency_installation',
      'application_build_completed', 'application_tests_completed', 'sdk_wasm_initialized_in_node', 'sdk_wasm_output_bound',
      'application_output_checked', 'public_assets_preserved', 'application_resource_smoke_completed',
      'runtime_context_prepared', 'runtime_payload_identical']) consumer.qualification[name] = true;
    const baseline = structuredClone(input.baseline);
    baseline.dependency_install.sdk = structuredClone(consumer.dependency_install.sdk);
    const snapshots = Object.fromEntries([
      ['archive', 'archivePath'], ['manifest', 'manifestPath'],
      ['producer_report', 'producerReportPath'], ['baseline_report', 'baselineReportPath'],
    ].map(([name, option]) => [name, readFileSync(input.options[option])]));
    const { path: contextRoot, manifest_sha256: manifestSha256, ...contextManifest } = consumer.runtime_context;
    const options = { manifest: input.manifest, baseline, snapshots,
      verified: { root: contextRoot, manifest: contextManifest, manifest_sha256: manifestSha256 } };
    assert.equal(consumer.tests.test_count, assertions);
    assert.doesNotThrow(() => validateApplicationReleaseConsumer(consumer, options));
    for (const count of [...otherAssertions, assertions - 1, assertions + 1]) {
      const changed = structuredClone(consumer);
      changed.tests.test_count = count;
      assert.throws(() => validateApplicationReleaseConsumer(changed, options), /approved source test profile/);
    }
    const incomplete = structuredClone(consumer);
    incomplete.tests.completed_files.pop();
    assert.throws(() => validateApplicationReleaseConsumer(incomplete, options));
    const wrongRoster = structuredClone(input.manifest);
    wrongRoster.test_profile.files.pop();
    assert.throws(() => validateApplicationReleaseConsumer(consumer, { ...options, manifest: wrongRoster }), /roster changed/);
    const unknown = structuredClone(input.manifest);
    unknown.contract.sha256 = `sha256:${'0'.repeat(64)}`;
    assert.throws(() => validateApplicationReleaseConsumer(consumer, { ...options, manifest: unknown }), /unapproved source contract/);
    assert.equal(JSON.parse(readFileSync(input.options.reportPath)).fixture, true);
    assert.equal(JSON.parse(readFileSync(input.options.reportPath)).status, 'fixture-passed');
  }
});

test('only the exact 54 public modes may change; output bytes, paths, unexpected modes and resource records remain bound', (t) => {
  const input = fixture(t);
  const output = structuredClone(input.baseline.output);
  for (const row of output.files) row.mode = 0o644;
  output.inventory_sha256 = identity(output.files);
  assert.equal(compareApplicationPackageOutput(output, input.baseline).mode_transformations.length, 54);
  for (const change of [
    (value) => { value.files[0].sha256 = `sha256:${'0'.repeat(64)}`; },
    (value) => { value.files[0].bytes++; },
    (value) => { value.files[0].path = 'unexpected.json'; },
    (value) => { value.files.find((row) => row.path.startsWith('assets/')).mode = 0o600; },
    (value) => { value.files.find((row) => row.path === 'config.json').mode = 0o755; },
    (value) => { value.public_resources.pop(); },
  ]) {
    const changed = structuredClone(output); change(changed); changed.inventory_sha256 = identity(changed.files);
    assert.throws(() => compareApplicationPackageOutput(changed, input.baseline));
  }
});

for (const stage of ['npm-ci', 'npm-build', 'npm-test', 'resource-smoke']) {
  test(`source mutation during ${stage} fails closed and removes owned temporary state`, async (t) => {
    const input = fixture(t, { afterCommand: ({ options, restoredRoot }) => {
      if (options.stage === stage) write(restoredRoot, 'ui/package-lock.json', 'modified source');
    } });
    const result = await input.run();
    assert.equal(result.status, 'failed');
    assert.equal(result.failure.phase, stage);
    assert.equal(result.preservation.restored_source_unchanged, false);
    assert.ok(result.failure.messages.some((message) => message.includes('fixture source bytes changed')));
    assert.ok(Object.values(result.qualification).every((value) => value === false));
    assert.equal(result.cleanup.temporary_removed, true);
    assert.equal(existsSync(input.restoredRoot()), false);
  });
}

test('a pinned receipt altered by a child command is rejected before the next phase', async (t) => {
  let input;
  input = fixture(t, { afterCommand: ({ options }) => {
    if (options.stage === 'npm-ci') writeFileSync(input.options.producerReportPath, '{}');
  } });
  const result = await input.run();
  assert.equal(result.status, 'failed');
  assert.equal(result.failure.phase, 'npm-ci');
  assert.equal(result.preservation.pinned_inputs_unchanged, false);
  assert.equal(result.cleanup.temporary_removed, true);
  assert.equal(input.calls.some((call) => call.stage === 'dependency-inspection'), false);
});

test('an unsuccessful command retains failed diagnostics after proven process cleanup', async (t) => {
  const input = fixture(t, { afterCommand: ({ options }) => options.stage === 'npm-build' ? { status: 7, signal: null } : undefined });
  const result = await input.run();
  assert.equal(result.status, 'failed');
  assert.equal(result.failure.phase, 'npm-build');
  assert.equal(result.commands.at(-1).status, 7);
  assert.equal(result.cleanup.process_group_cleanup_completed, true);
  assert.equal(result.cleanup.temporary_removed, true);
  assert.deepEqual(JSON.parse(readFileSync(input.options.reportPath)), result);
});

test('successful test command exit cannot hide a skipped selected assertion', async (t) => {
  const input = fixture(t, { afterCommand: ({ args, options }) => {
    if (options.stage === 'npm-test') {
      const result = JSON.parse(readFileSync(args.at(-1)));
      result.testResults[0].assertionResults[0].status = 'pending';
      writeFileSync(args.at(-1), json(result));
    }
  } });
  const result = await input.run();
  assert.equal(result.status, 'failed');
  assert.equal(result.failure.phase, 'npm-test');
  assert.ok(result.failure.messages.some((message) => message.includes('skipped or failed')));
  assert.equal(result.cleanup.temporary_removed, true);
  assert.equal(input.calls.some((call) => call.stage === 'resource-smoke'), false);
});

test('a successful build cannot add unreviewed output even when its expected resources are intact', async (t) => {
  const input = fixture(t, { afterCommand: ({ options, restoredRoot }) => {
    if (options.stage === 'npm-build') write(restoredRoot, 'ui/dist-application/extra.json', '{}');
  } });
  const result = await input.run();
  assert.equal(result.status, 'failed');
  assert.equal(result.failure.phase, 'output-comparison');
  assert.ok(result.failure.messages.some((message) => message.includes('Consumer output inventory is invalid')));
  assert.equal(result.cleanup.temporary_removed, true);
  assert.equal(result.runtime_context, undefined);
});

test('uncertain process-group cleanup retains owned source/cache and prevents qualification', async (t) => {
  const input = fixture(t, { beforeCommand: ({ options }) => {
    if (options.stage === 'npm-ci') throw new Error('fixture process-group cleanup uncertain');
  } });
  const result = await input.run();
  t.after(() => rmSync(result.retained_diagnostic_directory, { recursive: true, force: true }));
  assert.equal(result.status, 'failed');
  assert.equal(result.cleanup.process_group_cleanup_completed, false);
  assert.equal(result.cleanup.temporary_removed, false);
  assert.equal(result.cleanup.source_removed, false);
  assert.equal(existsSync(input.restoredRoot()), true);
  assert.equal(path.dirname(input.restoredRoot()), result.retained_diagnostic_directory);
  assert.ok(Object.values(result.qualification).every((value) => value === false));
});

test('runtime mutation after source verification is caught by the final context check and cleaned', async (t) => {
  let changed = false;
  const input = fixture(t, { afterInventory: ({ options }) => {
    if (!changed && existsSync(options.runtimeContextDirectory)) {
      changed = true;
      write(options.runtimeContextDirectory, 'html/config.json', '{}');
    }
  } });
  const result = await input.run();
  assert.equal(changed, true);
  assert.equal(result.status, 'failed');
  assert.equal(result.failure.phase, 'runtime-context-final-verification');
  assert.equal(result.cleanup.runtime_context_removed, true);
  assert.equal(existsSync(input.options.runtimeContextDirectory), false);
  assert.ok(Object.values(result.qualification).every((value) => value === false));
});

test('consumer refuses destination reuse and symlink inputs without executing any package command', async (t) => {
  const existing = fixture(t);
  writeFileSync(existing.options.reportPath, 'user file');
  await assert.rejects(existing.run(), /already exists/);
  assert.equal(readFileSync(existing.options.reportPath, 'utf8'), 'user file');
  assert.equal(existing.calls.length, 0);
  const linked = fixture(t);
  const original = linked.options.archivePath;
  linked.options.archivePath = path.join(linked.temporary, 'linked.zip');
  symlinkSync(original, linked.options.archivePath);
  const result = await linked.run();
  assert.equal(result.status, 'failed');
  assert.equal(result.failure.phase, 'input-verification');
  assert.equal(linked.calls.length, 0);
  assert.equal(existsSync(original), true);
});
