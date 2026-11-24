import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  ADDITIONAL_OMISSIONS, OMITTED_DEMO_INPUTS, OMITTED_COMBINED_ADAPTERS,
  OMITTED_DEMO_MODULES, OMITTED_COMBINED_TEST_INPUTS, OMITTED_WEBSITE_BUILD_INPUTS, RETAINED_SHARED_INPUTS,
  planApplicationSourceClosure, rehearseApplicationSourceClosure, materializeApplicationDependencyProfile,
  compareApplicationProfileBaseline,
} from './application-source-closure.mjs';
import { canonicalJson } from './web-surface-contract.mjs';
import { APPLICATION_TEST_CONFIG, APPLICATION_TEST_FILES } from './application-test-profile.mjs';
import {
  APPLICATION_ASSET_OMISSIONS, APPLICATION_RETAINED_PUBLIC_FILES,
  APPLICATION_LOCALES, APPLICATION_LOCALE_NAMESPACES, APPLICATION_RESOURCE_MIME_TYPES,
} from './application-public-assets.mjs';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const harness = fileURLToPath(new URL('./application-source-closure.mjs', import.meta.url));
const ownership = JSON.parse(readFileSync(path.join(repositoryRoot, 'contracts/website-source-ownership.json'), 'utf8'));
const routeBytes = readFileSync(path.join(repositoryRoot, 'contracts/web-surface-routes.json'));
const organizationContract = readFileSync(path.join(repositoryRoot, 'contracts/organization-domain-behavior.json'));
const namespaces = ['common', 'console', 'onboarding', 'forms', 'errors', 'applicant', 'vendor'];
const runtimeInputs = ['ui/nginx.prod.conf', 'ui/scripts/application-runtime.Dockerfile',
  'scripts/ui-production-start.sh', 'scripts/load-secrets-env.sh'];

function put(root, relative, content) {
  const target = path.join(root, relative);
  mkdirSync(path.dirname(target), { recursive: true });
  writeFileSync(target, content);
}

function git(root, ...args) {
  const result = spawnSync('git', ['-C', root, '-c', 'user.name=Source closure fixture',
    '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', ...args], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}

function builder({ failure = false, marketing = false, mutateSource, outputSymlink = false, recreateOmitted,
  removePublic, tamperPublic, runtimeContext = false } = {}) {
  return `
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
const root = path.resolve('..');
assert.equal(process.argv[2], 'application');
assert.equal(process.env.MARTY_PRODUCTION_PAGES, 'public');
assert.equal(process.env.VITE_UI_VARIANT, 'public');
assert.equal(process.env.MARTY_COMMERCE_SOURCE_SHA, undefined);
assert.equal(process.env.VITE_API_URL, undefined);
for (const entry of ${JSON.stringify([...ownership.modules, ...ADDITIONAL_OMISSIONS])}) {
  assert.equal(fs.existsSync(path.join(root, entry)), false, entry);
}
for (const entry of ${JSON.stringify(RETAINED_SHARED_INPUTS)}) assert.equal(fs.existsSync(path.join(root, entry)), true, entry);
${recreateOmitted ? `
const recreated = path.join(root, ${JSON.stringify(ownership.modules[0])});
fs.mkdirSync(path.dirname(recreated), { recursive: true });
${recreateOmitted === 'symlink' ? "fs.symlinkSync('missing-source.jsx', recreated);" : recreateOmitted === 'directory'
    ? 'fs.mkdirSync(recreated);' : "fs.writeFileSync(recreated, '// regenerated omitted source');"}
` : ''}
${mutateSource ? `fs.writeFileSync(${JSON.stringify(mutateSource)}, '// illicit original-source mutation');` : ''}
${failure ? 'process.exit(23);' : ''}
const output = 'dist-application';
${outputSymlink ? "fs.symlinkSync(process.cwd(), output, 'dir'); process.exit(0);" : ''}
fs.mkdirSync(path.join(output, 'console'), { recursive: true });
fs.writeFileSync(path.join(output, 'index.html'), '<html><main>Application fixture</main></html>');
fs.writeFileSync(path.join(output, 'console/index.html'), '<html><main>Console fixture</main></html>');
${runtimeContext ? "fs.mkdirSync(path.join(output, 'assets')); fs.writeFileSync(path.join(output, 'assets/marty_api_client_bg-fixture.wasm'), Buffer.from([0,97,115,109,1,0,0,0]));" : ''}
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  return JSON.stringify(value);
}
const routes = JSON.parse(fs.readFileSync(path.join(root, 'contracts/web-surface-routes.json')));
const routeContract = { version: routes.schema_version, sha256: 'sha256:' + createHash('sha256').update(canonical(routes)).digest('hex') };
fs.writeFileSync(path.join(output, 'marty-web-routes.json'), JSON.stringify({ schema: 'marty.application-web-compatibility/v1', surface: 'application', source_sha: process.env.MARTY_UI_SHA, route_contract: routeContract }));
fs.mkdirSync(path.join(output, 'locales/en'), { recursive: true });
for (const namespace of ${JSON.stringify(namespaces)}) fs.writeFileSync(path.join(output, 'locales/en', namespace + '.json'), '{}');
for (const entry of ${JSON.stringify(APPLICATION_RETAINED_PUBLIC_FILES)}) {
  const destination = path.join(output, entry);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.copyFileSync(path.join('public', entry), destination);
}
${removePublic ? `fs.rmSync(path.join(output, ${JSON.stringify(removePublic)}));` : ''}
${tamperPublic ? `fs.writeFileSync(path.join(output, ${JSON.stringify(tamperPublic)}), '{"tampered":true}');` : ''}
${marketing ? "fs.mkdirSync(path.join(output, 'blog')); fs.writeFileSync(path.join(output, 'blog/index.html'), 'retained marketing');" : ''}
`;
}

function tester({ testFailure = false, testReportFault, recreateAfterTests = false } = {}) {
  return `
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
assert.deepEqual(process.argv.slice(2, -1), ['run', '--config', ${JSON.stringify(APPLICATION_TEST_CONFIG)}, '--reporter=json', '--outputFile']);
assert.equal(process.env.MARTY_PRODUCTION_PAGES, 'public');
assert.equal(process.env.VITE_UI_VARIANT, 'public');
assert.equal(process.env.MARTY_COMMERCE_SOURCE_SHA, undefined);
assert.equal(process.env.VITE_API_URL, undefined);
const root = path.resolve('..');
for (const entry of ${JSON.stringify([...ownership.modules, ...ADDITIONAL_OMISSIONS])}) {
  assert.equal(fs.existsSync(path.join(root, entry)), false, entry);
}
assert.equal(fs.existsSync(path.join(root, 'contracts/organization-domain-behavior.json')), true);
const selected = ${JSON.stringify(APPLICATION_TEST_FILES)};
for (const entry of selected) assert.equal(fs.existsSync(entry), true, entry);
${testFailure ? 'process.exit(17);' : ''}
${testReportFault === 'missing-report' ? 'process.exit(0);' : ''}
const result = { success: true, numTotalTests: selected.length, numPassedTests: selected.length,
  numFailedTests: 0, numPendingTests: 0, numTodoTests: 0,
  testResults: selected.map((entry) => ({ name: path.resolve(entry), status: 'passed',
    assertionResults: [{ status: 'passed', title: 'Synthetic harness fixture; real Vitest is a separate rehearsal' }] })) };
${testReportFault === 'missing-file' ? 'result.testResults.pop();' : ''}
${testReportFault === 'wrong-file' ? "result.testResults[0].name = path.resolve('src/not-selected.test.ts');" : ''}
${testReportFault === 'duplicate-file' ? 'result.testResults[0] = result.testResults[1];' : ''}
${testReportFault === 'skipped-test' ? "result.testResults[0].assertionResults[0].status = 'pending';" : ''}
${testReportFault === 'incorrect-count' ? 'result.numPassedTests = 0;' : ''}
fs.writeFileSync(process.argv.at(-1), JSON.stringify(result));
${recreateAfterTests ? `fs.writeFileSync(path.join(root, ${JSON.stringify(OMITTED_COMBINED_TEST_INPUTS[0])}), '// restored combined setup');` : ''}
`;
}

function resourceProbe({ resourceFailure = false, resourceFault, recreateAfterResources = false, runtimeContext = false } = {}) {
  return `
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
assert.deepEqual(process.argv.slice(2, -1), ['--dist', 'dist-application', '--report']);
${resourceFailure ? 'process.exit(19);' : ''}
${resourceFault === 'missing-report' ? 'process.exit(0);' : ''}
const output = path.resolve('dist-application');
const publicFiles = ${JSON.stringify(APPLICATION_RETAINED_PUBLIC_FILES)};
function record(entry) {
  const bytes = fs.readFileSync(path.join(output, entry));
  return { path: entry, bytes: bytes.length, sha256: 'sha256:' + createHash('sha256').update(bytes).digest('hex') };
}
const result = { schema: 'marty.application-resource-smoke/v1', status: 'passed',
  public_resources: publicFiles.map(record),
  served_resources: [...publicFiles, 'index.html', 'console/index.html', ${runtimeContext ? "'assets/marty_api_client_bg-fixture.wasm'" : ''}].map((entry) => ({
    ...record(entry), status: 200, content_type: ${JSON.stringify(APPLICATION_RESOURCE_MIME_TYPES)}[path.extname(entry)][0],
  })),
  entry_references: [], manifest_icons: [],
  locale_probe: { language: 'de', fallback_language: 'en', key: 'common.login', resolved_language: 'en',
    fallback_value: 'Login', localized_key: 'actions.cancel', localized_language: 'de', localized_value: 'Abbrechen',
    requests: ['de', 'en'].flatMap((locale) => ${JSON.stringify(APPLICATION_LOCALE_NAMESPACES)}.map((namespace) => '/locales/' + locale + '/' + namespace + '.json')).sort() },
  preview: { host: '127.0.0.1', port: 42641, closed: true },
  qualification: { resources_served: true, locale_fallback_observed: true, browser_startup_observed: false,
    host_deployment_tested: false, oidc_journey_tested: false } };
${resourceFault === 'missing-resource' ? 'result.served_resources.pop();' : ''}
${resourceFault === 'tampered-resource' ? "result.served_resources[0].sha256 = 'sha256:' + '0'.repeat(64);" : ''}
${resourceFault === 'html-as-script' ? "result.served_resources.find((entry) => entry.path === 'startup.js').content_type = 'text/html';" : ''}
${resourceFault === 'no-fallback' ? "result.locale_probe.resolved_language = 'de';" : ''}
${resourceFault === 'missing-locale-request' ? 'result.locale_probe.requests.pop();' : ''}
${resourceFault === 'open-preview' ? 'result.preview.closed = false;' : ''}
${resourceFault === 'broadened-qualification' ? 'result.qualification.browser_startup_observed = true;' : ''}
fs.writeFileSync(process.argv.at(-1), JSON.stringify(result));
${resourceFault === 'changed-output' ? "fs.writeFileSync(path.join(output, 'runtime-config.js'), '// changed after report');" : ''}
${resourceFault === 'changed-emitted-output' ? "fs.writeFileSync(path.join(output, 'index.html'), '<html>Changed after valid HTTP responses</html>');" : ''}
${recreateAfterResources ? `const restored = path.resolve('..', ${JSON.stringify(APPLICATION_ASSET_OMISSIONS[0])});
fs.mkdirSync(path.dirname(restored), { recursive: true }); fs.writeFileSync(restored, '// restored asset');` : ''}
`;
}

function fixture(t, buildOptions = {}) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'marty-application-source-fixture-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  put(root, '.gitignore', 'ui/node_modules/\nui/dist*/\n');
  put(root, 'contracts/website-source-ownership.json', JSON.stringify(ownership));
  put(root, 'contracts/web-surface-routes.json', routeBytes);
  put(root, 'contracts/organization-domain-behavior.json', organizationContract);
  for (const entry of [...ownership.modules, ...RETAINED_SHARED_INPUTS]) put(root, entry, '// retained fixture source\n');
  for (const entry of ADDITIONAL_OMISSIONS) put(root, entry, '{}\n');
  for (const entry of APPLICATION_RETAINED_PUBLIC_FILES) {
    let content = entry.endsWith('.json') ? '{}\n' : `Synthetic resource fixture: ${entry}\n`;
    if (entry === 'locales/en/common.json') content = JSON.stringify({ common: { login: 'Login' }, actions: { cancel: 'Cancel' } });
    if (entry === 'locales/de/common.json') content = JSON.stringify({ actions: { cancel: 'Abbrechen' } });
    put(root, `ui/public/${entry}`, content);
  }
  for (const entry of APPLICATION_TEST_FILES) put(root, `ui/${entry}`, '// selected test fixture\n');
  put(root, 'ui/package.json', JSON.stringify({ type: 'module' }));
  put(root, 'ui/package-lock.json', '{}\n');
  put(root, 'ui/bun.lock', '{}\n');
  for (const name of ['patch-prerenderer-ts-deepmerge.cjs', 'patch-checker-worker-cleanup.mjs', 'checker-worker-cleanup.mjs']) {
    put(root, `ui/scripts/${name}`, '// fresh-install input fixture\n');
  }
  for (const name of runtimeInputs) put(root, name, readFileSync(path.join(repositoryRoot, name)));
  put(root, 'ui/vite.config.ts', '// fixture config; the real Vite build is a separate rehearsal\n');
  for (const entry of ['ui/vitest.config.ts', `ui/${APPLICATION_TEST_CONFIG}`,
    'ui/scripts/application-test-profile.mjs', 'ui/scripts/application-public-assets.mjs',
    'ui/src/test/i18nApplicationTestSetup.js', 'ui/src/test/setup.ts']) {
    put(root, entry, '// required application test input\n');
  }
  put(root, 'ui/index.html', '<html>Fixture entry</html>');
  put(root, 'ui/console/index.html', '<html>Fixture console entry</html>');
  put(root, 'ui/scripts/build-web-surface.mjs', builder(buildOptions));
  put(root, 'ui/scripts/application-resource-smoke.mjs', resourceProbe(buildOptions));
  put(root, 'ui/node_modules/.bin/tsc', 'fixture');
  put(root, 'ui/node_modules/.bin/vite', 'fixture');
  put(root, 'ui/node_modules/vitest/vitest.mjs', tester(buildOptions));
  git(root, 'init', '--initial-branch=main');
  git(root, 'add', '.');
  git(root, 'commit', '-m', 'Synthetic source-closure fixture');
  return root;
}

test('the plan separates the original website roster from the 72-input application build/test/resource boundary', (t) => {
  const root = fixture(t);
  const plan = planApplicationSourceClosure({ repositoryRoot: root });
  assert.equal(ownership.modules.length, 34);
  assert.deepEqual(plan.boundary.website_roster, [...ownership.modules].sort());
  assert.deepEqual(plan.boundary.additional_omissions, [...ADDITIONAL_OMISSIONS]);
  assert.deepEqual(plan.boundary.application_only_omissions, {
    combined_entry_adapters: [...OMITTED_COMBINED_ADAPTERS],
    demo_modules: [...OMITTED_DEMO_MODULES],
    combined_test_setup_and_locale: [...OMITTED_COMBINED_TEST_INPUTS],
    public_assets: [...APPLICATION_ASSET_OMISSIONS],
    website_build_tools: [...OMITTED_WEBSITE_BUILD_INPUTS],
  });
  assert.equal(plan.boundary.omitted.length, 72);
  assert.equal(APPLICATION_ASSET_OMISSIONS.length, 26);
  assert.equal(new Set(APPLICATION_ASSET_OMISSIONS).size, 26);
  assert.deepEqual(plan.boundary.retained_public_files, [...APPLICATION_RETAINED_PUBLIC_FILES]);
  assert.equal(APPLICATION_RETAINED_PUBLIC_FILES.length, 54);
  assert.equal(APPLICATION_RETAINED_PUBLIC_FILES.filter((entry) => entry.startsWith('locales/')).length, 42);
  assert.equal(plan.boundary.ownership_audit_complete, false);
  assert.equal(plan.source.working_tree_dirty, false);
  assert.match(plan.source.input_inventory_sha256, /^sha256:[0-9a-f]{64}$/);
  for (const retained of RETAINED_SHARED_INPUTS) assert.ok(plan.boundary.retained.includes(retained), retained);
  assert.deepEqual(plan.test_profile.files, [...APPLICATION_TEST_FILES]);
  assert.deepEqual(plan.test_profile.shared_contracts, ['contracts/organization-domain-behavior.json']);
  assert.equal(plan.test_profile.files.length, 29);
  assert.ok(plan.boundary.retained.includes('contracts/organization-domain-behavior.json'));
  assert.ok(plan.boundary.retained.includes('ui/package-lock.json'));
});

test('fresh installation cannot select or fall back to the reusable dependency directory', (t) => {
  const root = fixture(t);
  assert.throws(() => rehearseApplicationSourceClosure({ repositoryRoot: root, freshInstall: true,
    dependencyDirectory: path.join(root, 'ui/node_modules') }), /mutually exclusive/);
  const report = rehearseApplicationSourceClosure({ repositoryRoot: root, freshInstall: true });
  assert.equal(report.status, 'failed');
  assert.match(report.error, /committed npm v3 lock/);
  assert.equal(report.build.dependency_mode, 'fresh-npm-ci');
  assert.equal(report.qualification.independent_dependency_installation, false);
  assert.equal(report.qualification.application_build_completed, false);
  assert.equal(report.qualification.source_checkout_unchanged, true);
  assert.equal(existsSync(path.dirname(report.export_directory)), false);
});

test('profile selection requires a fresh install and a separate full-profile baseline', (t) => {
  const root = fixture(t);
  assert.throws(() => planApplicationSourceClosure({ repositoryRoot: root, dependencyProfile: 'unknown' }), /Unsupported dependency profile/);
  assert.throws(() => planApplicationSourceClosure({ repositoryRoot: root, dependencyProfile: 'application' }), /requires a fresh install/);
  assert.throws(() => rehearseApplicationSourceClosure({ repositoryRoot: root, freshInstall: true,
    dependencyProfile: 'application' }), /baseline report is required/);
  assert.throws(() => rehearseApplicationSourceClosure({ repositoryRoot: root, freshInstall: true,
    baselineReport: '/tmp/unselected-baseline.json' }), /required only for the application/);
});

function profileMaterializationFixture(t) {
  const root = fixture(t);
  const directory = mkdtempSync(path.join(os.tmpdir(), 'marty-profile-materialization-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  for (const name of ['package.json', 'package-lock.json']) {
    put(root, `ui/profiles/application/${name}`, JSON.stringify({ selected: name }));
    put(directory, `ui/${name}`, readFileSync(path.join(root, `ui/${name}`)));
    put(directory, `ui/profiles/application/${name}`, readFileSync(path.join(root, `ui/profiles/application/${name}`)));
  }
  const plan = planApplicationSourceClosure({ repositoryRoot: root });
  const inputs = new Map(plan.source.files.map((row) => [row.path, row]));
  plan.dependency_profile = { name: 'application', substitutions: ['package.json', 'package-lock.json'].map((name) => ({
    path: `ui/${name}`, baseline: inputs.get(`ui/${name}`), selected: inputs.get(`ui/profiles/application/${name}`),
  })) };
  return { root, directory, plan };
}

test('profile materialization replaces exactly two export inputs and records both source identities', (t) => {
  const { root, directory, plan } = profileMaterializationFixture(t);
  const before = plan.source.files.map((row) => readFileSync(path.join(root, row.path)));
  const materialized = materializeApplicationDependencyProfile(plan, directory);
  assert.equal(materialized.length, 2);
  for (const row of materialized) {
    assert.deepEqual(readFileSync(path.join(directory, row.path)), readFileSync(path.join(root, row.selected.path)));
    assert.equal(row.materialized.sha256, row.selected.sha256);
    assert.notEqual(row.materialized.sha256, row.baseline.sha256);
  }
  assert.deepEqual(plan.source.files.map((row) => readFileSync(path.join(root, row.path))), before);
});

test('profile materialization refuses changed selected inputs, extra substitutions, and destination links', (t) => {
  const { root, directory, plan } = profileMaterializationFixture(t);
  const selected = plan.dependency_profile.substitutions[0].selected.path;
  const original = readFileSync(path.join(root, selected));
  put(root, selected, `${original}\n`);
  assert.throws(() => materializeApplicationDependencyProfile(plan, directory), /selected profile input changed/);
  put(root, selected, original);
  plan.dependency_profile.substitutions.push({ path: 'ui/vite.config.ts' });
  assert.throws(() => materializeApplicationDependencyProfile(plan, directory), /two reviewed package inputs/);
  plan.dependency_profile.substitutions.pop();
  rmSync(path.join(directory, 'ui/package.json'));
  symlinkSync(path.join(root, 'ui/package.json'), path.join(directory, 'ui/package.json'));
  assert.throws(() => materializeApplicationDependencyProfile(plan, directory), /not a regular file/);
});

function baselineFixture(t) {
  const root = fixture(t);
  const plan = planApplicationSourceClosure({ repositoryRoot: root });
  const hash = (value) => `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
  const publicResources = APPLICATION_RETAINED_PUBLIC_FILES.map((name) => {
    const row = plan.source.files.find((entry) => entry.path === `ui/public/${name}`);
    return { path: name, bytes: row.bytes, sha256: row.sha256 };
  });
  const files = publicResources.map((row) => ({ ...row, mode: 0o600 })).sort((a, b) => a.path.localeCompare(b.path));
  const output = { files, inventory_sha256: hash(files), public_resources: publicResources,
    english_namespaces: namespaces, locales: [...APPLICATION_LOCALES] };
  // Synthetic report data tests the comparison contract only. Real npm/build
  // qualification is exercised by the frozen-source local and hosted gates.
  const baseline = { schema: 'marty.application-source-closure-rehearsal/v4', status: 'passed', plan: structuredClone(plan),
    build: { dependency_mode: 'fresh-npm-ci', effective_source_sha: plan.source.commit,
      package_lock_sha256: plan.source.files.find((row) => row.path === 'ui/package-lock.json').sha256 },
    dependency_install: { mode: 'fresh-npm-ci', status: 'passed', dependency_profile: 'full', independent_dependency_installation: true },
    qualification: Object.fromEntries(['application_build_completed', 'application_tests_completed', 'omitted_sources_absent',
      'application_output_checked', 'source_checkout_unchanged', 'public_assets_preserved', 'application_resource_smoke_completed',
      'locale_fallback_observed', 'sdk_wasm_initialized_in_node', 'sdk_wasm_output_bound', 'independent_dependency_installation'].map((key) => [key, true])),
    output: structuredClone(output), resources: { result: { public_resources: structuredClone(publicResources) } } };
  plan.schema = 'marty.application-source-closure-plan/v5';
  return { plan, output, baseline, hash };
}

test('a matching full fresh baseline binds every output and public resource record', (t) => {
  const input = baselineFixture(t);
  const comparison = compareApplicationProfileBaseline(input);
  assert.equal(comparison.full_profile_fresh_install_passed, true);
  assert.equal(comparison.same_source_inputs, true);
  assert.equal(comparison.output_files_identical, true);
  assert.equal(comparison.public_resources_identical, true);
  assert.equal(comparison.output_inventory_sha256, input.output.inventory_sha256);
});

for (const [label, mutate] of [
  ['failed baseline', ({ baseline }) => { baseline.status = 'failed'; }],
  ['profile baseline', ({ baseline }) => { baseline.plan.dependency_profile = { name: 'application' }; }],
  ['reused install', ({ baseline }) => { baseline.build.dependency_mode = 'reused-installed-node_modules'; }],
  ['incomplete SDK proof', ({ baseline }) => { baseline.qualification.sdk_wasm_output_bound = false; }],
  ['source commit', ({ baseline }) => { baseline.plan.source.commit = '0'.repeat(40); }],
  ['source dirty status', ({ baseline }) => { baseline.plan.source.working_tree_dirty = true; }],
  ['source inventory digest', ({ baseline }) => { baseline.plan.source.input_inventory_sha256 = `sha256:${'0'.repeat(64)}`; }],
  ['route contract', ({ baseline }) => { baseline.plan.route_contract.version += 1; }],
  ['test contract', ({ baseline }) => { baseline.plan.test_profile.files.pop(); }],
  ['omission boundary', ({ baseline }) => { baseline.plan.boundary.omitted.pop(); }],
  ['source marker', ({ baseline }) => { baseline.build.effective_source_sha = 'development'; }],
  ['full lock binding', ({ baseline }) => { baseline.build.package_lock_sha256 = `sha256:${'0'.repeat(64)}`; }],
  ['output digest', ({ baseline }) => { baseline.output.inventory_sha256 = `sha256:${'0'.repeat(64)}`; }],
  ['self-consistent changed output', ({ baseline, hash }) => { baseline.output.files[0].bytes += 1; baseline.output.inventory_sha256 = hash(baseline.output.files); }],
  ['changed resource probe', ({ baseline }) => { baseline.resources.result.public_resources.pop(); }],
  ['changed profile inventory', ({ output }) => { output.files[0].mode = 0o777; }],
]) {
  test(`the profile cannot reuse a baseline with a ${label}`, (t) => {
    const input = baselineFixture(t);
    mutate(input);
    assert.throws(() => compareApplicationProfileBaseline(input));
  });
}

test('runtime context planning inventories both root startup scripts only when requested', (t) => {
  const root = fixture(t);
  const ordinary = planApplicationSourceClosure({ repositoryRoot: root });
  const packaged = planApplicationSourceClosure({ repositoryRoot: root, runtimeContext: true });
  for (const name of runtimeInputs.filter((name) => name.startsWith('scripts/'))) {
    assert.equal(ordinary.source.files.some((entry) => entry.path === name), false);
    assert.equal(packaged.source.files.some((entry) => entry.path === name), true);
    assert.ok(packaged.boundary.retained.includes(name));
  }
});

test('a runtime context is prepared only after successful source and output preservation', (t) => {
  const root = fixture(t, { runtimeContext: true });
  const parent = mkdtempSync(path.join(os.tmpdir(), 'marty-runtime-harness-'));
  t.after(() => rmSync(parent, { recursive: true, force: true }));
  const destination = path.join(parent, 'context');
  const report = rehearseApplicationSourceClosure({ repositoryRoot: root, runtimeContextDirectory: destination });
  assert.equal(report.status, 'passed', report.error);
  assert.equal(report.qualification.runtime_context_prepared, true);
  assert.equal(report.qualification.container_runtime_tested, false);
  assert.equal(report.qualification.package_graph_minimized, false);
  assert.equal(report.qualification.independent_dependency_installation, false);
  assert.ok(existsSync(path.join(destination, 'application-runtime-context.json')));
  assert.equal(existsSync(path.dirname(report.export_directory)), false);
});

test('source mutation during runtime preparation removes its context and revokes the preservation claim', (t) => {
  const root = fixture(t, { runtimeContext: true });
  const parent = mkdtempSync(path.join(os.tmpdir(), 'marty-runtime-source-mutation-'));
  t.after(() => rmSync(parent, { recursive: true, force: true }));
  const destination = path.join(parent, 'context');
  const actualMkdir = fs.mkdirSync;
  let mutated = false;
  let report;
  try {
    fs.mkdirSync = (filename, options) => {
      const result = actualMkdir(filename, options);
      if (filename === destination) {
        writeFileSync(path.join(root, RETAINED_SHARED_INPUTS[0]), '// source changed during packaging');
        mutated = true;
      }
      return result;
    };
    syncBuiltinESMExports();
    report = rehearseApplicationSourceClosure({ repositoryRoot: root, runtimeContextDirectory: destination });
  } finally {
    fs.mkdirSync = actualMkdir;
    syncBuiltinESMExports();
  }
  assert.equal(mutated, true, 'The mutation must happen inside the real context preparation');
  assert.equal(report.status, 'failed');
  assert.equal(report.qualification.source_checkout_unchanged, false);
  assert.equal(report.qualification.runtime_context_prepared, false);
  assert.equal(report.runtime_context, undefined);
  assert.equal(existsSync(destination), false);
  assert.equal(existsSync(path.dirname(report.export_directory)), false);
});

test('a source mutation followed by a throwing context writer cannot retain the earlier preservation claim', (t) => {
  const root = fixture(t, { runtimeContext: true });
  const parent = mkdtempSync(path.join(os.tmpdir(), 'marty-runtime-source-failure-'));
  t.after(() => rmSync(parent, { recursive: true, force: true }));
  const destination = path.join(parent, 'context');
  const actualWrite = fs.writeFileSync;
  let mutated = false;
  let report;
  try {
    fs.writeFileSync = (filename, content, options) => {
      const result = actualWrite(filename, content, options);
      if (typeof filename === 'string' && filename.startsWith(`${destination}/`)) {
        actualWrite(path.join(root, RETAINED_SHARED_INPUTS[0]), '// source changed before preparation failure');
        mutated = true;
        throw new Error('Synthetic context write failure');
      }
      return result;
    };
    syncBuiltinESMExports();
    report = rehearseApplicationSourceClosure({ repositoryRoot: root, runtimeContextDirectory: destination });
  } finally {
    fs.writeFileSync = actualWrite;
    syncBuiltinESMExports();
  }
  assert.equal(mutated, true);
  assert.equal(report.status, 'failed');
  assert.equal(report.qualification.source_checkout_unchanged, false);
  assert.equal(report.qualification.runtime_context_prepared, false);
  assert.equal(report.runtime_context, undefined);
  assert.equal(existsSync(destination), false);
  assert.equal(existsSync(path.dirname(report.export_directory)), false);
});

test('dirty source changes receive their own hashes and cannot be presented as a clean committed build', (t) => {
  const root = fixture(t);
  const before = planApplicationSourceClosure({ repositoryRoot: root });
  put(root, 'ui/src/application/routing/loginEntry.js', '// changed application source\n');
  put(root, 'ui/src/newApplicationModule.js', '// uncommitted application source\n');
  const after = planApplicationSourceClosure({ repositoryRoot: root });
  assert.equal(after.source.commit, before.source.commit);
  assert.equal(after.source.working_tree_dirty, true);
  assert.notEqual(after.source.input_inventory_sha256, before.source.input_inventory_sha256);
  assert.ok(after.boundary.retained.includes('ui/src/newApplicationModule.js'));
});

test('real child processes build and test only the disposable export while preserving original source', (t) => {
  const root = fixture(t);
  const before = planApplicationSourceClosure({ repositoryRoot: root });
  const report = rehearseApplicationSourceClosure({ repositoryRoot: root, keepExport: true });
  t.after(() => rmSync(path.dirname(report.export_directory), { recursive: true, force: true }));
  assert.equal(report.status, 'passed', report.error);
  assert.equal(report.qualification.application_build_completed, true);
  assert.equal(report.qualification.application_tests_completed, true);
  assert.equal(report.qualification.application_resource_smoke_completed, true);
  assert.equal(report.qualification.public_assets_preserved, true);
  assert.equal(report.qualification.locale_fallback_observed, true);
  assert.equal(report.qualification.browser_startup_observed, false);
  assert.equal(report.resources.result.public_resources.length, 54);
  assert.deepEqual(report.output.locales, [...APPLICATION_LOCALES]);
  assert.deepEqual(report.tests.result.completed_files, [...APPLICATION_TEST_FILES].sort());
  assert.equal(report.tests.result.test_count, APPLICATION_TEST_FILES.length);
  assert.match(report.tests.result.report_sha256, /^sha256:[0-9a-f]{64}$/);
  assert.equal(report.qualification.source_checkout_unchanged, true);
  assert.equal(report.build.dependency_mode, 'reused-installed-node_modules');
  assert.equal(report.build.effective_source_sha, before.source.commit);
  const marker = JSON.parse(readFileSync(path.join(report.export_directory, 'ui/dist-application/marty-web-routes.json'), 'utf8'));
  assert.equal(marker.source_sha, before.source.commit);
  assert.equal(report.qualification.independent_dependency_installation, false);
  for (const key of ['source_extraction_complete', 'oidc_journey_tested', 'host_deployment_tested', 'signed_release_produced']) {
    assert.equal(report.qualification[key], false, key);
  }
  for (const entry of report.plan.boundary.omitted) {
    assert.equal(existsSync(path.join(report.export_directory, entry)), false, entry);
    assert.equal(existsSync(path.join(root, entry)), true, entry);
  }
  for (const entry of RETAINED_SHARED_INPUTS) {
    assert.deepEqual(readFileSync(path.join(report.export_directory, entry)), readFileSync(path.join(root, entry)));
  }
  assert.deepEqual(planApplicationSourceClosure({ repositoryRoot: root }), before);
  assert.equal(existsSync(path.join(root, 'ui/dist-application')), false);
  assert.deepEqual(report.output.english_namespaces, namespaces);
});

test('a dirty rehearsal emits a development marker while retaining the base commit and exact input inventory', (t) => {
  const root = fixture(t);
  const committed = git(root, 'rev-parse', 'HEAD');
  put(root, 'ui/src/application/routing/loginEntry.js', '// changed development input\n');
  const report = rehearseApplicationSourceClosure({ repositoryRoot: root, keepExport: true });
  t.after(() => rmSync(path.dirname(report.export_directory), { recursive: true, force: true }));
  assert.equal(report.status, 'passed', report.error);
  assert.equal(report.plan.source.commit, committed);
  assert.equal(report.plan.source.working_tree_dirty, true);
  assert.equal(report.build.effective_source_sha, 'development');
  const marker = JSON.parse(readFileSync(path.join(report.export_directory, 'ui/dist-application/marty-web-routes.json'), 'utf8'));
  assert.equal(marker.source_sha, 'development');
  assert.equal(report.qualification.source_checkout_unchanged, true);
  assert.equal(report.qualification.signed_release_produced, false);
});

for (const kind of ['file', 'directory', 'symlink']) {
  test(`the build cannot restore an omitted input as a ${kind} and still pass the absence check`, (t) => {
    const root = fixture(t, { recreateOmitted: kind });
    const report = rehearseApplicationSourceClosure({ repositoryRoot: root });
    assert.equal(report.status, 'failed');
    assert.equal(report.qualification.application_build_completed, true);
    assert.equal(report.qualification.omitted_sources_absent, false);
    assert.match(report.error, /contains an omitted input/);
    assert.equal(report.qualification.source_checkout_unchanged, true);
    assert.equal(existsSync(path.dirname(report.export_directory)), false);
  });
}

test('build failure removes the disposable tree while preserving all original source inputs', (t) => {
  const root = fixture(t, { failure: true });
  const report = rehearseApplicationSourceClosure({ repositoryRoot: root });
  assert.equal(report.status, 'failed');
  assert.match(report.error, /exit code 23/);
  assert.equal(report.qualification.application_build_completed, false);
  assert.equal(report.qualification.application_tests_completed, false);
  assert.equal(report.qualification.source_checkout_unchanged, true);
  assert.equal(existsSync(path.dirname(report.export_directory)), false);
  for (const entry of ownership.modules) assert.equal(existsSync(path.join(root, entry)), true);
});

test('test failure removes the disposable tree instead of presenting the successful build as a completed rehearsal', (t) => {
  const root = fixture(t, { testFailure: true });
  const report = rehearseApplicationSourceClosure({ repositoryRoot: root });
  assert.equal(report.status, 'failed');
  assert.match(report.error, /Application tests failed with exit code 17/);
  assert.equal(report.qualification.application_build_completed, true);
  assert.equal(report.qualification.application_tests_completed, false);
  assert.equal(report.qualification.source_checkout_unchanged, true);
  assert.equal(existsSync(path.dirname(report.export_directory)), false);
});

for (const testReportFault of ['missing-report', 'missing-file', 'wrong-file', 'duplicate-file', 'skipped-test', 'incorrect-count']) {
  test(`successful test exit cannot conceal a ${testReportFault}`, (t) => {
    const root = fixture(t, { testReportFault });
    const report = rehearseApplicationSourceClosure({ repositoryRoot: root });
    assert.equal(report.status, 'failed');
    assert.equal(report.qualification.application_build_completed, true);
    assert.equal(report.qualification.application_tests_completed, false);
    assert.equal(report.qualification.source_checkout_unchanged, true);
    assert.equal(existsSync(path.dirname(report.export_directory)), false);
  });
}

for (const entry of ['locales/fr/common.json', 'favicon.ico', 'startup.js']) {
  for (const failure of ['removePublic', 'tamperPublic']) {
    test(`${failure} refuses a changed retained locale, icon or script: ${entry}`, (t) => {
      const root = fixture(t, { [failure]: entry });
      const report = rehearseApplicationSourceClosure({ repositoryRoot: root });
      assert.equal(report.status, 'failed');
      assert.match(report.error, /Retained application public resource/);
      assert.equal(report.qualification.public_assets_preserved, false);
      assert.equal(report.qualification.application_resource_smoke_completed, false);
      assert.equal(report.qualification.source_checkout_unchanged, true);
    });
  }
}

test('resource process failure leaves a successful build/test stage unqualified and cleans the export', (t) => {
  const root = fixture(t, { resourceFailure: true });
  const report = rehearseApplicationSourceClosure({ repositoryRoot: root });
  assert.equal(report.status, 'failed');
  assert.match(report.error, /Application resource smoke failed with exit code 19/);
  assert.equal(report.qualification.application_build_completed, true);
  assert.equal(report.qualification.application_tests_completed, true);
  assert.equal(report.qualification.application_resource_smoke_completed, false);
  assert.equal(report.qualification.source_checkout_unchanged, true);
  assert.equal(existsSync(path.dirname(report.export_directory)), false);
});

for (const resourceFault of ['missing-report', 'missing-resource', 'tampered-resource', 'html-as-script', 'no-fallback',
  'missing-locale-request', 'open-preview', 'broadened-qualification', 'changed-output', 'changed-emitted-output']) {
  test(`successful resource exit cannot conceal ${resourceFault}`, (t) => {
    const root = fixture(t, { resourceFault });
    const report = rehearseApplicationSourceClosure({ repositoryRoot: root });
    assert.equal(report.status, 'failed');
    if (resourceFault === 'changed-emitted-output') assert.match(report.error, /Resource probe changed the built output inventory/);
    assert.equal(report.qualification.application_resource_smoke_completed, false);
    assert.equal(report.qualification.source_checkout_unchanged, true);
    assert.equal(existsSync(path.dirname(report.export_directory)), false);
  });
}

test('the resource probe cannot restore an omitted asset after build and tests', (t) => {
  const root = fixture(t, { recreateAfterResources: true });
  const report = rehearseApplicationSourceClosure({ repositoryRoot: root });
  assert.equal(report.status, 'failed');
  assert.equal(report.qualification.omitted_sources_absent, false);
  assert.match(report.error, /contains an omitted input/);
  assert.equal(report.qualification.source_checkout_unchanged, true);
});

test('passing tests cannot restore an omitted combined input after the build', (t) => {
  const root = fixture(t, { recreateAfterTests: true });
  const report = rehearseApplicationSourceClosure({ repositoryRoot: root });
  assert.equal(report.status, 'failed');
  assert.equal(report.qualification.application_tests_completed, true);
  assert.equal(report.qualification.omitted_sources_absent, false);
  assert.match(report.error, /contains an omitted input/);
  assert.equal(report.qualification.source_checkout_unchanged, true);
});

test('successful build exit cannot conceal retained marketing output', (t) => {
  const root = fixture(t, { marketing: true });
  const report = rehearseApplicationSourceClosure({ repositoryRoot: root });
  assert.equal(report.status, 'failed');
  assert.equal(report.qualification.application_build_completed, true);
  assert.equal(report.qualification.application_output_checked, false);
  assert.match(report.error, /Marketing output/);
  assert.equal(existsSync(path.dirname(report.export_directory)), false);
});

test('an output directory symlink cannot redirect output verification outside the build', (t) => {
  const root = fixture(t, { outputSymlink: true });
  const report = rehearseApplicationSourceClosure({ repositoryRoot: root });
  assert.equal(report.status, 'failed');
  assert.match(report.error, /ordinary directory/);
  assert.equal(report.qualification.source_checkout_unchanged, true);
});

test('unexpected original-source mutation fails the rehearsal even when output is valid', (t) => {
  const root = fixture(t);
  const target = path.join(root, RETAINED_SHARED_INPUTS[0]);
  put(root, 'ui/scripts/build-web-surface.mjs', builder({ mutateSource: target }));
  const report = rehearseApplicationSourceClosure({ repositoryRoot: root });
  assert.equal(report.status, 'failed');
  assert.equal(report.qualification.source_checkout_unchanged, false);
  assert.match(report.error, /Source preservation failed/);
  assert.equal(existsSync(path.dirname(report.export_directory)), false);
});

test('shared application files cannot be added to the omission roster', (t) => {
  const root = fixture(t);
  put(root, 'contracts/website-source-ownership.json', JSON.stringify({ ...ownership,
    modules: [...ownership.modules, 'ui/src/contexts/AuthContext.jsx'] }));
  assert.throws(() => planApplicationSourceClosure({ repositoryRoot: root }), /Shared input cannot be omitted/);
});

test('traversal entries and symlinked source files are rejected before exporting', (t) => {
  const root = fixture(t);
  put(root, 'contracts/website-source-ownership.json', JSON.stringify({ ...ownership,
    modules: [...ownership.modules, 'ui/src/../../private.js'] }));
  assert.throws(() => planApplicationSourceClosure({ repositoryRoot: root }), /Invalid website module path/);
  put(root, 'contracts/website-source-ownership.json', JSON.stringify(ownership));
  const target = path.join(root, RETAINED_SHARED_INPUTS[0]);
  rmSync(target);
  symlinkSync(path.join(root, 'ui/package.json'), target);
  assert.throws(() => planApplicationSourceClosure({ repositoryRoot: root }), /not a regular file/);
});

test('parent-directory symlinks cannot import files outside the selected source tree', (t) => {
  const root = fixture(t);
  const parent = path.join(root, 'ui/src/contexts');
  const external = mkdtempSync(path.join(os.tmpdir(), 'marty-external-source-fixture-'));
  t.after(() => rmSync(external, { recursive: true, force: true }));
  put(external, 'AuthContext.jsx', '// outside source');
  put(external, 'BrandingContext.jsx', '// outside source');
  rmSync(parent, { recursive: true });
  symlinkSync(external, parent, 'dir');
  assert.throws(() => planApplicationSourceClosure({ repositoryRoot: root }), /ordinary directory|regular file/);
});

test('a missing fixed demo input fails instead of silently shrinking the audited omission set', (t) => {
  const root = fixture(t);
  rmSync(path.join(root, OMITTED_DEMO_INPUTS[0]));
  assert.throws(() => planApplicationSourceClosure({ repositoryRoot: root }), /ENOENT/);
});

for (const entry of [`ui/${APPLICATION_TEST_FILES[0]}`, 'contracts/organization-domain-behavior.json',
  'ui/public/locales/nl/vendor.json', APPLICATION_ASSET_OMISSIONS[0]]) {
  test(`a missing required test input refuses a narrower test claim: ${entry}`, (t) => {
    const root = fixture(t);
    rmSync(path.join(root, entry));
    assert.throws(() => planApplicationSourceClosure({ repositoryRoot: root }), /ENOENT/);
  });
}

test('the CLI writes a reviewable report outside the source tree without exporting inherited production settings', (t) => {
  const root = fixture(t);
  const reports = mkdtempSync(path.join(os.tmpdir(), 'marty-source-reports-'));
  t.after(() => rmSync(reports, { recursive: true, force: true }));
  const reportPath = path.join(reports, 'rehearsal.json');
  const result = spawnSync(process.execPath, [harness, '--repository-root', root, '--report', reportPath], {
    encoding: 'utf8', env: { ...process.env, MARTY_COMMERCE_SOURCE_SHA: 'private-source', VITE_API_URL: 'https://production.invalid' },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, '');
  const report = JSON.parse(readFileSync(reportPath, 'utf8'));
  assert.equal(report.status, 'passed');
  assert.equal(report.qualification.signed_release_produced, false);
  assert.equal(existsSync(path.dirname(report.export_directory)), false);
  assert.equal(git(root, 'status', '--porcelain'), '');
});

test('the CLI refuses to write a report through an outside symlink into the source checkout', (t) => {
  const root = fixture(t);
  const reports = mkdtempSync(path.join(os.tmpdir(), 'marty-report-link-fixture-'));
  t.after(() => rmSync(reports, { recursive: true, force: true }));
  symlinkSync(root, path.join(reports, 'linked-source'), 'dir');
  const result = spawnSync(process.execPath, [harness, '--repository-root', root,
    '--report', path.join(reports, 'linked-source/unwanted.json')], { encoding: 'utf8' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /outside the source checkout/);
  assert.equal(existsSync(path.join(root, 'unwanted.json')), false);
});
