import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  ADDITIONAL_OMISSIONS, OMITTED_DEMO_INPUTS, OMITTED_COMBINED_ADAPTERS,
  OMITTED_DEMO_MODULES, OMITTED_COMBINED_TEST_INPUTS, RETAINED_SHARED_INPUTS, planApplicationSourceClosure,
  rehearseApplicationSourceClosure,
} from './application-source-closure.mjs';
import { APPLICATION_TEST_CONFIG, APPLICATION_TEST_FILES } from './application-test-profile.mjs';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const harness = fileURLToPath(new URL('./application-source-closure.mjs', import.meta.url));
const ownership = JSON.parse(readFileSync(path.join(repositoryRoot, 'contracts/website-source-ownership.json'), 'utf8'));
const routeBytes = readFileSync(path.join(repositoryRoot, 'contracts/web-surface-routes.json'));
const organizationContract = readFileSync(path.join(repositoryRoot, 'contracts/organization-domain-behavior.json'));
const namespaces = ['common', 'console', 'onboarding', 'forms', 'errors', 'applicant', 'vendor'];

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

function builder({ failure = false, marketing = false, mutateSource, outputSymlink = false, recreateOmitted } = {}) {
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

function fixture(t, buildOptions = {}) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'marty-application-source-fixture-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  put(root, '.gitignore', 'ui/node_modules/\nui/dist*/\n');
  put(root, 'contracts/website-source-ownership.json', JSON.stringify(ownership));
  put(root, 'contracts/web-surface-routes.json', routeBytes);
  put(root, 'contracts/organization-domain-behavior.json', organizationContract);
  for (const entry of [...ownership.modules, ...RETAINED_SHARED_INPUTS]) put(root, entry, '// retained fixture source\n');
  for (const entry of ADDITIONAL_OMISSIONS) put(root, entry, '{}\n');
  for (const entry of APPLICATION_TEST_FILES) put(root, `ui/${entry}`, '// selected test fixture\n');
  put(root, 'ui/package.json', JSON.stringify({ type: 'module' }));
  put(root, 'ui/package-lock.json', '{}\n');
  put(root, 'ui/vite.config.ts', '// fixture config; the real Vite build is a separate rehearsal\n');
  for (const entry of ['ui/vitest.config.ts', `ui/${APPLICATION_TEST_CONFIG}`,
    'ui/scripts/application-test-profile.mjs', 'ui/src/test/i18nApplicationTestSetup.js', 'ui/src/test/setup.ts']) {
    put(root, entry, '// required application test input\n');
  }
  put(root, 'ui/index.html', '<html>Fixture entry</html>');
  put(root, 'ui/console/index.html', '<html>Fixture console entry</html>');
  put(root, 'ui/scripts/build-web-surface.mjs', builder(buildOptions));
  put(root, 'ui/node_modules/.bin/tsc', 'fixture');
  put(root, 'ui/node_modules/.bin/vite', 'fixture');
  put(root, 'ui/node_modules/vitest/vitest.mjs', tester(buildOptions));
  git(root, 'init', '--initial-branch=main');
  git(root, 'add', '.');
  git(root, 'commit', '-m', 'Synthetic source-closure fixture');
  return root;
}

test('the plan separates the original website roster from the 45-input application build/test boundary', (t) => {
  const root = fixture(t);
  const plan = planApplicationSourceClosure({ repositoryRoot: root });
  assert.equal(ownership.modules.length, 34);
  assert.deepEqual(plan.boundary.website_roster, [...ownership.modules].sort());
  assert.deepEqual(plan.boundary.additional_omissions, [...ADDITIONAL_OMISSIONS]);
  assert.deepEqual(plan.boundary.application_only_omissions, {
    combined_entry_adapters: [...OMITTED_COMBINED_ADAPTERS],
    demo_modules: [...OMITTED_DEMO_MODULES],
    combined_test_setup_and_locale: [...OMITTED_COMBINED_TEST_INPUTS],
  });
  assert.equal(plan.boundary.omitted.length, 45);
  assert.equal(plan.boundary.ownership_audit_complete, false);
  assert.equal(plan.source.working_tree_dirty, false);
  assert.match(plan.source.input_inventory_sha256, /^sha256:[0-9a-f]{64}$/);
  for (const retained of RETAINED_SHARED_INPUTS) assert.ok(plan.boundary.retained.includes(retained), retained);
  assert.deepEqual(plan.test_profile.files, [...APPLICATION_TEST_FILES]);
  assert.deepEqual(plan.test_profile.shared_contracts, ['contracts/organization-domain-behavior.json']);
  assert.equal(plan.test_profile.files.length, 23);
  assert.ok(plan.boundary.retained.includes('contracts/organization-domain-behavior.json'));
  assert.ok(plan.boundary.retained.includes('ui/package-lock.json'));
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

for (const entry of [`ui/${APPLICATION_TEST_FILES[0]}`, 'contracts/organization-domain-behavior.json']) {
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
