import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  closeSync, constants, existsSync, fstatSync, ftruncateSync, lstatSync, mkdirSync, mkdtempSync,
  openSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { canonicalJson } from './web-surface-contract.mjs';
import { validateWebsiteSourceOwnershipSchema } from './website-source-ownership.mjs';
import { validateWebSurfaceContract } from '../src/application/routing/webSurfaceContract.mjs';
import { APPLICATION_TEST_CONFIG, APPLICATION_TEST_FILES, APPLICATION_LEGACY_TEST_FILES } from './application-test-profile.mjs';
import { APPLICATION_INSTALL_INPUTS, installApplicationDependencies } from './application-dependency-install.mjs';
import {
  applicationDependencyProfileInputs, applicationPackageManager, APPLICATION_BUN_PACKAGE_MANAGER, validateApplicationDependencyProfile,
} from './application-dependency-profile.mjs';
import { createApplicationRuntimeContext } from './application-runtime-context.mjs';
import {
  APPLICATION_ASSET_OMISSIONS, APPLICATION_RETAINED_PUBLIC_FILES,
  APPLICATION_LOCALES, APPLICATION_LOCALE_NAMESPACES, APPLICATION_RESOURCE_MIME_TYPES,
} from './application-public-assets.mjs';

const DEFAULT_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const TEST_CONTRACTS = ['contracts/organization-domain-behavior.json'];
const CONTRACTS = ['contracts/website-source-ownership.json', 'contracts/web-surface-routes.json', ...TEST_CONTRACTS];
const RUNTIME_ROOT_INPUTS = ['scripts/ui-production-start.sh', 'scripts/load-secrets-env.sh'];
const RUNTIME_INPUTS = ['ui/nginx.prod.conf', 'ui/scripts/application-runtime.Dockerfile', ...RUNTIME_ROOT_INPUTS];

// These retired application build/test inputs remain forbidden even after
// physical removal. The original website ownership roster stays separate.
export const OMITTED_DEMO_INPUTS = Object.freeze([
  'ui/public/demos/manifests/2026.07.0.json',
  'ui/public/demos/manifests/2026.08.0.json',
  'ui/public/demos/manifests/index.json',
]);
export const OMITTED_COMBINED_ADAPTERS = Object.freeze([
  'ui/src/components/LandingPage.jsx',
  'ui/src/variants/publicSite.public.jsx',
]);
export const OMITTED_DEMO_MODULES = Object.freeze([
  'ui/src/generated/demoManifests.generated.js',
  'ui/src/generated/demoWalletSchema.generated.json',
  'ui/src/services/demoManifestService.js',
  'ui/src/services/platformDemoScenarios.js',
]);
export const OMITTED_COMBINED_TEST_INPUTS = Object.freeze([
  'ui/src/test/i18nTestSetup.js',
  'ui/public/locales/en/marketing.json',
]);
export const OMITTED_WEBSITE_BUILD_INPUTS = Object.freeze(['ui/scripts/website-build-tools.mjs']);
export const ADDITIONAL_OMISSIONS = Object.freeze([
  ...OMITTED_DEMO_INPUTS, ...OMITTED_COMBINED_ADAPTERS, ...OMITTED_DEMO_MODULES, ...OMITTED_COMBINED_TEST_INPUTS,
  ...APPLICATION_ASSET_OMISSIONS, ...OMITTED_WEBSITE_BUILD_INPUTS,
]);
export const RETAINED_SHARED_INPUTS = Object.freeze([
  'ui/src/application/routing/appHandoff.js',
  'ui/src/application/routing/authCallback.js',
  'ui/src/application/routing/loginEntry.js',
  'ui/src/application/routing/publicEntry.js',
  'ui/src/application/routing/webSurfaceContract.mjs',
  'ui/src/application/session/authSession.js',
  'ui/src/application/session/consoleSession.js',
  'ui/src/apps/shared/WebSurfaceBoundary.jsx',
  'ui/src/components/navigation/ConsoleHeaderBar.jsx',
  'ui/src/components/navigation/SidebarNavigation.jsx',
  'ui/src/contexts/AuthContext.jsx',
  'ui/src/contexts/BrandingContext.jsx',
  'ui/src/extensions/commerce/publicStub.jsx',
  'ui/src/variants/publicConfig.application.js',
  'ui/src/variants/publicConfig.public.js',
  'ui/src/variants/publicSite.application.jsx',
]);
const REQUIRED_INPUTS = [
  'ui/package.json', 'ui/package-lock.json', 'ui/index.html', 'ui/console/index.html',
  'ui/scripts/build-web-surface.mjs', 'ui/vite.config.ts', 'ui/vitest.config.ts',
  `ui/${APPLICATION_TEST_CONFIG}`, 'ui/scripts/application-test-profile.mjs',
  'ui/scripts/application-public-assets.mjs', 'ui/scripts/application-resource-smoke.mjs',
  'ui/src/test/i18nApplicationTestSetup.js', 'ui/src/test/setup.ts',
  ...APPLICATION_RETAINED_PUBLIC_FILES.map((entry) => `ui/public/${entry}`),
  ...RETAINED_SHARED_INPUTS,
];
const APPLICATION_NAMESPACES = ['common', 'console', 'onboarding', 'forms', 'errors', 'applicant', 'vendor'];
const EXCLUDED_OUTPUTS = ['blog', 'authors', 'demos', 'images/authors', 'images/demos', 'images/social',
  'llms.txt', 'robots.txt', 'sitemap.xml', 'sitemap-index.xml'];

function require(condition, message) {
  if (!condition) throw new Error(message);
}

function digest(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function git(root, args) {
  const result = spawnSync('git', ['-C', root, ...args], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  if (result.error) throw result.error;
  require(result.status === 0, 'Unable to inspect the source checkout');
  return result.stdout;
}

function relativeInput(value) {
  require(typeof value === 'string' && value && !path.isAbsolute(value) && !/[\\\x00-\x1f\x7f]/.test(value)
    && value.split('/').every((part) => part && part !== '.' && part !== '..'), 'Unsafe source input path');
  return value;
}

function readInput(root, relative) {
  const parts = relativeInput(relative).split('/');
  let parent = root;
  for (const part of parts.slice(0, -1)) {
    parent = path.join(parent, part);
    const metadata = lstatSync(parent);
    require(metadata.isDirectory() && !metadata.isSymbolicLink(), `Source parent is not an ordinary directory: ${relative}`);
  }
  const filename = path.join(root, ...parts);
  const metadata = lstatSync(filename);
  require(metadata.isFile() && !metadata.isSymbolicLink(), `Source input is not a regular file: ${relative}`);
  const descriptor = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const opened = fstatSync(descriptor);
    require(opened.isFile(), `Source input changed type: ${relative}`);
    const bytes = readFileSync(descriptor);
    return { bytes, record: { path: relative, bytes: bytes.length, sha256: digest(bytes), mode: opened.mode & 0o777 } };
  } finally {
    closeSync(descriptor);
  }
}

function sourcePaths(root, extraInputs = []) {
  const listed = git(root, ['ls-files', '--cached', '--others', '--exclude-standard', '-z', '--', 'ui', ...CONTRACTS, ...extraInputs])
    .split('\0').filter(Boolean);
  const paths = [...new Set(listed)].filter((entry) => !/^ui\/(?:node_modules|dist(?:-[^/]+)?)(?:\/|$)/.test(entry));
  for (const entry of paths) {
    relativeInput(entry);
    require(entry.startsWith('ui/') || CONTRACTS.includes(entry) || extraInputs.includes(entry), 'Source export is outside the reviewed UI boundary');
  }
  return paths.sort();
}

function sourceStatus(root) {
  return git(root, ['status', '--porcelain=v1', '-z', '--untracked-files=all']).split('\0').filter(Boolean);
}

function identity(records) {
  return digest(canonicalJson(records));
}

export function planApplicationSourceClosure({ repositoryRoot = DEFAULT_ROOT, freshInstall = false, runtimeContext = false,
  dependencyProfile = 'full', packageManager } = {}) {
  require(['full', 'application'].includes(dependencyProfile), 'Unsupported dependency profile');
  require(dependencyProfile === 'full' || freshInstall, 'The application dependency profile requires a fresh install');
  const root = realpathSync(repositoryRoot);
  const sourceManifest = JSON.parse(readInput(root, 'ui/package.json').bytes.toString('utf8'));
  packageManager = applicationPackageManager(sourceManifest, packageManager);
  const selectedTests = sourceManifest.packageManager ? APPLICATION_TEST_FILES : APPLICATION_LEGACY_TEST_FILES;
  require(realpathSync(git(root, ['rev-parse', '--show-toplevel']).trim()) === root, 'Select the actual repository root');
  const sourceSha = git(root, ['rev-parse', 'HEAD']).trim();
  require(/^[0-9a-f]{40}$/.test(sourceSha), 'Source checkout requires an exact commit');
  const ownership = validateWebsiteSourceOwnershipSchema(JSON.parse(readInput(root, CONTRACTS[0]).bytes.toString('utf8')));
  const routes = validateWebSurfaceContract(JSON.parse(readInput(root, CONTRACTS[1]).bytes.toString('utf8')));
  const extraInputs = runtimeContext ? RUNTIME_ROOT_INPUTS : [];
  const paths = sourcePaths(root, extraInputs);
  const omitted = new Set([...ownership.modules, ...ADDITIONAL_OMISSIONS]);
  const modeInputs = [...(runtimeContext ? RUNTIME_INPUTS : []),
    ...(freshInstall ? APPLICATION_INSTALL_INPUTS.map((entry) => `ui/${entry}`) : []),
    ...(dependencyProfile === 'application' ? applicationDependencyProfileInputs(packageManager) : [])];
  for (const entry of [...CONTRACTS, ...REQUIRED_INPUTS, ...selectedTests.map((entry) => `ui/${entry}`), ...modeInputs]) {
    require(paths.includes(entry), `Required reviewed source input is missing: ${entry}`);
  }
  for (const entry of RETAINED_SHARED_INPUTS) require(!omitted.has(entry), `Shared input cannot be omitted: ${entry}`);
  requireOmittedInputsAbsent({ boundary: { omitted: [...omitted] } }, root);
  for (const entry of omitted) require(!paths.includes(entry), `Retired input remains tracked in the source checkout: ${entry}`);
  const files = paths.map((entry) => readInput(root, entry).record);
  const status = sourceStatus(root);
  return {
    schema: `marty.application-source-closure-plan/${packageManager === 'bun'
      ? (dependencyProfile === 'application' ? 'v7' : 'v6') : (dependencyProfile === 'application' ? 'v5' : 'v4')}`,
    ...(packageManager === 'bun' ? { package_manager: { ...APPLICATION_BUN_PACKAGE_MANAGER } } : {}),
    repository_root: root,
    source: { commit: sourceSha, working_tree_dirty: status.length > 0, git_status: status,
      input_inventory_sha256: identity(files), files, extra_inputs: [...extraInputs] },
    route_contract: { version: routes.schema_version, sha256: digest(canonicalJson(routes)) },
    test_profile: { config: APPLICATION_TEST_CONFIG, files: [...selectedTests], shared_contracts: [...TEST_CONTRACTS] },
    ...(dependencyProfile === 'application' ? { dependency_profile: validateApplicationDependencyProfile({ repositoryRoot: root, packageManager }) } : {}),
    boundary: {
      website_roster: ownership.modules.slice().sort(),
      additional_omissions: [...ADDITIONAL_OMISSIONS],
      application_only_omissions: {
        combined_entry_adapters: [...OMITTED_COMBINED_ADAPTERS],
        demo_modules: [...OMITTED_DEMO_MODULES],
        combined_test_setup_and_locale: [...OMITTED_COMBINED_TEST_INPUTS],
        public_assets: [...APPLICATION_ASSET_OMISSIONS],
        website_build_tools: [...OMITTED_WEBSITE_BUILD_INPUTS],
      },
      omitted: [...omitted].sort(),
      retained: paths.filter((entry) => !omitted.has(entry)),
      retained_shared_inputs: [...RETAINED_SHARED_INPUTS],
      retained_public_files: [...APPLICATION_RETAINED_PUBLIC_FILES],
      ownership_audit_complete: false,
      scope: 'Application build and selected routing/authentication tests with audited inputs absent; remaining source, asset, package and workflow ownership is not complete.',
    },
  };
}

function outside(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative.startsWith(`..${path.sep}`) || relative === '..' || path.isAbsolute(relative);
}

function requireOmittedInputsAbsent(plan, root) {
  for (const relative of plan.boundary.omitted) {
    let present = true;
    try { lstatSync(path.join(root, relative)); } catch (error) {
      if (error.code === 'ENOENT') present = false;
      else throw error;
    }
    require(!present, `Application export contains an omitted input: ${relative}`);
  }
}

function effectiveSourceSha(plan) {
  return plan.source.working_tree_dirty ? 'development' : plan.source.commit;
}

function exportSource(plan, destination) {
  require(outside(plan.repository_root, destination), 'Disposable export must be outside the original checkout');
  require(!existsSync(destination), 'Disposable export must be new');
  mkdirSync(destination, { recursive: true, mode: 0o700 });
  const inventory = new Map(plan.source.files.map((entry) => [entry.path, entry]));
  for (const relative of plan.boundary.retained) {
    const input = readInput(plan.repository_root, relative);
    assert.deepEqual(input.record, inventory.get(relative), `Source changed before export: ${relative}`);
    const target = path.join(destination, relative);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, input.bytes, { flag: 'wx', mode: 0o600 });
  }
  requireOmittedInputsAbsent(plan, destination);
}

export function materializeApplicationDependencyProfile(plan, exported) {
  require(plan.dependency_profile?.name === 'application', 'No reviewed application dependency profile was selected');
  const bun = plan.dependency_profile.bun_lock_selected === true;
  assert.deepEqual(plan.dependency_profile.package_manager, bun ? APPLICATION_BUN_PACKAGE_MANAGER : undefined);
  assert.deepEqual(plan.dependency_profile.substitutions.map((row) => row.path),
    ['ui/package.json', 'ui/package-lock.json', ...(bun ? ['ui/bun.lock'] : [])],
    'Application profile substitutions exceeded the reviewed package inputs');
  return plan.dependency_profile.substitutions.map(({ path: relative, baseline, selected }) => {
    const original = readInput(plan.repository_root, relative);
    const replacement = readInput(plan.repository_root, selected.path);
    assert.deepEqual(original.record, baseline, 'The baseline package input changed before materialization');
    assert.deepEqual(replacement.record, selected, 'The selected profile input changed before materialization');
    const copied = readInput(exported, relative);
    require(copied.bytes.equals(original.bytes), 'The exported baseline input changed before materialization');
    const descriptor = openSync(path.join(exported, relative), constants.O_WRONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      require(fstatSync(descriptor).isFile(), 'The exported package input changed type');
      // The export is disposable. Replace only the selected copied inputs; the
      // inventoried source checkout and committed profile bytes stay intact.
      ftruncateSync(descriptor, 0);
      writeFileSync(descriptor, replacement.bytes);
    } finally { closeSync(descriptor); }
    const materialized = readInput(exported, relative).record;
    require(materialized.bytes === selected.bytes && materialized.sha256 === selected.sha256,
      'Application profile materialization differs from its selected source');
    return { path: relative, baseline, selected, materialized };
  });
}

function verifyMaterializedProfile(plan, exported, materialized) {
  if (!plan.dependency_profile) return;
  for (const row of materialized) {
    assert.deepEqual(readInput(exported, row.path).record, row.materialized, 'A materialized application package input changed');
    const selected = readInput(exported, row.selected.path).record;
    require(selected.bytes === row.selected.bytes && selected.sha256 === row.selected.sha256,
      'An exported application profile input changed');
  }
}

function validateBaselineReport(report, plan) {
  const bun = plan.package_manager?.name === 'bun';
  const version = bun ? 'v6' : 'v4'; const mode = bun ? 'fresh-bun-frozen' : 'fresh-npm-ci';
  require(report?.schema === `marty.application-source-closure-rehearsal/${version}` && report.status === 'passed'
    && report.plan?.schema === `marty.application-source-closure-plan/${version}` && !report.plan.dependency_profile,
  'The application profile requires a passed full-profile v4 baseline');
  require(report.build?.dependency_mode === mode && report.dependency_install?.mode === mode
    && report.dependency_install.status === 'passed' && report.dependency_install.dependency_profile === 'full'
    && report.dependency_install.independent_dependency_installation === true,
  'The application profile baseline must use the full fresh locked install');
  for (const value of [plan.package_manager, report.plan.package_manager, report.build.package_manager, report.dependency_install.package_manager]) {
    assert.deepEqual(value, bun ? APPLICATION_BUN_PACKAGE_MANAGER : undefined, 'Baseline package-manager evidence differs');
  }
  if (bun) require(report.build.dependency_lock_sha256 === plan.source.files.find((row) => row.path === 'ui/bun.lock').sha256
    && report.dependency_install.bun_lock_selected === true && report.dependency_install.bun_version === APPLICATION_BUN_PACKAGE_MANAGER.version,
  'Baseline did not preserve the selected frozen Bun lock and installer');
  for (const key of ['application_build_completed', 'application_tests_completed', 'omitted_sources_absent',
    'application_output_checked', 'source_checkout_unchanged', 'public_assets_preserved',
    'application_resource_smoke_completed', 'locale_fallback_observed', 'sdk_wasm_initialized_in_node',
    'sdk_wasm_output_bound', 'independent_dependency_installation']) {
    require(report.qualification?.[key] === true, `The full-profile baseline did not qualify ${key}`);
  }
  require(report.plan.source?.input_inventory_sha256 === identity(report.plan.source.files),
    'The baseline source inventory digest is invalid');
  assert.deepEqual(report.plan.source, plan.source, 'The baseline source differs from the selected profile source');
  assert.deepEqual(report.plan.route_contract, plan.route_contract, 'The baseline route contract differs');
  assert.deepEqual(report.plan.test_profile, plan.test_profile, 'The baseline selected test profile differs');
  assert.deepEqual(report.plan.boundary, plan.boundary, 'The baseline source boundary differs');
  require(report.build.effective_source_sha === effectiveSourceSha(plan)
    && report.build.package_lock_sha256 === plan.source.files.find((row) => row.path === 'ui/package-lock.json').sha256,
  'The baseline build does not bind the original source and full package lock');
  require(report.output && Array.isArray(report.output.files) && report.output.files.length > 0
    && report.output.inventory_sha256 === identity(report.output.files), 'The baseline output inventory digest is invalid');
  require(Array.isArray(report.output.public_resources) && Array.isArray(report.resources?.result?.public_resources),
    'The baseline public resource evidence is missing');
  assert.deepEqual(report.resources.result.public_resources, report.output.public_resources,
    'The baseline public resource probe differs from its output');
}

function readBaselineReport(filename, plan) {
  require(typeof filename === 'string' && path.isAbsolute(filename), 'The baseline report must be an absolute file');
  const parent = realpathSync(path.dirname(filename));
  require(parent === path.dirname(path.resolve(filename)) && outside(plan.repository_root, filename),
    'The baseline report must be outside the source through ordinary parents');
  require(lstatSync(filename).size <= 8 * 1024 * 1024, 'The baseline report exceeds its bound');
  const input = readInput(parent, path.basename(filename));
  const report = JSON.parse(input.bytes.toString('utf8'));
  validateBaselineReport(report, plan);
  return { report, sha256: input.record.sha256, bytes: input.record.bytes };
}

export function compareApplicationProfileBaseline({ baseline, plan, output }) {
  validateBaselineReport(baseline, plan);
  require(output?.inventory_sha256 === identity(output.files), 'The application profile output inventory digest is invalid');
  assert.deepEqual(output, baseline.output, 'Application profile output differs from the full-profile baseline');
  return { full_profile_fresh_install_passed: true, same_source_inputs: true, same_route_and_test_contracts: true,
    output_files_identical: true, public_resources_identical: true,
    output_inventory_sha256: output.inventory_sha256,
    output_files: output.files.length, public_resources: output.public_resources.length };
}

function filesIn(root, directory = root) {
  const files = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const filename = path.join(directory, entry.name);
    require(!entry.isSymbolicLink(), 'Build output must not contain symlinks');
    if (entry.isDirectory()) files.push(...filesIn(root, filename));
    else {
      require(entry.isFile(), 'Build output must contain only regular files');
      files.push(path.relative(root, filename).split(path.sep).join('/'));
    }
  }
  return files.sort();
}

export function verifyApplicationClosureOutput(exportRoot, plan) {
  const output = path.join(exportRoot, 'ui/dist-application');
  const outputType = lstatSync(output);
  require(outputType.isDirectory() && !outputType.isSymbolicLink(), 'Application output must be an ordinary directory');
  const files = filesIn(output);
  for (const entry of ['index.html', 'console/index.html', 'marty-web-routes.json']) {
    require(files.includes(entry) && readInput(output, entry).bytes.length > 0, `Application output is missing ${entry}`);
  }
  const marker = JSON.parse(readInput(output, 'marty-web-routes.json').bytes.toString('utf8'));
  assert.deepEqual(marker, {
    schema: 'marty.application-web-compatibility/v1', surface: 'application',
    source_sha: effectiveSourceSha(plan), route_contract: plan.route_contract,
  }, 'Application output marker differs from the rehearsal source and route contract');
  for (const entry of EXCLUDED_OUTPUTS) require(!existsSync(path.join(output, entry)), `Marketing output was retained: ${entry}`);
  require(!files.some((entry) => /^sitemap-\d+\.xml$/.test(entry)
    || /^locales\/[^/]+\/marketing\.json$/.test(entry)), 'Application output retained marketing locales or sitemap');
  for (const namespace of APPLICATION_NAMESPACES) {
    const filename = `locales/en/${namespace}.json`;
    require(files.includes(filename), `Application English fallback namespace is missing: ${namespace}`);
    const locale = JSON.parse(readInput(output, filename).bytes.toString('utf8'));
    require(locale && typeof locale === 'object' && !Array.isArray(locale), 'Invalid application fallback locale');
  }
  const source = new Map(plan.source.files.map((entry) => [entry.path, entry]));
  const publicResources = APPLICATION_RETAINED_PUBLIC_FILES.map((entry) => {
    require(files.includes(entry), `Retained application public resource is missing: ${entry}`);
    const actual = readInput(output, entry);
    const expected = source.get(`ui/public/${entry}`);
    require(expected && actual.record.bytes === expected.bytes && actual.record.sha256 === expected.sha256,
      `Retained application public resource differs from original source: ${entry}`);
    if (entry.startsWith('locales/')) {
      const locale = JSON.parse(actual.bytes.toString('utf8'));
      require(locale && typeof locale === 'object' && !Array.isArray(locale), `Invalid application locale: ${entry}`);
    }
    return { path: entry, bytes: actual.record.bytes, sha256: actual.record.sha256 };
  });
  const inventory = files.map((entry) => readInput(output, entry).record);
  return { files: inventory, inventory_sha256: identity(inventory), english_namespaces: [...APPLICATION_NAMESPACES],
    public_resources: publicResources, locales: [...APPLICATION_LOCALES] };
}

function buildEnvironment(sourceSha) {
  const environment = {};
  for (const key of ['PATH', 'HOME', 'TMPDIR', 'TEMP', 'TMP', 'SystemRoot', 'ComSpec', 'USERPROFILE', 'LOCALAPPDATA']) {
    if (process.env[key] !== undefined) environment[key] = process.env[key];
  }
  return { ...environment, MARTY_UI_SHA: sourceSha, MARTY_PRODUCTION_PAGES: 'public', VITE_UI_VARIANT: 'public' };
}

export { buildEnvironment as applicationBuildEnvironment, verifyApplicationTestResult, verifyApplicationResourceResult };

function verifyApplicationTestResult(temporary, exported, selectedFiles = APPLICATION_TEST_FILES) {
  const raw = readInput(temporary, 'application-tests.json').bytes;
  const result = JSON.parse(raw.toString('utf8'));
  require(result && typeof result === 'object' && result.success === true, 'Application test report did not succeed');
  require(Array.isArray(result.testResults) && result.testResults.length === selectedFiles.length,
    'Application test report did not complete the selected files');
  const uiRoot = path.join(exported, 'ui');
  const expected = [...selectedFiles].sort();
  const completed = [];
  let assertions = 0;
  for (const file of result.testResults) {
    require(file && typeof file.name === 'string' && file.status === 'passed'
      && Array.isArray(file.assertionResults) && file.assertionResults.length > 0,
    'Application test file did not complete');
    completed.push(path.relative(uiRoot, path.resolve(file.name)).split(path.sep).join('/'));
    require(file.assertionResults.every((entry) => entry && entry.status === 'passed'), 'Application tests were skipped or failed');
    assertions += file.assertionResults.length;
  }
  assert.deepEqual(completed.sort(), expected, 'Application test report differs from the selected file set');
  require(Number.isSafeInteger(result.numTotalTests) && result.numTotalTests === assertions
    && result.numPassedTests === assertions && result.numFailedTests === 0
    && result.numPendingTests === 0 && result.numTodoTests === 0,
  'Application test counts differ from completed assertions');
  return { completed_files: completed, test_count: assertions, report_sha256: digest(raw) };
}

function verifyApplicationResourceResult(temporary, exported, output) {
  const raw = readInput(temporary, 'application-resources.json').bytes;
  const result = JSON.parse(raw.toString('utf8'));
  require(result && result.schema === 'marty.application-resource-smoke/v1' && result.status === 'passed',
    'Application resource smoke did not succeed');
  require(Array.isArray(result.public_resources), 'Application resource report is missing public resources');
  assert.deepEqual(result.public_resources, output.public_resources, 'Resource probe differs from the preserved public resources');
  require(Array.isArray(result.served_resources) && result.served_resources.length > 0, 'Application resource report is missing served resources');
  const inventory = new Map(output.files.map((entry) => [entry.path, entry]));
  const required = new Set([...APPLICATION_RETAINED_PUBLIC_FILES, 'index.html', 'console/index.html',
    ...output.files.filter((entry) => /\.(?:m?js|wasm|css)$/.test(entry.path)).map((entry) => entry.path)]);
  const seen = new Set();
  for (const row of result.served_resources) {
    require(row && typeof row.path === 'string' && !seen.has(row.path), 'Duplicate or invalid served resource');
    const expected = inventory.get(row.path);
    require(expected && row.status === 200 && row.bytes === expected.bytes && row.sha256 === expected.sha256
      && typeof row.content_type === 'string' && row.content_type.length > 0, 'Served resource differs from the built output');
    require(APPLICATION_RESOURCE_MIME_TYPES[path.extname(row.path)]?.includes(row.content_type.split(';', 1)[0].trim().toLowerCase()),
      'Served resource content type differs from its asset type');
    seen.add(row.path);
  }
  require([...required].every((entry) => seen.has(entry)), 'Application resource report omitted a required response');
  require(result.preview && result.preview.host === '127.0.0.1' && Number.isInteger(result.preview.port)
    && result.preview.port > 0 && result.preview.port <= 65535 && result.preview.closed === true,
  'Application resource preview was not closed on loopback');
  assert.deepEqual(result.qualification, { resources_served: true, locale_fallback_observed: true,
    browser_startup_observed: false, host_deployment_tested: false, oidc_journey_tested: false },
  'Application resource smoke broadened its qualification');
  const locale = result.locale_probe;
  const en = JSON.parse(readInput(path.join(exported, 'ui/dist-application'), 'locales/en/common.json').bytes.toString('utf8'));
  const de = JSON.parse(readInput(path.join(exported, 'ui/dist-application'), 'locales/de/common.json').bytes.toString('utf8'));
  require(typeof en.common?.login === 'string' && en.common.login.length > 0 && de.common?.login === undefined
    && typeof de.actions?.cancel === 'string' && de.actions.cancel.length > 0, 'Real locale inputs do not support the selected fallback probe');
  require(locale && locale.language === 'de' && locale.fallback_language === 'en' && locale.key === 'common.login'
    && locale.resolved_language === 'en' && locale.fallback_value === en.common.login
    && locale.localized_key === 'actions.cancel' && locale.localized_language === 'de'
    && locale.localized_value === de.actions.cancel && Array.isArray(locale.requests),
  'Application resource report did not observe the selected locale fallback');
  const expectedRequests = ['de', 'en'].flatMap((language) => APPLICATION_LOCALE_NAMESPACES.map(
    (namespace) => `/locales/${language}/${namespace}.json`,
  )).sort();
  assert.deepEqual([...new Set(locale.requests)].sort(), expectedRequests, 'Locale backend requests differ from the application namespaces');
  return { ...result, report_sha256: digest(raw) };
}

function verifyOriginalSource(plan) {
  assert.deepEqual(sourcePaths(plan.repository_root, plan.source.extra_inputs), plan.source.files.map((entry) => entry.path), 'Original source input list changed');
  const after = plan.source.files.map((entry) => readInput(plan.repository_root, entry.path).record);
  assert.deepEqual(after, plan.source.files, 'Original source bytes changed');
  assert.deepEqual(sourceStatus(plan.repository_root), plan.source.git_status, 'Original Git status changed');
}

function requireInstalledDependencies(dependencies) {
  require(lstatSync(dependencies).isDirectory() && path.basename(dependencies) === 'node_modules', 'Select an installed node_modules directory');
  for (const executable of ['tsc', 'vite']) require(existsSync(path.join(dependencies, '.bin', executable)), `Installed build dependency is missing: ${executable}`);
  require(existsSync(path.join(dependencies, 'vitest/vitest.mjs')), 'Installed test dependency is missing: vitest');
}

export function rehearseApplicationSourceClosure({ repositoryRoot = DEFAULT_ROOT, dependencyDirectory,
  freshInstall = false, runtimeContextDirectory, keepExport = false, dependencyProfile = 'full', baselineReport, packageManager } = {}) {
  require(!(freshInstall && dependencyDirectory), 'Fresh install and reused dependencies are mutually exclusive');
  require(dependencyProfile === 'application' ? Boolean(baselineReport) : !baselineReport,
    'A baseline report is required only for the application dependency profile');
  const plan = planApplicationSourceClosure({ repositoryRoot, freshInstall, runtimeContext: Boolean(runtimeContextDirectory), dependencyProfile, packageManager });
  packageManager = plan.package_manager?.name || 'npm';
  const baseline = dependencyProfile === 'application' ? readBaselineReport(baselineReport, plan) : undefined;
  if (runtimeContextDirectory) {
    require(path.isAbsolute(runtimeContextDirectory), 'Runtime context must be an absolute new directory');
    const parent = realpathSync(path.dirname(runtimeContextDirectory));
    require(parent === path.dirname(path.resolve(runtimeContextDirectory)), 'Runtime context parent cannot use a symlink');
    runtimeContextDirectory = path.resolve(runtimeContextDirectory);
    require(outside(plan.repository_root, runtimeContextDirectory), 'Runtime context must be outside the original source');
    let present = true;
    try { lstatSync(runtimeContextDirectory); } catch (error) {
      if (error.code === 'ENOENT') present = false;
      else throw error;
    }
    require(!present, 'Runtime context must not replace an existing path');
  }
  let dependencies;
  if (!freshInstall) {
    dependencies = realpathSync(dependencyDirectory || path.join(plan.repository_root, 'ui/node_modules'));
    requireInstalledDependencies(dependencies);
  }
  require(outside(plan.repository_root, realpathSync(os.tmpdir())), 'Temporary exports must be outside the source checkout');
  const temporary = mkdtempSync(path.join(os.tmpdir(), 'marty-application-source-closure-'));
  const exported = path.join(temporary, 'source');
  if (freshInstall) dependencies = path.join(exported, 'ui/node_modules');
  const testArguments = ['node_modules/vitest/vitest.mjs', 'run', '--config', APPLICATION_TEST_CONFIG,
    '--reporter=json', '--outputFile', path.join(temporary, 'application-tests.json')];
  const resourceArguments = ['scripts/application-resource-smoke.mjs', '--dist', 'dist-application',
    '--report', path.join(temporary, 'application-resources.json')];
  const report = {
    schema: plan.schema.replace('-plan/', '-rehearsal/'),
    status: 'failed', plan,
    build: { command: ['node', 'scripts/build-web-surface.mjs', 'application'], node_version: process.version,
      dependency_mode: freshInstall ? (packageManager === 'bun' ? 'fresh-bun-frozen' : 'fresh-npm-ci') : 'reused-installed-node_modules', dependency_directory: dependencies,
      dependency_profile: dependencyProfile,
      ...(packageManager === 'bun' ? { package_manager: { ...APPLICATION_BUN_PACKAGE_MANAGER },
        dependency_lock_sha256: plan.source.files.find((entry) => entry.path === (dependencyProfile === 'application'
          ? 'ui/profiles/application/bun.lock' : 'ui/bun.lock')).sha256 } : {}),
      package_lock_sha256: plan.source.files.find((entry) => entry.path === (dependencyProfile === 'application'
        ? 'ui/profiles/application/package-lock.json' : 'ui/package-lock.json')).sha256,
      effective_source_sha: effectiveSourceSha(plan) },
    tests: { command: ['node', ...testArguments], selected_files: [...plan.test_profile.files] },
    resources: { command: ['node', ...resourceArguments] },
    qualification: { application_build_completed: false, application_tests_completed: false, omitted_sources_absent: false,
      application_output_checked: false, source_checkout_unchanged: false, source_extraction_complete: false,
      public_assets_preserved: false, application_resource_smoke_completed: false,
      locale_fallback_observed: false, browser_startup_observed: false,
      runtime_context_prepared: false, container_runtime_tested: false, package_graph_minimized: false,
      sdk_wasm_initialized_in_node: false, sdk_wasm_output_bound: false,
      independent_dependency_installation: false, oidc_journey_tested: false, host_deployment_tested: false,
      signed_release_produced: false },
    ...(dependencyProfile === 'application' ? { dependency_profile: { name: 'application',
      materialized_inputs: [], baseline_report: { path: baselineReport, bytes: baseline.bytes, sha256: baseline.sha256 },
      bun_lock_selected: packageManager === 'bun',
      ...(packageManager === 'bun' ? { package_manager: { ...APPLICATION_BUN_PACKAGE_MANAGER } } : {}),
      package_graph_minimized: false, output_identical_to_full_profile: false } } : {}),
    export_directory: exported, export_retained: keepExport,
  };
  let ownedContext = false;
  try {
    exportSource(plan, exported);
    if (dependencyProfile === 'application') {
      report.dependency_profile.materialized_inputs = materializeApplicationDependencyProfile(plan, exported);
    }
    if (freshInstall) {
      report.dependency_install = installApplicationDependencies({ uiRoot: path.join(exported, 'ui'), temporaryRoot: temporary,
        dependencyProfile, packageManager });
      requireOmittedInputsAbsent(plan, exported);
      requireInstalledDependencies(dependencies);
      report.qualification.independent_dependency_installation = true;
      report.qualification.sdk_wasm_initialized_in_node = true;
    } else {
      symlinkSync(dependencies, path.join(exported, 'ui/node_modules'), process.platform === 'win32' ? 'junction' : 'dir');
    }
    const result = spawnSync(process.execPath, ['scripts/build-web-surface.mjs', 'application'], {
      cwd: path.join(exported, 'ui'), env: buildEnvironment(report.build.effective_source_sha), stdio: ['ignore', 2, 2],
      timeout: 20 * 60 * 1000, shell: false,
    });
    if (result.error) throw result.error;
    require(result.status === 0, `Application build failed with exit code ${result.status}`);
    report.qualification.application_build_completed = true;
    requireOmittedInputsAbsent(plan, exported);
    const tests = spawnSync(process.execPath, testArguments, {
      cwd: path.join(exported, 'ui'), env: buildEnvironment(report.build.effective_source_sha), stdio: ['ignore', 2, 2],
      timeout: 20 * 60 * 1000, shell: false,
    });
    if (tests.error) throw tests.error;
    require(tests.status === 0, `Application tests failed with exit code ${tests.status}`);
    report.tests.result = verifyApplicationTestResult(temporary, exported, plan.test_profile.files);
    report.qualification.application_tests_completed = true;
    requireOmittedInputsAbsent(plan, exported);
    report.output = verifyApplicationClosureOutput(exported, plan);
    const resources = spawnSync(process.execPath, resourceArguments, {
      cwd: path.join(exported, 'ui'), env: buildEnvironment(report.build.effective_source_sha), stdio: ['ignore', 2, 2],
      timeout: 60 * 1000, shell: false,
    });
    if (resources.error) throw resources.error;
    require(resources.status === 0, `Application resource smoke failed with exit code ${resources.status}`);
    requireOmittedInputsAbsent(plan, exported);
    const finalOutput = verifyApplicationClosureOutput(exported, plan);
    assert.deepEqual(finalOutput, report.output, 'Resource probe changed the built output inventory');
    report.resources.result = verifyApplicationResourceResult(temporary, exported, finalOutput);
    if (dependencyProfile === 'application') {
      verifyMaterializedProfile(plan, exported, report.dependency_profile.materialized_inputs);
      report.dependency_profile.baseline_comparison = compareApplicationProfileBaseline({ baseline: baseline.report,
        plan, output: finalOutput });
      report.dependency_profile.output_identical_to_full_profile = true;
    }
    if (freshInstall) {
      const sdkWasm = report.dependency_install.sdk.wasm;
      const emitted = finalOutput.files.filter((entry) => /^assets\/marty_api_client_bg-[^/]+\.wasm$/.test(entry.path));
      require(emitted.length === 1 && emitted[0].bytes === sdkWasm.bytes && emitted[0].sha256 === sdkWasm.sha256,
        'Application output differs from the freshly installed SDK WASM');
      report.dependency_install.sdk.emitted_wasm = emitted[0];
      report.qualification.sdk_wasm_output_bound = true;
    }
    report.qualification.application_resource_smoke_completed = true;
    report.qualification.public_assets_preserved = true;
    report.qualification.locale_fallback_observed = true;
    report.qualification.omitted_sources_absent = true;
    report.qualification.application_output_checked = true;
    report.status = 'passed';
  } catch (error) {
    report.error = error.message;
  } finally {
    try {
      verifyOriginalSource(plan);
      report.qualification.source_checkout_unchanged = true;
    } catch (error) {
      report.status = 'failed';
      report.error = `Source preservation failed: ${error.message}`;
    }
    try {
      if (report.status === 'passed' && runtimeContextDirectory) {
        report.qualification.source_checkout_unchanged = false;
        const original = new Map(plan.source.files.map((entry) => [entry.path, entry]));
        for (const name of RUNTIME_INPUTS) {
          const actual = readInput(exported, name).record;
          const expected = original.get(name);
          require(actual.sha256 === expected.sha256 && actual.bytes === expected.bytes,
            `Runtime packaging input differs from inventoried source: ${name}`);
        }
        report.runtime_context = createApplicationRuntimeContext({ sourceRoot: exported,
          outputRoot: path.join(exported, 'ui/dist-application'), destination: runtimeContextDirectory,
          sourceCommit: plan.source.commit, outputInventory: report.output, resourceResult: report.resources.result });
        ownedContext = true;
        assert.deepEqual(verifyApplicationClosureOutput(exported, plan), report.output, 'Runtime packaging changed the built output inventory');
        requireOmittedInputsAbsent(plan, exported);
        if (dependencyProfile === 'application') verifyMaterializedProfile(plan, exported, report.dependency_profile.materialized_inputs);
      }
    } catch (error) {
      report.status = 'failed';
      report.error = `Runtime context failed: ${error.message}`;
    }
    // Context preparation can fail before returning ownership. Revalidate the
    // original inputs on that path too; no earlier preservation claim survives
    // an unverified preparation attempt.
    if (runtimeContextDirectory) {
      report.qualification.source_checkout_unchanged = false;
      try {
        verifyOriginalSource(plan);
        report.qualification.source_checkout_unchanged = true;
      } catch (error) {
        report.status = 'failed';
        report.error = `Source preservation failed after runtime preparation: ${error.message}`;
      }
    }
    try {
      if (!keepExport) rmSync(temporary, { recursive: true, force: true });
    } catch (error) {
      report.status = 'failed';
      report.error = `Export cleanup failed: ${error.message}`;
    }
    if (report.status !== 'passed' && ownedContext) {
      rmSync(runtimeContextDirectory, { recursive: true, force: true });
      delete report.runtime_context;
    }
    report.qualification.runtime_context_prepared = report.status === 'passed' && ownedContext;
  }
  return report;
}

function main() {
  const options = {};
  let reportPath;
  const arguments_ = process.argv.slice(2);
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === '--keep-export') options.keepExport = true;
    else if (argument === '--fresh-install') options.freshInstall = true;
    else if (['--repository-root', '--dependencies', '--runtime-context', '--dependency-profile', '--package-manager', '--baseline-report', '--report'].includes(argument)) {
      const value = arguments_[++index];
      require(value && !value.startsWith('--'), `Missing value for ${argument}`);
      if (argument === '--repository-root') options.repositoryRoot = value;
      else if (argument === '--dependencies') options.dependencyDirectory = value;
      else if (argument === '--runtime-context') options.runtimeContextDirectory = value;
      else if (argument === '--dependency-profile') options.dependencyProfile = value;
      else if (argument === '--package-manager') options.packageManager = value;
      else if (argument === '--baseline-report') options.baselineReport = value;
      else reportPath = path.resolve(value);
    } else throw new Error(`Unknown option: ${argument}`);
  }
  if (reportPath) {
    const destination = path.join(realpathSync(path.dirname(reportPath)), path.basename(reportPath));
    require(outside(realpathSync(options.repositoryRoot || DEFAULT_ROOT), destination), 'Write the rehearsal report outside the source checkout');
    require(!existsSync(reportPath), 'Rehearsal report already exists');
  }
  const report = rehearseApplicationSourceClosure(options);
  const encoded = `${JSON.stringify(report, null, 2)}\n`;
  if (reportPath) writeFileSync(reportPath, encoded, { flag: 'wx', mode: 0o600 });
  else process.stdout.write(encoded);
  if (report.status !== 'passed') process.exitCode = 1;
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try { main(); } catch (error) { console.error(error.message); process.exitCode = 1; }
}
