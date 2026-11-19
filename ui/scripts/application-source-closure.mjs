import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  closeSync, constants, existsSync, fstatSync, lstatSync, mkdirSync, mkdtempSync,
  openSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { canonicalJson } from './web-surface-contract.mjs';
import { validateWebsiteSourceOwnership } from './website-source-ownership.mjs';
import { validateWebSurfaceContract } from '../src/application/routing/webSurfaceContract.mjs';

const DEFAULT_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const CONTRACTS = ['contracts/website-source-ownership.json', 'contracts/web-surface-routes.json'];

// These exact raw inputs are read by the website demo generator/catalog. This
// rehearsal deliberately retains the generated projections and their reader.
export const OMITTED_DEMO_INPUTS = Object.freeze([
  'ui/public/demos/manifests/2026.07.0.json',
  'ui/public/demos/manifests/2026.08.0.json',
  'ui/public/demos/manifests/index.json',
]);
export const RETAINED_SHARED_INPUTS = Object.freeze([
  'ui/src/application/routing/appHandoff.js',
  'ui/src/application/routing/authCallback.js',
  'ui/src/application/routing/loginEntry.js',
  'ui/src/application/routing/publicEntry.js',
  'ui/src/application/routing/webSurfaceContract.mjs',
  'ui/src/apps/shared/WebSurfaceBoundary.jsx',
  'ui/src/components/navigation/ConsoleHeaderBar.jsx',
  'ui/src/components/navigation/SidebarNavigation.jsx',
  'ui/src/contexts/AuthContext.jsx',
  'ui/src/contexts/BrandingContext.jsx',
  'ui/src/extensions/commerce/publicStub.jsx',
  'ui/src/generated/demoManifests.generated.js',
  'ui/src/generated/demoWalletSchema.generated.json',
  'ui/src/services/demoManifestService.js',
  'ui/src/services/platformDemoScenarios.js',
  'ui/src/variants/publicConfig.application.js',
  'ui/src/variants/publicConfig.public.js',
  'ui/src/variants/publicSite.application.jsx',
]);
const REQUIRED_INPUTS = [
  'ui/package.json', 'ui/package-lock.json', 'ui/index.html', 'ui/console/index.html',
  'ui/scripts/build-web-surface.mjs', 'ui/vite.config.ts', ...RETAINED_SHARED_INPUTS,
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

function sourcePaths(root) {
  const listed = git(root, ['ls-files', '--cached', '--others', '--exclude-standard', '-z', '--', 'ui', ...CONTRACTS])
    .split('\0').filter(Boolean);
  const paths = [...new Set(listed)].filter((entry) => !/^ui\/(?:node_modules|dist(?:-[^/]+)?)(?:\/|$)/.test(entry));
  for (const entry of paths) {
    relativeInput(entry);
    require(entry.startsWith('ui/') || CONTRACTS.includes(entry), 'Source export is outside the reviewed UI boundary');
  }
  return paths.sort();
}

function sourceStatus(root) {
  return git(root, ['status', '--porcelain=v1', '-z', '--untracked-files=all']).split('\0').filter(Boolean);
}

function identity(records) {
  return digest(canonicalJson(records));
}

export function planApplicationSourceClosure({ repositoryRoot = DEFAULT_ROOT } = {}) {
  const root = realpathSync(repositoryRoot);
  require(realpathSync(git(root, ['rev-parse', '--show-toplevel']).trim()) === root, 'Select the actual repository root');
  const sourceSha = git(root, ['rev-parse', 'HEAD']).trim();
  require(/^[0-9a-f]{40}$/.test(sourceSha), 'Source checkout requires an exact commit');
  const ownership = validateWebsiteSourceOwnership(JSON.parse(readInput(root, CONTRACTS[0]).bytes.toString('utf8')), root);
  const routes = validateWebSurfaceContract(JSON.parse(readInput(root, CONTRACTS[1]).bytes.toString('utf8')));
  const paths = sourcePaths(root);
  const omitted = new Set([...ownership.modules, ...OMITTED_DEMO_INPUTS]);
  for (const entry of [...omitted, ...CONTRACTS, ...REQUIRED_INPUTS]) {
    require(paths.includes(entry), `Required reviewed source input is missing: ${entry}`);
  }
  for (const entry of RETAINED_SHARED_INPUTS) require(!omitted.has(entry), `Shared input cannot be omitted: ${entry}`);
  const files = paths.map((entry) => readInput(root, entry).record);
  const status = sourceStatus(root);
  return {
    schema: 'marty.application-source-closure-plan/v1',
    repository_root: root,
    source: { commit: sourceSha, working_tree_dirty: status.length > 0, git_status: status,
      input_inventory_sha256: identity(files), files },
    route_contract: { version: routes.schema_version, sha256: digest(canonicalJson(routes)) },
    boundary: {
      website_roster: ownership.modules.slice().sort(),
      additional_omissions: [...OMITTED_DEMO_INPUTS],
      omitted: [...omitted].sort(),
      retained: paths.filter((entry) => !omitted.has(entry)),
      retained_shared_inputs: [...RETAINED_SHARED_INPUTS],
      ownership_audit_complete: false,
      retained_demo_reason: 'Generated demo projections and their reader remain as a conservative retained source boundary; this rehearsal removes only the audited raw generator/catalog inputs.',
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
  const inventory = files.map((entry) => readInput(output, entry).record);
  return { files: inventory, inventory_sha256: identity(inventory), english_namespaces: [...APPLICATION_NAMESPACES] };
}

function buildEnvironment(sourceSha) {
  const environment = {};
  for (const key of ['PATH', 'HOME', 'TMPDIR', 'TEMP', 'TMP', 'SystemRoot', 'ComSpec', 'USERPROFILE', 'LOCALAPPDATA']) {
    if (process.env[key] !== undefined) environment[key] = process.env[key];
  }
  return { ...environment, MARTY_UI_SHA: sourceSha, MARTY_PRODUCTION_PAGES: 'public', VITE_UI_VARIANT: 'public' };
}

export function rehearseApplicationSourceClosure({ repositoryRoot = DEFAULT_ROOT, dependencyDirectory,
  keepExport = false } = {}) {
  const plan = planApplicationSourceClosure({ repositoryRoot });
  const dependencies = realpathSync(dependencyDirectory || path.join(plan.repository_root, 'ui/node_modules'));
  require(lstatSync(dependencies).isDirectory() && path.basename(dependencies) === 'node_modules', 'Select an installed node_modules directory');
  for (const executable of ['tsc', 'vite']) require(existsSync(path.join(dependencies, '.bin', executable)), `Installed build dependency is missing: ${executable}`);
  require(outside(plan.repository_root, realpathSync(os.tmpdir())), 'Temporary exports must be outside the source checkout');
  const temporary = mkdtempSync(path.join(os.tmpdir(), 'marty-application-source-closure-'));
  const exported = path.join(temporary, 'source');
  const report = {
    schema: 'marty.application-source-closure-rehearsal/v1',
    status: 'failed', plan,
    build: { command: ['node', 'scripts/build-web-surface.mjs', 'application'], node_version: process.version,
      dependency_mode: 'reused-installed-node_modules', dependency_directory: dependencies,
      package_lock_sha256: plan.source.files.find((entry) => entry.path === 'ui/package-lock.json').sha256,
      effective_source_sha: effectiveSourceSha(plan) },
    qualification: { application_build_completed: false, omitted_sources_absent: false,
      application_output_checked: false, source_checkout_unchanged: false, source_extraction_complete: false,
      independent_dependency_installation: false, oidc_journey_tested: false, host_deployment_tested: false,
      signed_release_produced: false },
    export_directory: exported, export_retained: keepExport,
  };
  try {
    exportSource(plan, exported);
    symlinkSync(dependencies, path.join(exported, 'ui/node_modules'), process.platform === 'win32' ? 'junction' : 'dir');
    const result = spawnSync(process.execPath, ['scripts/build-web-surface.mjs', 'application'], {
      cwd: path.join(exported, 'ui'), env: buildEnvironment(report.build.effective_source_sha), stdio: ['ignore', 2, 2],
      timeout: 20 * 60 * 1000, shell: false,
    });
    if (result.error) throw result.error;
    require(result.status === 0, `Application build failed with exit code ${result.status}`);
    report.qualification.application_build_completed = true;
    requireOmittedInputsAbsent(plan, exported);
    report.qualification.omitted_sources_absent = true;
    report.output = verifyApplicationClosureOutput(exported, plan);
    report.qualification.application_output_checked = true;
    report.status = 'passed';
  } catch (error) {
    report.error = error.message;
  } finally {
    try {
      assert.deepEqual(sourcePaths(plan.repository_root), plan.source.files.map((entry) => entry.path), 'Original source input list changed');
      const after = plan.source.files.map((entry) => readInput(plan.repository_root, entry.path).record);
      assert.deepEqual(after, plan.source.files, 'Original source bytes changed');
      assert.deepEqual(sourceStatus(plan.repository_root), plan.source.git_status, 'Original Git status changed');
      report.qualification.source_checkout_unchanged = true;
    } catch (error) {
      report.status = 'failed';
      report.error = `Source preservation failed: ${error.message}`;
    }
    if (!keepExport) rmSync(temporary, { recursive: true, force: true });
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
    else if (['--repository-root', '--dependencies', '--report'].includes(argument)) {
      const value = arguments_[++index];
      require(value && !value.startsWith('--'), `Missing value for ${argument}`);
      if (argument === '--repository-root') options.repositoryRoot = value;
      else if (argument === '--dependencies') options.dependencyDirectory = value;
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
