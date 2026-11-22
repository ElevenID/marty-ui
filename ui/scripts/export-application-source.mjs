import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync, closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync,
  readdirSync, readSync, realpathSync, rmSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  APPLICATION_SOURCE_ZIP_LIMITS, applicationSourcePath, decodeApplicationSourceZip, encodeApplicationSourceZip,
} from './application-source-zip.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const SELF = fileURLToPath(import.meta.url);
const CONTRACT = 'contracts/application-source-export.json';
// Source maps may evolve without changing the archive grammar. Each accepted
// map, including the initial package, is pinned to exact reviewed bytes.
const SOURCE_CONTRACTS = Object.freeze([
  Object.freeze({ path: CONTRACT, sha256: 'sha256:7df5cfa6e3c37f9c1c3c3a8034559608971ad4dca60954013c5487e41b270f41',
    files: 581, test_files: 26, assertions: 321 }),
  Object.freeze({ path: 'contracts/application-source-export-history/initial-v1.json',
    sha256: 'sha256:3b7fe6dfe7718c3d7bcc9d0fccf28c2e4d92a0bcdad1f592c86a51328669d8ad',
    files: 575, test_files: 24, assertions: 296 }),
]);
export const APPLICATION_SOURCE_MANIFEST_PATH = 'application-source-origin.json';
const MANIFEST_SCHEMA = 'marty.application-source-package/v1';
const RECEIPT_SCHEMA = 'marty.application-source-package-producer/v1';
const MAX_JSON = 8 * 1024 * 1024;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const OID = /^[0-9a-f]{40}$/;
const GENERATED = ['ui/node_modules', 'ui/dist-application'];
const SUBSTITUTIONS = ['ui/package.json', 'ui/package-lock.json'];
const FALSE_QUALIFICATION = Object.freeze({ source_extraction_complete: false, package_graph_minimized: false,
  browser_startup_observed: false, container_runtime_tested: false, host_deployment_tested: false,
  oidc_journey_tested: false, signed_release_produced: false, published: false, activated: false });

function require(condition, message) { if (!condition) throw new Error(message); }
function compare(a, b) { return a < b ? -1 : a > b ? 1 : 0; }
function hash(bytes) { return `sha256:${createHash('sha256').update(bytes).digest('hex')}`; }
function blobOid(bytes) { return createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex'); }
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function documentBytes(value) { return Buffer.from(`${canonical(value)}\n`); }
function object(value, label) {
  require(value && typeof value === 'object' && !Array.isArray(value), `Expected ${label} object`); return value;
}
function keys(value, expected, label) {
  object(value, label); assert.deepEqual(Object.keys(value).sort(), [...expected].sort(), `Unexpected ${label} fields`);
}

// Grammar validation comes first; the bounded second traversal rejects repeated
// keys, including escaped spellings, before any trust field is interpreted.
export function parseApplicationSourceJson(input, { maxBytes = MAX_JSON } = {}) {
  const bytes = Buffer.isBuffer(input) ? input : Buffer.from(input);
  require(bytes.length <= maxBytes, 'Application source JSON exceeds its bound');
  const text = bytes.toString('utf8');
  require(Buffer.from(text).equals(bytes), 'Application source JSON is not UTF-8');
  const parsed = JSON.parse(text); let index = 0;
  const whitespace = () => { while (index < text.length && /\s/.test(text[index])) index += 1; };
  const string = () => {
    const start = index++;
    while (index < text.length) {
      if (text[index++] === '"') return JSON.parse(text.slice(start, index));
      if (text[index - 1] === '\\') index += 1;
    }
    throw new Error('Incomplete application source JSON string');
  };
  function value(depth = 0) {
    require(depth <= 128, 'Application source JSON nesting exceeds its bound'); whitespace();
    if (text[index] === '{') {
      index += 1; whitespace(); const names = new Set();
      while (text[index] !== '}') {
        const key = string(); require(!names.has(key), `Duplicate application source JSON key: ${key}`); names.add(key);
        whitespace(); index += 1; value(depth + 1); whitespace();
        if (text[index] === ',') { index += 1; whitespace(); }
      }
      index += 1;
    } else if (text[index] === '[') {
      index += 1; whitespace();
      while (text[index] !== ']') { value(depth + 1); whitespace(); if (text[index] === ',') { index += 1; whitespace(); } }
      index += 1;
    } else if (text[index] === '"') string();
    else while (index < text.length && !/[\s,}\]]/.test(text[index])) index += 1;
  }
  value(); return object(parsed, 'application source JSON');
}

function ordinaryDirectory(value) {
  require(typeof value === 'string' && path.isAbsolute(value) && path.resolve(value) === value,
    'Application source paths must be canonical absolute paths');
  const stat = lstatSync(value);
  require(stat.isDirectory() && !stat.isSymbolicLink() && realpathSync(value) === value,
    'Application source directory must have ordinary parents');
  return value;
}
function absent(value) {
  try { lstatSync(value); return false; } catch (error) { if (error.code === 'ENOENT') return true; throw error; }
}
function outside(root, target) {
  const relative = path.relative(root, target); return relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative);
}
function newPath(value, sourceRoot = ROOT) {
  require(typeof value === 'string' && path.isAbsolute(value) && path.resolve(value) === value, 'Output must be a canonical absolute new path');
  ordinaryDirectory(path.dirname(value)); require(outside(sourceRoot, value), 'Output must be outside the source checkout');
  require(absent(value), 'Application source output must not replace an existing path'); return value;
}
function readAbsolute(filename, maxBytes = APPLICATION_SOURCE_ZIP_LIMITS.fileBytes) {
  require(typeof filename === 'string' && path.isAbsolute(filename) && path.resolve(filename) === filename,
    'Application source input must be an absolute file');
  ordinaryDirectory(path.dirname(filename));
  const stat = lstatSync(filename); require(stat.isFile() && !stat.isSymbolicLink(), 'Application source input must be a regular file');
  const descriptor = openSync(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const opened = fstatSync(descriptor);
    require(opened.isFile() && opened.size <= maxBytes, 'Application source input exceeds its bound');
    // Bound the read itself as well as the initial stat: a file that grows
    // after opening must not make a trusted-size check allocate without limit.
    const buffer = Buffer.alloc(opened.size + 1); let length = 0;
    while (length < buffer.length) {
      const count = readSync(descriptor, buffer, length, buffer.length - length, null);
      if (!count) break;
      length += count;
    }
    const bytes = buffer.subarray(0, length); const after = fstatSync(descriptor);
    require(bytes.length === opened.size && after.size === opened.size && after.mtimeMs === opened.mtimeMs
      && after.ctimeMs === opened.ctimeMs && after.mode === opened.mode,
      'Application source input changed during reading');
    return { bytes, mode: opened.mode & 0o7777 };
  } finally { closeSync(descriptor); }
}
function read(root, relative, maxBytes) { applicationSourcePath(relative); return readAbsolute(path.join(root, relative), maxBytes); }
function git(root, args) {
  return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
}
function sourceState(root) {
  ordinaryDirectory(root);
  require(realpathSync(git(root, ['rev-parse', '--show-toplevel']).trim()) === root, 'Expected the actual source Git root');
  require(git(root, ['status', '--porcelain=v1', '-z', '--untracked-files=all']) === '', 'Application source export requires a clean Git checkout');
  const commit = git(root, ['rev-parse', 'HEAD']).trim(); const tree = git(root, ['rev-parse', 'HEAD^{tree}']).trim();
  require(OID.test(commit) && OID.test(tree) && git(root, ['rev-parse', '--show-object-format']).trim() === 'sha1',
    'Application source export requires an exact SHA-1 Git commit/tree');
  const files = new Map();
  for (const row of git(root, ['ls-tree', '-r', '-z', 'HEAD']).split('\0').filter(Boolean)) {
    const tab = row.indexOf('\t'); const [mode, type, oid] = row.slice(0, tab).split(' '); const relative = row.slice(tab + 1);
    files.set(relative, { mode, type, oid });
  }
  return { commit, tree, files };
}

function validateContract(contract) {
  const approved = SOURCE_CONTRACTS.find((entry) => entry.sha256 === hash(Buffer.from(`${JSON.stringify(contract, null, 2)}\n`)));
  require(approved, 'Application source contract is not an approved current or historical map');
  keys(contract, ['schema', 'repository', 'source_boundary', 'manifest_path', 'inputs', 'omission_categories', 'omitted',
    'generated_state', 'test_profile', 'public_files', 'shared_contracts', 'retained_inactive_inputs', 'scope'], 'source export contract');
  require(contract.schema === 'marty.application-source-export/v1' && contract.repository === 'ElevenID/marty-ui'
    && contract.manifest_path === APPLICATION_SOURCE_MANIFEST_PATH, 'Unknown application source export contract');
  assert.deepEqual(contract.source_boundary.prefixes, ['ui/'], 'Unexpected application source boundary');
  assert.deepEqual(contract.generated_state, GENERATED, 'Unexpected generated-state exceptions');
  require(Array.isArray(contract.inputs) && contract.inputs.length === approved.files, 'The reviewed application source map has changed');
  require(Array.isArray(contract.omitted) && contract.omitted.length > 0 && contract.omitted.length <= 2048,
    'Invalid application source omission list');
  const destinations = new Set(); const sources = new Map(); let previous = '';
  for (const input of contract.inputs) {
    keys(input, ['source', 'path', 'roles'], 'source map row'); applicationSourcePath(input.source); applicationSourcePath(input.path);
    require(compare(previous, input.path) < 0 && !destinations.has(input.path.toLowerCase()), 'Source destinations must be unique and sorted');
    previous = input.path; destinations.add(input.path.toLowerCase());
    require(input.path !== APPLICATION_SOURCE_MANIFEST_PATH && Array.isArray(input.roles) && input.roles.length > 0
      && input.roles.every((role) => /^[a-z][a-z-]+$/.test(role)), 'Invalid application source role or self inventory');
    if (!sources.has(input.source)) sources.set(input.source, []); sources.get(input.source).push(input.path);
  }
  const duplicated = [...sources].filter(([, targets]) => targets.length !== 1);
  assert.deepEqual(duplicated, [
    ['ui/profiles/application/package-lock.json', ['ui/package-lock.json', 'ui/profiles/application/package-lock.json']],
    ['ui/profiles/application/package.json', ['ui/package.json', 'ui/profiles/application/package.json']],
  ], 'Only the two reviewed profile inputs may have multiple destinations');
  const mapped = contract.inputs.filter((row) => row.source !== row.path);
  assert.deepEqual(mapped.map(({ source, path: destination }) => ({ source, path: destination })), [
    { source: 'docs/restructuring/application-package-README.md', path: 'README.md' },
    { source: 'ui/profiles/application/package-lock.json', path: 'ui/package-lock.json' },
    { source: 'ui/profiles/application/package.json', path: 'ui/package.json' },
  ], 'The application source path substitutions changed');
  const omitted = new Set(); previous = '';
  for (const row of contract.omitted) {
    keys(row, ['source', 'role'], 'source omission'); applicationSourcePath(row.source);
    require(compare(previous, row.source) < 0 && !sources.has(row.source) && typeof contract.omission_categories[row.role] === 'string',
      'Application source omissions overlap or are unclassified');
    previous = row.source; omitted.add(row.source);
  }
  for (const name of contract.source_boundary.additional_files) applicationSourcePath(name);
  require(contract.test_profile.files.length === approved.test_files && contract.public_files.length === 54 && contract.shared_contracts.length === 3,
    'The selected application test/public/contract boundary changed');
  for (const name of ['LICENSE', 'README.md', ...contract.shared_contracts, 'scripts/load-secrets-env.sh', 'scripts/ui-production-start.sh', 'ui/nginx.prod.conf',
    ...contract.test_profile.files.map((name) => `ui/${name}`), ...contract.public_files.map((name) => `ui/public/${name}`)]) {
    require(destinations.has(name.toLowerCase()), `Required source package input is absent: ${name}`);
  }
  require(!destinations.has('scripts/installer_startup_process.py') && omitted.has('scripts/installer_startup_process.py'),
    'Platform process guardian must remain external diagnostic tooling');
  assert.deepEqual(contract.scope, { preserve_all_accepted_non_test_source_and_stories: true,
    source_ownership_audit_complete: false, package_graph_minimized: false, runtime_or_release_tooling_shipped: false });
  return contract;
}
function contractInput(root = ROOT) {
  const value = read(root, CONTRACT, MAX_JSON); return { ...value, contract: validateContract(parseApplicationSourceJson(value.bytes)) };
}
function manifestContract(manifest) {
  const approved = SOURCE_CONTRACTS.find((entry) => entry.sha256 === manifest?.contract?.sha256);
  require(approved, 'Application source manifest selects an unapproved source contract');
  const input = read(ROOT, approved.path, MAX_JSON);
  require(hash(input.bytes) === approved.sha256, 'Approved application source contract bytes changed');
  return { contract: validateContract(parseApplicationSourceJson(input.bytes)), approved };
}
export function applicationSourceTestPolicy(manifest) {
  const { contract, approved } = manifestContract(manifest);
  assert.deepEqual(manifest.test_profile, contract.test_profile, 'Application source test roster changed');
  return { test_profile: contract.test_profile, assertions: approved.assertions };
}
function gitInput(root, relative, state) {
  const entry = state.files.get(relative);
  require(entry && entry.type === 'blob' && ['100644', '100755'].includes(entry.mode) && OID.test(entry.oid),
    `Application source input is not an ordinary committed Git blob: ${relative}`);
  const input = read(root, relative);
  require(blobOid(input.bytes) === entry.oid, `Application source bytes differ from their Git blob: ${relative}`);
  const mode = entry.mode === '100755' ? 0o755 : 0o644;
  require(input.mode === mode, `Application source working mode differs from its Git mode: ${relative}`);
  return { bytes: input.bytes, record: { path: relative, bytes: input.bytes.length, sha256: hash(input.bytes),
    mode, git_mode: entry.mode, blob_oid: entry.oid } };
}
function dataRecord(row) {
  return { path: row.path, bytes: row.bytes, sha256: row.sha256, mode: row.mode };
}

export async function planApplicationSourceExport({ repositoryRoot = ROOT } = {}) {
  const root = ordinaryDirectory(path.resolve(repositoryRoot)); const state = sourceState(root);
  const { contract } = contractInput(root);
  const universe = [...state.files.keys()].filter((name) => name.startsWith('ui/') || contract.source_boundary.additional_files.includes(name)).sort();
  const selected = new Set(contract.inputs.map((row) => row.source));
  const omitted = new Set(contract.omitted.map((row) => row.source));
  assert.deepEqual(universe, [...new Set([...selected, ...omitted])].sort(), 'Tracked application source includes missing or unclassified inputs');
  const inputs = new Map(universe.map((name) => [name, gitInput(root, name, state)]));
  // Original checkout/profile evidence is needed only by the producer. Restore
  // and source validation have no Git, npm, browser or migration-driver import.
  const { planApplicationSourceClosure } = await import('./application-source-closure.mjs');
  const plan = planApplicationSourceClosure({ repositoryRoot: root, dependencyProfile: 'application', freshInstall: true, runtimeContext: true });
  require(plan.source.commit === state.commit && plan.source.working_tree_dirty === false, 'Source changed while the package was planned');
  assert.deepEqual(plan.test_profile, contract.test_profile, 'The selected application test contract drifted');
  assert.deepEqual([...plan.boundary.retained_public_files].sort(), [...contract.public_files].sort(), 'The selected public inventory drifted');
  assert.deepEqual(plan.boundary.omitted, contract.omitted.filter((row) => row.role === 'accepted-application-exclusion').map((row) => row.source),
    'The accepted 72 application exclusions changed');
  for (const row of plan.source.files) {
    const input = inputs.get(row.path);
    require(input && row.bytes === input.record.bytes && row.sha256 === input.record.sha256, 'Original closure inventory differs from committed source');
  }
  const files = contract.inputs.map((row) => ({ ...inputs.get(row.source).record, path: row.path, source: row.source, roles: row.roles }));
  const fixture = root !== path.resolve(ROOT);
  const manifest = {
    schema: MANIFEST_SCHEMA, fixture,
    source: { repository: contract.repository, commit: state.commit, tree: state.tree, object_format: 'sha1', working_tree_dirty: false },
    archive: { format: 'zip-stored', manifest_path: APPLICATION_SOURCE_MANIFEST_PATH, manifest_self_excluded: true, directory_mode: 0o755 },
    contract: inputs.get(CONTRACT).record, files, source_inventory_sha256: hash(canonical(files)),
    route_contract: plan.route_contract, test_profile: contract.test_profile,
    contracts: files.filter((row) => contract.shared_contracts.includes(row.path)),
    dependency_profile: { name: 'application', removed_roots: plan.dependency_profile.removed_roots,
      bun_lock_selected: false, package_graph_minimized: false },
    substitutions: plan.dependency_profile.substitutions,
    omission_policy: { source_boundary: contract.source_boundary, categories: contract.omission_categories,
      inputs: contract.omitted.map((row) => ({ ...inputs.get(row.source).record, source: row.source, role: row.role })) },
    retained_inactive_inputs: contract.retained_inactive_inputs, qualification: { ...FALSE_QUALIFICATION },
  };
  validateApplicationSourcePackageManifest(manifest, { contract });
  const manifestBytes = documentBytes(manifest);
  require(manifestBytes.length <= MAX_JSON, 'Application source manifest exceeds its bound');
  return { root, state, inputs, plan, manifest, manifestBytes,
    entries: files.map((row) => ({ path: row.path, bytes: inputs.get(row.source).bytes, mode: row.mode })) };
}

function validateRecord(row, label) {
  applicationSourcePath(row.path);
  require(Number.isSafeInteger(row.bytes) && row.bytes >= 0 && row.bytes <= APPLICATION_SOURCE_ZIP_LIMITS.fileBytes
    && DIGEST.test(row.sha256) && ['100644', '100755'].includes(row.git_mode) && OID.test(row.blob_oid)
    && row.mode === (row.git_mode === '100755' ? 0o755 : 0o644), `Invalid ${label} byte/Git identity`);
}
export function validateApplicationSourcePackageManifest(manifest, { contract = manifestContract(manifest).contract } = {}) {
  validateContract(contract);
  keys(manifest, ['schema', 'fixture', 'source', 'archive', 'contract', 'files', 'source_inventory_sha256', 'route_contract', 'test_profile',
    'contracts', 'dependency_profile', 'substitutions', 'omission_policy', 'retained_inactive_inputs', 'qualification'], 'source manifest');
  require(manifest.schema === MANIFEST_SCHEMA && typeof manifest.fixture === 'boolean', 'Unknown application source manifest');
  keys(manifest.source, ['repository', 'commit', 'tree', 'object_format', 'working_tree_dirty'], 'source origin');
  require(manifest.source.repository === contract.repository && OID.test(manifest.source.commit) && OID.test(manifest.source.tree)
    && manifest.source.object_format === 'sha1' && manifest.source.working_tree_dirty === false, 'Application source origin must be an exact clean commit');
  assert.deepEqual(manifest.archive, { format: 'zip-stored', manifest_path: APPLICATION_SOURCE_MANIFEST_PATH,
    manifest_self_excluded: true, directory_mode: 0o755 }, 'Unreviewed application source archive format');
  require(Array.isArray(manifest.files) && manifest.files.length === contract.inputs.length, 'Application source inventory is incomplete');
  let total = 0;
  for (let index = 0; index < manifest.files.length; index++) {
    const row = manifest.files[index]; const wanted = contract.inputs[index];
    keys(row, ['path', 'source', 'bytes', 'sha256', 'mode', 'git_mode', 'blob_oid', 'roles'], 'source file'); validateRecord(row, 'source file');
    assert.deepEqual({ path: row.path, source: row.source, roles: row.roles }, wanted, 'Application source path map changed'); total += row.bytes;
  }
  require(total <= APPLICATION_SOURCE_ZIP_LIMITS.archiveBytes && manifest.source_inventory_sha256 === hash(canonical(manifest.files)),
    'Application source inventory digest or total size differs');
  keys(manifest.contract, ['path', 'bytes', 'sha256', 'mode', 'git_mode', 'blob_oid'], 'source contract'); validateRecord(manifest.contract, 'source contract');
  const contractBytes = Buffer.from(`${JSON.stringify(contract, null, 2)}\n`);
  require(manifest.contract.path === CONTRACT && manifest.contract.bytes === contractBytes.length
    && manifest.contract.sha256 === hash(contractBytes) && manifest.contract.blob_oid === blobOid(contractBytes),
    'Application source manifest selects a different reviewed contract');
  keys(manifest.route_contract, ['version', 'sha256'], 'route contract');
  require(Number.isInteger(manifest.route_contract.version) && manifest.route_contract.version > 0 && DIGEST.test(manifest.route_contract.sha256),
    'Invalid application route contract identity');
  assert.deepEqual(manifest.test_profile, contract.test_profile, 'Application source test roster changed');
  assert.deepEqual(manifest.contracts, manifest.files.filter((row) => contract.shared_contracts.includes(row.path)), 'Application source contract inventory differs');
  keys(manifest.dependency_profile, ['name', 'removed_roots', 'bun_lock_selected', 'package_graph_minimized'], 'dependency profile');
  assert.deepEqual(manifest.dependency_profile, { name: 'application', removed_roots: [
    '@elevenid/marty-blog', '@prerenderer/rollup-plugin', '@prerenderer/renderer-puppeteer', 'vite-plugin-sitemap',
  ], bun_lock_selected: false, package_graph_minimized: false }, 'Application source dependency selection changed');
  require(Array.isArray(manifest.substitutions) && manifest.substitutions.length === 2, 'Application source requires exactly two profile substitutions');
  assert.deepEqual(manifest.substitutions.map((row) => row.path), SUBSTITUTIONS, 'Application source substitutions changed');
  for (const row of manifest.substitutions) {
    keys(row, ['path', 'baseline', 'selected'], 'profile substitution');
    for (const item of [row.baseline, row.selected]) {
      keys(item, ['path', 'bytes', 'sha256', 'mode'], 'substitution input'); applicationSourcePath(item.path);
      require(Number.isSafeInteger(item.bytes) && item.bytes >= 0 && DIGEST.test(item.sha256) && item.mode === 0o644, 'Invalid profile substitution input');
    }
    const selected = manifest.files.find((file) => file.path === row.path);
    const copy = manifest.files.find((file) => file.path === row.selected.path);
    require(row.baseline.path === row.path && row.selected.path === `ui/profiles/application/${path.posix.basename(row.path)}`
      && copy && selected.source === copy.source && selected.blob_oid === copy.blob_oid, 'Application profile provenance copies differ');
    assert.deepEqual(dataRecord(copy), row.selected, 'Selected profile input differs from its provenance copy');
    assert.deepEqual({ ...dataRecord(selected), path: row.selected.path }, row.selected, 'Materialized profile differs from selected bytes');
  }
  keys(manifest.omission_policy, ['source_boundary', 'categories', 'inputs'], 'omission policy');
  assert.deepEqual(manifest.omission_policy.source_boundary, contract.source_boundary);
  assert.deepEqual(manifest.omission_policy.categories, contract.omission_categories);
  require(Array.isArray(manifest.omission_policy.inputs) && manifest.omission_policy.inputs.length === contract.omitted.length,
    'Application source omission inventory is incomplete');
  for (let index = 0; index < contract.omitted.length; index++) {
    const row = manifest.omission_policy.inputs[index]; const wanted = contract.omitted[index];
    keys(row, ['path', 'source', 'role', 'bytes', 'sha256', 'mode', 'git_mode', 'blob_oid'], 'omitted source'); validateRecord(row, 'omitted source');
    require(row.path === wanted.source && row.source === wanted.source && row.role === wanted.role, 'Application source omissions changed');
  }
  for (const row of manifest.substitutions) {
    assert.deepEqual(dataRecord(manifest.omission_policy.inputs.find((item) => item.path === row.path)), row.baseline,
      'Baseline dependency input differs from its declared omission');
  }
  assert.deepEqual(manifest.retained_inactive_inputs, contract.retained_inactive_inputs);
  assert.deepEqual(manifest.qualification, FALSE_QUALIFICATION, 'Source package broadened its qualification');
  return manifest;
}

export function validateApplicationSourceBaseline(report, { plan } = {}) {
  require(report?.schema === 'marty.application-source-closure-rehearsal/v5' && report.status === 'passed'
    && (report.fixture === undefined || report.fixture === false)
    && report.plan?.schema === 'marty.application-source-closure-plan/v5', 'Source package requires a passed actual v5 application baseline');
  require(plan?.schema === 'marty.application-source-closure-plan/v5' && !plan.source.working_tree_dirty, 'Source package requires a clean current profile plan');
  assert.deepEqual(report.plan.source, plan.source, 'Source package baseline source differs');
  for (const name of ['route_contract', 'test_profile', 'boundary', 'dependency_profile']) assert.deepEqual(report.plan[name], plan[name], `Baseline ${name} differs`);
  require(report.plan.source.input_inventory_sha256 === hash(canonical(report.plan.source.files)), 'Baseline source inventory digest differs');
  require(report.build?.dependency_mode === 'fresh-npm-ci' && report.build.dependency_profile === 'application'
    && report.build.effective_source_sha === plan.source.commit
    && report.build.package_lock_sha256 === plan.dependency_profile.source_inputs.find((row) => row.path.endsWith('/package-lock.json')).sha256,
  'Baseline build did not use the current application lock/source');
  require(report.dependency_install?.status === 'passed' && report.dependency_install.mode === 'fresh-npm-ci'
    && report.dependency_install.dependency_profile === 'application' && report.dependency_install.independent_dependency_installation === true
    && report.dependency_install.bun_lock_selected === false && report.dependency_install.sdk?.initialized_in_node === true,
  'Baseline did not prove an independent application dependency install');
  for (const key of ['application_build_completed', 'application_tests_completed', 'omitted_sources_absent', 'application_output_checked',
    'source_checkout_unchanged', 'public_assets_preserved', 'application_resource_smoke_completed', 'locale_fallback_observed',
    'sdk_wasm_initialized_in_node', 'sdk_wasm_output_bound', 'independent_dependency_installation']) {
    require(report.qualification?.[key] === true, `Baseline did not qualify ${key}`);
  }
  for (const key of ['source_extraction_complete', 'package_graph_minimized', 'browser_startup_observed', 'container_runtime_tested',
    'oidc_journey_tested', 'host_deployment_tested', 'signed_release_produced']) {
    require(report.qualification?.[key] === false, 'Baseline report broadened its qualification');
  }
  require(report.dependency_profile?.name === 'application' && report.dependency_profile.bun_lock_selected === false
    && report.dependency_profile.output_identical_to_full_profile === true
    && Array.isArray(report.dependency_profile.materialized_inputs), 'Baseline profile evidence is incomplete');
  assert.deepEqual(report.dependency_profile.materialized_inputs.map(({ path: name, baseline, selected }) => ({ path: name, baseline, selected })),
    plan.dependency_profile.substitutions, 'Baseline profile materializations differ');
  for (const row of report.dependency_profile.materialized_inputs) assert.deepEqual(row.materialized,
    { ...row.selected, path: row.path, mode: 0o600 }, 'Baseline materialized profile bytes differ');
  assert.deepEqual(report.tests?.selected_files, plan.test_profile.files, 'Baseline selected tests differ');
  assert.deepEqual(report.tests?.result?.completed_files, [...plan.test_profile.files].sort(), 'Baseline did not complete every selected test');
  require(Number.isSafeInteger(report.tests.result.test_count) && report.tests.result.test_count >= plan.test_profile.files.length
    && DIGEST.test(report.tests.result.report_sha256), 'Baseline test evidence is incomplete');
  require(Array.isArray(report.output?.files) && report.output.files.length > 0
    && report.output.inventory_sha256 === hash(canonical(report.output.files)), 'Baseline output digest differs');
  const seen = new Set();
  for (const row of report.output.files) {
    applicationSourcePath(row.path);
    require(!seen.has(row.path) && Number.isSafeInteger(row.bytes) && row.bytes > 0 && DIGEST.test(row.sha256) && [0o600, 0o644].includes(row.mode),
      'Baseline output inventory is invalid'); seen.add(row.path);
  }
  const expectedPublic = plan.boundary.retained_public_files.map((name) => {
    const row = plan.source.files.find((item) => item.path === `ui/public/${name}`);
    return { path: name, bytes: row.bytes, sha256: row.sha256 };
  });
  assert.deepEqual(report.output.public_resources, expectedPublic, 'Baseline public resources differ');
  require(report.resources?.result?.schema === 'marty.application-resource-smoke/v1' && report.resources.result.status === 'passed'
    && report.resources.result.preview?.closed === true && report.resources.result.qualification?.resources_served === true,
  'Baseline resource smoke was not completed');
  assert.deepEqual(report.resources.result.public_resources, expectedPublic, 'Baseline resource probe differs');
  const comparison = report.dependency_profile.baseline_comparison;
  for (const key of ['full_profile_fresh_install_passed', 'same_source_inputs', 'same_route_and_test_contracts', 'output_files_identical', 'public_resources_identical']) {
    require(comparison?.[key] === true, 'Baseline full/profile comparison is incomplete');
  }
  require(comparison.output_inventory_sha256 === report.output.inventory_sha256 && comparison.output_files === report.output.files.length
    && comparison.public_resources === expectedPublic.length, 'Baseline output comparison digest/counts differ');
  const emitted = report.output.files.filter((row) => /^assets\/marty_api_client_bg-[^/]+\.wasm$/.test(row.path));
  require(emitted.length === 1 && emitted[0].bytes === report.dependency_install.sdk.wasm?.bytes
    && emitted[0].sha256 === report.dependency_install.sdk.wasm?.sha256, 'Baseline SDK WASM output differs');
  return report;
}

function sourceUnchanged(prepared) {
  const after = sourceState(prepared.root);
  require(after.commit === prepared.state.commit && after.tree === prepared.state.tree, 'Application source commit changed during export');
  for (const [name, original] of prepared.inputs) assert.deepEqual(gitInput(prepared.root, name, after).record, original.record,
    'Application source changed during export');
}
function receiptBytes(value, label) {
  keys(value, ['bytes', 'sha256'], label);
  require(Number.isSafeInteger(value.bytes) && value.bytes > 0 && DIGEST.test(value.sha256), `Invalid ${label} identity`);
}
export function validateApplicationSourceProducerReceipt(receipt, { archiveSha256, manifestSha256, manifest, baselineReportSha256 } = {}) {
  validateApplicationSourcePackageManifest(manifest);
  keys(receipt, ['schema', 'status', 'fixture', 'source_commit', 'source_tree', 'archive', 'manifest', 'baseline_report',
    'source_inventory_sha256', 'source_preserved', 'archive_manifest_identical', 'qualification'], 'producer receipt');
  require(receipt.schema === RECEIPT_SCHEMA && receipt.fixture === manifest.fixture
    && receipt.status === (receipt.fixture ? 'fixture-passed' : 'passed'), 'Invalid source producer receipt status');
  require(receipt.source_commit === manifest.source.commit && receipt.source_tree === manifest.source.tree
    && receipt.source_inventory_sha256 === manifest.source_inventory_sha256 && receipt.source_preserved === true
    && receipt.archive_manifest_identical === true, 'Source producer receipt does not bind the manifest');
  for (const key of ['archive', 'manifest', 'baseline_report']) receiptBytes(receipt[key], `producer ${key}`);
  const bytes = documentBytes(manifest);
  require(receipt.manifest.bytes === bytes.length && receipt.manifest.sha256 === hash(bytes)
    && receipt.manifest.sha256 === manifestSha256 && DIGEST.test(archiveSha256) && receipt.archive.sha256 === archiveSha256
    && DIGEST.test(baselineReportSha256) && receipt.baseline_report.sha256 === baselineReportSha256,
  'Source producer receipt pins differ');
  assert.deepEqual(receipt.qualification, { source_package_created: !receipt.fixture, same_source_profile_baseline_bound: !receipt.fixture,
    ...FALSE_QUALIFICATION }, 'Producer receipt broadened its qualification');
  return receipt;
}

export async function exportApplicationSourcePackage({ repositoryRoot = ROOT, archivePath, manifestPath, reportPath, baselineReportPath } = {}) {
  const prepared = await planApplicationSourceExport({ repositoryRoot });
  const targets = [archivePath, manifestPath, reportPath].map((name) => newPath(name, prepared.root));
  require(new Set(targets).size === targets.length, 'Source package output paths must be distinct');
  require(path.extname(archivePath) === '.zip' && path.extname(manifestPath) === '.json' && path.extname(reportPath) === '.json',
    'Source package output extensions must be ZIP/JSON');
  require(outside(prepared.root, baselineReportPath), 'Baseline report must be outside the source checkout');
  const baselineInput = readAbsolute(baselineReportPath, MAX_JSON);
  validateApplicationSourceBaseline(parseApplicationSourceJson(baselineInput.bytes), { plan: prepared.plan });
  const entries = [...prepared.entries, { path: APPLICATION_SOURCE_MANIFEST_PATH, bytes: prepared.manifestBytes, mode: 0o644 }];
  const archive = encodeApplicationSourceZip(entries);
  const decoded = decodeApplicationSourceZip(archive);
  assert.deepEqual(decoded.map((row) => ({ path: row.path, bytes: row.bytes.length, sha256: hash(row.bytes), mode: row.mode })),
    entries.map((row) => ({ path: row.path, bytes: row.bytes.length, sha256: hash(row.bytes), mode: row.mode })).sort((a, b) => compare(a.path, b.path)),
  'Source archive round-trip differs');
  sourceUnchanged(prepared);
  require(readAbsolute(baselineReportPath, MAX_JSON).bytes.equals(baselineInput.bytes), 'Baseline report changed during export');
  const receipt = { schema: RECEIPT_SCHEMA, status: prepared.manifest.fixture ? 'fixture-passed' : 'passed', fixture: prepared.manifest.fixture,
    source_commit: prepared.state.commit, source_tree: prepared.state.tree,
    archive: { bytes: archive.length, sha256: hash(archive) }, manifest: { bytes: prepared.manifestBytes.length, sha256: hash(prepared.manifestBytes) },
    baseline_report: { bytes: baselineInput.bytes.length, sha256: hash(baselineInput.bytes) },
    source_inventory_sha256: prepared.manifest.source_inventory_sha256, source_preserved: true, archive_manifest_identical: true,
    qualification: { source_package_created: !prepared.manifest.fixture, same_source_profile_baseline_bound: !prepared.manifest.fixture, ...FALSE_QUALIFICATION } };
  validateApplicationSourceProducerReceipt(receipt, { archiveSha256: receipt.archive.sha256, manifestSha256: receipt.manifest.sha256,
    manifest: prepared.manifest, baselineReportSha256: receipt.baseline_report.sha256 });
  const created = [];
  try {
    for (const [name, bytes] of [[archivePath, archive], [manifestPath, prepared.manifestBytes], [reportPath, documentBytes(receipt)]]) {
      writeFileSync(name, bytes, { flag: 'wx', mode: 0o644 }); created.push(name); chmodSync(name, 0o644);
    }
    sourceUnchanged(prepared);
  } catch (error) { for (const name of created) rmSync(name, { force: true }); throw error; }
  return receipt;
}

export function validateApplicationSourceInventory({ destination, manifest, allowGenerated = false } = {}) {
  const root = ordinaryDirectory(destination); validateApplicationSourcePackageManifest(manifest);
  require(typeof allowGenerated === 'boolean', 'Generated source validation policy must be explicit');
  const expected = new Map(manifest.files.map((row) => [row.path, row]));
  const directories = new Set();
  for (const name of [...expected.keys(), APPLICATION_SOURCE_MANIFEST_PATH]) {
    const parts = name.split('/'); for (let index = 1; index < parts.length; index++) directories.add(parts.slice(0, index).join('/'));
  }
  const seen = new Set(); const generated = [];
  function visit(directory, prefix = '') {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      applicationSourcePath(relative); require(!entry.isSymbolicLink(), 'Restored application source contains a link');
      if (allowGenerated && GENERATED.includes(relative)) {
        require(entry.isDirectory(), 'Generated dependency/output root must be an ordinary directory'); generated.push(relative); continue;
      }
      if (entry.isDirectory()) { require(directories.has(relative), `Unexpected restored source directory: ${relative}`); visit(path.join(directory, entry.name), relative); }
      else {
        require(entry.isFile(), 'Restored application source contains a special file');
        const actual = read(root, relative, relative === APPLICATION_SOURCE_MANIFEST_PATH ? MAX_JSON : undefined);
        if (relative === APPLICATION_SOURCE_MANIFEST_PATH) {
          require(actual.mode === 0o644 && actual.bytes.equals(documentBytes(manifest)), 'Internal application source manifest changed');
        } else {
          const wanted = expected.get(relative);
          require(wanted && actual.bytes.length === wanted.bytes && hash(actual.bytes) === wanted.sha256
            && blobOid(actual.bytes) === wanted.blob_oid && actual.mode === wanted.mode, `Restored source bytes or mode differ: ${relative}`);
        }
        seen.add(relative);
      }
    }
  }
  visit(root);
  assert.deepEqual([...seen].sort(), [...expected.keys(), APPLICATION_SOURCE_MANIFEST_PATH].sort(), 'Restored source inventory is incomplete');
  return { root, source_inventory_sha256: manifest.source_inventory_sha256, files: manifest.files.length,
    source_preserved: true, generated_roots: generated.sort() };
}

export function restoreApplicationSourcePackage({ archivePath, manifestPath, expectedArchiveSha256, expectedManifestSha256, destination } = {}) {
  require(DIGEST.test(expectedArchiveSha256) && DIGEST.test(expectedManifestSha256), 'Source restore requires independent archive and manifest SHA-256 pins');
  newPath(destination);
  const archive = readAbsolute(archivePath, APPLICATION_SOURCE_ZIP_LIMITS.archiveBytes).bytes;
  const external = readAbsolute(manifestPath, MAX_JSON).bytes;
  require(hash(archive) === expectedArchiveSha256 && hash(external) === expectedManifestSha256, 'Application source artifact pins differ');
  const manifest = validateApplicationSourcePackageManifest(parseApplicationSourceJson(external));
  require(external.equals(documentBytes(manifest)), 'Application source manifest encoding is not canonical');
  const entries = decodeApplicationSourceZip(archive);
  const expected = new Map(manifest.files.map((row) => [row.path, row]));
  require(entries.length === expected.size + 1, 'Source ZIP membership differs from its manifest');
  let internal = false;
  for (const entry of entries) {
    if (entry.path === APPLICATION_SOURCE_MANIFEST_PATH) {
      require(entry.bytes.equals(external) && entry.mode === 0o644, 'Internal and external source manifests differ'); internal = true;
    } else {
      const wanted = expected.get(entry.path);
      require(wanted && entry.bytes.length === wanted.bytes && hash(entry.bytes) === wanted.sha256
        && blobOid(entry.bytes) === wanted.blob_oid && entry.mode === wanted.mode, `Source ZIP file differs from its manifest: ${entry.path}`);
    }
  }
  require(internal, 'Source ZIP is missing its internal origin manifest');
  let owned = false;
  try {
    mkdirSync(destination, { mode: 0o700 }); owned = true;
    for (const entry of entries) {
      const parent = path.dirname(path.join(destination, entry.path)); mkdirSync(parent, { recursive: true, mode: 0o755 });
      ordinaryDirectory(parent);
      const target = path.join(destination, entry.path); writeFileSync(target, entry.bytes, { flag: 'wx', mode: entry.mode }); chmodSync(target, entry.mode);
    }
    chmodSync(destination, 0o755);
    validateApplicationSourceInventory({ destination, manifest });
  } catch (error) { if (owned) rmSync(destination, { recursive: true, force: true }); throw error; }
  return { root: destination, manifest, archive_sha256: expectedArchiveSha256, manifest_sha256: expectedManifestSha256,
    source_inventory_sha256: manifest.source_inventory_sha256 };
}

async function main() {
  const names = new Map([['--archive', 'archivePath'], ['--manifest', 'manifestPath'], ['--report', 'reportPath'], ['--baseline-report', 'baselineReportPath']]);
  const args = process.argv.slice(2); const options = {};
  while (args.length) {
    const name = names.get(args.shift()); require(name && !Object.hasOwn(options, name) && args.length, 'Unknown, repeated or incomplete source export option');
    options[name] = args.shift();
  }
  require(Object.keys(options).length === names.size, 'Source export requires --archive, --manifest, --report and --baseline-report');
  const result = await exportApplicationSourcePackage(options);
  console.log(JSON.stringify({ status: result.status, source_commit: result.source_commit, archive: result.archive, manifest: result.manifest }));
}

if (process.argv[1] && path.resolve(process.argv[1]) === SELF) {
  // The planner imports the closure, which imports this module's policy.
  // Complete module evaluation before awaiting that CLI work.
  main().catch((error) => { console.error(`Application source export failed: ${error.message}`); process.exitCode = 1; });
}
