import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import {
  chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync,
  rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import os from 'node:os';
import { syncBuiltinESMExports } from 'node:module';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import {
  APPLICATION_SOURCE_MANIFEST_PATH, applicationSourceTestPolicy, exportApplicationSourcePackage, parseApplicationSourceJson,
  planApplicationSourceExport, restoreApplicationSourcePackage, validateApplicationSourceBaseline,
  validateApplicationSourceInventory, validateApplicationSourcePackageManifest, validateApplicationSourceProducerReceipt,
} from './export-application-source.mjs';
import { applicationSourcePath, decodeApplicationSourceZip, encodeApplicationSourceZip } from './application-source-zip.mjs';

const ROOT = fileURLToPath(new URL('../../', import.meta.url));
const CONTRACT = 'contracts/application-source-export.json';
function digest(bytes) { return `sha256:${createHash('sha256').update(bytes).digest('hex')}`; }
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function document(value) { return Buffer.from(`${canonical(value)}\n`); }
function temporary(t) {
  const directory = mkdtempSync(path.join(os.tmpdir(), 'application-source-package-test-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return directory;
}
function git(root, ...args) {
  return execFileSync('git', ['-C', root, '-c', 'user.name=Source package fixture',
    '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', ...args],
  { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
}
function sourceFixture(t, sourceRoot = ROOT) {
  const directory = temporary(t); const root = path.join(directory, 'source'); mkdirSync(root);
  // The later Website Surface tests run after CI rewrites dependency URIs and
  // its working Bun lock. Build this protocol fixture from the exact committed
  // Git objects, as the earlier source-package gate does before that bootstrap.
  const commit = git(sourceRoot, 'rev-parse', 'HEAD').trim();
  const contract = parseApplicationSourceJson(git(sourceRoot, 'show', `${commit}:${CONTRACT}`));
  const sources = [...new Set([...contract.inputs.map((row) => row.source), ...contract.omitted.map((row) => row.source)])];
  const tree = new Map(git(sourceRoot, 'ls-tree', '-r', '-z', commit).split('\0').filter(Boolean).map((row) => {
    const tab = row.indexOf('\t'); const [mode, type, oid] = row.slice(0, tab).split(' ');
    return [row.slice(tab + 1), { mode, type, oid }];
  }));
  const selected = sources.map((name) => {
    const entry = tree.get(name);
    assert.ok(entry && entry.type === 'blob' && ['100644', '100755'].includes(entry.mode), `Missing committed ordinary fixture input: ${name}`);
    return { name, ...entry };
  });
  const objects = execFileSync('git', ['-C', sourceRoot, 'cat-file', '--batch'], {
    input: `${selected.map((row) => row.oid).join('\n')}\n`, maxBuffer: 64 * 1024 * 1024,
  });
  let offset = 0;
  for (const row of selected) {
    const end = objects.indexOf(10, offset); assert.ok(end >= offset, 'Incomplete fixture Git object header');
    const [oid, type, length] = objects.subarray(offset, end).toString('ascii').split(' ');
    assert.equal(oid, row.oid); assert.equal(type, 'blob');
    const size = Number(length); assert.ok(Number.isSafeInteger(size) && size >= 0 && end + size + 1 < objects.length);
    const target = path.join(root, row.name); mkdirSync(path.dirname(target), { recursive: true });
    const mode = row.mode === '100755' ? 0o755 : 0o644;
    writeFileSync(target, objects.subarray(end + 1, end + 1 + size)); chmodSync(target, mode);
    offset = end + 1 + size; assert.equal(objects[offset++], 10, 'Missing fixture Git object terminator');
  }
  assert.equal(offset, objects.length, 'Unexpected fixture Git object data');
  git(root, 'init', '--quiet'); git(root, 'add', '--force', '.'); git(root, 'commit', '--quiet', '-m', 'Source package protocol fixture');
  return { directory, root };
}

// This exercises the report protocol only. Its separate source Git root makes
// the producer emit fixture-passed with every qualification flag false; no
// installation, browser, or runtime claim comes from this synthetic baseline.
function protocolBaseline(plan) {
  const publicResources = plan.boundary.retained_public_files.map((name) => {
    const source = plan.source.files.find((row) => row.path === `ui/public/${name}`);
    return { path: name, bytes: source.bytes, sha256: source.sha256 };
  });
  const wasm = Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]);
  const files = [...publicResources.map((row) => ({ ...row, mode: 0o600 })),
    { path: 'assets/marty_api_client_bg-fixture.wasm', bytes: wasm.length, sha256: digest(wasm), mode: 0o644 }]
    .sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
  const inventory = digest(canonical(files));
  return {
    schema: 'marty.application-source-closure-rehearsal/v5', status: 'passed', plan,
    build: { dependency_mode: 'fresh-npm-ci', dependency_profile: 'application', effective_source_sha: plan.source.commit,
      package_lock_sha256: plan.dependency_profile.source_inputs.find((row) => row.path.endsWith('/package-lock.json')).sha256 },
    dependency_install: { status: 'passed', mode: 'fresh-npm-ci', dependency_profile: 'application',
      independent_dependency_installation: true, bun_lock_selected: false,
      sdk: { initialized_in_node: true, wasm: { bytes: wasm.length, sha256: digest(wasm) } } },
    qualification: Object.fromEntries([
      ...['application_build_completed', 'application_tests_completed', 'omitted_sources_absent', 'application_output_checked',
        'source_checkout_unchanged', 'public_assets_preserved', 'application_resource_smoke_completed', 'locale_fallback_observed',
        'sdk_wasm_initialized_in_node', 'sdk_wasm_output_bound', 'independent_dependency_installation'].map((key) => [key, true]),
      ...['source_extraction_complete', 'package_graph_minimized', 'browser_startup_observed', 'container_runtime_tested',
        'oidc_journey_tested', 'host_deployment_tested', 'signed_release_produced'].map((key) => [key, false]),
    ]),
    dependency_profile: { name: 'application', bun_lock_selected: false, output_identical_to_full_profile: true,
      materialized_inputs: plan.dependency_profile.substitutions.map((row) => ({ ...row,
        materialized: { ...row.selected, path: row.path, mode: 0o600 } })),
      baseline_comparison: { full_profile_fresh_install_passed: true, same_source_inputs: true, same_route_and_test_contracts: true,
        output_files_identical: true, public_resources_identical: true, output_inventory_sha256: inventory,
        output_files: files.length, public_resources: publicResources.length } },
    tests: { selected_files: plan.test_profile.files,
      result: { completed_files: [...plan.test_profile.files].sort(), test_count: 367, report_sha256: digest('Synthetic protocol fixture') } },
    output: { files, inventory_sha256: inventory, public_resources: publicResources },
    resources: { result: { schema: 'marty.application-resource-smoke/v1', status: 'passed', preview: { closed: true },
      qualification: { resources_served: true }, public_resources: publicResources } },
  };
}
function artifacts(directory, suffix = '') {
  return { archivePath: path.join(directory, `source${suffix}.zip`), manifestPath: path.join(directory, `source${suffix}.json`),
    reportPath: path.join(directory, `producer${suffix}.json`) };
}

test('stored source ZIP is deterministic, round-trips binary bytes, and preserves executable modes', () => {
  const entries = [{ path: 'ui/start.sh', bytes: Buffer.from('#!/bin/sh\n'), mode: 0o755 },
    { path: 'LICENSE', bytes: Buffer.from([0, 255, 1, 0, 128]), mode: 0o644 }];
  const encoded = encodeApplicationSourceZip(entries);
  assert.deepEqual(encoded, encodeApplicationSourceZip([...entries].reverse()));
  assert.deepEqual(decodeApplicationSourceZip(encoded), [...entries].reverse());
});

test('source paths reject traversal, alternate separators, reserved filenames, and collisions', () => {
  for (const name of ['../outside', '/root', 'a/../b', 'a//b', 'a\\b', 'a/', 'a/.', 'a/b.', 'AUX.txt', 'dir/COM1', 'x\0y']) {
    assert.throws(() => applicationSourcePath(name), /Unsafe/);
  }
  for (const names of [['File', 'file'], ['ui', 'ui/source.js'], ['UI', 'ui/source.js']]) {
    assert.throws(() => encodeApplicationSourceZip(names.map((name) => ({ path: name, bytes: Buffer.alloc(0), mode: 0o644 }))),
      /Duplicate|collision/);
  }
});

test('source ZIP rejects ambiguous headers, links, compression, corruption, and trailing bytes', () => {
  const original = encodeApplicationSourceZip([{ path: 'a.txt', bytes: Buffer.from('hello'), mode: 0o644 }]);
  const central = original.readUInt32LE(original.length - 6);
  const changes = [
    ['local compression', (bytes) => bytes.writeUInt16LE(8, 8)],
    ['central compression', (bytes) => bytes.writeUInt16LE(8, central + 10)],
    ['encryption flag', (bytes) => bytes.writeUInt16LE(0x801, central + 8)],
    ['data descriptor', (bytes) => bytes.writeUInt16LE(0x808, central + 8)],
    ['symlink type', (bytes) => bytes.writeUInt32LE((0o120644 << 16) >>> 0, central + 38)],
    ['special mode', (bytes) => bytes.writeUInt32LE((0o104644 << 16) >>> 0, central + 38)],
    ['timestamp', (bytes) => bytes.writeUInt16LE(1, central + 12)],
    ['local filename mismatch', (bytes) => { bytes[30] = 'b'.charCodeAt(0); }],
    ['payload corruption', (bytes) => { bytes[35] ^= 1; }],
    ['incorrect directory size', (bytes) => bytes.writeUInt32LE(0, bytes.length - 10)],
    ['traversal', (bytes) => { bytes.write('../aa', 30); bytes.write('../aa', central + 46); }],
  ];
  for (const [label, mutate] of changes) {
    const bytes = Buffer.from(original); mutate(bytes); assert.throws(() => decodeApplicationSourceZip(bytes), undefined, label);
  }
  assert.throws(() => decodeApplicationSourceZip(Buffer.concat([original, Buffer.from('x')])), /trailing/);
  assert.throws(() => decodeApplicationSourceZip(original.subarray(0, 15)), /Invalid/);
});

test('source JSON rejects escaped duplicate keys, non-UTF-8, excessive depth and oversized documents', () => {
  assert.deepEqual(parseApplicationSourceJson('{"outer":{"x":"quoted \\\" value"}}'), { outer: { x: 'quoted " value' } });
  for (const text of ['{"status":"failed","status":"passed"}', '{"outer":{"sha256":"a","sha\\u0032\\u0035\\u0036":"b"}}']) {
    assert.throws(() => parseApplicationSourceJson(text), /Duplicate/);
  }
  assert.throws(() => parseApplicationSourceJson(Buffer.from([123, 34, 120, 34, 58, 34, 255, 34, 125])), /UTF-8/);
  assert.throws(() => parseApplicationSourceJson(`{"x":${'['.repeat(129)}0${']'.repeat(129)}}`), /nesting/);
  assert.throws(() => parseApplicationSourceJson('{}', { maxBytes: 1 }), /bound/);
});

test('historical source-map selection preserves its exact inventory and rejects altered or unknown maps', async (t) => {
  const { root } = sourceFixture(t);
  const prepared = await planApplicationSourceExport({ repositoryRoot: root });
  const originalInputs = new Map([...prepared.manifest.files, ...prepared.manifest.omission_policy.inputs]
    .map((row) => [row.source, row]));
  for (const accepted of [
    { path: 'initial-v1.json', files: 575, assertions: 296,
      sha256: 'sha256:3b7fe6dfe7718c3d7bcc9d0fccf28c2e4d92a0bcdad1f592c86a51328669d8ad' },
    { path: 'before-static-auth-origins-v1.json', files: 581, assertions: 321,
      sha256: 'sha256:7df5cfa6e3c37f9c1c3c3a8034559608971ad4dca60954013c5487e41b270f41' },
  ]) {
  const legacyBytes = readFileSync(path.join(ROOT, 'contracts/application-source-export-history', accepted.path));
  const legacyContract = parseApplicationSourceJson(legacyBytes);
  assert.equal(digest(legacyBytes), accepted.sha256);
  // A structural fixture tests archived map selection. It makes no claim that
  // this current-source synthetic projection was executed or released earlier.
  const historical = structuredClone(prepared.manifest);
  historical.contract = { path: CONTRACT, bytes: legacyBytes.length, sha256: digest(legacyBytes), mode: 0o644, git_mode: '100644',
    blob_oid: createHash('sha1').update(Buffer.from(`blob ${legacyBytes.length}\0`)).update(legacyBytes).digest('hex') };
  historical.files = legacyContract.inputs.map((wanted) => {
    const existing = historical.files.find((entry) => entry.path === wanted.path);
    assert.ok(existing, wanted.path);
    return { ...existing, ...wanted };
  });
  historical.source_inventory_sha256 = digest(canonical(historical.files));
  historical.test_profile = legacyContract.test_profile;
  historical.omission_policy.categories = legacyContract.omission_categories;
  // A test promoted into today's selected suite was an omission in older
  // accepted maps. Reconstruct that map's full inventory from committed
  // records instead of carrying today's smaller omission list into it.
  historical.omission_policy.inputs = legacyContract.omitted.map((wanted) => {
    const existing = originalInputs.get(wanted.source); assert.ok(existing, wanted.source);
    const { bytes, sha256, mode, git_mode, blob_oid } = existing;
    return { path: wanted.source, ...wanted, bytes, sha256, mode, git_mode, blob_oid };
  });
  historical.retained_inactive_inputs = legacyContract.retained_inactive_inputs;
  validateApplicationSourcePackageManifest(historical);
  assert.equal(historical.files.length, accepted.files);
  assert.equal(applicationSourceTestPolicy(historical).assertions, accepted.assertions);
  const missing = structuredClone(historical); missing.files.pop();
  missing.source_inventory_sha256 = digest(canonical(missing.files));
  assert.throws(() => validateApplicationSourcePackageManifest(missing), /inventory is incomplete/);
  const unknown = structuredClone(historical); unknown.contract.sha256 = `sha256:${'0'.repeat(64)}`;
  assert.throws(() => validateApplicationSourcePackageManifest(unknown), /unapproved source contract/);
  const arbitrary = structuredClone(legacyContract); arbitrary.inputs.pop();
  assert.throws(() => validateApplicationSourcePackageManifest(historical, { contract: arbitrary }), /not an approved/);
  }
});

test('source exporter CLI resolves its closure import before bounded baseline refusal', (t) => {
  const { directory, root } = sourceFixture(t);
  const relative = 'ui/scripts/export-application-source.mjs';
  const entry = path.join(root, relative);
  // Exercise the current CLI in a clean, isolated Git fixture, including when
  // these changes have not been committed to the checkout running this test.
  writeFileSync(entry, readFileSync(new URL('./export-application-source.mjs', import.meta.url)));
  git(root, 'add', relative);
  git(root, 'commit', '--allow-empty', '--quiet', '-m', 'Current source exporter CLI fixture');
  const output = artifacts(directory, '-cli');
  const baseline = path.join(directory, 'absent-baseline.json');
  const child = spawnSync(process.execPath, [entry,
    '--archive', output.archivePath, '--manifest', output.manifestPath,
    '--report', output.reportPath, '--baseline-report', baseline],
  { cwd: root, encoding: 'utf8', timeout: 30_000, maxBuffer: 1024 * 1024 });
  assert.equal(child.error, undefined);
  assert.equal(child.signal, null);
  assert.equal(child.status, 1, child.stderr);
  assert.match(child.stderr, /Application source export failed: ENOENT:/);
  assert.ok(child.stderr.includes(baseline), 'The CLI must reach the baseline read after planning');
  assert.doesNotMatch(child.stderr, /unsettled top-level await/i);
  assert.equal(child.stdout, '');
  assert.ok(Object.values(output).every((filename) => !existsSync(filename)));
  assert.equal(git(root, 'status', '--porcelain'), '');
});

test('the exact source map exports deterministically and restores a closed ordinary source inventory', async (t) => {
  const { directory, root } = sourceFixture(t);
  const prepared = await planApplicationSourceExport({ repositoryRoot: root });
  const baseline = protocolBaseline(prepared.plan); const baselineReportPath = path.join(directory, 'baseline.json');
  writeFileSync(baselineReportPath, document(baseline));
  const first = artifacts(directory); const second = artifacts(directory, '-again');
  const receipt = await exportApplicationSourcePackage({ repositoryRoot: root, baselineReportPath, ...first });
  await exportApplicationSourcePackage({ repositoryRoot: root, baselineReportPath, ...second });
  assert.equal(receipt.status, 'fixture-passed'); assert.equal(receipt.fixture, true);
  assert.ok(Object.values(receipt.qualification).every((value) => value === false));
  assert.deepEqual(readFileSync(first.archivePath), readFileSync(second.archivePath));
  assert.deepEqual(readFileSync(first.manifestPath), readFileSync(second.manifestPath));
  const manifest = parseApplicationSourceJson(readFileSync(first.manifestPath));
  assert.equal(manifest.files.length, 585);
  assert.equal(decodeApplicationSourceZip(readFileSync(first.archivePath)).length, 586);
  assert.equal(manifest.source.commit, git(root, 'rev-parse', 'HEAD').trim());
  const restore = (destination, options = {}) => restoreApplicationSourcePackage({ ...first,
    expectedArchiveSha256: receipt.archive.sha256, expectedManifestSha256: receipt.manifest.sha256, destination, ...options });
  const destination = path.join(directory, 'restored'); restore(destination);
  assert.equal(existsSync(path.join(destination, '.git')), false);
  assert.equal(existsSync(path.join(destination, 'ui/scripts/application-package-consumer.mjs')), false);
  assert.deepEqual(readFileSync(path.join(destination, 'ui/package.json')),
    readFileSync(path.join(root, 'ui/profiles/application/package.json')));
  assert.equal(validateApplicationSourceInventory({ destination, manifest }).files, 585);
  assert.equal(lstatSync(path.join(destination, APPLICATION_SOURCE_MANIFEST_PATH)).mode & 0o777, 0o644);

  await t.test('restore rejects incorrect pins and existing destinations without modifying them', () => {
    const missing = path.join(directory, 'not-created');
    assert.throws(() => restore(missing, { expectedArchiveSha256: digest('wrong') }), /pins differ/);
    assert.equal(existsSync(missing), false);
    const before = readFileSync(path.join(destination, 'LICENSE'));
    assert.throws(() => restore(destination), /replace an existing/);
    assert.deepEqual(readFileSync(path.join(destination, 'LICENSE')), before);
    const linked = path.join(directory, 'linked'); symlinkSync(destination, linked);
    assert.throws(() => restore(path.join(linked, 'child')), /ordinary parents/);
    assert.equal(existsSync(path.join(destination, 'child')), false);
  });

  await t.test('matching artifact hashes cannot hide changed internal manifest, member bytes or member modes', () => {
    const original = decodeApplicationSourceZip(readFileSync(first.archivePath));
    for (const [name, mutate] of [
      ['bytes', (rows) => { rows.find((row) => row.path === 'LICENSE').bytes = Buffer.from('changed'); }],
      ['mode', (rows) => { rows.find((row) => row.path === 'LICENSE').mode = 0o755; }],
      ['manifest', (rows) => { rows.find((row) => row.path === APPLICATION_SOURCE_MANIFEST_PATH).bytes = Buffer.from('{}'); }],
      ['extra', (rows) => { rows.push({ path: 'unlisted.txt', bytes: Buffer.from('x'), mode: 0o644 }); }],
    ]) {
      const rows = original.map((row) => ({ ...row, bytes: Buffer.from(row.bytes) })); mutate(rows);
      const bytes = encodeApplicationSourceZip(rows); const archivePath = path.join(directory, `${name}.zip`); writeFileSync(archivePath, bytes);
      const target = path.join(directory, `rejected-${name}`);
      assert.throws(() => restore(target, { archivePath, expectedArchiveSha256: digest(bytes) }), /differs|differ/);
      assert.equal(existsSync(target), false);
    }
  });

  await t.test('restored inventory detects source drift and permits only the two declared generated roots', () => {
    const filename = path.join(destination, 'LICENSE'); const bytes = readFileSync(filename);
    writeFileSync(filename, 'mutated');
    assert.throws(() => validateApplicationSourceInventory({ destination, manifest }), /bytes or mode differ/);
    writeFileSync(filename, bytes); chmodSync(filename, 0o600);
    assert.throws(() => validateApplicationSourceInventory({ destination, manifest }), /bytes or mode differ/);
    chmodSync(filename, 0o644);
    mkdirSync(path.join(destination, 'ui/node_modules'));
    assert.throws(() => validateApplicationSourceInventory({ destination, manifest }), /Unexpected.*directory/);
    assert.deepEqual(validateApplicationSourceInventory({ destination, manifest, allowGenerated: true }).generated_roots, ['ui/node_modules']);
    rmSync(path.join(destination, 'ui/node_modules'), { recursive: true });
    symlinkSync(directory, path.join(destination, 'ui/node_modules'));
    assert.throws(() => validateApplicationSourceInventory({ destination, manifest, allowGenerated: true }), /contains a link/);
    rmSync(path.join(destination, 'ui/node_modules'));
  });

  await t.test('manifest and producer receipt validation preserve source, contract, and qualification bindings', () => {
    const pins = { archiveSha256: receipt.archive.sha256, manifestSha256: receipt.manifest.sha256,
      baselineReportSha256: receipt.baseline_report.sha256, manifest };
    validateApplicationSourceProducerReceipt(receipt, pins);
    for (const mutate of [
      (value) => { value.contract.bytes += 1; }, (value) => { value.contract.blob_oid = '0'.repeat(40); },
      (value) => { value.qualification.published = true; }, (value) => { value.files[0].source = 'unexpected'; },
    ]) {
      const value = structuredClone(manifest); mutate(value); assert.throws(() => validateApplicationSourcePackageManifest(value));
    }
    const broadened = structuredClone(receipt); broadened.qualification.published = true;
    assert.throws(() => validateApplicationSourceProducerReceipt(broadened, pins), /broadened/);
    assert.throws(() => validateApplicationSourceProducerReceipt(receipt, { ...pins, baselineReportSha256: digest('other') }), /pins differ/);
  });

  await t.test('baseline validation rejects fixture, incomplete, changed-source, and wrong-SDK evidence', () => {
    for (const mutate of [
      (value) => { value.fixture = true; }, (value) => { value.fixture = 'false'; }, (value) => { value.plan.source.commit = '0'.repeat(40); },
      (value) => { value.tests.result.completed_files.pop(); }, (value) => { value.qualification.source_checkout_unchanged = false; },
      (value) => { value.dependency_install.sdk.wasm.sha256 = digest('other'); },
      (value) => { value.build.package_lock_sha256 = digest('other'); },
    ]) {
      const value = structuredClone(baseline); mutate(value);
      assert.throws(() => validateApplicationSourceBaseline(value, { plan: prepared.plan }));
    }
  });

  await t.test('a baseline that grows during reading fails within the original bounded buffer without publishing outputs', async () => {
    const before = readFileSync(baselineReportPath); const identity = lstatSync(baselineReportPath);
    const original = fs.readSync; let changed = false;
    fs.readSync = (fd, buffer, offset, length, position) => {
      const opened = fs.fstatSync(fd);
      if (!changed && opened.dev === identity.dev && opened.ino === identity.ino) {
        assert.equal(buffer.length, before.length + 1); assert.ok(length <= before.length + 1);
        fs.appendFileSync(baselineReportPath, Buffer.alloc(1024, 32)); changed = true;
      }
      return original(fd, buffer, offset, length, position);
    };
    syncBuiltinESMExports();
    const output = artifacts(directory, '-growing');
    try {
      await assert.rejects(exportApplicationSourcePackage({ repositoryRoot: root, baselineReportPath, ...output }), /changed during reading/);
      assert.equal(changed, true); assert.ok(Object.values(output).every((filename) => !existsSync(filename)));
    } finally {
      fs.readSync = original; syncBuiltinESMExports(); writeFileSync(baselineReportPath, before);
    }
  });

  await t.test('protocol fixtures retain committed bytes and modes after bootstrap rewrites the working dependency inputs', async (subtest) => {
    const packagePath = path.join(root, 'ui/package.json'); const lockPath = path.join(root, 'ui/bun.lock');
    const packageBytes = readFileSync(packagePath); const lockBytes = readFileSync(lockPath);
    const pkg = JSON.parse(packageBytes);
    pkg.dependencies['@elevenid/marty-api-core'] = 'file:/runner-temp/marty-api-core.tgz';
    pkg.dependencies['@elevenid/marty-blog'] = 'file:/runner-temp/marty-blog.tgz';
    try {
      writeFileSync(packagePath, `${JSON.stringify(pkg, null, 2)}\n`);
      writeFileSync(lockPath, '// Simulated bootstrap replacement; original Git object remains selected.\n');
      chmodSync(path.join(root, 'LICENSE'), 0o755);
      assert.notEqual(git(root, 'status', '--porcelain'), '');
      const selected = sourceFixture(subtest, root);
      assert.deepEqual(readFileSync(path.join(selected.root, 'ui/package.json')), packageBytes);
      assert.deepEqual(readFileSync(path.join(selected.root, 'ui/bun.lock')), lockBytes);
      assert.equal(lstatSync(path.join(selected.root, 'LICENSE')).mode & 0o777, 0o644);
      const plan = await planApplicationSourceExport({ repositoryRoot: selected.root });
      assert.equal(plan.manifest.fixture, true); assert.equal(plan.manifest.files.length, 585);
      assert.equal(plan.plan.source.working_tree_dirty, false);
    } finally {
      writeFileSync(packagePath, packageBytes); writeFileSync(lockPath, lockBytes);
      chmodSync(path.join(root, 'LICENSE'), 0o644);
    }
  });

  await t.test('producer refuses untracked inputs and mode drift that Git fileMode ignores', async () => {
    const filename = path.join(root, 'LICENSE'); git(root, 'config', 'core.fileMode', 'false');
    chmodSync(filename, 0o755); assert.equal(git(root, 'status', '--porcelain'), '');
    await assert.rejects(planApplicationSourceExport({ repositoryRoot: root }), /working mode differs/);
    chmodSync(filename, 0o644);
    writeFileSync(path.join(root, 'untracked-file'), 'unexpected');
    await assert.rejects(planApplicationSourceExport({ repositoryRoot: root }), /clean Git checkout/);
    rmSync(path.join(root, 'untracked-file'));
    const target = path.join(root, 'ui/new-input.js'); writeFileSync(target, 'export {};');
    git(root, 'add', 'ui/new-input.js'); git(root, 'commit', '--quiet', '-m', 'Unclassified fixture input');
    await assert.rejects(planApplicationSourceExport({ repositoryRoot: root }), /missing or unclassified/);
  });
});
