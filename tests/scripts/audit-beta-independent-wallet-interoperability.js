#!/usr/bin/env node
// Thin fixed entrypoint. The source-pinned recorder owns the shared native flow;
// the product and wallet Rust services perform issuance and verification.
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

function requireSource(repository, revision) {
  assert(/^[a-f0-9]{40}$/.test(revision || ''), 'An exact source revision is required');
  const head = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: repository, encoding: 'utf8' });
  const status = spawnSync('git', ['status', '--porcelain', '--untracked-files=all'], { cwd: repository, encoding: 'utf8' });
  assert(head.status === 0 && status.status === 0 && !status.stdout.trim() && head.stdout.trim() === revision,
    'Retained native capture requires the exact clean source worktree');
}

async function main(env = process.env) {
  const uiRoot = path.resolve(__dirname, '../..');
  assert(env.DEMO_INDEPENDENT_RECORDER_REPOSITORY && env.DEMO_INDEPENDENT_GATEWAY_CONFIG && env.DEMO_ARTIFACT_DIR,
    'The dedicated retained gateway, recorder source and fresh artifact directory are required');
  assert.equal(env.RECORD_VIDEO, '1', 'Retained native evidence requires two fresh device recordings');
  const recorderRoot = path.resolve(env.DEMO_INDEPENDENT_RECORDER_REPOSITORY);
  requireSource(uiRoot, env.DEMO_INDEPENDENT_DRIVER_REVISION);
  requireSource(recorderRoot, env.DEMO_INDEPENDENT_RECORDER_REVISION);
  const origin = new URL(env.BETA_ORIGIN);
  assert(origin.protocol === 'https:' && origin.href === `${origin.origin}/`, 'The source-bound HTTPS service origin is required');
  const { runRetainedIndependent } = require(path.join(recorderRoot, 'src/retainedIndependentWallet'));
  const report = await runRetainedIndependent({ configPath: path.resolve(env.DEMO_INDEPENDENT_GATEWAY_CONFIG),
    outputRoot: path.resolve(env.DEMO_ARTIFACT_DIR), uiRoot,
    uiRevision: env.DEMO_INDEPENDENT_DRIVER_REVISION, recorderRevision: env.DEMO_INDEPENDENT_RECORDER_REVISION,
    serviceOrigin: origin.origin, env });
  requireSource(uiRoot, env.DEMO_INDEPENDENT_DRIVER_REVISION);
  requireSource(recorderRoot, env.DEMO_INDEPENDENT_RECORDER_REVISION);
  if (report.status !== 'PASS') process.exitCode = 1;
  return report;
}

if (require.main === module) main().catch(() => {
  console.error('Retained native capture is BLOCKED. Verify the exact source, frozen native inputs and retained diagnostic report.');
  process.exitCode = 1;
});
module.exports = { main, requireSource };
