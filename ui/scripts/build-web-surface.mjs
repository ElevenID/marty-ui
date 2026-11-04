import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { pruneSelfhostDist } from './prune-selfhost-dist.mjs';

const surface = process.argv[2];
if (!['website', 'application'].includes(surface)) throw new Error('Expected website or application surface');
const projectRoot = fileURLToPath(new URL('../', import.meta.url));
const binDir = path.join(projectRoot, 'node_modules', '.bin');
const env = { ...process.env, MARTY_UI_SURFACE: surface };
if (env.VITE_UI_VARIANT === 'selfhost') throw new Error('Production surfaces cannot use the customer variant');

function localBin(name) {
  if (process.platform === 'win32') {
    for (const suffix of ['.cmd', '.exe']) {
      const candidate = path.join(binDir, `${name}${suffix}`);
      if (existsSync(candidate)) return candidate;
    }
  }
  return path.join(binDir, name);
}
function quoteWindowsArg(value) {
  return /[\s"&()<>^|]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}
function run(command, args) {
  const shim = process.platform === 'win32' && command.endsWith('.cmd');
  const result = spawnSync(shim ? (process.env.ComSpec || 'cmd.exe') : command,
    shim ? ['/d', '/s', '/c', [command, ...args].map(quoteWindowsArg).join(' ')] : args,
    { cwd: projectRoot, env, stdio: 'inherit', shell: false });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}

run(process.execPath, [path.join(projectRoot, 'scripts/generate-demo-manifest-module.mjs')]);
run(localBin('tsc'), ['-p', 'tsconfig.build.json']);
run(localBin('vite'), ['build']);
if (surface === 'application') pruneSelfhostDist(path.join(projectRoot, 'dist-application'));
