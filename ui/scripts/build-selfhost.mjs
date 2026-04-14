import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');
const binDir = path.join(projectRoot, 'node_modules', '.bin');

function localBin(name) {
  return path.join(binDir, process.platform === 'win32' ? `${name}.cmd` : name);
}

function quoteWindowsArg(value) {
  if (!/[\s"&()<>^|]/.test(value)) {
    return value;
  }

  return `"${value.replace(/"/g, '""')}"`;
}

function run(command, args) {
  const isWindowsCmdShim = process.platform === 'win32' && command.toLowerCase().endsWith('.cmd');
  const spawnCommand = isWindowsCmdShim ? (process.env.ComSpec || 'cmd.exe') : command;
  const spawnArgs = isWindowsCmdShim
    ? ['/d', '/s', '/c', [quoteWindowsArg(command), ...args.map(quoteWindowsArg)].join(' ')]
    : args;

  const result = spawnSync(spawnCommand, spawnArgs, {
    cwd: projectRoot,
    stdio: 'inherit',
    shell: false,
  });

  if (result.error) {
    throw result.error;
  }

  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

run(localBin('tsc'), ['-p', 'tsconfig.build.json']);
run(localBin('vite'), ['build', '--mode', 'selfhost']);
run(process.execPath, [path.join(projectRoot, 'scripts', 'prune-selfhost-dist.mjs')]);