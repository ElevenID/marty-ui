import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');
const binDir = path.join(projectRoot, 'node_modules', '.bin');

function localBin(name) {
  return path.join(binDir, process.platform === 'win32' ? `${name}.cmd` : name);
}

function parseEnvFile(pathname) {
  if (!fs.existsSync(pathname)) {
    return {};
  }

  return Object.fromEntries(
    fs.readFileSync(pathname, 'utf8')
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => line && !line.startsWith('#') && line.includes('='))
      .map((line) => {
        const separatorIndex = line.indexOf('=');
        const key = line.slice(0, separatorIndex).trim();
        let value = line.slice(separatorIndex + 1).trim();

        if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
          value = value.slice(1, -1);
        }

        return [key, value];
      }),
  );
}

function resolveSelfhostEnvFile() {
  const configuredPath = process.env.SELFHOST_ENV_FILE || '.env.selfhost.production.local';
  return path.isAbsolute(configuredPath)
    ? configuredPath
    : path.resolve(projectRoot, '..', configuredPath);
}

function firstNonEmpty(...values) {
  return values.find((value) => typeof value === 'string' && value.trim())?.trim() || '';
}

function hostnameOf(value) {
  if (!value) {
    return '';
  }

  try {
    return new URL(value).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function seedSelfhostBuildEnv() {
  const selfhostEnvFile = resolveSelfhostEnvFile();
  const selfhostEnv = parseEnvFile(selfhostEnvFile);

  for (const [key, value] of Object.entries(selfhostEnv)) {
    if (process.env[key] === undefined) {
      process.env[key] = value;
    }
  }

  if (process.env.VITE_UI_VARIANT === undefined) {
    process.env.VITE_UI_VARIANT = 'selfhost';
  }

  // Self-host UI is served by the same edge proxy as /v1 and /api. Keep browser
  // API calls same-origin by default so beta/dev .env files cannot leak into a
  // production customer bundle.
  if (process.env.VITE_API_URL === undefined) {
    process.env.VITE_API_URL = '';
  }

  const publicBaseUrl = firstNonEmpty(
    process.env.UI_BASE_URL,
    process.env.PUBLIC_API_URL,
    process.env.PUBLIC_URL,
  );

  if (process.env.VITE_PUBLIC_URL === undefined && publicBaseUrl) {
    process.env.VITE_PUBLIC_URL = publicBaseUrl;
  }

  const publicHost = firstNonEmpty(
    process.env.PUBLIC_DOMAIN,
    hostnameOf(process.env.UI_BASE_URL),
    hostnameOf(process.env.PUBLIC_API_URL),
  ).toLowerCase();
  const apiHost = hostnameOf(process.env.VITE_API_URL);
  const additionalHosts = (process.env.UI_ADDITIONAL_BASE_URLS || '')
    .split(',')
    .map((entry) => hostnameOf(entry.trim()))
    .filter(Boolean);

  if (apiHost && publicHost && apiHost !== publicHost && !additionalHosts.includes(apiHost)) {
    console.error(
      `[selfhost-ui] Refusing to build: VITE_API_URL host ${apiHost} does not match PUBLIC_DOMAIN ${publicHost}.`,
    );
    process.exit(1);
  }

  if (fs.existsSync(selfhostEnvFile)) {
    console.log(`[selfhost-ui] Loaded deployment env from ${path.relative(projectRoot, selfhostEnvFile)}`);
  } else {
    console.warn(`[selfhost-ui] ${selfhostEnvFile} not found; building with same-origin API defaults.`);
  }
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

seedSelfhostBuildEnv();
run(localBin('tsc'), ['-p', 'tsconfig.build.json']);
run(localBin('vite'), ['build', '--mode', 'selfhost']);
run(process.execPath, [path.join(projectRoot, 'scripts', 'prune-selfhost-dist.mjs')]);