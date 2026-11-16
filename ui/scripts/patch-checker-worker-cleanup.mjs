import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
export const checkerVersion = '0.14.5';
export const cleanupFilename = 'marty-checker-cleanup.js';
const cleanupSource = readFileSync(path.join(scriptDirectory, 'checker-worker-cleanup.mjs'), 'utf8');
export const sha256 = (source) => createHash('sha256').update(source).digest('hex');

// Deliberately tied to the locked upstream release. Revisit/remove this patch
// when upgrading checker; unknown package contents must not be edited by guess.
export const patches = [
  {
    file: 'dist/main.js',
    before: '3aa4a758fd1475a63ce629c1d0ba70c51d7e44aece4644ce3af21e1b75da85ea',
    after: '110e11f18bbd1302501f9c1e0eeb3914406ff45dbe3303c8addd2c4351a07a32',
    replacements: [
      ['import "./types.js";', 'import "./types.js";\nimport { disposeCheckerWorker } from "./marty-checker-cleanup.js";'],
      ['\t\t\tif (viteMode === "serve") for (const checker of checkers) {\n\t\t\t\tconst { worker } = checker.serve;\n\t\t\t\tworker.terminate();\n\t\t\t}', '\t\t\tif (viteMode === "serve") {\n\t\t\t\ttry {\n\t\t\t\t\tawait Promise.all(checkers.map(({ serve: { worker } }) => disposeCheckerWorker(worker)));\n\t\t\t\t} catch (error) {\n\t\t\t\t\tconst message = `[vite-plugin-checker] Checker cleanup failed: ${error instanceof Error ? error.message : String(error)}`;\n\t\t\t\t\tif (logger) logger.error(message);\n\t\t\t\t\telse console.error(message);\n\t\t\t\t\tthrow error;\n\t\t\t\t}\n\t\t\t}'],
    ],
  },
  {
    file: 'dist/worker.js',
    before: '7c954c1872702b9db21ef6b9d91b47d70842307d56da76be06deb6e2c8aa59ec',
    after: '728a3da9f7966cee1fd0a69720306c834889aeb8aeb43fa6f300a4f03724f47f',
    replacements: [
      ['import "./types.js";', 'import "./types.js";\nimport { DISPOSE_REQUEST, disposeDiagnostic } from "./marty-checker-cleanup.js";'],
      ['\t\t\tlet diagnostic = null;', '\t\t\tlet diagnostic = null;\n\t\t\tlet configuring = Promise.resolve();'],
      ['\t\t\t\t\t\tdiagnostic.configureServer(action.payload);', '\t\t\t\t\t\tconfiguring = Promise.resolve(diagnostic.configureServer(action.payload));'],
      ['\t\t\t\t\tcase "unref":', '\t\t\t\t\tcase DISPOSE_REQUEST:\n\t\t\t\t\t\tvoid disposeDiagnostic(diagnostic, configuring, port);\n\t\t\t\t\t\tbreak;\n\t\t\t\t\tcase "unref":'],
    ],
  },
  {
    file: 'dist/checkers/typescript/main.js',
    before: 'd63914990cc5349f120873d79a2768c8fd5162bf4bf804fb9129aaee62ab653c',
    after: '2923049a37cac3c54e0fa4727860c8627b4a70bbab16186bb05c6759b13485bd',
    replacements: [
      ['import "../../types.js";', 'import "../../types.js";\nimport { stopOwnedProcess } from "../../marty-checker-cleanup.js";'],
      ['\tlet currDiagnostics = [];', '\tlet currDiagnostics = [];\n\tlet disposeNativeTsc = async () => {};'],
      ['\treturn {\n\t\tconfig:', '\treturn {\n\t\tdispose: () => disposeNativeTsc(),\n\t\tconfig:'],
      ['\t\t\t\tlet logChunk = "";', '\t\t\t\tdisposeNativeTsc = () => stopOwnedProcess(tscProcess);\n\t\t\t\tlet logChunk = "";'],
    ],
  },
];

export function transformedSource(source, patch) {
  let next = source;
  for (const [before, after] of patch.replacements) {
    if (next.split(before).length !== 2) throw new Error(`Unexpected checker patch target in ${patch.file}`);
    next = next.replace(before, after);
  }
  return next;
}

function replaceFile(filename, source) {
  // Bun may hardlink package files from its shared cache. Replace the directory
  // entry atomically instead of modifying a cached inode in place.
  const directory = mkdtempSync(path.join(path.dirname(filename), '.marty-checker-'));
  try {
    const temporary = path.join(directory, 'patched');
    const mode = existsSync(filename) ? statSync(filename).mode & 0o777 : 0o644;
    writeFileSync(temporary, source, { mode });
    renameSync(temporary, filename);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

export function applyCheckerPatch(packageRoot = path.resolve(scriptDirectory, '../node_modules/vite-plugin-checker')) {
  if (!existsSync(packageRoot)) return 0; // Development dependencies may be omitted.
  const installed = JSON.parse(readFileSync(path.join(packageRoot, 'package.json'), 'utf8'));
  if (installed.version !== checkerVersion) {
    throw new Error(`Checker cleanup patch requires vite-plugin-checker ${checkerVersion}; found ${installed.version}. Review the patch before upgrading.`);
  }
  // Validate every input before writing any file, including partially patched installs.
  const writes = patches.map((patch) => {
    const filename = path.join(packageRoot, patch.file);
    const source = readFileSync(filename, 'utf8');
    if (sha256(source) === patch.after) return null;
    if (sha256(source) !== patch.before) throw new Error(`Unrecognized vite-plugin-checker contents: ${patch.file}`);
    const next = transformedSource(source, patch);
    if (sha256(next) !== patch.after) throw new Error(`Checker cleanup patch digest mismatch: ${patch.file}`);
    return { filename, source: next };
  }).filter(Boolean);
  const helperFilename = path.join(packageRoot, 'dist', cleanupFilename);
  if (existsSync(helperFilename) && readFileSync(helperFilename, 'utf8') !== cleanupSource) {
    throw new Error('Unrecognized installed checker cleanup helper. Reinstall dependencies before applying the patch.');
  }
  for (const { filename, source } of writes) replaceFile(filename, source);
  if (!existsSync(helperFilename)) replaceFile(helperFilename, cleanupSource);
  return writes.length;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.log(`Applied the native TypeScript checker cleanup fix to ${applyCheckerPatch()} checker file(s).`);
}
