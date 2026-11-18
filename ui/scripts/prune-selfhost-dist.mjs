import { existsSync, readdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { SELFHOST_EXCLUDED_STATIC_PATHS } from './selfhost-build-contract.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const distDir = path.resolve(__dirname, '..', 'dist-selfhost');

const removeIfPresent = (targetPath) => {
  if (existsSync(targetPath)) {
    rmSync(targetPath, { recursive: true, force: true });
  }
};

export function pruneSelfhostDist(directory) {
  for (const relativePath of SELFHOST_EXCLUDED_STATIC_PATHS) {
    removeIfPresent(path.join(directory, relativePath));
  }
  for (const entry of readdirSync(directory)) {
    if (/^sitemap-\d+\.xml$/.test(entry)) removeIfPresent(path.join(directory, entry));
  }
  const localesDirectory = path.join(directory, 'locales');
  if (existsSync(localesDirectory)) {
    for (const locale of readdirSync(localesDirectory, { withFileTypes: true })) {
      if (locale.isDirectory()) removeIfPresent(path.join(localesDirectory, locale.name, 'marketing.json'));
    }
  }
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  pruneSelfhostDist(distDir);
}
