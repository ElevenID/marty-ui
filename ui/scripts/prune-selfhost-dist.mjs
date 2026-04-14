import { existsSync, readdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const distDir = path.resolve(__dirname, '..', 'dist-selfhost');

const removeIfPresent = (targetPath) => {
  if (existsSync(targetPath)) {
    rmSync(targetPath, { recursive: true, force: true });
  }
};

removeIfPresent(path.join(distDir, 'blog'));
removeIfPresent(path.join(distDir, 'authors'));
removeIfPresent(path.join(distDir, 'llms.txt'));
removeIfPresent(path.join(distDir, 'robots.txt'));
removeIfPresent(path.join(distDir, 'sitemap.xml'));
removeIfPresent(path.join(distDir, 'sitemap-index.xml'));
removeIfPresent(path.join(distDir, 'sitemap-0.xml'));

const localesDir = path.join(distDir, 'locales');
if (existsSync(localesDir)) {
  for (const localeName of readdirSync(localesDir)) {
    removeIfPresent(path.join(localesDir, localeName, 'marketing.json'));
  }
}