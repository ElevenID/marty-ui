import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const publicIndexPath = path.join(projectRoot, 'index.html');

describe('public index HTML', () => {
  it('does not render temporary legal-link bootstrap content', () => {
    const html = fs.readFileSync(publicIndexPath, 'utf8');

    expect(html).not.toContain('bootstrap-legal-links');
    expect(html).not.toContain('Public site legal links');
  });

  it('keeps prerendered markup hidden behind a stable loading surface until styles are ready', () => {
    const html = fs.readFileSync(publicIndexPath, 'utf8');

    expect(html).toContain("document.documentElement.classList.add('app-loading')");
    expect(html).toContain('html.app-loading #root');
    expect(html).toContain('<body class="app-loading">');
    expect(html).toContain('class="app-loading-shell"');
  });
});
