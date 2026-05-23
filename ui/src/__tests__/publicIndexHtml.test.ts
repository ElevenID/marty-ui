import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const publicIndexPath = path.join(projectRoot, 'index.html');

describe('public index HTML', () => {
  it('does not render temporary legal-link bootstrap content before React mounts', () => {
    const html = fs.readFileSync(publicIndexPath, 'utf8');

    expect(html).not.toContain('bootstrap-legal-links');
    expect(html).not.toContain('Public site legal links');
    expect(html).not.toContain('html.app-loading #root');
    expect(html).not.toContain('<body class="app-loading">');
  });
});