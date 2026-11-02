import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { selfhostBuildContractPlugin } from '../../../scripts/selfhost-build-contract.mjs';
import { pruneSelfhostDist } from '../../../scripts/prune-selfhost-dist.mjs';

describe('customer build exclusion', () => {
  it('rejects every marketing page imported by the production route module', () => {
    const productionRoutes = path.resolve('src/variants/publicSite.public.jsx');
    const imports = [...readFileSync(productionRoutes, 'utf8').matchAll(/import\(['"]([^'"]+)['"]\)/g)];
    expect(imports.length).toBeGreaterThan(20);
    for (const [, imported] of imports) {
      const moduleId = imported.startsWith('.')
        ? `${path.resolve(path.dirname(productionRoutes), imported)}.jsx`
        : `/workspace/node_modules/${imported}/index.js`;
      expect(() => selfhostBuildContractPlugin().generateBundle({}, {
        'entry.js': { type: 'chunk', modules: { [moduleId]: {} } },
      })).toThrow('Customer UI includes production marketing modules');
    }
  });

  it('allows the customer entry and application modules', () => {
    expect(() => selfhostBuildContractPlugin().generateBundle({}, {
      'entry.js': { type: 'chunk', modules: {
        '/workspace/ui/src/variants/publicSite.selfhost.jsx': {},
        '/workspace/ui/src/components/ApplyPage.jsx': {},
        '/workspace/ui/src/apps/console/ConsoleRoutes.jsx': {},
      } },
    })).not.toThrow();
  });

  it('removes copied marketing artifacts while retaining application assets', () => {
    const directory = mkdtempSync(path.join(tmpdir(), 'marty-customer-build-'));
    const excluded = [
      'blog/rss.xml', 'demos/manifests/index.json', 'images/authors/author.png',
      'images/demos/demo.png', 'images/social/blog.png', 'llms.txt', 'robots.txt',
      'sitemap.xml', 'sitemap-index.xml', 'sitemap-12.xml',
      'locales/en/marketing.json', 'locales/fr/marketing.json',
    ];
    const retained = [
      'index.html', 'console/index.html', 'assets/application.js', 'runtime-config.js',
      'startup.js', 'favicon.ico', 'locales/en/common.json', 'locales/fr/console.json',
    ];
    try {
      for (const file of [...excluded, ...retained]) {
        mkdirSync(path.dirname(path.join(directory, file)), { recursive: true });
        writeFileSync(path.join(directory, file), 'fixture');
      }
      pruneSelfhostDist(directory);
      expect(excluded.filter((file) => existsSync(path.join(directory, file)))).toEqual([]);
      expect(retained.filter((file) => existsSync(path.join(directory, file)))).toEqual(retained);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
});
