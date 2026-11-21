import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { selfhostBuildContractPlugin } from '../../../scripts/selfhost-build-contract.mjs';
import { pruneSelfhostDist } from '../../../scripts/prune-selfhost-dist.mjs';
import { WEBSITE_SOURCE_OWNERSHIP } from '../../../scripts/website-source-ownership.mjs';

describe('customer build exclusion', () => {
  it('rejects every retired marketing module even when its source no longer exists', () => {
    expect(WEBSITE_SOURCE_OWNERSHIP.modules).toHaveLength(34);
    for (const moduleId of [
      ...WEBSITE_SOURCE_OWNERSHIP.modules.map((entry) => `/workspace/${entry}`),
      '/workspace/node_modules/@elevenid/marty-blog/index.js',
      '/workspace/ui/src/variants/publicSite.public.jsx',
    ]) {
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
