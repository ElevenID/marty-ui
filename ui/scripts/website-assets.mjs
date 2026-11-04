import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export function websiteAssetBase(revision) {
  if (!/^(?:development|[a-f0-9]{40}(?:-[a-f0-9]{40})?)$/.test(revision)) throw new Error('Invalid website asset revision');
  return `/_website/${revision}/`;
}

export function websiteAssetsPlugin(revision) {
  const base = websiteAssetBase(revision);
  const publicRoot = fileURLToPath(new URL('../public/', import.meta.url));
  return {
    name: 'website-assets',
    enforce: 'pre',
    buildStart() {
      const emitDirectory = (directory, prefix = '') => {
        for (const entry of readdirSync(directory, { withFileTypes: true })) {
          const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
          const absolute = path.join(directory, entry.name);
          if (entry.isDirectory()) { emitDirectory(absolute, relative); continue; }
          if (!entry.isFile() || relative.endsWith('.html')) continue;
          // Product translations and test harnesses do not belong in the website.
          if (/^locales\/[^/]+\//.test(relative) && !/\/(?:common|marketing)\.json$/.test(relative)) continue;
          let source = readFileSync(absolute);
          if (relative === 'manifest.json') {
            const manifest = JSON.parse(source.toString());
            manifest.icons = manifest.icons.map((icon) => ({ ...icon, src: `${base}${icon.src.replace(/^\//, '')}` }));
            manifest.start_url = '/';
            manifest.scope = '/';
            source = `${JSON.stringify(manifest)}\n`;
          }
          const fileName = relative === 'runtime-config.js' ? '_website/runtime-config.js'
            : ['llms.txt', 'blog/rss.xml'].includes(relative) ? relative : `${base.slice(1)}${relative}`;
          this.emitFile({ type: 'asset', fileName, source });
        }
      };
      emitDirectory(publicRoot);
    },
    transformIndexHtml: {
      order: 'pre',
      handler(html) {
        return html.replace('src="/src/index.jsx"', 'src="/src/website.jsx"')
          .replace('src="/runtime-config.js"', 'src="/_website/runtime-config.js"')
          .replace(/((?:src|href)=")\/(favicon\.ico(?:\?[^\"]*)?|apple-touch-icon\.png|manifest\.json|startup\.js)(")/g,
            `$1${base}$2$3`);
      },
    },
    transform(code, id) {
      if (!id.replace(/\\/g, '/').includes('/@elevenid/marty-blog/')) return null;
      // The pinned blog package publishes local public image URLs in its data.
      // Rewrite those owned assets; links and external image origins stay intact.
      const transformed = code.replace(/(["'`])\/images(?=\/|["'`])/g, `$1${base}images`);
      return transformed === code ? null : { code: transformed, map: null };
    },
  };
}
