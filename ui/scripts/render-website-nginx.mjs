import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { WEB_SURFACE_ROUTES } from './web-surface-contract.mjs';
import { websiteBuildRevision } from './web-surface-build-contract.mjs';
import { websiteAssetBase } from './website-assets.mjs';

export function renderWebsiteNginx(revision) {
  websiteAssetBase(revision); // Reject arbitrary text in the generated configuration.
  const lines = [
    '# Generated from contracts/web-surface-routes.json. Do not edit route ownership here.',
    `set $marty_website_revision "${revision}";`,
  ];
  for (const route of WEB_SURFACE_ROUTES.website.exact_paths) {
    if (/^\/pricing\/?$/.test(route)) continue; // Ownership is reserved; commercial details are withheld.
    const files = /\.(?:txt|xml|json)$/.test(route);
    const candidate = route === '/' ? '/index.html' : `${route.replace(/\/$/, '')}/index.html`;
    lines.push(`location = ${route} {`,
      `    try_files ${files ? '$uri =404' : route === '/' ? '/index.html =404' : `${candidate} /index.html`};`,
      '    expires -1;',
      '}');
  }
  for (const prefix of WEB_SURFACE_ROUTES.website.path_prefixes) {
    if (prefix === '/_website/') continue; // Resource policy is stronger than page fallbacks.
    lines.push(`location ${prefix} {`, '    try_files $uri/index.html /index.html;', '    expires -1;', '}');
  }
  for (const pattern of WEB_SURFACE_ROUTES.website.filename_patterns) {
    lines.push(`location ~ ${pattern} {`, '    try_files $uri =404;', '    expires -1;', '}');
  }
  return `${lines.join('\n')}\n`;
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  const revision = websiteBuildRevision({ sourceSha: process.env.MARTY_UI_SHA || 'development',
    commerceSha: process.env.MARTY_COMMERCE_SOURCE_SHA, pages: process.env.MARTY_PRODUCTION_PAGES || 'public',
    revision: process.env.MARTY_WEBSITE_REVISION });
  process.stdout.write(renderWebsiteNginx(revision));
}
