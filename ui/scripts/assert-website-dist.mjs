import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { WEB_ROUTE_CONTRACT } from './web-surface-contract.mjs';
import { websiteBuildRevision } from './web-surface-build-contract.mjs';

const directory = path.resolve(process.argv[2] || 'dist-website');
const metadata = JSON.parse(readFileSync(path.join(directory, 'marty-website-release.json'), 'utf8'));
assert.equal(metadata.schema, 'marty.website-image/v1');
assert.equal(metadata.surface, 'website');
assert.deepEqual(metadata.route_contract, WEB_ROUTE_CONTRACT);
const revision = websiteBuildRevision({ sourceSha: metadata.source_sha, pages: metadata.production_pages,
  commerceSha: metadata.commerce_extension?.source_sha, revision: metadata.revision });
const prefix = `/_website/${revision}/`;
assert.equal(existsSync(path.join(directory, 'pricing')), false, 'private pricing must not be prerendered');
assert.equal(existsSync(path.join(directory, 'console')), false, 'website must not publish a console entry');
assert.equal(existsSync(path.join(directory, 'marty-ui-release.json')), false, 'website must not claim stack identity');
const root = readFileSync(path.join(directory, 'index.html'), 'utf8');
assert.match(root, /<h1\b/i, 'homepage must be prerendered');
assert.match(root, /prerender-status-code/);
assert.ok(root.includes('/_website/runtime-config.js'));
assert.ok(root.includes(`${prefix}assets/`));
assert.ok(!/https?:\/\/(?:localhost|127\.0\.0\.1|\[::1\])/.test(root), 'loopback URLs must not survive prerendering');

let documents = 0;
function checkHtml(directoryPath) {
  for (const entry of readdirSync(directoryPath, { withFileTypes: true })) {
    const filename = path.join(directoryPath, entry.name);
    if (entry.isDirectory()) { checkHtml(filename); continue; }
    if (!entry.isFile() || !entry.name.endsWith('.html')) continue;
    documents += 1;
    const html = readFileSync(filename, 'utf8');
    for (const match of html.matchAll(/<a\b[^>]*href=["']([^"']+)["']/gi)) {
      const url = new URL(match[1], 'https://elevenidllc.com');
      assert.ok(url.origin !== 'https://elevenidllc.com' || !/^\/pricing(?:\/|$)/.test(url.pathname), `pricing link in ${filename}`);
    }
    for (const match of html.matchAll(/(?:src|href)=["'](\/_website\/[^"']+)["']/g)) {
      const resource = match[1].split(/[?#]/)[0];
      assert.ok(resource === '/_website/runtime-config.js' || resource.startsWith(prefix), `stale asset namespace in ${filename}`);
      assert.ok(existsSync(path.join(directory, resource.slice(1))), `missing ${resource} referenced by ${filename}`);
    }
    assert.ok(!/(?:src|href)=["']\/(?:assets|locales|images)\//.test(html), `root resource namespace leaked in ${filename}`);
  }
}
checkHtml(directory);
assert.ok(documents > 1, 'website must include prerendered public routes');
const robots = readFileSync(path.join(directory, 'robots.txt'), 'utf8');
assert.match(robots, /Sitemap:/i);
assert.match(robots, /Disallow: \/v1\/\*/i);
const urls = [];
for (const entry of readdirSync(directory).filter((name) => /^sitemap(?:-[^.]+|-index)?\.xml$/.test(name))) {
  const xml = readFileSync(path.join(directory, entry), 'utf8');
  if (!/<urlset\b/.test(xml)) continue;
  urls.push(...[...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((match) => match[1]));
}
assert.ok(urls.length > 1, 'sitemap URL set is missing');
assert.equal(new Set(urls).size, urls.length, 'sitemap URLs must be unique');
assert.equal(urls.filter((url) => new URL(url).pathname === '/').length, 1, 'homepage must occur once');
assert.ok(urls.some((url) => /^\/product\/?$/.test(new URL(url).pathname)));
for (const url of urls) assert.ok(!/^\/(?:console|login|auth|docs|pricing|_website)(?:\/|$)/.test(new URL(url).pathname), `application or resource route in sitemap: ${url}`);
console.log(`Website artifacts verified: ${documents} HTML documents, namespaced resources, provenance, crawler files.`);
