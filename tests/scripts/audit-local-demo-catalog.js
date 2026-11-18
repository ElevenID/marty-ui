'use strict';

// Local public-catalog audit. Auth and external media are explicit fixtures;
// this does not qualify authenticated issuance or external video playback.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const os = require('node:os');
const { chromium } = require('playwright');

const baseUrl = new URL(process.env.DEMO_AUDIT_BASE_URL || 'http://127.0.0.1:4173');
if (!['http:', 'https:'].includes(baseUrl.protocol)
  || !['localhost', '127.0.0.1', '[::1]'].includes(baseUrl.hostname)
  || baseUrl.username || baseUrl.password || baseUrl.pathname !== '/' || baseUrl.search || baseUrl.hash) {
  throw new Error('DEMO_AUDIT_BASE_URL must be a local loopback HTTP origin');
}
const origin = baseUrl.origin;
const out = path.resolve(process.env.DEMO_AUDIT_OUTPUT_DIR || path.join(os.tmpdir(), 'marty-demo-catalog-audit'));
const screenshots = process.env.DEMO_AUDIT_SCREENSHOTS === '1';
fs.mkdirSync(out, { recursive: true });
const report = {
  started_at: new Date().toISOString(),
  schema_version: 1,
  scope: 'Local public UI, real browser and served manifests; unauthenticated session fixture; no backend qualification',
  ui_mode: process.env.DEMO_AUDIT_UI_MODE || 'unspecified',
  base_url: origin,
  playwright_version: require('playwright/package.json').version,
  fixtures: ['GET /v1/auth/me -> unauthenticated', 'YouTube frame content only for consent test', 'Controlled manifest failure/review-state responses'],
  checks: [],
  page_errors: [],
  external_request_failures: [],
};

async function main() {
  const browser = await chromium.launch({
    executablePath: process.env.DEMO_AUDIT_BROWSER_EXECUTABLE || undefined,
    headless: true,
  });
  report.browser_version = browser.version();
  report.custom_browser_executable = Boolean(process.env.DEMO_AUDIT_BROWSER_EXECUTABLE);
  try {
    const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    await context.route('**/v1/auth/me', route => route.fulfill({
      status: 200, contentType: 'application/json', body: JSON.stringify({ authenticated: false, user: null }),
    }));
    const page = await context.newPage();
    page.on('pageerror', error => report.page_errors.push(error.message));
    page.on('requestfailed', request => {
      const url = new URL(request.url());
      if (url.origin !== origin) report.external_request_failures.push({ origin: url.origin, error: request.failure()?.errorText });
    });
    const index = await (await context.request.get(origin + '/demos/manifests/index.json')).json();
    const manifests = [];
    for (const release of index.releases) {
      const manifest = await (await context.request.get(origin + release.manifest_url)).json();
      manifests.push(manifest);
    }
    const latest = manifests.find(manifest => manifest.stack_version === index.latest_available_stack_version);
    assert.ok(latest);
    const served = [];
    page.on('response', response => {
      if (response.url().includes('/demos/manifests/')) served.push({ path: new URL(response.url()).pathname, status: response.status() });
    });
    await page.goto(origin + '/demos');
    await page.getByRole('heading', { level: 1, name: latest.release_name, exact: true }).waitFor();
    assert.equal(await page.evaluate(() => window.__ELEVENID_PRERENDER__ == null), true, 'Build prerender marker must not be present in a served page');
    assert.ok(served.some(row => row.path.endsWith('/index.json')));
    assert.ok(served.some(row => row.path.endsWith('/' + latest.stack_version + '.json')));
    report.checks.push({ name: 'Ordinary headless browser fetches served manifests without the build marker', result: 'PASS', requests: served.slice() });
    for (const width of [320, 390, 768, 1440]) {
      await page.setViewportSize({ width, height: width < 768 ? 844 : 1000 });
      await page.goto(origin + '/demos');
      await page.getByRole('heading', { level: 1, name: latest.release_name, exact: true }).waitFor();
      await page.locator('[data-demo-render-state="settled"]').waitFor();
      const metrics = await page.evaluate(() => ({ width: innerWidth, document: document.documentElement.scrollWidth }));
      const overflow = metrics.document > width ? await page.evaluate(() => [...document.querySelectorAll('body *')].map(element => ({ tag: element.tagName, text: element.textContent?.trim().slice(0, 90), x: element.getBoundingClientRect().x, right: element.getBoundingClientRect().right, width: element.getBoundingClientRect().width })).filter(item => item.right > innerWidth + 1).slice(0, 15)) : [];
      report.checks.push({ name: 'Catalog viewport ' + width, result: metrics.document <= width ? 'PASS' : 'FAIL', metrics, overflow });
      if (screenshots && width === 320) await page.screenshot({ path: path.join(out, 'catalog-320-internal.png'), fullPage: true });
    }
    if (screenshots) await page.screenshot({ path: path.join(out, 'catalog-internal.png'), fullPage: true });
    for (const manifest of manifests) {
      for (const scenario of manifest.scenarios) {
        const route = '/demos/' + manifest.stack_version + '/' + scenario.slug;
        await page.goto(origin + route);
        await page.getByRole('heading', { level: 1, name: scenario.title, exact: true }).waitFor();
        await page.getByRole('heading', { level: 2, name: 'Transcript', exact: true }).waitFor();
        const poster = page.getByTestId('demo-video-player').locator('img');
        await poster.waitFor();
        await page.waitForFunction(() => {
          const image = document.querySelector('[data-testid="demo-video-player"] img');
          return image && image.complete && image.naturalWidth > 0;
        });
        assert.equal(await page.locator('iframe[src*="youtube"]').count(), 0);
        report.checks.push({ name: 'Scenario ' + manifest.stack_version + '/' + scenario.slug, result: 'PASS', publication_state: scenario.state });
      }
    }
    const publicManifest = manifests.find(manifest => manifest.scenarios.some(scenario => scenario.state === 'PUBLIC' && scenario.youtube_id));
    const publicScenario = publicManifest.scenarios.find(scenario => scenario.state === 'PUBLIC' && scenario.youtube_id);
    await page.route('https://www.youtube-nocookie.com/**', route => route.fulfill({ status: 200, contentType: 'text/html', body: '<!doctype html><title>Local playback boundary fixture</title>' }));
    const publicPath = '/demos/' + publicManifest.stack_version + '/' + publicScenario.slug;
    await page.goto(origin + publicPath);
    await page.getByRole('button', { name: 'Load ' + publicScenario.title + ' from YouTube', exact: true }).click();
    const frame = page.getByTitle(publicScenario.title + ' video', { exact: true });
    await frame.waitFor();
    assert.ok((await frame.getAttribute('src')).includes('/embed/' + publicScenario.youtube_id));
    const chapter = publicScenario.chapters.find(item => item.start_seconds > 0);
    if (chapter) {
      await page.getByRole('button', { name: new RegExp(chapter.title.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) }).click();
      await page.waitForFunction(seconds => document.querySelector('iframe')?.src.includes('start=' + seconds), chapter.start_seconds);
    }
    report.checks.push({ name: 'Public video requires consent and chapter seeking preserves it', result: 'PASS', boundary: 'Local frame fixture; external YouTube playback not qualified' });
    const reviewManifest = structuredClone(publicManifest);
    const reviewScenario = reviewManifest.scenarios.find(item => item.slug === publicScenario.slug);
    reviewScenario.state = 'YOUTUBE_UNLISTED';
    reviewScenario.published_at = null;
    reviewScenario.publication_attestation = null;
    const manifestRoute = '**/demos/manifests/' + publicManifest.stack_version + '.json';
    await page.route(manifestRoute, route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(reviewManifest) }));
    await page.goto(origin + publicPath);
    await page.getByText('Recording in review', { exact: true }).waitFor();
    assert.equal(await page.getByRole('button', { name: /Load .* from YouTube/ }).count(), 0);
    assert.equal(await page.locator('iframe[src*="youtube"]').count(), 0);
    report.checks.push({ name: 'Unlisted review-state video is not playable', result: 'PASS' });
    await page.unroute(manifestRoute);
    const latestManifestRoute = '**/demos/manifests/' + latest.stack_version + '.json';
    await page.route(latestManifestRoute, route => route.fulfill({ status: 503, contentType: 'application/json', body: '{}' }));
    await page.goto(origin + '/demos');
    await page.getByText('Demo evidence could not be loaded (503).', { exact: true }).waitFor();
    await page.getByRole('button', { name: /retry/i }).waitFor();
    await page.unroute(latestManifestRoute);
    await page.getByRole('button', { name: /retry/i }).click();
    await page.getByRole('heading', { level: 1, name: latest.release_name, exact: true }).waitFor();
    report.checks.push({ name: 'Served manifest 503 is visible and Retry recovers', result: 'PASS' });
    const malformed = structuredClone(latest);
    delete malformed.scenarios[0].assertions;
    await page.route(latestManifestRoute, route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(malformed) }));
    await page.goto(origin + '/demos');
    await page.getByRole('button', { name: /retry/i }).waitFor();
    const message = await page.locator('body').innerText();
    assert.ok(message.includes('assertions'));
    report.checks.push({ name: 'Missing assertions produce recoverable error instead of render crash', result: 'PASS' });
    await page.unroute(latestManifestRoute);
    assert.deepEqual(report.page_errors, []);
    report.result = report.checks.some(check => check.result !== 'PASS') ? 'FAIL' : 'PASS';
    if (report.result !== 'PASS') process.exitCode = 1;
    await context.close();
  } catch (error) {
    report.result = 'FAIL';
    report.error = error.stack || String(error);
    process.exitCode = 1;
  } finally {
    await browser.close();
    report.finished_at = new Date().toISOString();
    const failures = new Map();
    for (const failure of report.external_request_failures) {
      const key = JSON.stringify(failure);
      failures.set(key, { ...failure, count: (failures.get(key)?.count || 0) + 1 });
    }
    report.external_request_failures = [...failures.values()];
    report.check_count = report.checks.length;
    const reportPath = path.join(out, 'report.json');
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2) + '\n');
    console.log(JSON.stringify({ result: report.result, checks: report.check_count, error: report.error, report_path: reportPath }, null, 2));
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
