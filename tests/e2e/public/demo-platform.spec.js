const { test, expect } = require('@playwright/test');

const viewports = [
  { name: 'mobile-320', width: 320, height: 700 },
  { name: 'mobile-390', width: 390, height: 844 },
  { name: 'tablet-768', width: 768, height: 900 },
  { name: 'desktop-1440', width: 1440, height: 1000 },
];

function observeBrowser(page) {
  const expectedOrigin = new URL(process.env.BASE_URL || 'http://127.0.0.1:4173').origin;
  const failures = [];
  const pageErrors = [];
  const consoleErrors = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(message.text());
  });
  page.on('response', (response) => {
    const url = new URL(response.url());
    if (url.origin === expectedOrigin && response.status() >= 400) {
      failures.push(`${response.status()} ${response.request().method()} ${url.pathname}`);
    }
  });
  page.on('requestfailed', (request) => {
    const url = new URL(request.url());
    if (url.origin === expectedOrigin) {
      failures.push(`${request.failure()?.errorText || 'failed'} ${request.method()} ${url.pathname}`);
    }
  });
  return { failures, pageErrors, consoleErrors };
}

async function assertStablePage(page, telemetry) {
  await expect(page.locator('[data-demo-render-state="settled"]')).toBeVisible();
  const metrics = await page.evaluate(() => ({
    scrollWidth: document.documentElement.scrollWidth,
    viewportWidth: window.innerWidth,
    images: [...document.images].map((image) => ({ src: image.currentSrc, complete: image.complete, width: image.naturalWidth })),
    loadingShellVisible: getComputedStyle(document.querySelector('.app-loading-shell')).display !== 'none',
  }));
  expect(metrics.scrollWidth).toBeLessThanOrEqual(metrics.viewportWidth);
  expect(metrics.loadingShellVisible).toBe(false);
  expect(metrics.images.every((image) => image.complete && image.width > 0)).toBe(true);
  expect(telemetry.pageErrors).toEqual([]);
  expect(telemetry.consoleErrors).toEqual([]);
  expect(telemetry.failures).toEqual([]);
}

for (const viewport of viewports) {
  test(`${viewport.name} renders catalog and scenario without overflow or first-paint failure`, async ({ page }) => {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    await page.addInitScript(() => {
      window.__elevenIdFirstPaint = [];
      const sample = () => {
        const root = document.querySelector('#root');
        const shell = document.querySelector('.app-loading-shell');
        if (root && shell) {
          window.__elevenIdFirstPaint.push({
            ready: document.documentElement.classList.contains('app-ready'),
            rootVisibility: getComputedStyle(root).visibility,
            shellDisplay: getComputedStyle(shell).display,
          });
        }
        if (performance.now() < 1800) requestAnimationFrame(sample);
      };
      requestAnimationFrame(sample);
    });
    const telemetry = observeBrowser(page);

    await page.goto('/demos', { waitUntil: 'domcontentloaded' });
    await expect(page.getByRole('heading', { level: 1, name: 'Credential Lifecycle Foundation' })).toBeVisible();
    await expect(page.getByText('ElevenID LLC Credential Platform', { exact: true })).toBeVisible();
    await expect(page.getByText('Version v2026.07.0', { exact: true })).toBeVisible();
    await expect(page.getByText('Implements MIP 0.3.1')).toBeVisible();
    await expect(page.getByRole('combobox', { name: 'Platform version' })).toContainText('v2026.07.0');
    await assertStablePage(page, telemetry);
    const firstPaint = await page.evaluate(() => window.__elevenIdFirstPaint);
    expect(firstPaint.filter((sample) => !sample.ready).every((sample) => sample.rootVisibility === 'hidden' && sample.shellDisplay !== 'none')).toBe(true);
    await page.screenshot({ path: test.info().outputPath(`${viewport.name}-catalog.png`), fullPage: true });

    await page.getByRole('link', { name: /Membership Badge and Login/ }).click();
    await expect(page.getByRole('heading', { level: 1, name: 'Membership Badge and Login' })).toBeVisible();
    await expect(page.getByText('Recording publication pending')).toBeVisible();
    await expect(page.locator('iframe[src*="youtube-nocookie.com"]')).toHaveCount(0);
    await expect(page.getByRole('heading', { level: 2, name: 'Transcript' })).toBeVisible();
    await assertStablePage(page, telemetry);
    await page.screenshot({ path: test.info().outputPath(`${viewport.name}-scenario.png`), fullPage: true });
  });
}

test('every release scenario has a canonical detail page and valid poster', async ({ page }) => {
  const telemetry = observeBrowser(page);
  const index = await (await page.request.get('/demos/manifests/index.json')).json();
  const release = index.releases[0];
  const manifest = await (await page.request.get(release.manifest_url)).json();
  for (const scenario of manifest.scenarios) {
    await page.goto(`/demos/${manifest.stack_version}/${scenario.slug}`);
    await expect(page.getByRole('heading', { level: 1, name: scenario.title })).toBeVisible();
    await expect(page.locator('link[rel="canonical"]')).toHaveAttribute('href', `https://elevenidllc.com/demos/${manifest.stack_version}/${scenario.slug}`);
    await assertStablePage(page, telemetry);
  }
});
