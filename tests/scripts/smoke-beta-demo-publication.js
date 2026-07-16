#!/usr/bin/env node
/* eslint-disable no-console */

const fs = require('fs');
const path = require('path');
const { chromium } = require('@playwright/test');

const BETA_ORIGIN = process.env.BETA_ORIGIN || 'https://beta.elevenidllc.com';
const manifestPath = process.env.ELEVENID_DEMO_MANIFEST;
const videoId = process.env.ELEVENID_DEMO_VIDEO_ID;
const reportPath = process.env.ELEVENID_DEMO_SMOKE_REPORT;
const PUBLIC_BROWSER_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36';

async function main() {
  if (!manifestPath || !videoId || !reportPath) throw new Error('Demo manifest, video ID, and smoke report path are required');
  const manifest = JSON.parse(fs.readFileSync(path.resolve(manifestPath), 'utf8'));
  const scenario = manifest.scenarios.find((item) => item.youtube_id === videoId);
  if (!scenario) throw new Error(`Manifest does not contain video ${videoId}`);
  const browser = await chromium.launch({ headless: true });
  const report = {
    schemaVersion: 1,
    stackVersion: manifest.stack_version,
    scenarioSlug: scenario.slug,
    videoId,
    betaOrigin: BETA_ORIGIN,
    viewports: [],
    pageErrors: [],
    requestFailures: [],
    passed: false,
  };
  try {
    for (const width of [320, 390, 768, 1440]) {
      const context = await browser.newContext({
        viewport: { width, height: width < 768 ? 844 : 1000 },
        userAgent: PUBLIC_BROWSER_USER_AGENT,
      });
      const page = await context.newPage();
      page.on('pageerror', (error) => report.pageErrors.push(error.message));
      page.on('requestfailed', (request) => {
        const url = request.url();
        if (!url.includes('googlevideo.com') && !url.startsWith(`https://www.youtube-nocookie.com/embed/${videoId}`)) {
          report.requestFailures.push(url);
        }
      });
      await page.goto(`${BETA_ORIGIN}/demos/${manifest.stack_version}/${scenario.slug}`, {
        waitUntil: 'domcontentloaded',
        timeout: 60_000,
      });
      const load = page.getByRole('button', { name: new RegExp(`Load ${scenario.title} from YouTube`, 'i') });
      await load.waitFor({ state: 'visible', timeout: 30_000 });
      const dimensions = await page.evaluate(() => ({
        scrollWidth: document.documentElement.scrollWidth,
        clientWidth: document.documentElement.clientWidth,
      }));
      await load.click();
      const player = page.getByTitle(`${scenario.title} video`);
      await player.waitFor({ state: 'visible', timeout: 30_000 });
      const source = await player.getAttribute('src');
      if (!source?.includes(`youtube-nocookie.com/embed/${videoId}`)) throw new Error('Demo page embedded the wrong YouTube video');
      report.viewports.push({ width, ...dimensions, overflow: dimensions.scrollWidth > dimensions.clientWidth });
      await context.close();
    }
    const embed = await fetch(`https://www.youtube-nocookie.com/embed/${videoId}`);
    if (!embed.ok) throw new Error(`YouTube embed returned HTTP ${embed.status}`);
    report.passed = report.pageErrors.length === 0
      && report.requestFailures.length === 0
      && report.viewports.every((item) => !item.overflow);
  } finally {
    report.completedAt = new Date().toISOString();
    fs.mkdirSync(path.dirname(path.resolve(reportPath)), { recursive: true });
    fs.writeFileSync(path.resolve(reportPath), `${JSON.stringify(report, null, 2)}\n`, 'utf8');
    await browser.close();
  }
  if (!report.passed) throw new Error('Public demo page smoke failed');
  console.log(JSON.stringify(report, null, 2));
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
