#!/usr/bin/env node
'use strict';

// The hosted image already carries Chromium's shared libraries. Verify the
// exact lockfile-selected browser can launch instead of running an unbounded
// package-manager update on every queue entry. Missing libraries remain fatal.
const { chromium } = require('@playwright/test');

async function main() {
  const browser = await chromium.launch({ headless: true, timeout: 30_000 });
  try {
    const page = await browser.newPage();
    await page.goto('data:text/html,<title>Browser runtime check</title>');
    if (await page.title() !== 'Browser runtime check') {
      throw new Error('Pinned browser runtime check failed');
    }
    console.log('Pinned Chromium launched and rendered successfully.');
  } finally {
    await browser.close();
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
