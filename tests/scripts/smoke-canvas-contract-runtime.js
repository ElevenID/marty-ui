'use strict';

// Build-time runtime check only. This does not contact Canvas or qualify a demo.
const assert = require('node:assert/strict');
const { chromium } = require('@playwright/test');

(async () => {
  assert(Number(process.versions.node.split('.')[0]) >= 24, 'Canvas contract requires Node 24 or later');
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage();
    await page.setContent('<button>Runtime smoke check</button>');
    await page.getByRole('button', { name: 'Runtime smoke check' }).click();
    console.log(JSON.stringify({ scope: 'CONTAINER_RUNTIME_SMOKE_ONLY', node: process.versions.node,
      playwright: require('@playwright/test/package.json').version, chromium: browser.version(), result: 'PASS' }));
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
