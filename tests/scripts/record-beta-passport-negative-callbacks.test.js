'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { validateCase, validatePair, scanCase, parseArgs, recordCase } = require('./record-beta-passport-negative-callbacks');

const digest = (value) => createHash('sha256').update(value).digest('hex');

function result(name) {
  return {
    schema: 'marty.passport-beta-negative-callback-case/v1',
    verified: true, physical_claim: 'not_claimed', case: name,
    release: { source_commit: 'a'.repeat(40), stack_manifest_sha256: 'b'.repeat(64) },
    deployment: { aggregate_deployment_receipt_sha256: 'c'.repeat(64),
      aggregate_plan_sha256: 'd'.repeat(64) },
    evidence: {
      http_status: name === 'unsigned' ? 422 : 404,
      webhook_owner: 'issuance-native',
      request_kind: name === 'unsigned' ? 'missing_signature_header' : 'signed_foreign_organization',
      response_projection: name === 'unsigned'
        ? { missing_signature_header: true } : { webhook_job_not_found: true },
      organization_commitment: name === 'unsigned' ? '1'.repeat(64) : '2'.repeat(64),
      source_job_commitment: '3'.repeat(64), bureau_job_commitment: '4'.repeat(64),
      job_state_before_commitment: '5'.repeat(64), job_state_after_commitment: '5'.repeat(64),
      ...(name === 'foreign' ? { signature_valid: true, foreign_organization: true } : {}),
    },
  };
}

test('only the exact two selected-job denial cases join', () => {
  const unsigned = result('unsigned');
  const foreign = result('foreign');
  assert.doesNotThrow(() => validatePair(unsigned, foreign));
  for (const mutate of [
    (item) => { item.release.stack_manifest_sha256 = 'e'.repeat(64); },
    (item) => { item.deployment.aggregate_plan_sha256 = 'e'.repeat(64); },
    (item) => { item.evidence.source_job_commitment = 'e'.repeat(64); },
    (item) => { item.evidence.bureau_job_commitment = 'e'.repeat(64); },
    (item) => { item.evidence.job_state_after_commitment = 'e'.repeat(64); },
    (item) => { item.evidence.organization_commitment = unsigned.evidence.organization_commitment; },
    (item) => { item.evidence.http_status = 200; },
    (item) => { item.evidence.callback_signature = 'private'; },
  ]) {
    const changed = structuredClone(foreign);
    mutate(changed);
    assert.throws(() => validatePair(unsigned, changed));
  }
  assert.throws(() => validateCase(unsigned, 'foreign'));
});

test('privacy scan must pass for the exact recorded clip', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'passport-negative-media-test-'));
  try {
    const videoSha256 = digest('uncut-video');
    const captured = { videoPath: path.join(directory, 'unsigned-callback-uncut.webm'), videoSha256 };
    const scanner = { scan: async () => ({ schemaVersion: 1, passed: true,
      findings: [], videoSha256, frameSamplingFps: 2 }) };
    const reportSha = await scanCase(scanner, 'unsigned', captured, directory);
    const file = path.join(directory, 'unsigned-callback-privacy-scan.json');
    assert.equal(reportSha, digest(fs.readFileSync(file)));
    assert.deepEqual(Object.keys(JSON.parse(fs.readFileSync(file))).sort(),
      ['schemaVersion', 'passed', 'findings', 'videoSha256', 'frameSamplingFps'].sort());
    await assert.rejects(scanCase({ scan: async () => ({ ...(await scanner.scan()),
      videoSha256: digest('different') }) }, 'foreign', captured, directory));
    await assert.rejects(scanCase({ scan: async () => ({ ...(await scanner.scan()),
      passed: false }) }, 'foreign', captured, directory));
  } finally {
    fs.rmSync(path.join(directory, 'unsigned-callback-privacy-scan.json'), { force: true });
    fs.rmdirSync(directory);
  }
});

test('recording CLI rejects missing and repeated source paths', () => {
  assert.throws(() => parseArgs(['--artifact-dir', '/tmp/artifacts']));
  assert.throws(() => parseArgs(['--artifact-dir', '/tmp/a', '--artifact-dir', '/tmp/b',
    '--private-handoff', '/tmp/private', '--output-dir', '/tmp/out',
    '--recorder-root', '/tmp/recorder']));
});

test('one continuous browser clip spans the live probe result', {
  skip: process.env.PASSPORT_NEGATIVE_VIDEO_BROWSER_TEST !== '1',
}, async () => {
  const { chromium } = require('@playwright/test');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'passport-negative-video-test-'));
  const browser = await chromium.launch({ headless: true, args: ['--no-proxy-server'] });
  try {
    const routedBrowser = { newContext: async (options) => {
      const context = await browser.newContext(options);
      await context.route('https://beta.elevenidllc.com/v1/passport/webhooks/personalization',
        (route) => route.fulfill({ status: 422, contentType: 'application/json',
          body: JSON.stringify({ detail: [{ type: 'missing',
            loc: ['header', 'x-personalization-signature'] }] }) }));
      return context;
    } };
    const captured = await recordCase(routedBrowser, 'unsigned', { outputDir: directory },
      async (_name, _paths, bridge) => {
        const receipt = await new Promise((resolve, reject) => {
          const request = http.request({ hostname: '127.0.0.1', port: bridge.port,
            path: '/callback', method: 'POST', headers: {
              'Content-Type': 'application/json', 'X-Probe-Bridge-Token': bridge.token,
            } }, (response) => {
            const chunks = [];
            response.on('data', (chunk) => chunks.push(chunk));
            response.on('end', () => resolve(JSON.parse(Buffer.concat(chunks).toString())));
          });
          request.once('error', reject);
          request.end(JSON.stringify({ body_b64: Buffer.from('{}').toString('base64'),
            signature: null }));
        });
        assert.deepEqual(receipt, { http_status: 422,
          response_projection: { missing_signature_header: true } });
        return result('unsigned');
      });
    assert.equal(captured.result.case, 'unsigned');
    assert.equal(captured.videoSha256, digest(fs.readFileSync(captured.videoPath)));
    assert.ok(fs.statSync(captured.videoPath).size > 0);
    assert.deepEqual(fs.readdirSync(directory), ['unsigned-callback-uncut.webm']);
    if (process.env.PASSPORT_NEGATIVE_SCAN_ROOT) {
      const scanner = require(path.join(process.env.PASSPORT_NEGATIVE_SCAN_ROOT,
        'src', 'secretScan.js'));
      const scanSha = await scanCase(scanner, 'unsigned', captured, directory);
      assert.match(scanSha, /^[0-9a-f]{64}$/);
      fs.unlinkSync(path.join(directory, 'unsigned-callback-privacy-scan.json'));
    }
    fs.unlinkSync(captured.videoPath);
  } finally {
    await browser.close();
    fs.rmdirSync(directory);
  }
});
