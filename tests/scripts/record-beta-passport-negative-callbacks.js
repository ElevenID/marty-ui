#!/usr/bin/env node
/* eslint-disable no-console */
'use strict';

// Record each live denial during its own continuous browser video. The page
// contains only fixed, sanitized labels; the protected Python probe owns the
// HTTP request and exact selected-job checks. No media is publishable until
// this script's separate frame/OCR/QR scans and the preliminary gate pass.
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { spawn, execFileSync } = require('node:child_process');
const { createHash, randomBytes } = require('node:crypto');

const ROOT = path.resolve(__dirname, '..', '..');
const SHA256 = /^[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const CASES = ['unsigned', 'foreign'];
const MAX_VIDEO_BYTES = 128 * 1024 * 1024;
const BETA_ORIGIN = 'https://beta.elevenidllc.com';
const WEBHOOK = `${BETA_ORIGIN}/v1/passport/webhooks/personalization`;
const BOOTSTRAP = `${BETA_ORIGIN}/__marty_negative_probe__`;
const SAFE_PAGE = '<html><body style="background:#0f172a;color:#f8fafc;font:32px Arial;padding:60px"><main><h1>Protected Marty beta callback probe</h1><p id="case"></p><p id="status">Live beta request in progress</p></main></body></html>';

function requireProof(condition, message) {
  if (!condition) throw new Error(message);
}

function fileDigest(file) {
  return createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function inside(candidate, parent) {
  const relative = path.relative(parent, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..'
    && !path.isAbsolute(relative));
}

function readJson(file) {
  const stat = fs.lstatSync(file);
  requireProof(stat.isFile() && !stat.isSymbolicLink() && stat.size > 0 && stat.size <= 1024 * 1024,
    'Negative callback evidence file is invalid');
  const value = JSON.parse(fs.readFileSync(file, 'utf8'));
  requireProof(value && typeof value === 'object' && !Array.isArray(value),
    'Negative callback evidence must be an object');
  return value;
}

function validateCase(result, name) {
  const evidence = result?.evidence;
  const baseKeys = ['http_status', 'webhook_owner', 'request_kind',
    'response_projection', 'organization_commitment', 'source_job_commitment',
    'bureau_job_commitment', 'job_state_before_commitment', 'job_state_after_commitment'];
  const expectedKeys = name === 'foreign'
    ? [...baseKeys, 'signature_valid', 'foreign_organization'] : baseKeys;
  requireProof(result?.schema === 'marty.passport-beta-negative-callback-case/v1'
    && JSON.stringify(Object.keys(result).sort()) === JSON.stringify([
      'schema', 'verified', 'physical_claim', 'case', 'evidence', 'release', 'deployment',
    ].sort())
    && result.verified === true && result.case === name
    && result.physical_claim === 'not_claimed'
    && JSON.stringify(Object.keys(result.release || {}).sort()) === JSON.stringify([
      'source_commit', 'stack_manifest_sha256',
    ].sort())
    && JSON.stringify(Object.keys(result.deployment || {}).sort()) === JSON.stringify([
      'aggregate_deployment_receipt_sha256', 'aggregate_plan_sha256',
    ].sort())
    && COMMIT.test(result.release?.source_commit)
    && SHA256.test(result.release?.stack_manifest_sha256)
    && SHA256.test(result.deployment?.aggregate_deployment_receipt_sha256)
    && SHA256.test(result.deployment?.aggregate_plan_sha256)
    && evidence && typeof evidence === 'object'
    && JSON.stringify(Object.keys(evidence).sort()) === JSON.stringify(expectedKeys.sort())
    && evidence.webhook_owner === 'issuance-native'
    && SHA256.test(evidence.organization_commitment)
    && SHA256.test(evidence.source_job_commitment)
    && SHA256.test(evidence.bureau_job_commitment)
    && SHA256.test(evidence.job_state_before_commitment)
    && evidence.job_state_after_commitment === evidence.job_state_before_commitment,
  'Negative callback case or selected job proof is incomplete');
  if (name === 'unsigned') {
    requireProof(evidence.http_status === 422
      && evidence.request_kind === 'missing_signature_header'
      && evidence.response_projection?.missing_signature_header === true,
    'Unsigned native callback denial is unproven');
  } else {
    requireProof(evidence.http_status === 404
      && evidence.request_kind === 'signed_foreign_organization'
      && evidence.signature_valid === true && evidence.foreign_organization === true
      && evidence.response_projection?.webhook_job_not_found === true,
    'Signed foreign-organization callback denial is unproven');
  }
  return evidence;
}

function validatePair(unsigned, foreign) {
  const left = validateCase(unsigned, 'unsigned');
  const right = validateCase(foreign, 'foreign');
  for (const field of ['source_commit', 'stack_manifest_sha256']) {
    requireProof(unsigned.release[field] === foreign.release[field],
      'Negative callback cases use different signed releases');
  }
  for (const field of ['aggregate_deployment_receipt_sha256', 'aggregate_plan_sha256']) {
    requireProof(unsigned.deployment[field] === foreign.deployment[field],
      'Negative callback cases use different beta deployments');
  }
  for (const field of ['source_job_commitment', 'bureau_job_commitment',
    'job_state_before_commitment']) {
    requireProof(left[field] === right[field],
      'Negative callback cases do not refer to one unchanged selected job');
  }
  requireProof(left.organization_commitment !== right.organization_commitment,
    'Foreign callback organization is not distinct');
}

function parseArgs(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    requireProof(['--artifact-dir', '--private-handoff', '--output-dir', '--recorder-root']
      .includes(name) && typeof argv[index + 1] === 'string' && argv[index + 1],
    'Negative callback recording arguments are incomplete');
    requireProof(!Object.hasOwn(result, name), 'Negative callback recording argument repeated');
    result[name] = argv[index + 1];
  }
  requireProof(Object.keys(result).length === 4, 'Negative callback recording inputs are incomplete');
  return result;
}

function preflight(args, environment = process.env) {
  requireProof(!environment.BETA_LOCAL_PROXY, 'Negative recording requires direct beta TLS and DNS');
  requireProof(typeof environment.PASSPORT_ACCEPTANCE_API_KEY === 'string'
    && environment.PASSPORT_ACCEPTANCE_API_KEY.length >= 32,
  'Protected beta API key is unavailable');
  requireProof(COMMIT.test(environment.PASSPORT_DEMO_RECORDER_COMMIT || ''),
    'Pinned demo recorder revision is unavailable');
  const artifactDir = fs.realpathSync(args['--artifact-dir']);
  const privateInput = args['--private-handoff'];
  requireProof(!fs.lstatSync(privateInput).isSymbolicLink(),
    'Protected private handoff cannot be a symlink');
  const privateHandoff = fs.realpathSync(privateInput);
  const recorderRoot = fs.realpathSync(args['--recorder-root']);
  const requestedOutput = path.resolve(args['--output-dir']);
  const outputDir = path.join(fs.realpathSync(path.dirname(requestedOutput)),
    path.basename(requestedOutput));
  requireProof(fs.statSync(artifactDir).isDirectory()
    && fs.statSync(recorderRoot).isDirectory()
    && fs.statSync(privateHandoff).isFile()
    && (process.platform === 'win32' || (fs.statSync(privateHandoff).mode & 0o077) === 0)
    && !inside(privateHandoff, ROOT) && !inside(privateHandoff, artifactDir)
    && !inside(outputDir, ROOT) && !inside(outputDir, artifactDir)
    && !inside(privateHandoff, outputDir) && !inside(outputDir, privateHandoff)
    && !fs.existsSync(outputDir),
  'Protected negative recording paths overlap or already exist');
  const revision = execFileSync('git', ['-C', recorderRoot, 'rev-parse', 'HEAD'],
    { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  requireProof(revision === environment.PASSPORT_DEMO_RECORDER_COMMIT,
    'Demo recorder does not match its pinned revision');
  const trackedChanges = execFileSync('git', ['-C', recorderRoot, 'status', '--porcelain',
    '--untracked-files=no'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  requireProof(!trackedChanges.trim(), 'Pinned demo recorder has local changes');
  const scannerPath = path.join(recorderRoot, 'src', 'secretScan.js');
  requireProof(fs.lstatSync(scannerPath).isFile() && !fs.lstatSync(scannerPath).isSymbolicLink(),
  'Pinned demo recorder privacy scanner is unavailable');
  return { artifactDir, privateHandoff, recorderRoot, outputDir };
}

function runProbe(name, paths, bridge) {
  return new Promise((resolve, reject) => {
    const output = path.join(paths.outputDir, `${name}-callback-result.json`);
    const child = spawn('python3', [
      path.join(ROOT, 'scripts', 'probe_passport_beta_negative_callbacks.py'),
      '--artifact-dir', paths.artifactDir,
      '--private-handoff', paths.privateHandoff,
      '--output', output, '--case', name,
    ], { cwd: ROOT, stdio: 'ignore', shell: false,
      env: { ...process.env,
        PASSPORT_NEGATIVE_BROWSER_BRIDGE_PORT: String(bridge.port),
        PASSPORT_NEGATIVE_BROWSER_BRIDGE_TOKEN: bridge.token } });
    let settled = false;
    const timer = setTimeout(() => child.kill(), 300_000);
    child.once('error', () => {
      if (!settled) { settled = true; clearTimeout(timer); reject(new Error('Protected callback probe could not start')); }
    });
    child.once('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (code !== 0) reject(new Error('Protected callback probe failed'));
      else {
        try { resolve(readJson(output)); } catch { reject(new Error('Protected callback result is invalid')); }
      }
    });
  });
}

async function createBridge(page, name) {
  const token = randomBytes(32).toString('hex');
  let receipt = null;
  let attempted = false;
  const server = http.createServer(async (request, response) => {
    try {
      requireProof(!attempted && request.method === 'POST' && request.url === '/callback'
        && request.headers['x-probe-bridge-token'] === token,
      'Protected browser bridge rejected request');
      attempted = true;
      const chunks = [];
      let size = 0;
      for await (const chunk of request) {
        size += chunk.length;
        requireProof(size <= 8192, 'Protected browser bridge request is oversized');
        chunks.push(chunk);
      }
      const payload = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      requireProof(payload && typeof payload === 'object'
        && Object.keys(payload).sort().join(',') === 'body_b64,signature'
        && typeof payload.body_b64 === 'string'
        && /^[A-Za-z0-9+/]+={0,2}$/.test(payload.body_b64)
        && (name === 'unsigned' ? payload.signature === null
          : /^vault:v[0-9]+:[A-Za-z0-9+/]{43}=$/.test(payload.signature)),
      'Protected browser bridge payload is invalid');
      const body = Buffer.from(payload.body_b64, 'base64').toString('utf8');
      const result = await page.evaluate(async ({ url, jsonBody, signature }) => {
        const headers = { 'Content-Type': 'application/json', Accept: 'application/json' };
        if (signature !== null) headers['x-personalization-signature'] = signature;
        const observed = await fetch(url, { method: 'POST', headers, body: jsonBody,
          credentials: 'omit', redirect: 'manual', cache: 'no-store' });
        let detail = null;
        try { detail = (await observed.json()).detail; } catch { /* invalid body fails below */ }
        return {
          http_status: observed.status,
          response_projection: {
            missing_signature_header: Array.isArray(detail) && detail.length === 1
              && detail[0]?.type === 'missing'
              && JSON.stringify(detail[0]?.loc) === JSON.stringify(['header', 'x-personalization-signature']),
            webhook_job_not_found: detail === 'Physical document job not found',
          },
        };
      }, { url: WEBHOOK, jsonBody: body, signature: payload.signature });
      const projection = name === 'unsigned'
        ? { missing_signature_header: true } : { webhook_job_not_found: true };
      requireProof(result.http_status === (name === 'unsigned' ? 422 : 404)
        && result.response_projection[Object.keys(projection)[0]] === true,
      'Live browser callback denial is unproven');
      receipt = { http_status: result.http_status, response_projection: projection };
      await page.locator('#status').evaluate((node, value) => { node.textContent = value; },
        name === 'unsigned' ? 'Live beta HTTP 422: missing signature header'
          : 'Live beta HTTP 404: signed foreign organization denied');
      response.writeHead(200, { 'Content-Type': 'application/json' });
      response.end(JSON.stringify(receipt));
    } catch {
      response.writeHead(502, { 'Content-Type': 'application/json' });
      response.end('{}');
    }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return { port: server.address().port, token,
    get receipt() { return receipt; },
    close: () => new Promise((resolve) => server.close(resolve)) };
}

async function recordCase(browser, name, paths, probe = runProbe,
  bridgeFactory = createBridge) {
  const context = await browser.newContext({
    viewport: { width: 1280, height: 720 },
    serviceWorkers: 'block',
    recordVideo: { dir: paths.outputDir, size: { width: 1280, height: 720 } },
  });
  let video;
  let bridge;
  try {
    await context.route(BOOTSTRAP, (route) => route.fulfill({ status: 200,
      contentType: 'text/html', body: SAFE_PAGE }));
    const page = await context.newPage();
    video = page.video();
    await page.goto(BOOTSTRAP, { waitUntil: 'domcontentloaded', timeout: 30_000 });
    requireProof(new URL(page.url()).origin === BETA_ORIGIN,
      'Protected browser probe did not retain beta origin');
    await page.locator('#case').evaluate((node, value) => { node.textContent = value; },
      name === 'unsigned' ? 'Unsigned callback: expected HTTP 422'
        : 'Signed foreign-organization callback: expected HTTP 404');
    bridge = await bridgeFactory(page, name);
    const result = await probe(name, paths, bridge);
    validateCase(result, name);
    requireProof(bridge.receipt?.http_status === result.evidence.http_status
      && JSON.stringify(bridge.receipt.response_projection)
        === JSON.stringify(result.evidence.response_projection),
    'Recorded browser callback differs from protected job probe');
    await page.locator('#status').evaluate((node, value) => { node.textContent = value; },
      name === 'unsigned' ? 'HTTP 422 verified. Selected job unchanged.'
        : 'HTTP 404 verified. Selected job unchanged.');
    await page.waitForTimeout(1600);
    await context.close();
    const file = path.join(paths.outputDir, `${name}-callback-uncut.webm`);
    requireProof(!fs.existsSync(file), 'Negative callback video already exists');
    await video.saveAs(file);
    const raw = await video.path();
    requireProof(inside(raw, paths.outputDir) && raw !== file,
      'Raw negative callback video path is outside the protected directory');
    fs.unlinkSync(raw);
    const stat = fs.lstatSync(file);
    requireProof(stat.isFile() && stat.size > 0 && stat.size <= MAX_VIDEO_BYTES,
      'Negative callback video is missing or oversized');
    return { result, videoPath: file, videoSha256: fileDigest(file) };
  } finally {
    if (bridge) await bridge.close();
    await context.close().catch(() => {});
  }
}

async function scanCase(scanner, name, captured, outputDir) {
  const scan = await scanner.scan(outputDir, captured.videoPath);
  requireProof(scan?.schemaVersion === 1 && scan.passed === true
    && Array.isArray(scan.findings) && scan.findings.length === 0
    && scan.videoSha256 === captured.videoSha256
    && Number(scan.frameSamplingFps) >= 2,
  'Negative callback video privacy scan failed');
  const projected = { schemaVersion: 1, passed: true, findings: [],
    videoSha256: captured.videoSha256, frameSamplingFps: scan.frameSamplingFps };
  const file = path.join(outputDir, `${name}-callback-privacy-scan.json`);
  fs.writeFileSync(file, `${JSON.stringify(projected, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  return fileDigest(file);
}

async function main() {
  const paths = preflight(parseArgs(process.argv.slice(2)));
  fs.mkdirSync(paths.outputDir, { mode: 0o700 });
  const scanner = require(path.join(paths.recorderRoot, 'src', 'secretScan.js'));
  const { chromium } = require('@playwright/test');
  const browser = await chromium.launch({ headless: true, args: ['--no-proxy-server'] });
  const runs = {};
  try {
    for (const name of CASES) {
      const captured = await recordCase(browser, name, paths);
      runs[name] = { ...captured.result.evidence,
        video_sha256: captured.videoSha256,
        privacy_scan_report_sha256: await scanCase(scanner, name, captured, paths.outputDir) };
      runs[`${name}Result`] = captured.result;
    }
    validatePair(runs.unsignedResult, runs.foreignResult);
    requireProof(runs.unsigned.video_sha256 !== runs.foreign.video_sha256,
      'Negative callback clips are identical');
    const report = {
      schema: 'marty.passport-beta-negative-media/v1', verified: true,
      physical_claim: 'not_claimed',
      release: runs.unsignedResult.release,
      deployment: runs.unsignedResult.deployment,
      negative_runs: { unsigned: runs.unsigned, foreign: runs.foreign },
    };
    fs.writeFileSync(path.join(paths.outputDir, 'negative-callback-media.json'),
      `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  } finally {
    await browser.close();
  }
}

if (require.main === module) {
  main().catch(() => { console.error('Protected negative callback media recording blocked'); process.exitCode = 1; });
}

module.exports = { validateCase, validatePair, scanCase, parseArgs, preflight,
  recordCase, createBridge };
