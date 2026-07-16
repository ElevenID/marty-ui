#!/usr/bin/env node

import { existsSync, mkdirSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

const betaOrigin = process.env.CANVAS_OSS_MARTY_ORIGIN || 'https://beta.elevenidllc.com';
const output = process.env.CANVAS_OSS_MONITOR_OUTPUT || '/artifacts/beta-continuity.json';
const stopFile = process.env.CANVAS_OSS_MONITOR_STOP_FILE || '/artifacts/stop-beta-monitor';
const intervalSeconds = Number(process.env.CANVAS_OSS_MONITOR_INTERVAL_SECONDS || 30);

if (betaOrigin !== 'https://beta.elevenidllc.com') {
  throw new Error('Continuity monitor is pinned to the beta Marty origin.');
}
if (!Number.isInteger(intervalSeconds) || intervalSeconds < 5 || intervalSeconds > 300) {
  throw new Error('Continuity monitor interval must be between 5 and 300 seconds.');
}

let terminating = false;
process.on('SIGTERM', () => { terminating = true; });
process.on('SIGINT', () => { terminating = true; });

function now() {
  return new Date().toISOString();
}

function writeReport(report) {
  mkdirSync(dirname(output), { recursive: true });
  const temporary = `${output}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(report, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  renameSync(temporary, output);
}

async function getJson(path) {
  const response = await fetch(`${betaOrigin}${path}`, {
    headers: { 'Cache-Control': 'no-cache', 'User-Agent': 'canvas-oss-portability-monitor/1' },
    redirect: 'error',
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) throw new Error(`Beta ${path} returned HTTP ${response.status}.`);
  return response.json();
}

async function assertBeta() {
  const ready = await fetch(`${betaOrigin}/ready`, {
    headers: { 'Cache-Control': 'no-cache', 'User-Agent': 'canvas-oss-portability-monitor/1' },
    redirect: 'error',
    signal: AbortSignal.timeout(20_000),
  });
  if (!ready.ok) throw new Error(`Beta readiness returned HTTP ${ready.status}.`);
  const [services, ui] = await Promise.all([
    getJson('/.well-known/marty-release'),
    getJson('/marty-ui-release.json'),
  ]);
  if (!services.release_version || services.release_version !== ui.release_version) {
    throw new Error('Beta UI and services release versions differ.');
  }
  if (!services.marty_ui_sha || services.marty_ui_sha !== ui.marty_ui_sha) {
    throw new Error('Beta UI and services source IDs differ.');
  }
}

const report = {
  schema_version: 1,
  execution_boundary: 'docker_compose_service',
  compose_service: 'canvas-continuity-monitor',
  host_runtime_process: false,
  started_at: now(),
  finished_at: null,
  checks: 0,
  failures: 0,
};

while (!terminating && !existsSync(stopFile)) {
  report.checks += 1;
  try {
    await assertBeta();
  } catch {
    report.failures += 1;
  }
  writeReport(report);
  if (!terminating && !existsSync(stopFile)) {
    await new Promise((resolve) => setTimeout(resolve, intervalSeconds * 1000));
  }
}

report.finished_at = now();
writeReport(report);
process.exitCode = report.failures === 0 && report.checks > 0 ? 0 : 1;
