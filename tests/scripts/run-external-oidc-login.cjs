#!/usr/bin/env node
'use strict';

// Operator-assisted, real-provider login qualification. Never attaches to a
// personal browser or imports authentication state. The deployed Auth service
// remains responsible for token validation; this is not an OIDC validator.
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID, createHash } = require('node:crypto');

class QualificationError extends Error {
  constructor(code) { super(code); this.code = code; }
}
function check(value, code) { if (!value) throw new QualificationError(code); }
function httpsUrl(value) {
  let url;
  try { url = new URL(value); } catch { throw new QualificationError('invalid_https_url'); }
  check(typeof value === 'string' && value.trim() === value && value.length <= 2048
    && !/[\s\u0000-\u001f\u007f]/.test(value) && url.protocol === 'https:'
    && !url.username && !url.password && !url.hash, 'invalid_https_url');
  return url;
}
function text(value, maximum = 256) {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum
    && value.trim() === value && !/[\u0000-\u001f\u007f-\u009f]/.test(value);
}
function options(argv) {
  const cfg = { origin: '', 'authorization-endpoint': '', 'client-id': '', email: '',
    'user-id': '', 'organization-id': '', 'source-sha': '', 'output-dir': '',
    'required-role': '', 'timeout-seconds': '300', 'export-session': 'false' };
  const seen = new Set();
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i]?.slice(2);
    check(argv[i]?.startsWith('--') && Object.hasOwn(cfg, key) && !seen.has(key)
      && typeof argv[i + 1] === 'string' && !argv[i + 1].startsWith('--'), 'invalid_arguments');
    seen.add(key); cfg[key] = argv[i + 1];
  }
  for (const key of ['origin', 'authorization-endpoint', 'client-id', 'email', 'user-id',
    'organization-id', 'source-sha', 'output-dir']) check(text(cfg[key], 2048), 'required_argument_missing');
  check(httpsUrl(cfg.origin).origin === cfg.origin, 'canonical_origin_required');
  check(!httpsUrl(cfg['authorization-endpoint']).search, 'bare_authorization_endpoint_required');
  check(['client-id', 'email', 'user-id', 'organization-id'].every(key => text(cfg[key])), 'invalid_identity_configuration');
  check(!cfg['required-role'] || text(cfg['required-role'], 80), 'invalid_required_role');
  check(/^[a-f0-9]{40}$/.test(cfg['source-sha']), 'source_sha_required');
  check(/^[0-9]+$/.test(cfg['timeout-seconds']) && Number(cfg['timeout-seconds']) >= 30
    && Number(cfg['timeout-seconds']) <= 900, 'invalid_timeout');
  check(['true', 'false'].includes(cfg['export-session']), 'invalid_export_option');
  check(path.isAbsolute(cfg['output-dir']) && path.resolve(cfg['output-dir']) === cfg['output-dir'],
    'absolute_output_directory_required');
  check(process.env.NODE_TLS_REJECT_UNAUTHORIZED !== '0' && !process.env.DEBUG
    && !process.env.PWDEBUG && !process.env.PW_TEST_CONNECT_WS_ENDPOINT,
  'unsafe_runtime_environment');
  return cfg;
}

function single(query, key) {
  const values = query.getAll(key);
  check(values.length === 1 && text(values[0], 2048), 'authorization_parameter_invalid');
  return values[0];
}
function authorization(location, cfg) {
  const url = httpsUrl(location);
  const expected = httpsUrl(cfg['authorization-endpoint']);
  check(url.origin === expected.origin && url.pathname === expected.pathname,
    'authorization_endpoint_mismatch');
  const q = url.searchParams;
  check(!['client_secret', 'access_token', 'id_token', 'error'].some(key => q.has(key)),
    'unsafe_authorization_parameters');
  check(single(q, 'client_id') === cfg['client-id'] && single(q, 'response_type') === 'code',
    'authorization_client_mismatch');
  check(single(q, 'redirect_uri') === cfg.origin + '/v1/auth/callback', 'callback_origin_mismatch');
  check(single(q, 'scope').split(' ').includes('openid'), 'openid_scope_required');
  check(single(q, 'code_challenge_method') === 'S256'
    && /^[A-Za-z0-9_-]{43}$/.test(single(q, 'code_challenge')), 's256_pkce_required');
  const state = single(q, 'state');
  const nonce = single(q, 'nonce');
  check(state.length >= 16 && !/\s/.test(state) && nonce.length >= 16 && !/\s/.test(nonce),
    'state_and_nonce_required');
  return { state, url: url.href };
}

// Only main-frame navigation events reach this observer. Keep all codes,
// state, nonce and authorization URLs in memory, never in the receipt.
function createJourney(cfg) {
  let pending = null;
  let visited = false;
  let completed = false;
  let failure = null;
  const loginUrl = cfg.origin + '/v1/auth/login?redirect_uri=%2F';
  function guard(fn) {
    if (failure) return;
    try { fn(); } catch (error) {
      failure = error instanceof QualificationError ? error : new QualificationError('invalid_navigation');
    }
  }
  return {
    loginUrl,
    request(raw, method) {
      guard(() => {
        const url = new URL(raw);
        const endpoint = httpsUrl(cfg['authorization-endpoint']);
        if (url.origin === endpoint.origin && url.pathname === endpoint.pathname) {
          check(method === 'GET' && pending && !completed && url.href === pending.url,
            'unexpected_authorization_navigation');
          visited = true;
        }
      });
    },
    response(raw, status, location, method) {
      guard(() => {
        const url = new URL(raw);
        if (url.href === loginUrl) {
          check(!pending && method === 'GET' && [302, 303].includes(status), 'login_start_failed');
          pending = authorization(location, cfg);
        } else if (url.origin === cfg.origin && url.pathname === '/v1/auth/callback') {
          httpsUrl(raw);
          check(pending && visited && !completed && method === 'GET', 'unexpected_callback');
          check(!url.searchParams.has('error') && !url.searchParams.has('error_description'), 'provider_rejected_login');
          check(single(url.searchParams, 'state') === pending.state, 'callback_state_mismatch');
          single(url.searchParams, 'code');
          check([302, 303].includes(status), 'callback_failed');
          check(text(location, 8192), 'callback_failed');
          const destination = httpsUrl(new URL(location, cfg.origin).href);
          check(destination.origin === cfg.origin && !destination.searchParams.has('auth_error'), 'callback_failed');
          completed = true;
          pending = null;
        }
      });
    },
    assertHealthy() { if (failure) throw failure; },
    get complete() { return completed && !failure; },
  };
}

async function api(request, origin, route, method = 'GET') {
  const response = await request.fetch(origin + route, { method, maxRedirects: 0, timeout: 15000,
    headers: { Accept: 'application/json', 'Cache-Control': 'no-store', Origin: origin } });
  try {
    const status = response.status();
    if (method === 'POST') {
      check([302, 303].includes(status), 'logout_request_failed');
      return null;
    }
    if (status === 401 && route === '/v1/auth/me') return { authenticated: false };
    check(status === 200, 'application_api_failed');
    const headers = response.headers();
    check(/^application\/json(?:\s*;|$)/i.test(headers['content-type'] || ''), 'application_json_required');
    const declared = headers['content-length'];
    check(!declared || (/^[0-9]+$/.test(declared) && Number(declared) <= 262144), 'response_too_large');
    const body = await response.body();
    check(body.length <= 262144, 'response_too_large');
    try { return JSON.parse(body.toString('utf8')); }
    catch { throw new QualificationError('application_json_invalid'); }
  } finally { await response.dispose(); }
}
function anonymous(me) { check(me?.authenticated === false, 'anonymous_session_required'); }
function identity(me, cfg) {
  const user = me?.user;
  check(me?.authenticated === true && user && !Array.isArray(user)
    && user.email === cfg.email && (user.user_id || user.id) === cfg['user-id'], 'operator_identity_mismatch');
  check(!user.impersonation, 'impersonated_session_refused');
  if (cfg['required-role']) check(Array.isArray(user.roles) && user.roles.includes(cfg['required-role']),
    'operator_role_mismatch');
}
function membership(items, cfg) {
  check(Array.isArray(items) && items.filter(item => item?.id === cfg['organization-id']).length === 1,
    'operator_membership_mismatch');
}
function applicationCookies(cookies, origin) {
  const hostname = new URL(origin).hostname;
  const names = new Set();
  const selected = cookies.filter(cookie => cookie.domain === hostname && cookie.secure === true && cookie.httpOnly === true
    && ['/', '/v1', '/v1/'].includes(cookie.path) && !Object.hasOwn(cookie, 'partitionKey')
    && Number.isFinite(cookie.expires) && (cookie.expires === -1 || cookie.expires > Date.now() / 1000));
  check(selected.length > 0, 'application_session_cookie_required');
  return selected.map(cookie => {
    check(text(cookie.name) && /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(cookie.name)
      && typeof cookie.value === 'string' && cookie.value.length <= 8192
      && /^[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*$/.test(cookie.value)
      && ['Strict', 'Lax', 'None'].includes(cookie.sameSite) && !names.has(cookie.name), 'ambiguous_session_cookie');
    names.add(cookie.name);
    return { name: cookie.name, value: cookie.value, domain: hostname, path: cookie.path,
      expires: cookie.expires, httpOnly: true, secure: true, sameSite: cookie.sameSite };
  });
}

function prepareOutput(directory) {
  const repo = path.resolve(__dirname, '../..');
  check(directory !== repo && !directory.startsWith(repo + path.sep), 'output_must_be_outside_checkout');
  const parent = path.dirname(directory);
  let component = path.parse(parent).root;
  for (const part of parent.slice(component.length).split(path.sep).filter(Boolean)) {
    component = path.join(component, part);
    const info = fs.lstatSync(component);
    check(info.isDirectory() && !info.isSymbolicLink(), 'output_parent_symlink_refused');
  }
  const info = fs.lstatSync(parent);
  check(typeof process.getuid === 'function' && info.uid === process.getuid()
    && (info.mode & 0o777) === 0o700, 'owned_private_output_parent_required');
  fs.mkdirSync(directory, { mode: 0o700 }); // Existing runs are never overwritten.
  const created = fs.lstatSync(directory);
  return (name, value) => {
    check(['receipt.json', 'session-export.json'].includes(name), 'invalid_output_name');
    const current = fs.lstatSync(directory);
    check(current.isDirectory() && !current.isSymbolicLink() && current.uid === process.getuid()
      && current.dev === created.dev && current.ino === created.ino
      && (current.mode & 0o777) === 0o700, 'private_output_directory_required');
    const data = JSON.stringify(value, null, 2) + '\n';
    check(Buffer.byteLength(data) <= 1048576, 'output_too_large');
    const fd = fs.openSync(path.join(directory, name), fs.constants.O_WRONLY | fs.constants.O_CREAT
      | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    try { fs.writeFileSync(fd, data); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  };
}

async function browserLogin(context, cfg, notify, sleep) {
  const page = await context.newPage();
  const journey = createJourney(cfg);
  const isMain = request => request.isNavigationRequest() && request.frame() === page.mainFrame();
  const onRequest = request => { if (isMain(request)) journey.request(request.url(), request.method()); };
  const onResponse = response => {
    const request = response.request();
    if (isMain(request)) journey.response(response.url(), response.status(), response.headers().location, request.method());
  };
  page.on('request', onRequest); page.on('response', onResponse);
  try {
    notify({ event: 'complete_login_in_isolated_test_browser' });
    const deadline = Date.now() + Number(cfg['timeout-seconds']) * 1000;
    await page.goto(journey.loginUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
    while (!journey.complete) {
      journey.assertHealthy();
      check(!page.isClosed(), 'test_browser_closed');
      check(Date.now() < deadline, 'provider_login_timeout');
      await sleep(200);
    }
    journey.assertHealthy();
    identity(await api(context.request, cfg.origin, '/v1/auth/me'), cfg);
    membership(await api(context.request, cfg.origin, '/v1/organizations/mine'), cfg);
  } finally {
    page.off('request', onRequest); page.off('response', onResponse);
    await page.close().catch(() => {});
  }
}

async function qualify(cfg, playwright, notify = () => {}, sleep = ms => new Promise(resolve => setTimeout(resolve, ms))) {
  const write = prepareOutput(cfg['output-dir']);
  const binding = Object.fromEntries(['origin', 'authorization-endpoint', 'client-id', 'email',
    'user-id', 'organization-id', 'required-role', 'source-sha'].map(key => [key, cfg[key]]));
  const receipt = { configurationSha256: createHash('sha256').update(JSON.stringify(binding)).digest('hex'),
    schema: 'elevenid.external-oidc-browser-qualification/v1', runId: randomUUID(),
    declaredSourceSha: cfg['source-sha'], sourceDeploymentVerified: false,
    result: 'stopped', loginVerified: false, sessionVerified: false, membershipVerified: false,
    requiredRoleVerified: false, localLogoutVerified: false, oldSessionRejected: false,
    providerLogoutVerified: false, mfaVerified: false, tokenClaimsIndependentlyInspected: false,
    issuanceVerified: false, persistenceVerified: false, rotationVerified: false,
    repeatLoginVerified: false, exportedSession: false };
  let stage = 'browser_launch';
  let browser;
  let context;
  let replay;
  let exportState;
  try {
    browser = await playwright.chromium.launch({ headless: false });
    context = await browser.newContext({ ignoreHTTPSErrors: false, serviceWorkers: 'block' });
    stage = 'anonymous_baseline';
    anonymous(await api(context.request, cfg.origin, '/v1/auth/me'));
    stage = 'external_provider';
    const provider = await api(context.request, cfg.origin, '/v1/auth/provider');
    check(provider?.provider_mode === 'external', 'external_provider_required');
    stage = 'provider_login';
    await browserLogin(context, cfg, notify, sleep);
    receipt.loginVerified = receipt.sessionVerified = receipt.membershipVerified = true;
    receipt.requiredRoleVerified = Boolean(cfg['required-role']);
    stage = 'session_replay_baseline';
    const oldCookies = applicationCookies(await context.cookies(), cfg.origin);
    replay = await browser.newContext({ ignoreHTTPSErrors: false, serviceWorkers: 'block' });
    await replay.addCookies(oldCookies);
    identity(await api(replay.request, cfg.origin, '/v1/auth/me'), cfg);
    stage = 'local_logout';
    await api(context.request, cfg.origin, '/v1/auth/logout', 'POST');
    anonymous(await api(context.request, cfg.origin, '/v1/auth/me'));
    receipt.localLogoutVerified = true;
    stage = 'old_session_rejection';
    anonymous(await api(replay.request, cfg.origin, '/v1/auth/me'));
    receipt.oldSessionRejected = true;
    if (cfg['export-session'] === 'true') {
      // A logged-out cookie is useless for issuance acceptance. A second real
      // login is required; only application cookies are exported, never IdP state.
      stage = 'repeat_login';
      await context.close();
      context = await browser.newContext({ ignoreHTTPSErrors: false, serviceWorkers: 'block' });
      anonymous(await api(context.request, cfg.origin, '/v1/auth/me'));
      await browserLogin(context, cfg, notify, sleep);
      receipt.repeatLoginVerified = true;
      exportState = { cookies: applicationCookies(await context.cookies(), cfg.origin), origins: [] };
    }
    receipt.result = 'passed';
  } catch (error) {
    receipt.stage = stage;
    receipt.code = error instanceof QualificationError ? error.code : 'qualification_step_failed';
  } finally {
    for (const resource of [replay, context, browser]) {
      if (!resource) continue;
      try { await resource.close(); } catch {
        receipt.result = 'stopped'; receipt.stage = 'cleanup'; receipt.code = 'browser_cleanup_failed';
      }
    }
  }
  if (receipt.result === 'passed' && exportState) {
    write('session-export.json', exportState);
    receipt.exportedSession = true;
  }
  receipt.finishedAt = new Date().toISOString();
  write('receipt.json', receipt);
  return receipt;
}

async function main(argv) {
  if (argv.length === 1 && argv[0] === '--help') {
    process.stdout.write('Usage: node tests/scripts/run-external-oidc-login.cjs\n'
      + '  --origin HTTPS_ORIGIN --authorization-endpoint EXACT_HTTPS_ENDPOINT\n'
      + '  --client-id CLIENT_ID --email EXPECTED_EMAIL --user-id EXPECTED_MARTY_ID\n'
      + '  --organization-id EXPECTED_ORG_ID --source-sha DECLARED_40_HEX_SHA\n'
      + '  --output-dir NEW_ABSOLUTE_DIRECTORY [--required-role EXACT_ROLE]\n'
      + '  [--timeout-seconds 30..900] [--export-session true|false]\n'
      + 'Run on a Linux/macOS desktop with the existing tests Playwright install.\n'
      + 'Output parent must be owned, mode 0700, and outside the checkout.\n'
      + 'Complete authentication/MFA manually in the isolated test browser.\n');
    return;
  }
  const cfg = options(argv);
  // Load the repository's existing dependency only when executing a live run.
  const result = await qualify(cfg, require('@playwright/test'),
    value => process.stdout.write(JSON.stringify(value) + '\n'));
  process.stdout.write(JSON.stringify(result) + '\n');
  if (result.result !== 'passed') process.exitCode = 1;
}
if (require.main === module) main(process.argv.slice(2)).catch(error => {
  process.stdout.write(JSON.stringify({ result: 'stopped', code:
    error instanceof QualificationError ? error.code : 'qualification_setup_failed' }) + '\n');
  process.exitCode = 1;
});
module.exports = { QualificationError, options, authorization, createJourney, api, anonymous,
  identity, membership, applicationCookies, prepareOutput, browserLogin, qualify };
