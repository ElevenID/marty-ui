'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

function resolveUiCandidateDist(root, configured = process.env.MARTY_UI_CANDIDATE_DIST, dependencies = {}) {
  const value = String(configured || '').trim();
  if (!value) return null;
  const expected = fs.realpathSync(path.join(root, 'ui', 'dist'));
  const candidate = fs.realpathSync(path.resolve(value));
  if (candidate !== expected) {
    throw new Error('MARTY_UI_CANDIDATE_DIST must resolve to this worktree\'s ui/dist directory');
  }
  for (const relative of ['index.html', path.join('console', 'index.html'), 'assets']) {
    if (!fs.existsSync(path.join(candidate, relative))) {
      throw new Error(`Local UI candidate is incomplete: missing ${relative}`);
    }
  }
  const sourceState = dependencies.sourceState || (() => {
    const revision = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' });
    const status = spawnSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' });
    return {
      revision: revision.status === 0 ? revision.stdout.trim() : '',
      clean: status.status === 0 && !status.stdout.trim(),
    };
  });
  const state = sourceState();
  if (!/^[0-9a-f]{40}$/.test(state.revision)) {
    throw new Error('Local UI candidate source revision could not be resolved');
  }
  if (!state.clean) {
    throw new Error('Local UI candidate requires a clean committed worktree');
  }
  return {
    absolute: candidate,
    relative: 'ui/dist',
    sourceRevision: state.revision,
  };
}

function candidateUiFileForRequest(candidate, pathname, resourceType) {
  if (!candidate || ['/v1/', '/api/', '/auth/'].some((prefix) => pathname.startsWith(prefix))) return null;
  const relative = resourceType === 'document' && (pathname === '/console' || pathname.startsWith('/console/'))
    ? path.join('console', 'index.html')
    : decodeURIComponent(pathname).replace(/^[/\\]+/, '');
  const resolved = path.resolve(candidate.absolute, relative || 'index.html');
  const relation = path.relative(candidate.absolute, resolved);
  if (!relation || (!relation.startsWith('..') && !path.isAbsolute(relation))) {
    return fs.existsSync(resolved) && fs.statSync(resolved).isFile() ? resolved : null;
  }
  return null;
}

function contentTypeFor(candidatePath) {
  const extension = path.extname(candidatePath).toLowerCase();
  return {
    '.css': 'text/css; charset=utf-8',
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.png': 'image/png',
    '.svg': 'image/svg+xml',
    '.webp': 'image/webp',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2',
    '.wasm': 'application/wasm',
  }[extension] || 'application/octet-stream';
}

async function installUiCandidateRoute(context, candidate, betaOrigin) {
  if (!candidate) return;
  await context.route(`${betaOrigin}/**`, async (route) => {
    const request = route.request();
    if (request.method() !== 'GET') return route.continue();
    const candidatePath = candidateUiFileForRequest(
      candidate,
      new URL(request.url()).pathname,
      request.resourceType(),
    );
    if (!candidatePath) return route.continue();
    return route.fulfill({
      status: 200,
      contentType: contentTypeFor(candidatePath),
      headers: { 'cache-control': 'no-store' },
      body: fs.readFileSync(candidatePath),
    });
  });
}

module.exports = {
  candidateUiFileForRequest,
  contentTypeFor,
  installUiCandidateRoute,
  resolveUiCandidateDist,
};
