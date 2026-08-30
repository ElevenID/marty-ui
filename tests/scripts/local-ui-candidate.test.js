'use strict';

const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('node:test');
const {
  candidateUiFileForRequest,
  contentTypeFor,
  resolveUiCandidateDist,
} = require('./local-ui-candidate');

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'marty-ui-candidate-'));
  const dist = path.join(root, 'ui', 'dist');
  fs.mkdirSync(path.join(dist, 'console'), { recursive: true });
  fs.mkdirSync(path.join(dist, 'assets'));
  fs.writeFileSync(path.join(dist, 'index.html'), 'public');
  fs.writeFileSync(path.join(dist, 'console', 'index.html'), 'console');
  fs.writeFileSync(path.join(dist, 'assets', 'app.js'), 'app');
  return { root, dist };
}

test('binds a complete local candidate to one clean committed worktree', () => {
  const { root, dist } = fixture();
  const candidate = resolveUiCandidateDist(root, dist, {
    sourceState: () => ({ revision: 'a'.repeat(40), clean: true }),
  });
  assert.equal(candidate.absolute, fs.realpathSync(dist));
  assert.equal(candidate.sourceRevision, 'a'.repeat(40));
  assert.throws(() => resolveUiCandidateDist(root, dist, {
    sourceState: () => ({ revision: 'a'.repeat(40), clean: false }),
  }), /clean committed worktree/);
});

test('serves only candidate UI files and never intercepts APIs or escaped paths', () => {
  const { dist } = fixture();
  const candidate = { absolute: dist };
  assert.equal(candidateUiFileForRequest(candidate, '/console/applicant', 'document'), path.join(dist, 'console', 'index.html'));
  assert.equal(candidateUiFileForRequest(candidate, '/assets/app.js', 'script'), path.join(dist, 'assets', 'app.js'));
  assert.equal(candidateUiFileForRequest(candidate, '/v1/auth/me', 'fetch'), null);
  assert.equal(candidateUiFileForRequest(candidate, '/../secret', 'script'), null);
  assert.equal(contentTypeFor('font.woff2'), 'font/woff2');
});
