'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  candidateUiFileForRequest,
  resolveUiCandidateDist,
  resolveVerificationIssuerDid,
  selectRenewedCredential,
} = require('./audit-beta-credential-lifecycle');

test('local UI candidate is exact, committed, and never intercepts API routes', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'marty-ui-candidate-'));
  const dist = path.join(root, 'ui', 'dist');
  fs.mkdirSync(path.join(dist, 'console'), { recursive: true });
  fs.mkdirSync(path.join(dist, 'assets'), { recursive: true });
  fs.writeFileSync(path.join(dist, 'index.html'), 'public');
  fs.writeFileSync(path.join(dist, 'console', 'index.html'), 'console');
  fs.writeFileSync(path.join(dist, 'assets', 'app.js'), 'app');
  try {
    const candidate = resolveUiCandidateDist(root, dist, {
      sourceState: () => ({ revision: 'a'.repeat(40), clean: true }),
    });
    assert.deepEqual(candidate, {
      absolute: fs.realpathSync(dist),
      relative: 'ui/dist',
      sourceRevision: 'a'.repeat(40),
    });
    assert.equal(
      candidateUiFileForRequest(candidate, '/console/org/operate/issuance', 'document'),
      path.join(fs.realpathSync(dist), 'console', 'index.html'),
    );
    assert.equal(
      candidateUiFileForRequest(candidate, '/assets/app.js', 'script'),
      path.join(fs.realpathSync(dist), 'assets', 'app.js'),
    );
    assert.equal(candidateUiFileForRequest(candidate, '/v1/auth/me', 'fetch'), null);
    assert.equal(candidateUiFileForRequest(candidate, '/../outside', 'script'), null);
    assert.throws(
      () => resolveUiCandidateDist(root, dist, {
        sourceState: () => ({ revision: 'a'.repeat(40), clean: false }),
      }),
      /clean committed worktree/,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('verification issuer identity is bound to the issued credential unless explicitly overridden', () => {
  assert.equal(
    resolveVerificationIssuerDid('', { issuer_did: 'did:web:beta.elevenidllc.com:orgs:demo' }),
    'did:web:beta.elevenidllc.com:orgs:demo',
  );
  assert.equal(
    resolveVerificationIssuerDid('did:web:reviewed.example', { issuer_did: 'did:web:ignored.example' }),
    'did:web:reviewed.example',
  );
  assert.throws(() => resolveVerificationIssuerDid('', {}), /absent/);
});

test('renewal waits for the one successor linked to the exact predecessor', () => {
  const records = [
    { id: 'source', credential_template_id: 'template', renewed_from_credential_id: null },
    { id: 'unrelated', credential_template_id: 'other', renewed_from_credential_id: 'source' },
    { id: 'successor', credential_template_id: 'template', renewed_from_credential_id: 'source' },
  ];
  assert.equal(selectRenewedCredential(records, 'template', 'source').id, 'successor');
  assert.equal(selectRenewedCredential(records.slice(0, 2), 'template', 'source'), null);
  assert.throws(
    () => selectRenewedCredential([...records, { ...records[2], id: 'duplicate' }], 'template', 'source'),
    /multiple successor/,
  );
});
