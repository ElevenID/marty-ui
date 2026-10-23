#!/usr/bin/env node
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { createDemoLiveEvidence } = require('./demo-live-evidence');

function boundFile(file) {
  if (!file || !path.isAbsolute(file) || fs.lstatSync(file).isSymbolicLink()
      || !fs.statSync(file).isFile()) throw Error('D12 requires an explicit regular bound input file');
  return { path: file, sha256: createHash('sha256').update(fs.readFileSync(file)).digest('hex') };
}

async function main() {
  if (process.env.RECORD_VIDEO !== '0') {
    const error = new Error('D12 fresh operations require --functional-rerun; recording support remains pending');
    error.code = 'D12_RECORDING_UNSUPPORTED';
    throw error;
  }
  const root = path.resolve(__dirname, '../..');
  const revision = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();
  const runtimeReceipt = boundFile(process.env.DEMO_D12_RUNTIME_RECEIPT);
  const runtime = JSON.parse(fs.readFileSync(runtimeReceipt.path, 'utf8'));
  const deployment = JSON.parse(fs.readFileSync(runtime.deploymentManifest, 'utf8'));
  const productWorkspace = process.env.DEMO_D12_PRODUCT_WORKSPACE;
  const python = process.env.DEMO_PYTHON_EXECUTABLE;
  if (!productWorkspace || !path.isAbsolute(productWorkspace) || !fs.statSync(productWorkspace).isDirectory()
      || !python || !path.isAbsolute(python)) throw Error('D12 requires explicit fixed product workspace and Python');
  // Only paths/hashes enter the public acknowledged fixture. The child loads
  // private custody bytes after HELLO, source verification and runtime binding.
  const inputs = { runtimeReceipt, deploymentManifest: boundFile(runtime.deploymentManifest),
    sourceManifest: boundFile(runtime.sourceManifest),
    stackManifest: boundFile(path.resolve(path.dirname(runtime.deploymentManifest), deployment.deployed_demo_manifest)),
    privateFixture: boundFile(process.env.DEMO_D12_PRIVATE_FIXTURE), productWorkspace };
  let client;
  try {
    client = await createDemoLiveEvidence();
    return await client.runPythonCapture({ repository: root, revision,
      entrypoint: 'scripts/beta_passport_functional_audit.py', pythonExecutable: python,
      fixtureFile: 'passport-fresh-operation-input.json', inputs });
  } finally {
    client?.close();
  }
}

if (require.main === module) main().catch(error => {
  console.error(error.code === 'D12_RECORDING_UNSUPPORTED'
    ? 'D12 fresh operations require --functional-rerun; recording support remains pending'
    : 'D12 owned fresh-operation adapter failed; private recovery inputs remain private');
  process.exitCode = 1;
});
module.exports = { boundFile, main };
