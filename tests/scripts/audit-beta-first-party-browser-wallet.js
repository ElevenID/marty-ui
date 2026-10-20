#!/usr/bin/env node
// Fixed recorder entrypoint; all product actions stay in the shared driver.
const { main } = require('./verify-beta-credential-login');
const { redact } = require('./verify-beta-waltid-acceptance');

main({ retainedFirstParty: true }).catch(error => {
  console.error(JSON.stringify({ error: redact(error.stack || error.message || String(error)) }));
  process.exitCode = 1;
});
