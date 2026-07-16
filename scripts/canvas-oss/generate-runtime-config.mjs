#!/usr/bin/env node

import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

const outputArg = process.argv[2];
if (!outputArg) {
  throw new Error('Usage: generate-runtime-config.mjs OUTPUT_DIRECTORY');
}

const output = resolve(outputArg);
if (existsSync(output) && readdirSync(output).length > 0) {
  throw new Error(`Refusing to overwrite non-empty Canvas runtime config directory: ${output}`);
}
mkdirSync(output, { recursive: true });

const canvasOrigin = process.env.CANVAS_OSS_ORIGIN || 'https://canvas-test.elevenidllc.com';
if (canvasOrigin !== 'https://canvas-test.elevenidllc.com') {
  throw new Error('Portable acceptance Canvas origin must be https://canvas-test.elevenidllc.com');
}

function write(name, contents) {
  writeFileSync(`${output}/${name}`, `${contents.trim()}\n`, { encoding: 'utf8', mode: 0o644 });
}

const keyNames = ['jwk-past.json', 'jwk-present.json', 'jwk-future.json'];
const offsets = [-7, 0, 7];
const keys = keyNames.map((name, index) => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = privateKey.export({ format: 'jwk' });
  const date = new Date(Date.now() + offsets[index] * 24 * 60 * 60 * 1000).toISOString();
  return [name, JSON.stringify({ ...jwk, kid: `canvas-oss-${date}`, alg: 'RS256', use: 'sig' })];
});

write('database.yml', `
common: &common
  adapter: postgresql
  host: canvas-postgres
  password: <%= File.read(ENV.fetch('POSTGRES_PASSWORD_FILE')).strip %>
  encoding: utf8
  username: postgres
  timeout: 5000
  prepared_statements: false
  use_qualified_names: true
  shard_name: public
  schema_search_path: "''"
production:
  <<: *common
  database: canvas_production
`);

write('redis.yml', `
production:
  url: redis://canvas-redis:6379/0
  connect_timeout: 0.5
  circuit_breaker:
    error_threshold: 1
    error_timeout: 2
`);

write('cache_store.yml', `
production:
  cache_store: redis_cache_store
`);

write('domain.yml', `
production:
  domain: canvas-test.elevenidllc.com
`);

write('outgoing_mail.yml', `
production:
  address: canvas-mail
  port: 1025
  domain: canvas-test.elevenidllc.com
  outgoing_address: canvas-oss-portability@elevenidllc.com
  default_name: Canvas OSS Portability
`);

write('security.yml', `
production:
  encryption_key: ${randomBytes(32).toString('hex')}
  jwt_encryption_keys:
    - ${randomBytes(32).toString('hex')}
  lti_iss: '${canvasOrigin}'
`);

write('session_store.yml', `
production:
  session_store: encrypted_cookie_store
  expire_after: 14400
  same_site: None
  secure: true
`);

write('delayed_jobs.yml', `
default:
  workers:
    - queue: canvas_queue
`);

write('dynamic_settings.yml', `
production:
  store:
    canvas:
      lti-keys:
${keys.map(([name, value]) => `        ${name}: '${value}'`).join('\n')}
`);

write('generation.json', JSON.stringify({
  schema_version: 1,
  canvas_origin: canvasOrigin,
  operator_configuration_only: true,
  canvas_source_files_modified: false,
  custom_plugins: [],
}, null, 2));

console.log(`Generated ephemeral Canvas operator configuration in ${output}`);
