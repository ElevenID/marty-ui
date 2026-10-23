// Shared stock operator configuration format; no Canvas source patch or credential domain logic.
export const CANVAS_ORIGIN = 'https://canvas-test.elevenidllc.com';
export const KEY_NAMES = ['jwk-past.json', 'jwk-present.json', 'jwk-future.json'];
const normalized = value => value.trim() + '\n';
export function renderRuntimeConfiguration({ encryptionKey, jwtKey, keys }) {
  return Object.fromEntries(Object.entries({
    'database.yml': `
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
  database: canvas_production`,
    'redis.yml': `
production:
  url: redis://canvas-redis:6379/0
  connect_timeout: 0.5
  circuit_breaker:
    error_threshold: 1
    error_timeout: 2`,
    'cache_store.yml': `
production:
  cache_store: redis_cache_store`,
    'domain.yml': `
production:
  domain: canvas-test.elevenidllc.com`,
    'outgoing_mail.yml': `
production:
  address: canvas-mail
  port: 1025
  domain: canvas-test.elevenidllc.com
  outgoing_address: canvas-oss-portability@elevenidllc.com
  default_name: Canvas OSS Portability`,
    'security.yml': `
production:
  encryption_key: ${encryptionKey}
  jwt_encryption_keys:
    - ${jwtKey}
  lti_iss: '${CANVAS_ORIGIN}'`,
    'session_store.yml': `
production:
  session_store: encrypted_cookie_store
  expire_after: 14400
  same_site: None
  secure: true`,
    'delayed_jobs.yml': `
default:
  workers:
    - queue: canvas_queue`,
    'dynamic_settings.yml': `
production:
  store:
    canvas:
      lti-keys:
${keys.map(([name, value]) => `        ${name}: '${value}'`).join('\n')}`,
  }).map(([name,value]) => [name,normalized(value)]));
}
export const CONFIGURATION_NAMES = Object.keys(renderRuntimeConfiguration({encryptionKey:'',jwtKey:'',keys:[]}));
function requireCondition(condition, message) { if (!condition) throw new Error(message); }
export function validateRuntimeConfiguration(input) {
  const files = Object.fromEntries(Object.entries(input).map(([name,value]) => [name,value.replaceAll('\r\n','\n')]));
  requireCondition(Object.keys(files).length === CONFIGURATION_NAMES.length && CONFIGURATION_NAMES.every(name => typeof files[name] === 'string'),
    'Canvas operator configuration file inventory differs');
  const security=files['security.yml'];
  const encryptionKey=security.match(/^  encryption_key: ([a-f0-9]{64})$/m)?.[1];
  const jwtKey=security.match(/^    - ([a-f0-9]{64})$/m)?.[1];
  requireCondition(encryptionKey && jwtKey,'Canvas security configuration has invalid key fields');
  const matches=[...files['dynamic_settings.yml'].matchAll(/^        (jwk-(?:past|present|future)\.json): '([^\r\n']+)'$/gm)];
  requireCondition(matches.length === KEY_NAMES.length,'Canvas LTI configuration has invalid slots');
  const required=['kty','n','e','d','p','q','dp','dq','qi','kid','alg','use'].sort();
  const keys=matches.map((match,index) => {
    requireCondition(match[1] === KEY_NAMES[index],'Canvas LTI slot order differs');
    let key;
    try {key=JSON.parse(match[2]);} catch {throw new Error('Canvas LTI key JSON is invalid');}
    requireCondition(key && typeof key === 'object' && JSON.stringify(Object.keys(key).sort()) === JSON.stringify(required),
      'Canvas LTI key fields differ');
    requireCondition(key.kty === 'RSA' && key.alg === 'RS256' && key.use === 'sig','Canvas LTI key type differs');
    for(const member of ['n','e','d','p','q','dp','dq','qi']) {
      requireCondition(typeof key[member] === 'string' && /^[A-Za-z0-9_-]{1,4096}$/.test(key[member]),'Canvas LTI key encoding is invalid');
    }
    requireCondition(typeof key.kid === 'string' && /^canvas-oss-\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(key.kid),
      'Canvas LTI key identifier differs');
    return [match[1],JSON.stringify(key)];
  });
  const expected=renderRuntimeConfiguration({encryptionKey,jwtKey,keys});
  for(const name of CONFIGURATION_NAMES) {
    requireCondition(files[name] === expected[name],`Canvas operator ${name} differs from the reviewed generator format`);
  }
  return {state:'REVIEWED_CANVAS_CONFIGURATION_VALID',configurationFiles:[...CONFIGURATION_NAMES],productionDemoReady:false};
}
