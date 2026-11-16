'use strict';
// Pure contract tests. No browser, public trust or deployed startup is asserted.
const test = require('node:test');
const assert = require('node:assert/strict');
const core = require('../../scripts/installer_startup_browser.cjs');

function fixture() {
  const value = {
    schema: 'elevenid.installer-startup-browser-input/v1',
    request: { observation_id: '11111111-1111-4111-8111-111111111111', challenge: 'a'.repeat(64) },
    installation_id: '22222222-2222-4222-8222-222222222222', engine_id: 'fixture-engine',
    canonical_origin: 'https://marty.example.com', public_entry_origin: 'https://8.8.4.4',
    app_name: 'Actual fixture brand', assets: [],
    runtime: { schema: 'elevenid.installer-browser-runtime/v1', platform: 'linux/amd64',
      node_version: '24.22.1', playwright_version: '1.62.1', chromium_revision: '1234',
      chromium_version: '151.0.7922.34', manifest_sha256: '1'.repeat(64),
      node_sha256: '2'.repeat(64), chromium_sha256: '3'.repeat(64) },
  };
  for (const name of ['native_sha256','operator_sha256','context_sha256','selection_sha256','certificate_der_sha256'])
    value[name] = 'b'.repeat(64);
  for (const pathname of ['/','/assets/main-123.js','/config.json','/runtime-config.js','/startup.js'])
    value.assets.push({path:pathname,media_type:pathname === '/' ? 'text/html'
      : pathname === '/config.json' ? 'application/json' : 'application/javascript',size_bytes:100,sha256:'c'.repeat(64)});
  return value;
}

test('canonical input preserves Python sorted ASCII JSON including Unicode and trailing LF', () => {
  assert.equal(core.canonical({z:'Márty 😀',a:1}), '{"a":1,"z":"M\\u00e1rty \\ud83d\\ude00"}\n');
  const value = fixture();
  assert.equal(core.input(value), value);
});

for (const name of ['url','ip-identity','dns-alias','redirect','launch-override','tls-bypass','runtime','duplicate-asset','media','budget','challenge']) {
  test(`closed browser input refuses ${name}`, () => {
    const value=fixture();
    if (name==='url') value.public_entry_origin+='/?override=1';
    else if (name==='ip-identity') value.canonical_origin='https://8.8.4.4';
    else if (name==='dns-alias') value.public_entry_origin='https://other.example.com';
    else if (name==='redirect') value.canonical_origin='https://user:pass@marty.example.com';
    else if (name==='launch-override') value.args=['--no-sandbox'];
    else if (name==='tls-bypass') value.ignoreHTTPSErrors=true;
    else if (name==='runtime') value.runtime.playwright_version='other';
    else if (name==='duplicate-asset') value.assets.push({...value.assets[1]});
    else if (name==='media') value.assets[1].media_type='text/html';
    else if (name==='budget') value.assets.forEach(item => item.size_bytes=4*1024*1024);
    else value.request.challenge='0';
    assert.throws(() => core.input(value));
  });
}

test('IP path gate excludes all session/auth/API and encoded traversal requests', () => {
  for (const pathname of ['/','/assets/main.js','/locales/en/common.json','/images/brand/logo.svg'])
    assert.equal(core.staticPath(pathname),true);
  for (const pathname of ['/v1/auth/me','/v1/auth/login','/console','/assets/../v1/auth/me','/assets/%2e%2e/test',
    '/assets/a%2fb.js','/config.json/extra','//assets/main.js']) assert.equal(core.staticPath(pathname),false);
});

test('rendered landing requires exact shipped response bodies, media, status and retained IP URL', () => {
  const expected=fixture();
  const landing={url:expected.public_entry_origin+'/',heading_count:1,branding_visible:true,image_count:1,images_loaded:true,
    screenshot_sha256:'d'.repeat(64),assets:expected.assets.map(item => ({...item,status:200})),certificate_der_sha256:expected.certificate_der_sha256};
  core.checkLanding(landing,expected);
  for (const name of ['body','status','html-fallback','missing','blank','redirect','image','leaf']) {
    const value=structuredClone(landing);
    if(name==='body')value.assets[1].sha256='0'.repeat(64);
    else if(name==='status')value.assets[1].status=304;
    else if(name==='html-fallback')value.assets[1].media_type='text/html';
    else if(name==='missing')value.assets.pop();
    else if(name==='blank')value.heading_count=0;
    else if(name==='redirect')value.url=expected.canonical_origin+'/';
    else if(name==='image')value.images_loaded=false;
    else value.certificate_der_sha256='0'.repeat(64);
    assert.throws(() => core.checkLanding(value,expected),name);
  }
});
