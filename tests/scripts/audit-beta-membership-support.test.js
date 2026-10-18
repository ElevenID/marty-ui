'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { guards, credentialPath, expirySql, verifyForeignSignature, assertions } = require('./audit-beta-membership-support');
const env = { BETA_ORIGIN:'https://beta.elevenidllc.com',MARTY_TEST_WALLET_ORIGIN:'http://127.0.0.1:8787',D05_SYNTHETIC_FIXTURE:'1',MARTY_TEST_WALLET_HOLDER_KID:'did:key:synthetic',TEST_ADMIN_EMAIL:'operator@example.test',TEST_ADMIN_PASSWORD:'test' };
test('fixture guards reject production, remote wallet and unacknowledged synthetic work',()=>{
 guards(env,'expired-offer');
 for(const change of [{BETA_ORIGIN:'https://elevenidllc.com'},{MARTY_TEST_WALLET_ORIGIN:'https://wallet.example.test'},{D05_SYNTHETIC_FIXTURE:'0'}]) assert.throws(()=>guards({...env,...change},'expired-offer'));
 assert.throws(()=>guards(env,'primary-demo'));
});
test('expiry mutation accepts only UUID and scopes pending beta organization transaction',()=>{
 assert.throws(()=>expirySql("x'; DELETE FROM users;--"));
 const query=expirySql('11111111-1111-1111-1111-111111111111');
 assert.match(query,/organization_id='00000000-0000-0000-0000-000000000001' AND status='pending'/);
});
test('foreign signature evidence rejects tampering, private keys and controller substitution',()=>{
 const {publicKey,privateKey}=crypto.generateKeyPairSync('ec',{namedCurve:'P-256'});const did='did:web:beta.elevenidllc.com:orgs:synthetic';const kid=did+'#key';
 const head=Buffer.from(JSON.stringify({alg:'ES256',kid})).toString('base64url'), payload=Buffer.from(JSON.stringify({iss:did})).toString('base64url');
 const signature=crypto.sign('sha256',Buffer.from(head+'.'+payload),{key:privateKey,dsaEncoding:'ieee-p1363'}).toString('base64url');const raw=head+'.'+payload+'.'+signature;
 const document={id:did,assertionMethod:[kid],verificationMethod:[{id:kid,controller:did,publicKeyJwk:publicKey.export({format:'jwk'})}]};
 assert.match(verifyForeignSignature(raw,document,did),/^[a-f0-9]{64}$/);
 assert.throws(()=>verifyForeignSignature(head+'.'+Buffer.from(JSON.stringify({iss:did,changed:true})).toString('base64url')+'.'+signature,document,did));
 for(const mutate of [d=>d.verificationMethod[0].controller='did:web:other.test',d=>d.verificationMethod[0].publicKeyJwk.d='secret',d=>d.assertionMethod=[]]) {const copy=structuredClone(document);mutate(copy);assert.throws(()=>verifyForeignSignature(raw,copy,did));}
});
test('no-session, recovery and cleanup are mandatory supporting-lane outcomes',()=>{
 for(const lane of ['expired-offer','untrusted-issuer']) {
  const required=assertions(lane,{});assert.ok(Object.values(required).every(x=>x===false));
  const checks=Object.fromEntries(Object.keys(required).map(k=>[k,true]));assert.ok(Object.values(assertions(lane,checks)).every(Boolean));
  checks.fixture_cleanup=false;assert.equal(assertions(lane,checks).fixture_cleanup,false);
 }
});

test("cleanup accepts actual urn UUID credential IDs and rejects path injection",()=>{assert.equal(credentialPath("urn:uuid:11111111-1111-1111-1111-111111111111"),"/v1/issued-credentials/urn%3Auuid%3A11111111-1111-1111-1111-111111111111/revoke");assert.throws(()=>credentialPath("../other"));});
