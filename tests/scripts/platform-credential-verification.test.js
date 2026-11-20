'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const verifier=require('./platform-credential-verification');
test('real ES256 and RS256 signatures require the exact published key',()=>{
 for(const alg of ['ES256','RS256']){
  const pair=alg==='ES256'?crypto.generateKeyPairSync('ec',{namedCurve:'P-256'}):crypto.generateKeyPairSync('rsa',{modulusLength:2048});
  const input=[{alg,kid:'did:web:issuer.example#key'},{iss:'did:web:issuer.example',vct:'https://issuer.example/type'}].map(x=>Buffer.from(JSON.stringify(x)).toString('base64url')).join('.');
  const options=alg==='ES256'?{key:pair.privateKey,dsaEncoding:'ieee-p1363'}:pair.privateKey;
  const signature=crypto.sign(alg==='ES256'?'sha256':'RSA-SHA256',Buffer.from(input),options).toString('base64url');
  const compact=input+'.'+signature;assert.equal(verifier.verifyCompactJws(compact,pair.publicKey.export({format:'jwk'})).payload.iss,'did:web:issuer.example');
  assert.throws(()=>verifier.verifyCompactJws(input+'.'+Buffer.alloc(64).toString('base64url'),pair.publicKey.export({format:'jwk'})));
 }
});
test('DID key selection requires assertion authority and exact key ID',()=>{
 const key={id:'did:web:issuer.example#key',publicKeyJwk:{kty:'EC'}};
 assert.equal(verifier.didWebResolutionUrl('did:web:issuer.example:org'),'https://issuer.example/org/did.json');
 assert.equal(verifier.verificationMethodFromDidDocument({verificationMethod:[key],assertionMethod:[key.id]},key.id),key);
 assert.throws(()=>verifier.verificationMethodFromDidDocument({verificationMethod:[key],assertionMethod:[]},key.id));
 assert.throws(()=>verifier.verificationMethodFromDidDocument({verificationMethod:[key],assertionMethod:[key.id]},key.id+'foreign'));
});
test('unimplemented owned-wallet adapter refuses before any HTTP request',async()=>{
 await assert.rejects(verifier.receiveAndVerifyCredential('unused',{vct:'https://issuer.example/type',credential_payload_format:'SD_JWT_VC'},'https://issuer.example',{}),e=>e.code==='owned_wallet_adapter_unavailable');
});
