'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {readBoundedSecretFile}=require('./canvas-secret-files');
const digest=value=>crypto.createHash('sha256').update(value).digest('hex');
test('reads actual bounded secret bytes rather than the filename and trims only one final newline',()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'canvas-secret-'));
 try{const file=path.join(root,'email');fs.writeFileSync(file,'admin@owned.test\r\n');const value=readBoundedSecretFile(file,{root,sha256:digest(fs.readFileSync(file))});assert.equal(value.value,'admin@owned.test');assert.notEqual(value.value,file);assert.throws(()=>readBoundedSecretFile(file,{root,sha256:'0'.repeat(64)}));}
 finally{fs.rmSync(root,{recursive:true});}
});
test('absent, raw-scalar, outside-root, empty, oversized and symlink files fail without leaking paths',()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'canvas-secret-'));const outside=fs.mkdtempSync(path.join(os.tmpdir(),'canvas-outside-'));
 try{
  const valid=path.join(root,'valid');fs.writeFileSync(valid,'secret');const empty=path.join(root,'empty');fs.writeFileSync(empty,'');const large=path.join(root,'large');fs.writeFileSync(large,'x'.repeat(4097));const external=path.join(outside,'external');fs.writeFileSync(external,'secret');
  const alias=path.join(root,'alias');fs.symlinkSync(outside,alias,'junction');
  for(const file of ['raw-login',path.join(root,'missing'),empty,large,external,path.join(alias,'external')])assert.throws(()=>readBoundedSecretFile(file,{root}),error=>!error.message.includes(root)&&!error.message.includes(file));
 }finally{fs.rmSync(root,{recursive:true});fs.rmSync(outside,{recursive:true});}
});
