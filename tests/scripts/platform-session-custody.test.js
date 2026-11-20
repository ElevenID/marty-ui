'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {createPlatformCaptureCustody}=require('./platform-session-custody');
test('platform custody preserves exact bounded session until confirmed cleanup',t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'platform-custody-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const c=createPlatformCaptureCustody('platform-unit-1234',dir),file=path.join(dir,'platform-unit-1234-betaAdminSession.json');
 for(const role of ['canvasAdminSession','canvasLearnerSession','canvasOwnedClientSecret','foreign'])assert.throws(()=>c.retain(role,'private'));
 assert.throws(()=>c.retain('betaAdminSession','x'.repeat(131073)));
 c.retain('betaAdminSession','original-cookie');assert.equal(fs.readFileSync(file,'utf8'),'original-cookie');
 c.retain('betaAdminSession','same-owned-session');assert.equal(fs.readFileSync(file,'utf8'),'same-owned-session');
 assert.equal(c.retire(),true);assert(!fs.existsSync(file));assert.equal(JSON.parse(fs.readFileSync(path.join(dir,'platform-unit-1234.custody.json'))).state,'RETIRED');
});
