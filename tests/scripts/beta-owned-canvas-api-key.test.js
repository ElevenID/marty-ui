 'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path');
const {createHash}=require('node:crypto');
const m=require('./beta-owned-canvas-api-key');
const ORG='00000000-0000-0000-0000-000000000001',ID='346d13d3-0fe4-4dde-9283-9ff6462acf57';
function fixture(t){const root=fs.mkdtempSync(path.join(os.tmpdir(),'canvas-key-control-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const ref=(name,value)=>{const file=path.join(root,name);fs.writeFileSync(file,typeof value==='string'?value:JSON.stringify(value));
  return {path:file,sha256:createHash('sha256').update(fs.readFileSync(file)).digest('hex')};};
 const input={mode:'readback',outputDir:root,expectedUserId:ID,adminEmail:ref('email','synthetic@controlled.test'),adminPassword:ref('password','private-control')};
 const p={schema:'marty.canvas-owned-api-key-plan/v1',runId:'d07d08-20261105-b8c73f2e',name:'Canvas native D07D08 d07d08-20261105-b8c73f2e',
  organizationId:ORG,scopes:[...m.SCOPES],ttlSeconds:7200,callbacks:false,isTest:true,createOnlyOnce:true,cleanup:'revoke-exact-id-and-readback',
  outputSecret:'api-key.private',idempotencyKey:ID,adminEmailSha256:input.adminEmail.sha256,adminPasswordSha256:input.adminPassword.sha256};
 input.plan=ref('plan.json',p);const expiry=new Date(Date.now()+7200000).toISOString();
 const row={id:ID,organization_id:ORG,name:p.name,scopes:[...m.SCOPES],expires_at:expiry,enabled:true};
 input.secret=ref('api-key.private','mk_test_'+'a'.repeat(43)+'\n');
 input.created=ref('created.json',{schema:'marty.canvas-api-key-created/v1',id:ID,runId:p.runId,name:p.name,organizationId:ORG,
  expiresAt:expiry,secretFile:input.secret.path,secretRetired:false});
 const write=(name,value)=>fs.writeFileSync(path.join(root,name),JSON.stringify(value));return {root,ref,input,p,row,write};}
test('exact historical key readback never POSTs',async t=>{const f=fixture(t),calls=[];
 const result=await m.keyOperation(f.input,f.p,async(method)=>{calls.push(method);return {status:200,body:[f.row]};},f.write);
 assert.equal(result.state,'ACTIVE_SCOPED_KEY');assert.deepEqual(calls,['GET']);});
test('foreign org/name/scope and expiry drift refuse before revoke',async t=>{for(const field of ['organization_id','name','scopes','expires_at']){
 const f=fixture(t);f.input.mode='revoke';f.row[field]=field==='scopes'?['trust:read']:'foreign';const calls=[];
 await assert.rejects(m.keyOperation(f.input,f.p,async method=>{calls.push(method);return {status:200,body:[f.row]};},f.write));assert.deepEqual(calls,['GET']);assert(fs.existsSync(f.input.secret.path));}});
test('exact revoke readback then secret retirement',async t=>{const f=fixture(t);f.input.mode='revoke';const calls=[];
 const result=await m.keyOperation(f.input,f.p,async method=>{calls.push(method);if(method==='DELETE'){f.row.enabled=false;return {status:204};}
 return {status:200,body:[f.row]};},f.write);assert.equal(result.state,'REVOKED');assert(!fs.existsSync(f.input.secret.path));assert.deepEqual(calls,['GET','DELETE','GET']);});
test('unknown DELETE preserves secret and reports uncertainty',async t=>{const f=fixture(t);f.input.mode='revoke';
 await assert.rejects(m.keyOperation(f.input,f.p,async method=>method==='DELETE'?{status:503}:{status:200,body:[f.row]},f.write),{code:'REVOKE_OUTCOME_UNKNOWN'});
 assert(fs.existsSync(f.input.secret.path));});
test('durable create intent prevents replay after unknown POST',async t=>{const f=fixture(t);f.input.mode='create';
 f.input.secretOutput=path.join(f.root,'new-api-key.private');f.input.createIntentPath=path.join(f.root,'intent.json');let posts=0;
 const api=async method=>{if(method==='POST'){posts++;return {status:503};}return {status:200,body:[]};};
 await assert.rejects(m.keyOperation(f.input,f.p,api,f.write),{code:'CREATE_OUTCOME_UNKNOWN'});
 await assert.rejects(m.keyOperation(f.input,f.p,api,f.write),{code:'CREATE_ALREADY_ATTEMPTED'});assert.equal(posts,1);});
test('create uses exact body/idempotency and retains one-time secret',async t=>{const f=fixture(t);f.input.mode='create';
 f.input.secretOutput=path.join(f.root,'new-api-key.private');f.input.createIntentPath=path.join(f.root,'intent.json');let made=false;
 const result=await m.keyOperation(f.input,f.p,async(method,url,body,idem)=>{
 if(method==='POST'){assert.equal(idem,f.p.idempotencyKey);assert.deepEqual(Object.keys(body).sort(),['expires_at','is_test','name','scopes']);
 assert.deepEqual(body.scopes,m.SCOPES);assert.equal(body.is_test,true);assert(Math.abs(Date.parse(body.expires_at)-Date.now()-7200000)<5000);
 made=true;f.row.expires_at=body.expires_at;return {status:201,body:{...f.row,key:'mk_test_'+'b'.repeat(43)}};}
 return {status:200,body:made?[f.row]:[]};},f.write);
 assert.equal(result.id,ID);assert.equal(fs.readFileSync(f.input.secretOutput,'utf8'),'mk_test_'+'b'.repeat(43)+'\n');});
function dependencies(f,changes={}){const events=[],cookies=[{name:'sessionId',value:'CONTROLLED',domain:'beta.elevenidllc.com',path:'/',secure:true,httpOnly:true},
  {name:'activeOrg',value:ORG,domain:'beta.elevenidllc.com',path:'/',secure:false,httpOnly:false}];
 const custody={retain(role,value){events.push('retain');assert.equal(role,'betaAdminSession');assert.deepEqual(JSON.parse(value),cookies);},retire(){events.push('custody-retire');}};
 const page={evaluate:async()=>ORG},context={newPage:async()=>page,cookies:async()=>cookies,request:{get:async()=>({status:()=>200,json:async()=>({authenticated:true,user:{...(changes.legacyIdOnly?{id:ID}:{user_id:changes.wrongIdentity?'foreign':ID}),email:'synthetic@controlled.test'}})})}};
 const deps={createCustody:()=>custody,launch:async()=>({newContext:async()=>context,close:async()=>{events.push('browser-close');if(changes.closeFailure)throw Error('secret-value');}}),
 login:async()=>events.push('login'),selectOrg:async()=>events.push('select'),originalContext:async original=>{assert.deepEqual(original,cookies);events.push('original-context');return {session:{original:true},isolated:{dispose:async()=>events.push('dispose')}};},
 retireSession:async(session,owner)=>{assert(session.original);assert.equal(owner,custody);events.push('logout-original-denial');if(changes.retireFailure)throw Error('secret-cookie');return {logoutStatus:303,oldCookieAuthenticated:false};}};
 return {deps,events};}
test('original cookies persisted before key work; retirement precedes browser/custody close',async t=>{const f=fixture(t),{deps,events}=dependencies(f);
 await m.withAdmin(f.input,f.p,deps,async()=>{
 const metadata=JSON.parse(fs.readFileSync(path.join(f.root,'session-cookie-metadata.json')));
 assert.deepEqual(metadata.cookies.map(x=>x.name),['sessionId','activeOrg']);
 assert.equal(metadata.cookies[1].secure,false);assert.equal(metadata.cookies[1].httpOnly,false);
 assert(metadata.cookies.every(x=>Object.keys(x).sort().join(',')==='domain,httpOnly,name,path,secure'));
 assert(!JSON.stringify(metadata).includes('CONTROLLED'));assert(!JSON.stringify(metadata).includes(ORG));
 events.push('key-effect');return {id:ID};});
 assert(events.indexOf('retain')<events.indexOf('key-effect'));assert(events.indexOf('logout-original-denial')<events.indexOf('browser-close'));
 assert(events.indexOf('browser-close')<events.indexOf('custody-retire'));assert.equal(JSON.parse(fs.readFileSync(path.join(f.root,'result.json'))).complete,true);});
for(const failure of ['wrongIdentity','legacyIdOnly','retireFailure','closeFailure'])test(failure+' retains cookie custody and never qualifies',async t=>{
 const f=fixture(t),{deps,events}=dependencies(f,{[failure]:true});let effects=0;
 await assert.rejects(m.withAdmin(f.input,f.p,deps,async()=>{effects++;return {id:ID};}));
 assert(!events.includes('custody-retire'));if(['wrongIdentity','legacyIdOnly'].includes(failure))assert.equal(effects,0);
 const result=JSON.parse(fs.readFileSync(path.join(f.root,'result.json')));assert.equal(result.complete,false);assert.equal(result.releaseQualified,false);
 assert(!JSON.stringify(result).includes('secret-'));});
test('unknown API error is value-free and original session still retired',async t=>{const f=fixture(t),{deps,events}=dependencies(f);
 await assert.rejects(m.withAdmin(f.input,f.p,deps,async()=>{throw Object.assign(Error('credential-path-secret'),{code:'provider-raw-secret'});}),{code:'KEY_LIFECYCLE_FAILED'});
 assert(events.includes('logout-original-denial'));assert(!events.includes('custody-retire'));
 assert(!fs.readFileSync(path.join(f.root,'result.json'),'utf8').includes('credential-path-secret'));});
test('raw secret tamper is refused even with matching claimed ID',async t=>{const f=fixture(t);fs.appendFileSync(f.input.secret.path,'changed');let calls=0;
 await assert.rejects(m.keyOperation(f.input,f.p,async()=>{calls++;},f.write),{code:'BOUND_REF_CHANGED'});assert.equal(calls,0);});
test('plan stays exact seven scopes and hash-bound credentials',t=>{const f=fixture(t);assert.equal(m.planFrom(f.input).organizationId,ORG);
 f.p.scopes=f.p.scopes.slice(1);f.input.plan=f.ref('plan.json',f.p);assert.throws(()=>m.planFrom(f.input),{code:'PLAN_CHANGED'});});
