 'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const m=require('./native-maintenance-metadata');
function withGitSqlFixture(body){
 const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto'),cp=require('node:child_process');
 const repo=path.resolve(__dirname,'../..'),dir=fs.mkdtempSync(path.join(os.tmpdir(),'marty-d12-git-sql-')),refs={};
 try{
  for(const [name,sha256]of Object.entries(m.SQL_SOURCES)){
   const bytes=cp.execFileSync('git',['show',m.D12_SOURCE+':scripts/sql/'+name],{cwd:repo,maxBuffer:1024*1024});
   assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),sha256,'EXACT_GIT_BLOB_SQL_REQUIRED:'+name);
   const file=path.join(dir,name);fs.writeFileSync(file,bytes);refs[name]={path:file,sha256,bytes:bytes.length};
  }
  return body({refs,bytes:name=>fs.readFileSync(refs[name].path),dir});
 }finally{fs.rmSync(dir,{recursive:true});}
}
function withCurrentBaseline(body,{runId='d12-db-readonly-ui7af-r1',operatorRevision='7afc3d9a05dc003d44c1ca2018ab2238844a7c24'}={}){
 const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto'),cp=require('node:child_process');
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'marty-d12-current-baseline-'));
 const digest=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
 const write=(name,value)=>{const file=path.join(dir,name),bytes=Buffer.isBuffer(value)?value:Buffer.from(JSON.stringify(value)+'\n');
  fs.writeFileSync(file,bytes);return {path:file,sha256:digest(bytes),bytes:bytes.length};};
 try{
  const engine='11111111-1111-4111-8111-111111111111';
  const sql=cp.execFileSync('git',['show','HEAD:scripts/sql/passport-beta-maintenance-catalog.sql'],
   {cwd:path.resolve(__dirname,'../..'),maxBuffer:1024*1024});
  assert.equal(digest(sql),m.CATALOG_SQL_SHA);
  const sqlRef=write('catalog.sql',sql),before=write('before.json',{databaseIdentity:{containerId:'a'.repeat(64),imageId:'sha256:'+'b'.repeat(64),startedAt:'2026-11-09T00:00:00Z',hostPid:42}});
  const source=write('source.json',{schema:'marty.d12-db-preview-source-closure/v2',state:'SOURCE_ONLY_OPERATOR_EXPORTED_NO_RUNTIME_READ',operatorRevision,
   buildSourceRevision:m.D12_CURRENT_SOURCE,buildCoreRevision:m.D12_CURRENT_CORE,applyAuthorized:false,runtimeDeployed:false});
  const observation=write('catalog.json',{schema:'marty.native-maintenance-catalog-observation/v1',runId,
   databaseIdentity:JSON.parse(fs.readFileSync(before.path)).databaseIdentity,source:sqlRef,
   projection:{schema:'marty.native-maintenance-catalog/v1',control:{database:'marty',databaseOid:'16387',systemIdentifier:'7702258360779493410'}}});
  const proof=write('proof.json',{schema:'marty.d12-current-database-preimage-proof/v1',state:'READ_ONLY_IDENTITY_OBSERVED',
   source,databaseBefore:before,catalogSql:sqlRef,catalogObservation:observation,engineId:engine,
   sqlRead:true,runtimeWrites:false,dispatchAuthorized:false});
  const job=write('job.json',{schema:'marty.windows-job-result/v1',state:'COMPLETE',exitCode:0,jobClosed:true,
   terminalActiveProcesses:0,forcedTermination:false,hostMarginBreached:false,timedOut:false,
   jobMemoryBytes:1024**3,hostMarginBytes:1024**3,assignedBeforeResume:true,processCreatedSuspended:true});
  return body({engine,before,sqlRef,baseline:{catalog:observation,proof,job},write});
 }finally{fs.rmSync(dir,{recursive:true});}
}
test('current D12 database scope refuses stale source and unbound preimage',()=>{
 const approved='a'.repeat(64),engine='11111111-1111-4111-8111-111111111111',scope=m.closedScope(m.D12_PROFILE,approved,engine);
 assert.equal(scope.source,m.D12_SOURCE);assert.equal(scope.core,m.D12_CORE);
 assert.equal(scope.databaseBeforeSha256,approved);
 assert.notEqual(scope.source,m.SOURCE);
 assert.equal(scope.engineId,engine);
 assert.throws(()=>m.closedScope(m.D12_PROFILE,'b'.repeat(40),engine));
 assert.throws(()=>m.closedScope(m.D12_PROFILE,approved,'not-an-engine'));
 assert.throws(()=>m.closedScope('foreign-profile',approved));
 assert.equal(m.closedScope().source,m.SOURCE);
});
test('D12 metadata selects only the reviewed current source and Core pair',()=>{
 withCurrentBaseline(({engine,before,baseline})=>{
  const current=m.closedScope(m.D12_PROFILE,before.sha256,engine,m.D12_CURRENT_SOURCE,m.D12_CURRENT_CORE,baseline);
  assert.equal(current.source,m.D12_CURRENT_SOURCE);assert.equal(current.core,m.D12_CURRENT_CORE);
  assert.equal(current.target.systemIdentifier,'7702258360779493410');
  assert.equal(m.closedScope(m.D12_PROFILE,before.sha256,engine).source,m.D12_SOURCE);
  assert.throws(()=>m.closedScope(m.D12_PROFILE,before.sha256,engine,m.D12_CURRENT_SOURCE,m.D12_CURRENT_CORE));
  for(const [source,core] of [[m.D12_SOURCE,m.D12_CURRENT_CORE],[m.D12_CURRENT_SOURCE,m.D12_CORE],['0'.repeat(40),m.D12_CURRENT_CORE],[m.D12_CURRENT_SOURCE,undefined]])
   assert.throws(()=>m.closedScope(m.D12_PROFILE,before.sha256,engine,source,core,baseline),/UNREVIEWED_D12_SOURCE_LINEAGE/);
  assert.throws(()=>m.closedScope(m.D12_PROFILE,before.sha256,engine,m.D12_SOURCE,m.D12_CORE,baseline));
 });
});
test('a second reviewed baseline run binds its own Git source and catalog receipt',()=>{
 withCurrentBaseline(({engine,before,baseline})=>{
  assert.equal(m.closedScope(m.D12_PROFILE,before.sha256,engine,m.D12_CURRENT_SOURCE,m.D12_CURRENT_CORE,baseline).target.systemIdentifier,'7702258360779493410');
  assert.throws(()=>m.closedScope(m.D12_PROFILE,'0'.repeat(64),engine,m.D12_CURRENT_SOURCE,m.D12_CURRENT_CORE,baseline));
  assert.throws(()=>m.closedScope(m.D12_PROFILE,before.sha256,'22222222-2222-4222-8222-222222222222',m.D12_CURRENT_SOURCE,m.D12_CURRENT_CORE,baseline));
  assert.throws(()=>m.closedScope(m.D12_PROFILE,before.sha256,engine,m.D12_CURRENT_SOURCE,m.D12_CURRENT_CORE,
   {...baseline,catalog:{...baseline.catalog,sha256:'0'.repeat(64)}}));
 },{runId:'d12-db-readonly-fresh-r2',operatorRevision:'1'.repeat(40)});
 withCurrentBaseline(({engine,before,baseline})=>{
  assert.throws(()=>m.closedScope(m.D12_PROFILE,before.sha256,engine,m.D12_CURRENT_SOURCE,m.D12_CURRENT_CORE,baseline),/D12_BASELINE_OPERATOR_GIT_REVISION_REQUIRED/);
 },{runId:'d12-db-readonly-fresh-r3',operatorRevision:'not-a-git-revision'});
});
test('current-source read-only catalog establishes a first baseline without authorizing fenced execution',()=>{
 withCurrentBaseline(({engine,before,sqlRef})=>{
  const identity=JSON.parse(require('node:fs').readFileSync(before.path)).databaseIdentity;
  const row={Id:identity.containerId,Image:identity.imageId,
   State:{Running:true,StartedAt:identity.startedAt,Pid:identity.hostPid},
   Config:{Labels:{'com.docker.compose.project':'elevenid-beta','com.docker.compose.service':'postgres'}}};
  const calls=[];
  const readDocker=argv=>{calls.push(argv);
   if(argv[0]==='info')return JSON.stringify({ID:engine});
   if(argv[0]==='inspect')return JSON.stringify([row]);
   if(argv[0]==='exec')return JSON.stringify({schema:'marty.native-maintenance-catalog/v1',
    control:{database:'marty',systemIdentifier:'7702258360779493410',databaseOid:'16387'}})+'\n';
   throw Error('UNREVIEWED_DOCKER_COMMAND');};
  const input={runId:'fresh-current-observation',rolloutProfile:m.D12_PROFILE,
   sourceRevision:m.D12_CURRENT_SOURCE,coreRevision:m.D12_CURRENT_CORE,
   approvedDatabaseBeforeSha256:before.sha256,approvedEngineId:engine,databaseBefore:before,sql:sqlRef};
  const observed=m.observeCatalog(input,{readDocker});
  assert.equal(observed.runId,input.runId);assert.equal(observed.projection.control.systemIdentifier,'7702258360779493410');
  assert.deepEqual(calls.map(argv=>argv[0]),['info','inspect','exec','info','inspect']);
  assert(calls[2].includes('PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=5000'));
  assert.throws(()=>m.closedScope(m.D12_PROFILE,before.sha256,engine,m.D12_CURRENT_SOURCE,m.D12_CURRENT_CORE));
  assert.throws(()=>m.observeCatalog({...input,approvedDatabaseBeforeSha256:'0'.repeat(64)},{readDocker}));
  assert.throws(()=>m.observeCatalog({...input,approvedEngineId:'22222222-2222-4222-8222-222222222222'},{readDocker}));
  assert.throws(()=>m.observeCatalog({...input,coreRevision:m.D12_CORE},{readDocker}),/UNREVIEWED_D12_SOURCE_LINEAGE/);
 });
});
test('current D12 operation proof reaches ordered journal checks with exact lineage',()=>{
 const fs=require('node:fs'),path=require('node:path'),os=require('node:os'),crypto=require('node:crypto');
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'marty-current-d12-proof-'));
 try{
  const file=path.join(dir,'executor.py'),bytes=Buffer.from('exact reviewed executor');fs.writeFileSync(file,bytes);
  const executorSource={path:file,sha256:crypto.createHash('sha256').update(bytes).digest('hex'),bytes:bytes.length};
  withCurrentBaseline(({engine,before,baseline,write})=>{
  const scope=m.closedScope(m.D12_PROFILE,before.sha256,engine,m.D12_CURRENT_SOURCE,m.D12_CURRENT_CORE,baseline);
  const context={runId:'run',selectionSha256:'b'.repeat(64),identity:{},executorSource,scope};
  const state={schema:scope.stateSchema,phase:'DATABASE_MAINTENANCE_COMPLETED',runId:'run',
   sourceRevision:m.D12_CURRENT_SOURCE,coreRevision:m.D12_CURRENT_CORE,
   selectionSha256:context.selectionSha256,databaseIdentity:{},executorSource,operations:[]};
  assert.throws(()=>m.orderedOperations(state,{},[],context),/0 !== 15/);
  assert.throws(()=>m.orderedOperations({...state,sourceRevision:m.D12_SOURCE},{},[],context));
  assert.throws(()=>m.orderedOperations({...state,coreRevision:m.D12_CORE},{},[],context));
  const identity=JSON.parse(fs.readFileSync(before.path)).databaseIdentity;
  const operationState=write('operation-state.json',{...state,databaseIdentity:identity});
  const proof={schema:'marty.native-maintenance-metadata-proof/v1',databaseBefore:before,operationState};
  assert.throws(()=>m.validateProof(proof,[],{runId:'run',selectionSha256:context.selectionSha256,
   executorSource,rolloutProfile:m.D12_PROFILE,sourceRevision:m.D12_CURRENT_SOURCE,
   coreRevision:m.D12_CURRENT_CORE,baseline,approvedDatabaseBeforeSha256:before.sha256,
   approvedEngineId:engine}),/0 !== 15/);
  });
 }finally{fs.rmSync(dir,{recursive:true});}
});
function catalog(){return {schema:'marty.native-maintenance-catalog/v1',control:{database:'marty',databaseOid:'16387',systemIdentifier:'7698090346923700258',fenceTable:'passport_cutover.state',activeMartyConnections:0,activeMigratorConnections:0,roles:['marty','marty_beta_migrator','marty_passport_fence_owner'].map(name=>({name,canLogin:false,superuser:false}))},acl:{appIssuanceCreate:false,appFlowCreate:false},ledgerTables:{issuance:'issuance_service.rust_schema_migrations',flow:'flow_service.rust_schema_versions'},aclTables:{flowIntent:'flow_service.physical_start_intents',cancellationHistory:'issuance_service.passport_job_administrative_cancellations'},ledgers:{issuance:['baseline','0010_passport_start_idempotency','0011_passport_administrative_cancellation'],flow:['rust_flow_0001','rust_flow_0002']},relations:['flow_service.physical_start_intents','flow_service.flow_definitions','flow_service.flow_instances','issuance_service.physical_document_jobs','issuance_service.passport_beta_batch_intents','issuance_service.passport_job_administrative_cancellations','passport_cutover.state','passport_cutover.native_migration_receipt'].map(n=>({schema:n.split('.')[0],name:n.split('.')[1],kind:'r',owner:'marty_passport_fence_owner'}))};}
test('current fenced catalog checks actual bound target while historical target stays pinned',()=>{
 withCurrentBaseline(({engine,before,baseline,write})=>{
  const scope=m.closedScope(m.D12_PROFILE,before.sha256,engine,m.D12_CURRENT_SOURCE,m.D12_CURRENT_CORE,baseline);
  const current=catalog();current.control.systemIdentifier=scope.target.systemIdentifier;
  m.catalog(current,'BEFORE_SCHEMA',scope);
  assert.throws(()=>m.catalog(catalog(),'BEFORE_SCHEMA',scope));
  assert.throws(()=>m.catalog(current,'BEFORE_SCHEMA'));
  const invalidJob=write('bad-job.json',{schema:'marty.windows-job-result/v1',state:'COMPLETE',exitCode:false,
   jobClosed:true,terminalActiveProcesses:0,forcedTermination:false,hostMarginBreached:false,timedOut:false,
   jobMemoryBytes:1024**3,hostMarginBytes:1024**3,assignedBeforeResume:true,processCreatedSuspended:true});
  assert.throws(()=>m.closedScope(m.D12_PROFILE,before.sha256,engine,m.D12_CURRENT_SOURCE,m.D12_CURRENT_CORE,
   {...baseline,job:invalidJob}));
 });
});
test('current unfenced observation cannot become a fenced projection',()=>{const c=catalog();c.control.fenceTable=null;c.control.roles=[{name:'marty',canLogin:true,superuser:false}];assert.throws(()=>m.catalog(c,'BEFORE_SCHEMA'));});
test('catalog phases enforce real login/count/identity distinctions',()=>{const c=catalog();m.catalog(c,'BEFORE_SCHEMA');assert.throws(()=>m.catalog(c,'BEFORE_START'));c.control.roles[0].canLogin=true;m.catalog(c,'BEFORE_START');c.control.activeMartyConnections=1;assert.throws(()=>m.catalog(c,'BEFORE_START'));});
for(const [name,edit]of [['foreign database',c=>c.control.databaseOid='5'],['duplicate role',c=>c.control.roles[2]=c.control.roles[1]],['app create',c=>c.acl.appFlowCreate=true],['migrator login',c=>c.control.roles[1].canLogin=true],['duplicate ledger',c=>c.ledgers.flow.push('rust_flow_0001')]])test(name+' refuses',()=>{const c=catalog();edit(c);assert.throws(()=>m.catalog(c,'BEFORE_SCHEMA'));});
test('canonical SQL receipt refuses garbage/missing/duplicate receipt',()=>{const s='marty.passport-beta-fence-verification/v1';assert.equal(m.sqlOutput(Buffer.from('42\n'+JSON.stringify({schema:s})),s).schema,s);for(const raw of ['DO\n','{}','{"schema":"'+s+'"}\n{"schema":"'+s+'"}'])assert.throws(()=>m.sqlOutput(Buffer.from(raw),s));});
test('owner after transition must be rust_owner same exact epoch/function receipt',()=>{const v={schema:'marty.passport-beta-rust-owner-verification/v1',phase:'rust_owner',fence_epoch:2,transition_txid:3,transitioned_at:'2026-10-29T00:00:00Z',functions_md5:{f:'a'.repeat(32)}};const t={...v,schema:'marty.passport-beta-rust-owner-transition/v1'};m.ownerReceipt(v,t,2);assert.throws(()=>m.ownerReceipt({...v,phase:'fully_fenced'},t,2));assert.throws(()=>m.ownerReceipt(v,{...t,transition_txid:4},2));});
test('attestation source/digest/owner are independently compared',()=>{const v={schema:'marty.passport-beta-native-migration-attestation/v1',fence_epoch:2,source_commit:m.SOURCE,migration_set_sha256:'a'.repeat(64),relation_owner:'marty_passport_fence_owner',app_can_read:false,installed_at:'2026-10-29T00:00:00Z'};m.attestation(v,2,'a'.repeat(64));for(const edit of [{source_commit:'b'.repeat(40)},{app_can_read:true},{migration_set_sha256:'b'.repeat(64)}])assert.throws(()=>m.attestation({...v,...edit},2,'a'.repeat(64)));});

for(const [name,edit]of [['missing native migration',c=>c.ledgers.flow=['rust_flow_0001']],['missing issuer migration',c=>c.ledgers.issuance.pop()],['missing relation',c=>c.relations.pop()],['wrong relation owner',c=>c.relations[0].owner='marty'],['wrong ACL relation',c=>c.aclTables.flowIntent=null]])test(name+' refuses after-catalog qualification',()=>{const c=catalog();c.control.roles[0].canLogin=true;edit(c);assert.throws(()=>m.catalog(c,'BEFORE_START'));});


test('both standalone verifiers authenticate one exact generated trigger guard',()=>{
 withGitSqlFixture(({refs})=>{
 for(const name of ['passport-beta-fence-verify.sql','passport-beta-rust-owner-verify.sql']){
  const raw=m.operationalSql(name,refs).toString();assert(!raw.includes('\\ir '));assert.equal(raw.split('DO $native_triggers$').length-1,1);
  assert(raw.includes('FULL JOIN actual'));assert(raw.includes("'0011_passport_administrative_cancellation'"));
 }
 const helper='passport-beta-issuer-trigger-verify.sql';assert.throws(()=>m.operationalSql('passport-beta-fence-verify.sql',{...refs,[helper]:{...refs[helper],sha256:'0'.repeat(64)}}));
 });
});


test('one canonical generator covers template and standalone verifier callers',()=>{
 withGitSqlFixture(({bytes})=>{
 const guard=bytes('passport-beta-issuer-trigger-verify.sql');
 for(const name of ['passport-beta-fence-verify.sql','passport-beta-rust-owner-verify.sql']){
  const standalone=bytes(name);assert(!/^\\[a-z]/im.test(standalone.toString()));
  assert(m.generateStandaloneVerifier(name,standalone,guard).equals(standalone));
  const template=Buffer.from(standalone.toString().replace(guard.toString(),'\\ir passport-beta-issuer-trigger-verify.sql'));
  assert(m.generateStandaloneVerifier(name,template,guard).equals(standalone));
  const stale=Buffer.from(standalone.toString().replace('FULL JOIN actual','LEFT JOIN actual'));
  assert(m.generateStandaloneVerifier(name,stale,guard).equals(standalone));
 }
 assert.throws(()=>m.generateStandaloneVerifier('unreviewed.sql',Buffer.from('SELECT 1'),guard));
 });
});

test('CRLF checkout bytes cannot impersonate the exact exported SQL blob',()=>{
 withGitSqlFixture(({refs,bytes,dir})=>{
  const fs=require('node:fs'),path=require('node:path'),name='passport-beta-native-attestation.sql';
  const normalized=bytes(name);assert(normalized.includes(10));
  fs.writeFileSync(path.join(dir,name),Buffer.from(normalized.toString().replaceAll('\n','\r\n')));
  assert.throws(()=>m.operationalSql(name,refs));
 });
});
