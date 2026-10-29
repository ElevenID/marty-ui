 'use strict';
// Synthetic/mock transport controls only: never actual deployment or qualification.
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const runtime=require('./functional-debug-runtime'),shared=require('./passport-maintenance-runtime'),latest=require('./native-maintenance-runtime');
const metadata=require('./native-maintenance-metadata'),fs=require('node:fs'),path=require('node:path');
const hash=s=>crypto.createHash('sha256').update(s).digest('hex');
function generations(){
 const names='auth organization credential-template trust-profile applicant notification compliance-profile presentation-policy deployment-profile flow verification revocation-profile device-registration issuance issuance-native canvas-sync-worker passport-beta-bureau gateway signing-keys passport-callback-signer canvas-sandbox ui-prod'.split(' ');
 const selection={profile:latest.PROFILE,state:'SELECTED_NOT_DEPLOYED',sourceRevision:latest.SOURCE,coreRevision:latest.CORE,roleBinaries:latest.ROLES,
  binaries:Object.fromEntries(Object.keys(latest.ROLES).map(role=>[role,{path:'/new/'+latest.ROLES[role],sha256:hash('new'+role)}])),scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false};
 const before=names.map(role=>{const binary=role==='ui-prod'?null:latest.ROLES[role]||'marty-'+role,sha256=binary?hash(role):null,uid=role==='applicant'?0:10001;
  return {role,binary,source:hash('prior').slice(0,40),...(role==='issuance-native'?{coreSource:hash('old-core').slice(0,40)}:{}),sha256,kind:'SYNTHETIC_CONTROL',imageId:'sha256:'+hash('image'),project:role==='ui-prod'?'elevenid-beta-ui':'elevenid-beta',containerId:hash('old'+role),hostPid:1,startedAt:'2026-10-28T00:00:00Z',health:role==='canvas-sync-worker'?null:'healthy',effectiveUid:uid,configuredRuntimeUid:uid,executablePath:binary?'/usr/local/bin/'+binary:null,processExecutableSha256:sha256,binaryMounts:binary?[{type:'bind',source:'/old/'+binary,destination:'/usr/local/bin/'+binary,writable:false}]:[]};});
 const expected=before.map(row=>({...row,requiredObservation:Object.fromEntries(['containerId','imageId','health','executablePath','processExecutableSha256','binaryMounts','startedAt','hostPid','effectiveUid','configuredRuntimeUid'].map(k=>[k,row[k]]))}));
 const observed=before.map(row=>({...structuredClone(row),service:row.role,running:true,status:'running',binarySha256:row.sha256,startedAt:'2026-10-28T01:00:00Z',hostPid:2,
  ...(latest.ROLES[row.role]?{containerId:hash('new'+row.role),effectiveUid:10001,configuredRuntimeUid:10001,effectiveGid:10001,configuredRuntimeGid:10001,binarySha256:selection.binaries[row.role].sha256,processExecutableSha256:selection.binaries[row.role].sha256,binaryMounts:[{...row.binaryMounts[0],source:selection.binaries[row.role].path}]}:{})}));
 return {before,expected,observed,selection};
}
test('closed4 actual-row comparator changes applicant UID/GID and preserves18 lineages',()=>{
 const f=generations(),rows=shared.validateGenerations(f.expected,f.before,f.selection,f.observed);assert.equal(rows.length,22);
 for(const row of rows){if(latest.ROLES[row.role]){assert.equal(row.source,latest.SOURCE);assert.equal(row.requiredEffectiveGid,10001);}else assert.equal(row.containerId,f.before.find(x=>x.role===row.role).containerId);}
});
for(const [name,change]of Object.entries({
 'missing applicant GID':f=>delete f.observed.find(x=>x.role==='applicant').effectiveGid,
 'root applicant':f=>f.observed.find(x=>x.role==='applicant').effectiveUid=0,
 'configured root GID':f=>f.observed.find(x=>x.role==='applicant').configuredRuntimeGid=0,
 'wrong configured applicant UID':f=>f.observed.find(x=>x.role==='applicant').configuredRuntimeUid=0,
 'preexisting nonroot not reviewed preimage':f=>f.before.find(x=>x.role==='applicant').effectiveUid=10001,
 'extra selected proxy':f=>f.selection.roleBinaries={...f.selection.roleBinaries,issuance:'marty-issuance-service'},
 'retained role recreated':f=>f.observed.find(x=>x.role==='auth').containerId=hash('foreign'),
 'old selected generation':f=>f.observed.find(x=>x.role==='flow').startedAt=f.before[0].startedAt,
 'old retained generation':f=>f.observed.find(x=>x.role==='auth').startedAt=f.before[0].startedAt,
 'selected writable mount':f=>f.observed.find(x=>x.role==='gateway').binaryMounts[0].writable=true,
}))test('four-role guard rejects '+name,()=>{const f=generations();change(f);assert.throws(()=>shared.validateGenerations(f.expected,f.before,f.selection,f.observed));});
function fixture(t){
 const f=generations(),docs=new Map(),buffers=new Map();let sequence=0;const add=value=>{const sha256=hash(JSON.stringify(value)+sequence++),ref={path:'/synthetic/'+sha256,sha256};docs.set(sha256,value);return ref;};
 t.mock.method(runtime,'boundJson',ref=>{assert(docs.has(ref.sha256),'Unbound synthetic document');return docs.get(ref.sha256);});
 const addBytes=bytes=>{const sha256=hash(bytes);buffers.set(sha256,bytes);return {path:'/synthetic/'+sha256,sha256,bytes:bytes.length};};
 t.mock.method(runtime,'boundBytes',ref=>buffers.get(ref.sha256)||Buffer.from('SYNTHETIC_SOURCE_OR_BACKUP_ONLY'));
 t.mock.method(runtime,'verifyBoundFile',()=>123);
 t.mock.method(runtime,'expectedRuntime',()=>f.expected);
 t.mock.method(runtime,'observeDocker',row=>f.observed.find(x=>x.role===row.role));
 const baseProfile={path:'/synthetic/base',sha256:shared.BASE},beforeBinding={path:'/synthetic/before',sha256:shared.BEFORE};docs.set(shared.BASE,{});docs.set(shared.BEFORE,{roles:f.before});
 const proof=()=>add({synthetic:true});const freeze={path:'/synthetic/freeze',sha256:latest.FREEZE};docs.set(latest.FREEZE,{productRevision:latest.SOURCE,coreRevision:latest.CORE,imagesBuilt:false,releaseQualified:false});
 const spec={rootProof:{synthetic:true}},prepared={buildProfile:latest.BUILD,uiRevision:latest.SOURCE,coreRevision:latest.CORE,runId:'11111111-1111-4111-8111-111111111111',journalBackend:spec,sourceFreezeReceipt:freeze,roleBinaries:Object.fromEntries(latest.ALL29.map(k=>[k,k]))};
 f.selection.preparedSource=add(prepared);f.selection.journal={runId:prepared.runId,specification:spec};
 const binaries=Object.fromEntries(latest.ALL29.map(k=>[k,{path:'/synthetic/'+k,sha256:hash(k)}]));for(const [role,binary]of Object.entries(latest.ROLES))binaries[binary]=f.selection.binaries[role];
 const receipt={...prepared,state:'PASSED',exitCode:0,oomKilled:false,canonicalAllServices:true,source:latest.SOURCE,preparationSha256:f.selection.preparedSource.sha256,imagesBuilt:false,releaseQualified:false,recordingQualified:false,binaries};
 for(const k of ['originalCargoLock','localizedCargoLock','localizedLockProof','lockedLocalizedMetadata','coreFeatureResolution','productionFeatureTree','canonicalCompilerLog','coreCompilerArtifacts'])receipt[k]=proof();
 f.selection.canonicalBuildReceipt=add(receipt);const selection=add(f.selection),buildReply={ok:true,name:'build-receipt.json',rootProof:spec.rootProof,sha256:f.selection.canonicalBuildReceipt.sha256,value:receipt};
 const readDocker=args=>args[0]==='ps'?f.before.map(x=>x.containerId).join('\n'): '3dbbbe66-1c98-4e0c-b0a6-f927c05e7341';
 const readJournal=()=>buildReply,inputs={baseProfile,beforeBinding,selection};const rb=shared.observeMaintenanceReadback(inputs,{readDocker,readJournal});const readback=add(rb);
 const plan=add({beforeBinding,scope:'ELF_LOADER_UID_COMPATIBILITY_ONLY',buildReceiptAuthoritativeSha256:f.selection.canonicalBuildReceipt.sha256});
 const compatibility={plan,result:add({schema:1,state:'ELF_LOADER_UID_COMPATIBILITY_PASS',planSha256:plan.sha256,candidateServiceEntrypointExecuted:false,signingOrApi:false,runtimeDeployed:false,rows:Object.entries(latest.ROLES).map(([role,binary])=>({binary,imageId:f.before.find(x=>x.role===role).imageId,sha256:f.selection.binaries[role].sha256,containerId:hash('compat'+role),uid:10001,gid:10001,exitCode:0,candidateReadableExecutable:true,loaderListSucceeded:true,ownedContainerRemoved:true}))})};
 const runId='22222222-2222-4222-8222-222222222222';const intent=add({runId,selectionSha256:selection.sha256,baseProfileSha256:shared.BASE,beforeBindingSha256:shared.BEFORE});
 const q={stopped:f.before.map(x=>({...x,running:false,paused:false,hostPid:0,containerExitCode:0,oomKilled:false,state:'exited'})),outcomes:Object.fromEntries(f.before.map(x=>[x.role,{terminal:true,stopAcknowledged:true,exitCode:0}]))};
 const quiescence=add(q),databaseIdentity={containerId:'f37ec29f5810b5ec0564ed47658c092eb73ed68496044d155ea75549a375745d',imageId:'sha256:fceb6f86328c36f2438fae3b851b0cc57c4a7e69a58c866d9ce24281f2cf0c9c',startedAt:'2026-10-27T15:53:15.069530075Z',hostPid:3728,project:'elevenid-beta',service:'postgres'};
 const backupFile=proof();const backup={runId,phase:'QUIESCED_FENCED_DATABASE_BACKUP',databaseIdentity,backupFile,quiescenceSha256:quiescence.sha256};
 const commands=['flow','issuance-native'].flatMap(role=>['migrate','verify-owned-schema'].map(command=>({role,command,runId,selectionSha256:selection.sha256,argv:['/usr/local/bin/'+latest.ROLES[role],command],elfSha256:f.selection.binaries[role].sha256,containerId:hash(role+command),state:'exited',exitCode:0,oomKilled:false})));
 const sourceRefs=Object.fromEntries(Object.entries(latest.SOURCE_PINS).map(([name,sha256])=>[name,{path:'/synthetic/'+name,sha256}]));
 const directory={uid:10001,gid:10001,mode:'0700',type:'directory',symlink:false},file={uid:0,gid:0,mode:'0644',type:'regular file',symlink:false,sha256:backupFile.sha256};
 const state={runId,quiescenceSha256:quiescence.sha256,oldContainerId:f.before.find(x=>x.role==='applicant').containerId,volumeName:'elevenid-beta-fresh-20261018_applicant_data',destination:'/app/data',entries:['applicant_store.json'],before:{directory,file},afterMigration:{directory:{...directory},file:{...file,uid:10001,gid:10001,mode:'0660'}},backup:backupFile,helperContainerId:hash('state-helper')};
 const cleanup={engineId:'3dbbbe66-1c98-4e0c-b0a6-f927c05e7341',containerIds:f.before.map(x=>x.containerId)};
 const outcome={schema:'marty.native-four-role-maintenance-outcome/v1',state:'MAINTENANCE_COMPLETED_FUNCTIONAL_ONLY',scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false,runId,engineId:cleanup.engineId,sourceRevision:latest.SOURCE,coreRevision:latest.CORE,baseProfileSha256:shared.BASE,beforeBindingSha256:shared.BEFORE,selectionSha256:selection.sha256,readbackSha256:readback.sha256,noAutomaticRollback:true,intent,intentDurability:{fileFsync:true,parentDirectory:{supported:true,synced:true}},sourceRefs,quiescence,databaseBackup:add(backup),schemaCommands:add(commands),applicantState:add(state),helperCleanup:add(cleanup)};

 // Source/transport composition fixture only. All Docker/journal calls remain mocks.
 const executorSource=proof();outcome.executorSource=executorSource;docs.get(intent.sha256).executorSource=executorSource;
 const identity=databaseIdentity,root=path.resolve(__dirname,'../..');
 const sqlSources=Object.fromEntries(Object.keys(metadata.SQL_SOURCES).map(name=>[name,addBytes(fs.readFileSync(path.join(root,'scripts/sql',name)))]));
 const migrationSources=Object.fromEntries(metadata.MIGRATIONS.map(([name])=>[name,addBytes(fs.readFileSync(path.join(root,name)))]));
 const migrationSet=metadata.migrationDigest(migrationSources),pgBefore={path:'/synthetic/database-before',sha256:metadata.PG_BASE_SHA};docs.set(pgBefore.sha256,{databaseIdentity:identity});
 const projection=canLogin=>({schema:'marty.native-maintenance-catalog/v1',control:{database:'marty',databaseOid:'16387',systemIdentifier:'7698090346923700258',fenceTable:'passport_cutover.state',activeMartyConnections:0,activeMigratorConnections:0,roles:['marty','marty_beta_migrator','marty_passport_fence_owner'].map(name=>({name,canLogin:name==='marty'&&canLogin,superuser:false}))},acl:{appIssuanceCreate:false,appFlowCreate:false},ledgerTables:{issuance:'issuance_service.rust_schema_migrations',flow:'flow_service.rust_schema_versions'},aclTables:{flowIntent:'flow_service.physical_start_intents',cancellationHistory:'issuance_service.passport_job_administrative_cancellations'},ledgers:{issuance:['0010_passport_start_idempotency','0011_passport_administrative_cancellation'],flow:['rust_flow_0002']},relations:['flow_service.physical_start_intents','flow_service.flow_definitions','flow_service.flow_instances','issuance_service.physical_document_jobs','issuance_service.passport_beta_batch_intents','issuance_service.passport_job_administrative_cancellations','passport_cutover.state','passport_cutover.native_migration_receipt'].map(name=>({schema:name.split('.')[0],name:name.split('.')[1],kind:'r',owner:'marty_passport_fence_owner'}))});
 const catalogSource=addBytes(fs.readFileSync(path.join(root,'scripts/sql/passport-beta-maintenance-catalog.sql')));
 const metadataBefore={schema:'marty.native-maintenance-catalog-observation/v1',runId,databaseIdentity:identity,source:catalogSource,projection:projection(false)};
 const metadataAfter={...metadataBefore,projection:projection(true)},beforeCatalog=add(metadataBefore),afterCatalog=add(metadataAfter);
 backup.catalogSha256=beforeCatalog.sha256;
 const fenceDoc={schema:'marty.passport-beta-fence-verification/v1',phase:'fully_fenced',epoch:1,functions_md5:{guard:'a'.repeat(32)}};
 const ownerDoc={schema:'marty.passport-beta-rust-owner-verification/v1',phase:'rust_owner',fence_epoch:1,transition_txid:2,transitioned_at:'2026-10-29T00:00:00Z',functions_md5:{guard:'b'.repeat(32)}};
 const transitionDoc={...ownerDoc,schema:'marty.passport-beta-rust-owner-transition/v1'};
 const markerDoc={schema:'marty.passport-beta-native-migration-attestation/v1',fence_epoch:1,source_commit:latest.SOURCE,migration_set_sha256:migrationSet,installed_at:'2026-10-29T00:00:00Z',relation_owner:'marty_passport_fence_owner',app_can_read:false};
 const target={'marty.passport_beta_verified_project':'elevenid-beta','marty.passport_beta_expected_system_identifier':'7698090346923700258','marty.passport_beta_expected_database_oid':'16387'};
 const settings={...target,'marty.passport_beta_expected_fence_epoch':'1','marty.passport_beta_expected_source_commit':latest.SOURCE,'marty.passport_beta_expected_native_migration_sha256':migrationSet};
 const sqlReceipts={},sqlRows={};
 for(const [id,kind,name]of metadata.DATABASE_ORDER){if(kind!=='sql')continue;
  const options=['FENCE_INSTALL','FENCE_VERIFY'].includes(id)?target:{...settings};if(id==='RUST_OWNER_VERIFY')options['marty.passport_beta_expected_transition_txid']='2';
  const json=id==='FENCE_VERIFY'?[fenceDoc]:id==='RUST_OWNER_TRANSITION'?[fenceDoc,ownerDoc,transitionDoc]:id==='RUST_OWNER_VERIFY'?[ownerDoc]:id==='NATIVE_ATTESTATION'?[markerDoc]:[];
  const row={runId,databaseIdentity:identity,source:sqlSources[name],argv:['psql','-X','-U','postgres','-d','marty','-At','-v','ON_ERROR_STOP=1','-f','-'],pgOptions:metadata.sessionOptions(options),stdin:addBytes(metadata.operationalSql(name,sqlSources)),stdout:addBytes(Buffer.from('BEGIN\nDO\n'+json.map(x=>JSON.stringify(x)+'\n').join('')+'COMMIT\n')),stderr:addBytes(Buffer.alloc(0)),state:'exited',exitCode:0,oomKilled:false};
  row.transportArgv=['docker','--context','desktop-linux','exec','-i','-e','PGOPTIONS='+row.pgOptions,identity.containerId,...row.argv];
  sqlRows[id]=row;sqlReceipts[name]=add(row);
 }
 for(const row of commands)Object.assign(row,{databaseIdentity:identity,sourceRevision:latest.SOURCE,coreRevision:latest.CORE,imageId:f.before.find(x=>x.role===row.role).imageId,stdout:addBytes(Buffer.alloc(0)),stderr:addBytes(Buffer.alloc(0))});
 const operations=metadata.DATABASE_ORDER.map(([id,kind,key],index)=>({stepId:id,state:'SUCCEEDED',unknownOutcome:false,exitCode:0,terminalDurability:{fileFsync:true,parentDirectory:{supported:true,synced:true}},sequence:index+1,intentSequence:2*index+1,terminalSequence:2*index+2,intentDurability:{fileFsync:true,parentDirectory:{supported:true,synced:true}},startedAt:new Date(Date.UTC(2026,9,29,0,0,index*2)).toISOString(),finishedAt:new Date(Date.UTC(2026,9,29,0,0,index*2+1)).toISOString(),receipt:kind==='sql'?sqlReceipts[key]:kind==='rust'?add(commands.find(x=>x.role+':'+x.command===key)):kind==='backup'?outcome.databaseBackup:key==='beforeCatalog'?beforeCatalog:afterCatalog}));
 const operationState={schema:'marty.native-four-role-operation-state/v1',phase:'DATABASE_MAINTENANCE_COMPLETED',runId,sourceRevision:latest.SOURCE,coreRevision:latest.CORE,selectionSha256:selection.sha256,databaseIdentity:identity,executorSource,operations};
 const metadataProof={schema:'marty.native-maintenance-metadata-proof/v1',databaseBefore:pgBefore,beforeCatalog,afterCatalog,sqlSources,sqlReceipts,migrationSources,databaseBackup:outcome.databaseBackup,operationState:add(operationState)};
 outcome.metadataProof=add(metadataProof);
 inputs.outcome=add(outcome);inputs.readback=readback;inputs.compatibility=compatibility;inputs.maintenanceJournal={runId,specification:spec};
 const readMaintenanceJournal=(_j,name)=>({ok:true,name,rootProof:spec.rootProof,sha256:name==='build-receipt.json'?inputs.outcome.sha256:name==='build-state.json'?metadataProof.operationState.sha256:intent.sha256,value:name==='build-receipt.json'?outcome:name==='build-state.json'?operationState:docs.get(intent.sha256)});
 return {...f,docs,buffers,inputs,outcome,commands,state,cleanup,backup,sourceRefs,q,metadataBefore,metadataAfter,metadataProof,operationState,sqlRows,readback:rb,selectionRef:selection,readDocker,readJournal,readMaintenanceJournal};
}
test('full synthetic actual-reader composition requires authoritative outcome and fresh22',t=>{
 const f=fixture(t),profile=latest.produceLatestProfile(f.inputs,f);assert.equal(profile.scope,'FUNCTIONAL_ONLY');assert.equal(profile.releaseQualified,false);assert.equal(latest.expectedLatestRuntime(profile).length,22);
});
for(const [name,mutate]of Object.entries({
 'raw state bytes despite success flags':f=>f.state.afterMigration.file.sha256=hash('changed-private-store'),
 'root state GID':f=>f.state.afterMigration.file.gid=0,
 'symlink state':f=>f.state.before.file.symlink=true,
 'wrong backup run':f=>f.backup.runId='33333333-3333-4333-8333-333333333333',
 'missing stop outcome':f=>delete f.q.outcomes.flow,
 'live stopped PID':f=>f.q.stopped[0].hostPid=123,
 'wrong fence database':f=>f.metadataAfter.databaseIdentity={foreign:'db'},
 'fence active connection':f=>f.metadataBefore.projection.control.activeMartyConnections=1,
 'foreign schema ELF':f=>f.commands[0].elfSha256=hash('foreign'),
 'failed schema command':f=>f.commands[0].exitCode=1,
 'altered schema source':f=>Object.values(f.sourceRefs)[0].sha256=hash('foreign-source'),
 'helper still registered':f=>f.cleanup.containerIds.push(f.state.helperContainerId),
 'non-durable intent':f=>f.outcome.intentDurability.parentDirectory.synced=false,
}))test('qualified outcome rejects '+name,t=>{const f=fixture(t);mutate(f);assert.throws(()=>latest.produceLatestProfile(f.inputs,f));});
test('a local receipt without original maintenance transport is not authority',()=>{assert.throws(()=>latest.produceLatestProfile({},{}),/ACTUAL_DOCKER_READER_REQUIRED/);});
test('fresh-reader mismatch cannot be replaced by stored passing rows',t=>{const f=fixture(t);const real=f.readMaintenanceJournal;f.readMaintenanceJournal=(j,n)=>n==='build-receipt.json'?{...real(j,n),sha256:hash('local-only')}:real(j,n);assert.throws(()=>latest.produceLatestProfile(f.inputs,f));});

test('fresh actual rows must match stored readback even when both independently validate',t=>{
 const f=fixture(t);runtime.observeDocker.mock.mockImplementation(row=>({...f.observed.find(x=>x.role===row.role),hostPid:3}));
 assert.throws(()=>latest.produceLatestProfile(f.inputs,f),/FRESH_ACTUAL22_MAINTENANCE_READBACK_REQUIRED/);
});

test('streamed private backup verification retains exact digest without assertion byte dumps',t=>{
 const fs=require('node:fs'),os=require('node:os'),path=require('node:path');
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'native-maintenance-bound-file-')),file=path.join(dir,'synthetic-backup');
 t.after(()=>{fs.unlinkSync(file);fs.rmdirSync(dir);});const bytes=Buffer.alloc(70000,97);fs.writeFileSync(file,bytes);
 const ref={path:file,sha256:hash(bytes)};assert.equal(runtime.verifyBoundFile(ref),bytes.length);
 assert.throws(()=>runtime.verifyBoundFile({...ref,sha256:hash('foreign')}),/Bound file changed/);
});

test('real Docker observation seam parses PID1 GID and enforces the configured pair',()=>{
 const f=generations(),expected=shared.validateGenerations(f.expected,f.before,f.selection,f.observed).find(x=>x.role==='applicant');
 let gid=10001,user='10001:10001';const seen=[];const read=args=>{seen.push(args[0]);
  if(args[0]==='ps')return expected.containerId;
  if(args[0]==='inspect')return JSON.stringify([{Id:expected.containerId,Image:expected.imageId,Config:{User:user,Labels:{'com.docker.compose.project':expected.project,'com.docker.compose.service':expected.role}},State:{Running:true,Status:'running',StartedAt:expected.startedAt,Pid:expected.hostPid,Health:{Status:'healthy'}},Mounts:expected.binaryMounts.map(m=>({Type:m.type,Source:m.source,Destination:m.destination,RW:m.writable}))}]);
  if(args[2]==='readlink')return expected.executablePath;
  if(args[2]==='sha256sum')return expected.sha256+'  synthetic';
  if(args[2]==='cat')return 'Uid:\t10001\t10001\t10001\t10001\nGid:\t10001\t'+gid+'\t10001\t10001\n';
  throw new Error('Unexpected read operation');
 };
 assert.equal(runtime.validateRuntimeObservation(expected,runtime.observeDocker(expected,read)).effectiveGid,10001);
 gid=0;assert.throws(()=>runtime.validateRuntimeObservation(expected,runtime.observeDocker(expected,read)));
 gid=10001;user='10001:0';assert.throws(()=>runtime.validateRuntimeObservation(expected,runtime.observeDocker(expected,read)));
 assert.equal(seen.filter(x=>x==='ps').length,3,'Real observer restored after earlier mocked transport tests');
});

for(const [name,mutate]of Object.entries({
 'Rust command source mismatch':f=>f.commands[0].sourceRevision='0'.repeat(40),
 'Rust Core mismatch':f=>f.commands[1].coreRevision='0'.repeat(40),
 'reused Rust helper':f=>f.commands[1].containerId=f.commands[0].containerId,
 'SQL before verify order':f=>[f.operationState.operations[6],f.operationState.operations[8]]=[f.operationState.operations[8],f.operationState.operations[6]],
 'unknown SQL outcome':f=>f.operationState.operations[0].unknownOutcome=true,
 'failed operation journal':f=>f.operationState.operations[0].exitCode=1,
 'unsynced pre-effect state':f=>f.operationState.operations[0].intentDurability.parentDirectory.synced=false,
 'unsynced terminal state':f=>f.operationState.operations[2].terminalDurability.parentDirectory.synced=false,
 'nonmonotonic terminal time':f=>f.operationState.operations[3].finishedAt='2026-10-28T00:00:00Z',
 'forged COMMIT boolean':f=>{const row=f.sqlRows.NATIVE_ATTESTATION;row.transactionCommitted=true;f.buffers.set(row.stdout.sha256,Buffer.from('BEGIN\nDO\n'));},
 'SQL target container mismatch':f=>f.sqlRows.NATIVE_ATTESTATION.transportArgv[7]='0'.repeat(64),
 'psql without ON_ERROR_STOP':f=>f.sqlRows.NATIVE_ATTESTATION.argv[9]='OFF',
 'changed SQL stdin':f=>{const row=f.sqlRows.NATIVE_ATTESTATION,sha256=hash('SELECT 1;');row.stdin={path:'/synthetic/tampered',sha256};f.buffers.set(sha256,Buffer.from('SELECT 1;'));},
 'wrong target session':f=>f.sqlRows.NATIVE_ATTESTATION.pgOptions+=' -c marty.passport_beta_expected_database_oid=1',
 'missing CLI journal receipt':f=>f.operationState.operations.splice(4,1),
 'wrong executor source':f=>f.operationState.executorSource={path:'/foreign',sha256:'0'.repeat(64)},
 'catalog before native migration':f=>f.metadataAfter.projection.ledgers.issuance.pop(),
}))test('journal-bound metadata refuses '+name,t=>{const f=fixture(t);mutate(f);assert.throws(()=>latest.produceLatestProfile(f.inputs,f));});
test('stored operation history cannot replace actual journal read',t=>{const f=fixture(t),read=f.readMaintenanceJournal;f.readMaintenanceJournal=(j,n)=>n==='build-state.json'?{...read(j,n),sha256:'0'.repeat(64)}:read(j,n);assert.throws(()=>latest.produceLatestProfile(f.inputs,f),/assert|actual|expected/i);});
