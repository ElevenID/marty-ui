 'use strict';
// Metadata projection and real SQL receipts; performs no database mutation.
// Domain correctness belongs to the source-bound Rust migrate/verify commands.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),util=require('node:util');
const runtime=require('./functional-debug-runtime');
const CORE='4320b5fa1c6f41231ee0aa2bc57d8008549f67ac';
const SOURCE='852dbb5cc0cca79cfe0bbbed5cb8fb94cda0ad34';
const same=(a,b,code)=>assert(util.isDeepStrictEqual(a,b),code);
const MIGRATIONS=Object.freeze([
 ['rust/services/flow/migrations/0003_physical_start_intents.sql','fd86a211a4b799b53827456ac1d5b8887ae3264c26ae889fb7714a1fa62e4edd'],
 ['rust/services/issuance/migrations/0010_passport_start_idempotency.sql','05b3aafe03b9aa258c8061db2d9ac1adb35f17f0d513b9995d48ee2ef2305801'],
 ['rust/services/issuance/migrations/0011_passport_administrative_cancellation.sql','9842f5ea39aab254d41cf7bc936411b813b853352a1e2de668594926dd08f682']]);
const CATALOG_SQL_SHA='e7972f5d018100c5288dbe4eca0df2dbaa61ce21f8a34991789a3a173ad8110c';
const PG_BASE_SHA='7edeffa3c4cbc10d02010dd0bfbd2e84e2cf4cf149e1c8d5bf7e834a5aedf075';
function observeCatalog(inputs,{readDocker}={}){
 assert.equal(typeof readDocker,'function','ACTUAL_DOCKER_READER_REQUIRED');
 assert.equal(inputs.databaseBefore.sha256,PG_BASE_SHA);const prior=runtime.boundJson(inputs.databaseBefore).databaseIdentity;
 assert.equal(inputs.sql.sha256,CATALOG_SQL_SHA);const sql=runtime.boundBytes(inputs.sql);
 function identity(){
  const info=JSON.parse(readDocker(['info','--format','{{json .}}']));assert.equal(info.ID,'3dbbbe66-1c98-4e0c-b0a6-f927c05e7341');
  const rows=JSON.parse(readDocker(['inspect',prior.containerId]));assert.equal(rows.length,1);const row=rows[0];
  assert.equal(row.Id,prior.containerId);assert.equal(row.Image,prior.imageId);assert.equal(row.State.Running,true);
  assert.equal(row.State.StartedAt,prior.startedAt);assert.equal(row.State.Pid,prior.hostPid);
  assert.equal(row.Config.Labels['com.docker.compose.project'],'elevenid-beta');assert.equal(row.Config.Labels['com.docker.compose.service'],'postgres');
  return prior;
 }
 const before=identity();
 const stdout=readDocker(['exec','-e','PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=5000',prior.containerId,
   'psql','-X','-U','postgres','-d','marty','-qAt','-v','ON_ERROR_STOP=1','-c',sql.toString('utf8')]);
 const projection=sqlOutput(Buffer.from(stdout),'marty.native-maintenance-catalog/v1');same(identity(),before,'CATALOG_DATABASE_CHANGED');
 return {schema:'marty.native-maintenance-catalog-observation/v1',runId:inputs.runId,databaseIdentity:before,source:inputs.sql,projection};
}
function migrationDigest(refs){
 same(Object.keys(refs).sort(),MIGRATIONS.map(x=>x[0]).sort(),'EXACT_NATIVE_MIGRATION_SOURCES');
 const hash=crypto.createHash('sha256');
 for(const [name,sha]of MIGRATIONS){assert.equal(refs[name].sha256,sha);const bytes=runtime.boundBytes(refs[name]);
  const size=Buffer.alloc(8);size.writeBigUInt64BE(BigInt(bytes.length));hash.update(name);hash.update(Buffer.from([0]));hash.update(size);hash.update(bytes);}
 return hash.digest('hex');
}
function catalog(value,phase){
 assert.equal(value.schema,'marty.native-maintenance-catalog/v1');
 const c=value.control;assert.equal(c.database,'marty');assert.equal(String(c.databaseOid),'16387');assert.equal(c.systemIdentifier,'7698090346923700258');
 assert(['BEFORE_SCHEMA','BEFORE_START'].includes(phase),'CLOSED_CATALOG_PHASE');
 assert.equal(c.fenceTable,'passport_cutover.state');assert.equal(c.activeMartyConnections,0);assert.equal(c.activeMigratorConnections,0);
 assert.equal(c.roles.length,3);assert.equal(new Set(c.roles.map(x=>x.name)).size,3);
 same(c.roles.map(x=>x.name).sort(),['marty','marty_beta_migrator','marty_passport_fence_owner'],'EXACT_FENCED_ROLES');
 for(const role of c.roles){assert.equal(role.superuser,false);assert.equal(role.canLogin,role.name==='marty'&&phase==='BEFORE_START');}
 assert.equal(value.acl.appIssuanceCreate,false);assert.equal(value.acl.appFlowCreate,false);
 same(value.ledgerTables,{issuance:'issuance_service.rust_schema_migrations',flow:'flow_service.rust_schema_versions'},'EXACT_NATIVE_LEDGERS');
 // Raw ledger/owner rows are evidence, not a replacement for Rust validators.
 for(const rows of Object.values(value.ledgers)){assert(Array.isArray(rows));assert.equal(new Set(rows).size,rows.length);}
 const keys=value.relations.map(x=>x.schema+'.'+x.name);assert.equal(new Set(keys).size,keys.length);
 if(phase==='BEFORE_START'){
  for(const version of ['0010_passport_start_idempotency','0011_passport_administrative_cancellation'])assert(value.ledgers.issuance.includes(version),'ISSUER_MIGRATION_METADATA_MISSING');
  // Flow0003 is recorded under rust_flow_0002 by the real source migration.rs.
  assert(value.ledgers.flow.includes('rust_flow_0002'),'FLOW_MIGRATION_METADATA_MISSING');
  same(value.aclTables,{flowIntent:'flow_service.physical_start_intents',cancellationHistory:'issuance_service.passport_job_administrative_cancellations'},'REQUIRED_ACL_RELATIONS_MISSING');
  for(const name of ['flow_service.physical_start_intents','flow_service.flow_definitions','flow_service.flow_instances','issuance_service.physical_document_jobs','issuance_service.passport_beta_batch_intents','issuance_service.passport_job_administrative_cancellations','passport_cutover.state','passport_cutover.native_migration_receipt']){
   const row=value.relations.find(x=>x.schema+'.'+x.name===name);assert(row,'REQUIRED_RELATION_MISSING');assert.equal(row.kind,'r');assert.equal(row.owner,'marty_passport_fence_owner');
  }
 }

 return c;
}
const SQL_SOURCES=Object.freeze({"passport-beta-fence-install.sql": "070d05156230ffc86658857ac8f7c7301d935cad772760942e40155030e6244f", "passport-beta-fence-drain.sql": "c1728e56e456a5e1a4d043d911fe6f16cb53addea60a00eed65724000bc0d2bc", "passport-beta-fence-verify.sql": "a228e73ff9e2820d01e31e6d06fca91d309a182e1a221a1548b8d10e14c480dd", "passport-beta-db-maintenance-start.sql": "0129b6047f8ad3db2fa271f4b275bca6160b68c3bb6625dcc3937aba6f241608", "passport-beta-batch-acl-finalize.sql": "5cca0125986da948eb5a684fc1ea24e349e680c967a6ff1e837659f4b22ee2ff", "passport-beta-db-enable-app-login.sql": "4f30d51de9978ce1c9c62c41fc4a8fb600b4b275d1c82535ffcf0f67a1001720", "passport-beta-rust-owner-transition.sql": "2cc812c71a6abc7db72f701ef83f51514ba620cfcba9af1f62025b3164bbe01a", "passport-beta-rust-owner-verify.sql": "3c098a5d6b13f95a63bdabdf5a029b119563ea7045ffe3cbb870f12d97386f0d", "passport-beta-native-attestation.sql": "9fea7b48ada94accad6920a51479b3dfeb2aea87603cba964a48041a2c2689eb"});
const SQL_INCLUDES=Object.freeze({
 'passport-beta-fence-install.sql':['passport-beta-fence-drain.sql'],
 'passport-beta-rust-owner-transition.sql':['passport-beta-fence-verify.sql','passport-beta-fence-drain.sql','passport-beta-rust-owner-verify.sql']});
function operationalSql(name,refs){
 assert(Object.hasOwn(SQL_SOURCES,name),'CLOSED_SQL_SOURCE_REQUIRED');
 assert.equal(refs[name].sha256,SQL_SOURCES[name]);const raw=runtime.boundBytes(refs[name]).toString('utf8');
 const seen=[];const result=raw.replace(/^\\ir\s+([^\r\n]+)\r?$/gm,(_line,include)=>{
  assert((SQL_INCLUDES[name]||[]).includes(include),'UNREVIEWED_SQL_INCLUDE');seen.push(include);return operationalSql(include,refs).toString('utf8');
 });
 same(seen,SQL_INCLUDES[name]||[],'EXACT_SQL_INCLUDES_REQUIRED');return Buffer.from(result);
}
function parseSqlOutput(bytes){
 const rows=bytes.toString('utf8').split(/\r?\n/).map(x=>x.trim()).filter(Boolean),documents=[],tags=[];
 for(const row of rows){
  if(/^\d+$/.test(row))continue; // source-bound transition set_config emits its txid
  if(/^(BEGIN|SET|DO|COMMIT|LOCK TABLE|CREATE TABLE|ALTER TABLE|ALTER FUNCTION|CREATE FUNCTION|CREATE SCHEMA|CREATE ROLE|CREATE TRIGGER|CREATE INDEX|ALTER SCHEMA|ALTER ROLE|REVOKE|GRANT|INSERT 0 1|UPDATE 1)$/.test(row)){tags.push(row);continue;}
  let value;try{value=JSON.parse(row);}catch{assert.fail('SQL_STDOUT_NOT_CANONICAL_JSON');}
  assert(value&&typeof value.schema==='string','SQL_STDOUT_UNKNOWN_DOCUMENT');documents.push(value);
 }
 return {documents,tags};
}
function sqlOutput(bytes,schema){
 const selected=parseSqlOutput(bytes).documents.filter(x=>x.schema===schema);
 assert.equal(selected.length,1,'EXACT_SQL_RECEIPT_REQUIRED');return selected[0];
}
function sessionOptions(settings){
 const names=Object.keys(settings).sort();for(const name of names){assert(/^marty\.passport_beta_[a-z0-9_]+$/.test(name));assert(/^[a-zA-Z0-9_-]+$/.test(String(settings[name])));}
 return '-c statement_timeout=60000 -c lock_timeout=10000 '+names.map(name=>'-c '+name+'='+settings[name]).join(' ');
}
function verifiedSql(step,name,refs,settings,identity,runId,schema=null){
 assert.equal(step.runId,runId);same(step.databaseIdentity,identity,'SQL_DATABASE_CHANGED');
 same(step.source,refs[name],'SQL_SOURCE_REF_CHANGED');
 same(step.argv,['psql','-X','-U','postgres','-d','marty','-At','-v','ON_ERROR_STOP=1','-f','-'],'EXACT_PSQL_INVOCATION_REQUIRED');
 assert.equal(step.pgOptions,sessionOptions(settings));
 same(step.transportArgv,['docker','--context','desktop-linux','exec','-i','-e','PGOPTIONS='+step.pgOptions,identity.containerId,...step.argv],'EXACT_TARGETED_PSQL_TRANSPORT_REQUIRED');
 const source=operationalSql(name,refs),stdin=runtime.boundBytes(step.stdin);
 assert(source.equals(stdin),'SQL_STDIN_SOURCE_CHANGED');
 assert.equal(step.state,'exited');assert.equal(step.exitCode,0);assert.equal(step.oomKilled,false);
 const output=runtime.boundBytes(step.stdout),parsed=parseSqlOutput(output);
 const schemas=name==='passport-beta-fence-verify.sql'?['marty.passport-beta-fence-verification/v1']:name==='passport-beta-rust-owner-transition.sql'?['marty.passport-beta-fence-verification/v1','marty.passport-beta-rust-owner-verification/v1','marty.passport-beta-rust-owner-transition/v1']:name==='passport-beta-rust-owner-verify.sql'?['marty.passport-beta-rust-owner-verification/v1']:name==='passport-beta-native-attestation.sql'?['marty.passport-beta-native-migration-attestation/v1']:[];
 same(parsed.documents.map(x=>x.schema).sort(),schemas.sort(),'EXACT_SQL_STDOUT_DOCUMENTS_REQUIRED');
 // psql -At emits COMMIT only after the exact source's transaction succeeds.
 // A caller-set transactionCommitted flag is neither read nor accepted.
 if(/^COMMIT;/m.test(source.toString('utf8')))assert(parsed.tags.includes('COMMIT'),'SQL_COMMIT_NOT_OBSERVED');
 return schema?sqlOutput(output,schema):null;
}
function fenceReceipt(value){
 assert.equal(value.schema,'marty.passport-beta-fence-verification/v1');assert.equal(value.phase,'fully_fenced');
 assert(Number.isSafeInteger(value.epoch)&&value.epoch>0,'EXACT_FENCE_EPOCH');assert(value.functions_md5&&Object.keys(value.functions_md5).length>0);
 for(const hash of Object.values(value.functions_md5))assert(/^[a-f0-9]{32}$/.test(hash));return value.epoch;
}
function ownerReceipt(value,transition,epoch){
 assert.equal(value.schema,'marty.passport-beta-rust-owner-verification/v1');assert.equal(transition.schema,'marty.passport-beta-rust-owner-transition/v1');
 for(const row of [value,transition]){assert.equal(row.phase,'rust_owner');assert.equal(row.fence_epoch,epoch);assert(Number.isSafeInteger(row.transition_txid)&&row.transition_txid>epoch);}
 for(const key of ['fence_epoch','transition_txid','transitioned_at','functions_md5'])same(value[key],transition[key],'OWNER_TRANSITION_RECEIPT_CHANGED');
}
function attestation(value,epoch,digest){
 assert.equal(value.schema,'marty.passport-beta-native-migration-attestation/v1');assert.equal(value.fence_epoch,epoch);
 assert.equal(value.source_commit,SOURCE);assert.equal(value.migration_set_sha256,digest);assert.equal(value.relation_owner,'marty_passport_fence_owner');assert.equal(value.app_can_read,false);
 assert(Number.isFinite(Date.parse(value.installed_at)),'ATTESTATION_INSTALL_TIME_REQUIRED');
}
const DATABASE_ORDER=Object.freeze([
 ['FENCE_INSTALL','sql','passport-beta-fence-install.sql'],
 ['FENCE_VERIFY','sql','passport-beta-fence-verify.sql'],
 ['MAINTENANCE_START','sql','passport-beta-db-maintenance-start.sql'],
 ['CATALOG_BEFORE_SCHEMA','catalog','beforeCatalog'],['DATABASE_BACKUP','backup','databaseBackup'],
 ['FLOW_MIGRATE','rust','flow:migrate'],['FLOW_VERIFY','rust','flow:verify-owned-schema'],
 ['ISSUER_MIGRATE','rust','issuance-native:migrate'],['ISSUER_VERIFY','rust','issuance-native:verify-owned-schema'],
 ['ACL_FINALIZE','sql','passport-beta-batch-acl-finalize.sql'],
 ['NATIVE_ATTESTATION','sql','passport-beta-native-attestation.sql'],
 ['ENABLE_APP_LOGIN','sql','passport-beta-db-enable-app-login.sql'],
 ['RUST_OWNER_TRANSITION','sql','passport-beta-rust-owner-transition.sql'],
 ['RUST_OWNER_VERIFY','sql','passport-beta-rust-owner-verify.sql'],
 ['CATALOG_BEFORE_START','catalog','afterCatalog']]);
function orderedOperations(state,proof,commands,{runId,selectionSha256,identity,executorSource}){
 assert.equal(state.schema,'marty.native-four-role-operation-state/v1');assert.equal(state.phase,'DATABASE_MAINTENANCE_COMPLETED');
 assert.equal(state.runId,runId);assert.equal(state.sourceRevision,SOURCE);assert.equal(state.coreRevision,CORE);assert.equal(state.selectionSha256,selectionSha256);
 same(state.databaseIdentity,identity,'OPERATION_DATABASE_CHANGED');same(state.executorSource,executorSource,'OPERATION_EXECUTOR_CHANGED');runtime.boundBytes(executorSource);
 assert.equal(state.operations.length,DATABASE_ORDER.length);let lastTime=0;const rows={};
 for(let index=0;index<DATABASE_ORDER.length;index++){
  const [id,kind,key]=DATABASE_ORDER[index],operation=state.operations[index];assert.equal(operation.state,'SUCCEEDED');assert.equal(operation.unknownOutcome,false);assert.equal(operation.exitCode,0);assert.equal(operation.stepId,id,'EXACT_DATABASE_OPERATION_ORDER');assert.equal(operation.sequence,index+1);
  assert.equal(operation.intentSequence,2*index+1);assert.equal(operation.terminalSequence,2*index+2);
  for(const barrier of [operation.intentDurability,operation.terminalDurability]){assert.equal(barrier.fileFsync,true);assert.equal(barrier.parentDirectory.supported,true);assert.equal(barrier.parentDirectory.synced,true);}
  const start=Date.parse(operation.startedAt),end=Date.parse(operation.finishedAt);assert(Number.isFinite(start)&&Number.isFinite(end)&&start>=lastTime&&end>=start,'DATABASE_OPERATION_TIME_ORDER');lastTime=end;
  const row=runtime.boundJson(operation.receipt);assert.equal(row.runId,runId);same(row.databaseIdentity,identity,'OPERATION_DATABASE_CHANGED');
  if(kind==='rust'){
   const expected=commands.find(x=>x.role+':'+x.command===key);assert(expected,'EXACT_RUST_COMMAND_REQUIRED');same(row,expected,'RUST_COMMAND_NOT_FROM_OPERATION_JOURNAL');
  }else if(kind==='sql')same(operation.receipt,proof.sqlReceipts[key],'SQL_RECEIPT_NOT_FROM_OPERATION_JOURNAL');
  else same(operation.receipt,proof[key],kind==='backup'?'BACKUP_NOT_FROM_OPERATION_JOURNAL':'CATALOG_NOT_FROM_OPERATION_JOURNAL');
  rows[id]=row;
 }
 return rows;
}
function validateProof(proof,commands,context){
 const {runId,selectionSha256,executorSource}=context;
 assert.equal(proof.schema,'marty.native-maintenance-metadata-proof/v1');assert.equal(proof.databaseBefore.sha256,PG_BASE_SHA);
 const identity=runtime.boundJson(proof.databaseBefore).databaseIdentity;
 const state=runtime.boundJson(proof.operationState),rows=orderedOperations(state,proof,commands,{runId,selectionSha256,identity,executorSource});
 const before=rows.CATALOG_BEFORE_SCHEMA,after=rows.CATALOG_BEFORE_START;
 for(const row of [before,after]){assert.equal(row.schema,'marty.native-maintenance-catalog-observation/v1');assert.equal(row.source.sha256,CATALOG_SQL_SHA);runtime.boundBytes(row.source);}
 catalog(before.projection,'BEFORE_SCHEMA');catalog(after.projection,'BEFORE_START');
 same(Object.keys(proof.sqlSources).sort(),Object.keys(SQL_SOURCES).sort(),'EXACT_OPERATIONAL_SQL_SOURCES');
 same(Object.keys(proof.sqlReceipts).sort(),DATABASE_ORDER.filter(x=>x[1]==='sql').map(x=>x[2]).sort(),'EXACT_METADATA_SQL_RECEIPTS');
 const digest=migrationDigest(proof.migrationSources);
 const target={'marty.passport_beta_verified_project':'elevenid-beta','marty.passport_beta_expected_system_identifier':'7698090346923700258','marty.passport_beta_expected_database_oid':'16387'};
 const fence=sqlOutput(runtime.boundBytes(rows.FENCE_VERIFY.stdout),'marty.passport-beta-fence-verification/v1'),epoch=fenceReceipt(fence);
 const expected={...target,'marty.passport_beta_expected_fence_epoch':String(epoch),'marty.passport_beta_expected_source_commit':SOURCE,'marty.passport_beta_expected_native_migration_sha256':digest};
 const transition=sqlOutput(runtime.boundBytes(rows.RUST_OWNER_TRANSITION.stdout),'marty.passport-beta-rust-owner-transition/v1');
 const owner=sqlOutput(runtime.boundBytes(rows.RUST_OWNER_VERIFY.stdout),'marty.passport-beta-rust-owner-verification/v1');ownerReceipt(owner,transition,epoch);
 for(const [id,kind,name]of DATABASE_ORDER){if(kind!=='sql')continue;
  const settings=['FENCE_INSTALL','FENCE_VERIFY'].includes(id)?target:{...expected};
  if(id==='RUST_OWNER_VERIFY')settings['marty.passport_beta_expected_transition_txid']=String(transition.transition_txid);
  verifiedSql(rows[id],name,proof.sqlSources,settings,identity,runId);
 }
 attestation(sqlOutput(runtime.boundBytes(rows.NATIVE_ATTESTATION.stdout),'marty.passport-beta-native-migration-attestation/v1'),epoch,digest);
 return {databaseIdentity:identity,fenceEpoch:epoch,sourceCommit:SOURCE,operationState:state};
}
module.exports={CORE,DATABASE_ORDER,SQL_SOURCES,operationalSql,sessionOptions,orderedOperations,parseSqlOutput,validateProof,observeCatalog,CATALOG_SQL_SHA,PG_BASE_SHA,SOURCE,MIGRATIONS,migrationDigest,catalog,sqlOutput,verifiedSql,fenceReceipt,ownerReceipt,attestation};
