 'use strict';
// Closed latest-main profile production from actual maintenance/build transports.
// No Docker mutation, SQL, state migration, reverse DDL or automatic retry here.
const assert=require('node:assert/strict'),crypto=require('node:crypto'),util=require('node:util');
const runtime=require('./functional-debug-runtime');
const shared=require('./passport-maintenance-runtime');
const metadata=require('./native-maintenance-metadata');
const {LATEST_PROFILE:PROFILE,LATEST_SOURCE:SOURCE,LATEST_ROLES:ROLES,LATEST_BUILD:BUILD,BASE,BEFORE,CORE}=shared;
const ENGINE='3dbbbe66-1c98-4e0c-b0a6-f927c05e7341';
const FREEZE='075a9bafaf27bd31acfe8372c3172e04cf584120882018ff327e71044b69a5c1';
const ALL29=Object.freeze(["marty-applicant", "marty-auth", "marty-canvas-sandbox", "marty-canvas-sync-worker", "marty-compliance-profile", "marty-credential-template", "marty-deployment-profile", "marty-device-registration", "marty-event-stream", "marty-flow", "marty-gateway", "marty-issuance-service", "marty-keyless-grpc-bridge", "marty-notification", "marty-oidf-keyless-edge", "marty-organization", "marty-passport-acceptance-api-key", "marty-passport-beta-bureau", "marty-passport-callback-signer", "marty-passport-callback-signer-supported", "marty-passport-keyless-edge", "marty-passport-provider-ingress", "marty-passport-tls-bootstrap", "marty-presentation-policy", "marty-revocation-profile", "marty-signing-keys", "marty-trust-profile", "marty-verification-service", "marty-verifier-positive-gate"]);
const SOURCE_PINS=Object.freeze({"rust/services/flow/migrations/0001_flow_schema.sql": "5fb16eb5abbac9783dd694f8092fa88f25ba4cff968beb87270e15f8acdbccac", "rust/services/flow/migrations/0002_builtin_flows.sql": "7ea33d3acc142f5ea6650b0e6532702e05476856be15a2502389bd9f755eb95b", "rust/services/flow/migrations/0003_physical_start_intents.sql": "fd86a211a4b799b53827456ac1d5b8887ae3264c26ae889fb7714a1fa62e4edd", "rust/services/issuance/migrations/0009_authenticated_mdoc_status_binding.sql": "b770d6ff59f8dd1e9e95c359d6c4227f3461792822bfae27c07ed6bc151cc719", "rust/services/issuance/migrations/0010_passport_start_idempotency.sql": "05b3aafe03b9aa258c8061db2d9ac1adb35f17f0d513b9995d48ee2ef2305801", "rust/services/issuance/migrations/0011_passport_administrative_cancellation.sql": "9842f5ea39aab254d41cf7bc936411b813b853352a1e2de668594926dd08f682", "rust/services/flow/src/schema_command.rs": "69803c102fb86f9b3002b773c8d166096ff1133859482441a5c1ccfc6ff02504", "rust/services/flow/src/migration.rs": "3f4aafe9ce1c316df51452b556b9fd8a7771f608f1287674b873d995ef176207", "rust/services/issuance/src/migration.rs": "41e32a782380876fca7b71cbdcb2e2e7f273d8705ed5c5625d65e57abf2f779c", "rust/services/flow/src/main.rs": "d232b858cf1dbf9702ff247f9cd2f93185adb0cbb43cb46bed7d845ee3430839", "rust/services/issuance/src/main.rs": "11c9453c1395367478f333bb8a64c056ad9c4bc9d0ef85e2f98c5d222c6ac2b0", "scripts/beta-state-volume-plan.ps1": "a7780de6e578c56cdbd90d580f19236392c270d65fc2c58ce2d191699557b0cf"});
const HASH=/^[a-f0-9]{64}$/;
const digest=b=>crypto.createHash('sha256').update(b).digest('hex');
const same=(a,b,code)=>assert(util.isDeepStrictEqual(a,b),code);
const exactKeys=(value,keys,code)=>same(Object.keys(value).sort(),[...keys].sort(),code);
function functional(value){assert.equal(value.scope,'FUNCTIONAL_ONLY');for(const k of ['releaseQualified','recordingQualified'])assert.equal(value[k],false);}
function latestSelection(selection){
 assert.equal(selection.profile,PROFILE);assert.equal(selection.state,'SELECTED_NOT_DEPLOYED');
 assert.equal(selection.sourceRevision,SOURCE);assert.equal(selection.coreRevision,CORE);functional(selection);
 same(selection.roleBinaries,ROLES,'CLOSED_FOUR_ROLE_MAP');exactKeys(selection.binaries,Object.keys(ROLES),'CLOSED_FOUR_ELFS');
 const prepared=runtime.boundJson(selection.preparedSource),receipt=runtime.boundJson(selection.canonicalBuildReceipt);
 assert.equal(prepared.buildProfile,BUILD);assert.equal(prepared.uiRevision,SOURCE);assert.equal(prepared.coreRevision,CORE);
 assert.equal(prepared.sourceFreezeReceipt.sha256,FREEZE);const freeze=runtime.boundJson(prepared.sourceFreezeReceipt);
 assert.equal(freeze.productRevision,SOURCE);assert.equal(freeze.coreRevision,CORE);assert.equal(freeze.imagesBuilt,false);assert.equal(freeze.releaseQualified,false);
 assert.equal(receipt.buildProfile,BUILD);assert.equal(receipt.source,SOURCE);assert.equal(receipt.uiRevision,SOURCE);assert.equal(receipt.coreRevision,CORE);
 assert.equal(receipt.state,'PASSED');assert.equal(receipt.exitCode,0);assert.equal(receipt.oomKilled,false);assert.equal(receipt.canonicalAllServices,true);
 for(const k of ['imagesBuilt','releaseQualified','recordingQualified'])assert.equal(receipt[k],false);
 assert.equal(receipt.preparationSha256,selection.preparedSource.sha256);assert.equal(receipt.runId,prepared.runId);
 same(receipt.roleBinaries,prepared.roleBinaries,'ALL29_PREPARATION_MAP');exactKeys(receipt.binaries,ALL29,'ALL29_TERMINAL_REQUIRED');
 same(prepared.roleBinaries,Object.fromEntries(ALL29.map(k=>[k,k])),'EXACT_ALL29_ROLE_MAP');
 for(const [role,binary]of Object.entries(ROLES))same(selection.binaries[role],receipt.binaries[binary],'SELECTED_BUILD_ELF');
 for(const key of ['originalCargoLock','localizedCargoLock','localizedLockProof','lockedLocalizedMetadata','coreFeatureResolution','productionFeatureTree','canonicalCompilerLog','coreCompilerArtifacts'])runtime.boundBytes(receipt[key]);
 return {prepared,receipt};
}
function compatibility(selection,refs,before){
 const p=runtime.boundJson(refs.plan),r=runtime.boundJson(refs.result);
 assert.equal(p.beforeBinding.sha256,BEFORE);same(runtime.boundJson(p.beforeBinding).roles,before,'COMPATIBILITY_CURRENT_PREIMAGE');
 assert.equal(p.scope,'ELF_LOADER_UID_COMPATIBILITY_ONLY');assert.equal(p.buildReceiptAuthoritativeSha256,selection.canonicalBuildReceipt.sha256);
 assert.equal(r.schema,1);assert.equal(r.state,'ELF_LOADER_UID_COMPATIBILITY_PASS');assert.equal(r.planSha256,refs.plan.sha256);
 for(const k of ['candidateServiceEntrypointExecuted','signingOrApi','runtimeDeployed'])assert.equal(r[k],false);
 assert.equal(r.rows.length,4);assert.equal(new Set(r.rows.map(x=>x.binary)).size,4);assert.equal(new Set(r.rows.map(x=>x.containerId)).size,4);
 same(r.rows.map(x=>x.binary).sort(),Object.values(ROLES).sort(),'COMPATIBILITY_EXACT4');
 for(const [role,binary]of Object.entries(ROLES)){
  const row=r.rows.find(x=>x.binary===binary);assert(HASH.test(row.containerId));assert.equal(row.sha256,selection.binaries[role].sha256);
  assert.equal(row.imageId,before.find(x=>x.role===role).imageId);assert.equal(row.uid,10001);assert.equal(row.gid,10001);assert.equal(row.exitCode,0);
  for(const k of ['candidateReadableExecutable','loaderListSucceeded','ownedContainerRemoved'])assert.equal(row[k],true);
 }
}
function sourceProof(refs){
 exactKeys(refs,Object.keys(SOURCE_PINS),'EXACT_SCHEMA_AND_STATE_SOURCES');
 for(const [name,sha]of Object.entries(SOURCE_PINS)){assert.equal(refs[name].sha256,sha);runtime.boundBytes(refs[name]);}
}
function stateTransition(record,before){
 const old=before.find(x=>x.role==='applicant');assert(old);
 assert.equal(record.oldContainerId,old.containerId);assert.equal(record.volumeName,'elevenid-beta-fresh-20261018_applicant_data');
 assert.equal(record.destination,'/app/data');same(record.entries,['applicant_store.json'],'APPLICANT_SINGLE_ORDINARY_FILE');
 const a=record.before,b=record.afterMigration;
 for(const x of [a,b]){assert.equal(x.directory.type,'directory');assert.equal(x.file.type,'regular file');assert.equal(x.directory.symlink,false);assert.equal(x.file.symlink,false);}
 same([a.directory.uid,a.directory.gid,a.directory.mode],[10001,10001,'0700'],'APPLICANT_PRIOR_DIRECTORY');
 same([a.file.uid,a.file.gid,a.file.mode],[0,0,'0644'],'APPLICANT_PRIOR_FILE');
 same([b.directory.uid,b.directory.gid,b.directory.mode],[10001,10001,'0700'],'APPLICANT_NEW_DIRECTORY');
 same([b.file.uid,b.file.gid,b.file.mode],[10001,10001,'0660'],'APPLICANT_NEW_FILE');
 assert(HASH.test(record.backup.sha256));runtime.verifyBoundFile(record.backup);
 // Never include private store bytes or DUMP values in assertion output.
 assert(a.file.sha256===record.backup.sha256&&b.file.sha256===record.backup.sha256,'APPLICANT_BACKUP_BYTES_CHANGED');
 assert(HASH.test(record.helperContainerId));return record.helperContainerId;
}
function quiescence(record,before){
 const rows=record.stopped;assert.equal(rows.length,22);assert.equal(new Set(rows.map(x=>x.role)).size,22);exactKeys(record.outcomes,before.map(x=>x.role),'ALL22_STOP_OUTCOMES');
 for(const old of before){
  const row=rows.find(x=>x.role===old.role),step=record.outcomes[old.role];assert(row);
  for(const k of ['containerId','imageId','sha256','binaryMounts','startedAt'])same(row[k],old[k],'STOP_IDENTITY_CHANGED');
  assert.equal(row.running,false);assert.equal(row.paused,false);assert.equal(row.hostPid,0);assert.equal(row.containerExitCode,0);assert.equal(row.oomKilled,false);assert.equal(row.state,'exited');
  assert.equal(step.terminal,true);assert.equal(step.stopAcknowledged,true);assert.equal(step.exitCode,0);
 }
}
function commandRows(rows,selection,before){
 assert.equal(rows.length,4);const expected=new Set(['flow:migrate','flow:verify-owned-schema','issuance-native:migrate','issuance-native:verify-owned-schema']);const helpers=[];
 for(const row of rows){
  const key=row.role+':'+row.command;assert(expected.delete(key),'EXACT_SCHEMA_COMMAND_SET');
  const binary=ROLES[row.role];assert(binary);same(row.argv,['/usr/local/bin/'+binary,row.command],'EXACT_SCHEMA_COMMAND_ARGV');
  assert.equal(row.sourceRevision,SOURCE);assert.equal(row.coreRevision,CORE);
  const role=row.command==='migrate'?'postgres':'marty';assert.equal(row.databaseRole,role);assert.equal(row.databaseLoginRole,'postgres');
  const url=new URL(runtime.boundBytes(row.databaseUrl).toString('utf8'));
  // Generic assertions avoid disclosing any private URL/credential value.
  assert(['postgres:','postgresql:'].includes(url.protocol)&&url.username==='postgres'&&url.hostname==='postgres'&&['','5432'].includes(url.port)&&url.pathname==='/marty'&&!url.hash,'EXACT_PRIVATE_SCHEMA_DATABASE_URL_REQUIRED');
  same([...url.searchParams.entries()],[['options[role]',role]],'EXACT_SQLX_DATABASE_ROLE_OPTIONS_REQUIRED');

  assert.equal(row.imageId,before.find(x=>x.role===row.role).imageId);runtime.boundBytes(row.stdout);runtime.boundBytes(row.stderr);
  assert.equal(row.elfSha256,selection.binaries[row.role].sha256);assert(HASH.test(row.containerId));assert(!before.some(x=>x.containerId===row.containerId));
  assert.equal(row.state,'exited');assert.equal(row.exitCode,0);assert.equal(row.oomKilled,false);helpers.push(row.containerId);
 }
 assert.equal(expected.size,0);assert.equal(new Set(helpers).size,4,'FOUR_UNIQUE_SCHEMA_HELPERS_REQUIRED');return helpers;
}
function outcomeDocuments(outcome,selection,before){
 assert.equal(outcome.schema,'marty.native-four-role-maintenance-outcome/v1');assert.equal(outcome.state,'MAINTENANCE_COMPLETED_FUNCTIONAL_ONLY');functional(outcome);
 assert.match(outcome.runId,/^[a-f0-9-]{36}$/);
 assert.equal(outcome.engineId,ENGINE);assert.equal(outcome.sourceRevision,SOURCE);assert.equal(outcome.coreRevision,CORE);
 assert.equal(outcome.baseProfileSha256,BASE);assert.equal(outcome.beforeBindingSha256,BEFORE);
 assert.equal(outcome.selectionSha256,selection._referenceSha256);assert.equal(outcome.noAutomaticRollback,true);
 const intent=runtime.boundJson(outcome.intent);
 assert.equal(intent.runId,outcome.runId);assert.equal(intent.selectionSha256,outcome.selectionSha256);
 assert.equal(intent.baseProfileSha256,BASE);assert.equal(intent.beforeBindingSha256,BEFORE);
 const durable=outcome.intentDurability;
 assert.equal(durable.fileFsync,true);assert.equal(durable.parentDirectory.supported,true);assert.equal(durable.parentDirectory.synced,true);
 sourceProof(outcome.sourceRefs);
 const stopped=runtime.boundJson(outcome.quiescence);quiescence(stopped,before);
 const commands=runtime.boundJson(outcome.schemaCommands);
 for(const row of commands){assert.equal(row.runId,outcome.runId);assert.equal(row.selectionSha256,outcome.selectionSha256);}
 const helpers=commandRows(commands,selection,before);
 same(outcome.executorSource,intent.executorSource,'INTENT_EXECUTOR_CHANGED');runtime.boundBytes(outcome.executorSource);
 const proof=runtime.boundJson(outcome.metadataProof);
 same(proof.databaseBackup,outcome.databaseBackup,'BACKUP_PROOF_REF_CHANGED');
 const verified=metadata.validateProof(proof,commands,{runId:outcome.runId,selectionSha256:outcome.selectionSha256,executorSource:outcome.executorSource});
 const backup=runtime.boundJson(outcome.databaseBackup);runtime.verifyBoundFile(backup.backupFile);
 same(verified.databaseIdentity,backup.databaseIdentity,'DATABASE_BACKUP_IDENTITY');assert.equal(backup.runId,outcome.runId);
 assert.equal(backup.phase,'QUIESCED_FENCED_DATABASE_BACKUP');assert.equal(backup.quiescenceSha256,outcome.quiescence.sha256);
 assert.equal(backup.catalogSha256,proof.beforeCatalog.sha256);
 const state=runtime.boundJson(outcome.applicantState);assert.equal(state.runId,outcome.runId);assert.equal(state.quiescenceSha256,outcome.quiescence.sha256);
 helpers.push(stateTransition(state,before));
 const cleanup=runtime.boundJson(outcome.helperCleanup);assert.equal(cleanup.engineId,ENGINE);assert(Array.isArray(cleanup.containerIds));assert.equal(new Set(cleanup.containerIds).size,cleanup.containerIds.length);
 for(const cid of helpers)assert(!cleanup.containerIds.includes(cid),'OWNED_SCHEMA_OR_STATE_HELPER_STILL_REGISTERED');
 return {helpers,operationState:verified.operationState,operationStateRef:proof.operationState};
}
function loaded(profile){
 assert.equal(profile.schema,'marty.functional-mixed-runtime/v2');functional(profile);assert(!profile.nativeOverlay&&!profile.maintenanceRestart);
 assert.equal(profile.baseProfile.sha256,BASE);
 exactKeys(profile,['schema','scope','releaseQualified','recordingQualified','baseProfile','nativeMaintenance'],'EXACT_LATEST_PROFILE_SHAPE');
 const x=profile.nativeMaintenance;assert(x);exactKeys(x,['beforeBinding','selection','compatibility','outcome','readback'],'EXACT_LATEST_PROFILE_BINDING');assert.equal(x.beforeBinding.sha256,BEFORE);
 const base=runtime.boundJson(profile.baseProfile),before=runtime.boundJson(x.beforeBinding),selection=runtime.boundJson(x.selection);
 latestSelection(selection);compatibility(selection,x.compatibility,before.roles);
 const outcome=runtime.boundJson(x.outcome),readback=runtime.boundJson(x.readback);
 assert.equal(outcome.selectionSha256,x.selection.sha256);assert.equal(outcome.readbackSha256,x.readback.sha256);
 outcomeDocuments(outcome,{...selection,_referenceSha256:x.selection.sha256},before.roles);
 assert.equal(readback.schema,'marty.native-four-role-maintenance-readback/v1');assert.equal(readback.scope,'NATIVE_MAINTENANCE_READBACK_ONLY');assert.equal(readback.engineId,ENGINE);
 assert.equal(readback.releaseQualified,false);assert.equal(readback.recordingQualified,false);functional(readback.binding);assert.equal(readback.binding.schema,'marty.functional-mixed-runtime-binding/v2');assert.equal(readback.binding.mixedSourceStack,true);
 assert.equal(readback.baseProfileSha256,BASE);assert.equal(readback.beforeBindingSha256,BEFORE);assert.equal(readback.selectionSha256,x.selection.sha256);
 assert.equal(readback.profileProduced,false);assert.equal(readback.applyAuthority,false);assert.equal(readback.migrationOutcomeQualified,false);
 const expected=runtime.expectedRuntime(base).map(row=>{const old=before.roles.find(x=>x.role===row.role);assert(old);return {...row,requiredObservation:Object.fromEntries(['containerId','imageId','health','executablePath','processExecutableSha256','binaryMounts','startedAt','hostPid','effectiveUid','configuredRuntimeUid'].map(k=>[k,old[k]]))};});
 const rows=shared.validateGenerations(expected,before.roles,selection,readback.observedRoles);same(rows,readback.binding.roles,'ACTUAL22_READBACK_ROWS_CHANGED');
 return {rows,outcome,selection,readback,before};
}
function expectedLatestRuntime(profile){return loaded(profile).rows;}
function produceLatestProfile(inputs,{readDocker,readJournal,readMaintenanceJournal}={}){
 assert.equal(typeof readDocker,'function','ACTUAL_DOCKER_READER_REQUIRED');assert.equal(typeof readJournal,'function','ORIGINAL_BUILD_JOURNAL_REQUIRED');assert.equal(typeof readMaintenanceJournal,'function','ORIGINAL_MAINTENANCE_JOURNAL_REQUIRED');
 const profile={schema:'marty.functional-mixed-runtime/v2',scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false,
  baseProfile:inputs.baseProfile,nativeMaintenance:{beforeBinding:inputs.beforeBinding,selection:inputs.selection,compatibility:inputs.compatibility,outcome:inputs.outcome,readback:inputs.readback}};
 const {outcome,readback}=loaded(profile);const journal=inputs.maintenanceJournal;
 assert.equal(outcome.runId,journal.runId);const actual=readMaintenanceJournal(journal,'build-receipt.json');
 assert.equal(actual.ok,true);assert.equal(actual.name,'build-receipt.json');same(actual.rootProof,journal.specification.rootProof,'MAINTENANCE_JOURNAL_ROOT');assert.equal(actual.sha256,inputs.outcome.sha256);same(actual.value,outcome,'ACTUAL_MAINTENANCE_OUTCOME_REQUIRED');
 const intent=readMaintenanceJournal(journal,'build-apply-intent.json');
 assert.equal(intent.ok,true);assert.equal(intent.name,'build-apply-intent.json');same(intent.rootProof,journal.specification.rootProof,'MAINTENANCE_INTENT_ROOT');
 assert.equal(intent.sha256,outcome.intent.sha256);same(intent.value,runtime.boundJson(outcome.intent),'ACTUAL_DURABLE_INTENT_REQUIRED');
 const proof=runtime.boundJson(outcome.metadataProof),stateReply=readMaintenanceJournal(journal,'build-state.json');
 assert.equal(stateReply.ok,true);assert.equal(stateReply.name,'build-state.json');same(stateReply.rootProof,journal.specification.rootProof,'MAINTENANCE_OPERATION_ROOT');
 assert.equal(stateReply.sha256,proof.operationState.sha256);same(stateReply.value,runtime.boundJson(proof.operationState),'ACTUAL_OPERATION_JOURNAL_REQUIRED');

 const observed=shared.observeMaintenanceReadback(inputs,{readDocker,readJournal});same(observed,readback,'FRESH_ACTUAL22_MAINTENANCE_READBACK_REQUIRED');
 const ids=readDocker(['ps','-aq','--no-trunc']).trim().split(/\s+/).filter(Boolean);
 const before=runtime.boundJson(inputs.beforeBinding);const selection={...runtime.boundJson(inputs.selection),_referenceSha256:inputs.selection.sha256};
 const {helpers}=outcomeDocuments(outcome,selection,before.roles);for(const cid of helpers)assert(!ids.includes(cid),'OWNED_HELPER_CLEANUP_NOT_ACTUAL');
 same(readMaintenanceJournal(journal,'build-receipt.json'),actual,'MAINTENANCE_JOURNAL_CHANGED');
 same(readMaintenanceJournal(journal,'build-state.json'),stateReply,'MAINTENANCE_OPERATION_JOURNAL_CHANGED');
 return profile;
}
module.exports={PROFILE,SOURCE,CORE,ROLES,BUILD,ALL29,FREEZE,SOURCE_PINS,latestSelection,compatibility,stateTransition,quiescence,commandRows,outcomeDocuments,expectedLatestRuntime,produceLatestProfile};
