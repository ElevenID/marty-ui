'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto');
const {verifyFunctionalRuntime,expectedRuntime,DEBUG_ROLES,RETAINED_ROLES}=require('./functional-debug-runtime');
const H=char=>char.repeat(64),R=char=>char.repeat(40),image='sha256:'+H('1');
function fixture(t){
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'functional-runtime-'));t.after(()=>fs.rmSync(dir,{recursive:true}));
 const roles=['auth','organization','credential-template','trust-profile','applicant','notification','compliance-profile','presentation-policy','deployment-profile','signing-keys','flow','verification','revocation-profile','device-registration','event-stream','issuance','issuance-native','canvas-sync-worker','gateway','passport-callback-signer','passport-beta-bureau','ui-prod'];
 const binary=role=>({issuance:'marty-issuance-service','issuance-native':'marty-issuance-service',verification:'marty-verification-service'})[role]||'marty-'+role;
 const outputs=[...new Set(roles.filter(role=>role!=='ui-prod').map(binary))].map(name=>({name,sha256:H('2')}));
 while(outputs.length<32)outputs.push({name:'marty-extra-'+outputs.length,sha256:H('2')});
 const baseline={source_kind:'local-worktree-snapshot',promotion_eligible:false,component_revisions:{'marty-ui':R('a')},images:roles.map(service=>({service,image_id:image}))};
 const build={state:'BUILD_SUCCEEDED',exitCode:0,sourceRevision:R('a'),actualBinaryOutputs:outputs};
 const debugHashes=Object.fromEntries([...new Set(Object.values(DEBUG_ROLES))].map(name=>[name,H('3')]));
 const write=(name,value,utf16=false)=>{const file=path.join(dir,name);fs.writeFileSync(file,utf16?Buffer.concat([Buffer.from([255,254]),Buffer.from(JSON.stringify(value),'utf16le')]):JSON.stringify(value));return {path:file,sha256:crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')};};
 const debugBuild=write('debug.json',{state:'BUILD_PASS_NOT_DEPLOYED',release_qualified:false,profile:'dev',source_clean_before_after:true,features:'default package features; KMS-only pinned dependencies; no test/feature overrides',builder_image_digest:'sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1',source_revision:R('b'),binary_sha256:debugHashes});
 const debugDeployment=write('deployment.json',{scope:'BETA_R32_D03_D05_DEBUG_BINARY_FUNCTIONAL_ONLY',state:'BETA_DEBUG_BINARIES_ACTIVE_FUNCTIONAL_ONLY',releaseQualified:false,productionTouched:false,imageBuilt:false,sourceRevision:R('b'),buildReceiptSha256:debugBuild.sha256,binarySha256:debugHashes,live:{ids:Object.fromEntries(Object.keys(DEBUG_ROLES).map((role,index)=>[role,H((index+4).toString(16))]))}},true);
 const retainedBuilds=Object.fromEntries(Object.entries(RETAINED_ROLES).map(([role,name])=>[role,write(role+'.json',{state:'PASSED',exitCode:0,binary:'/retained/'+name,source:R(role==='flow'?'c':'d'),binarySha256:H(role==='flow'?'a':'b')})]));
 const profile={schema:'marty.functional-mixed-runtime/v1',scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false,baselineDeployment:write('base.json',baseline),baselineBuild:write('build.json',build),debugDeployment,debugBuild,retainedBuilds};
 const observe=row=>({role:row.role,project:row.project,service:row.role,imageId:row.imageId,containerId:row.requiredContainerId||H('f'),running:true,status:'running',health:row.role==='canvas-sync-worker'?null:'healthy',binarySha256:row.sha256,executablePath:row.binary?'/usr/local/bin/'+row.binary:null,processExecutableSha256:row.sha256,binaryMounts:row.kind==='DEBUG_PRODUCTION_BINARY'||row.kind==='RETAINED_SOURCE_BOUND_BINARY'?[{type:'bind',source:'/source/'+row.binary,destination:'/usr/local/bin/'+row.binary,writable:false}]:[],hostPid:123,startedAt:'2026-10-26T00:00:00Z'});
 return {profile,observe,write};
}
test('eight executable overrides remain separate from baseline and cannot qualify release',t=>{const {profile,observe}=fixture(t);const result=verifyFunctionalRuntime(profile,{observe});assert.equal(result.roles.length,22);assert.equal(result.roles.filter(row=>row.kind==='DEBUG_PRODUCTION_BINARY').length,6);assert.equal(result.roles.filter(row=>row.kind==='RETAINED_SOURCE_BOUND_BINARY').length,2);assert.equal(result.releaseQualified,false);assert.equal(result.recordingQualified,false);assert.equal(result.roles.find(row=>row.role==='flow').source,R('c'));});
for(const mode of ['RELEASE','RECORDING'])test('reject '+mode+' before observing beta',t=>{const {profile}=fixture(t);assert.throws(()=>verifyFunctionalRuntime(profile,{qualification:mode,observe:()=>assert.fail('Must not observe')}),/cannot qualify/)});
for(const change of ['process','mounted','pidPath','health','tenant','container','image','writableMount'])test('reject actual runtime mismatch '+change,t=>{const {profile,observe}=fixture(t);assert.throws(()=>verifyFunctionalRuntime(profile,{observe:row=>{const actual=observe(row);if(row.role==='gateway'){
 if(change==='process')actual.processExecutableSha256=H('0');if(change==='mounted')actual.binarySha256=H('0');if(change==='pidPath')actual.executablePath='/usr/local/bin/marty-gateway (deleted)';if(change==='health')actual.health='unhealthy';if(change==='tenant')actual.project='elevenid-selfhost';if(change==='container')actual.containerId=H('0');if(change==='image')actual.imageId='sha256:'+H('0');if(change==='writableMount')actual.binaryMounts[0].writable=true;}return actual;}}));});
test('changed receipt rejects before runtime observation',t=>{const {profile}=fixture(t);fs.appendFileSync(profile.debugBuild.path,' ');assert.throws(()=>verifyFunctionalRuntime(profile,{observe:()=>assert.fail('No observation')}),/changed/);});
test('missing retained source cannot be silently labeled R32',t=>{const {profile}=fixture(t);delete profile.retainedBuilds.flow;assert.throws(()=>expectedRuntime(profile));});

test('failed observation identifies its role without leaking command errors or producing a binding',t=>{
 const {profile,observe}=fixture(t);const visited=[];
 assert.throws(()=>verifyFunctionalRuntime(profile,{observe:row=>{
  visited.push(row.role);if(row.role==='gateway')throw Error('private-command-error');return observe(row);
 }}),error=>error.code==='FUNCTIONAL_RUNTIME_OBSERVATION_FAILED'&&error.role==='gateway'
  &&error.message.includes('gateway')&&!error.message.includes('private-command-error'));
 assert.equal(visited.at(-1),'gateway');
});

test('prior in-place canonical overlay is explicit rather than relabeled R32',t=>{
 const {profile,observe,write}=fixture(t),roles=expectedRuntime(profile).filter(row=>row.binary);
 const files=[...new Set(roles.map(row=>row.binary))].map(binary_name=>({binary_name,sha256:H('5')}));
 profile.priorNativeBuild=write('prior-build.json',{state:'PASSED',source:R('e'),exitCode:0});
 profile.priorNativeArtifacts=write('prior-artifacts.json',{state:'PASSED',source:R('e'),releaseQualified:false,linuxReadbackMatched:true,files});
 profile.priorNativeOverlay=write('prior-overlay.json',{state:'APPLIED_LOCAL_ONLY',productionReleaseQualified:false,imagesBuiltForCandidate:false,imageSourceMarkerRemainsBaseline:true,sourceRevision:R('e'),buildReceiptSha256:profile.priorNativeBuild.sha256,buildArtifactsSha256:profile.priorNativeArtifacts.sha256,
  rows:roles.map(row=>({service:row.role,binary:row.binary,imageId:row.imageId,candidateSha256:H('5'),observedAfterSha256:H('5')}))});
 const result=verifyFunctionalRuntime(profile,{observe});const auth=result.roles.find(row=>row.role==='auth');
 assert.equal(auth.kind,'PRIOR_CANONICAL_NATIVE_OVERLAY');assert.equal(auth.source,R('e'));assert.equal(auth.sha256,H('5'));
 assert.equal(result.roles.find(row=>row.role==='gateway').source,R('b'));assert.equal(result.roles.find(row=>row.role==='flow').source,R('c'));
});


function issuanceFixture(t){
 const f=fixture(t),{ISSUANCE_SOURCE,ISSUANCE_CORE}=require('./functional-debug-runtime');
 const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
 const baseObserve=row=>({...f.observe(row),containerId:row.requiredContainerId||sha('base:'+row.role),effectiveUid:0,configuredRuntimeUid:0});
 const base=f.write('immutable-v1.json',f.profile),before=verifyFunctionalRuntime(f.profile,{observe:baseObserve});
 const build={scope:'ISSUANCE_ONLY_NATIVE_FUNCTIONAL_OVERLAY',state:'BUILD_SUCCEEDED',exitCode:0,profile:'dev',
  sourceRevision:ISSUANCE_SOURCE,coreRevision:ISSUANCE_CORE,sourceCleanBeforeAfter:true,releaseQualified:false,recordingQualified:false,imageBuilt:false,
  cargoCommand:'cargo build --locked --offline --message-format=json -p marty-issuance-service --bin marty-issuance-service',
  features:'issuance-package default features; KMS-only sources; no test/feature overrides; functional-only noncanonical selection',
  cargoIncremental:0,cargoProfileDevDebug:0,rustToolchain:'1.95.0',builderPlatform:'linux/amd64',binary:{name:'marty-issuance-service',sha256:H('9')}};
 build.sourcePreparation=f.write('prepared-source.json',{uiRevision:ISSUANCE_SOURCE,coreRevision:ISSUANCE_CORE,
  uiTree:'3c11b3cee95d533a650ac1f31504ccf320ec2494',coreTree:'6ac871ff0b6862e2f5f19374b853f6f7c52049bb',
  sourceInventories:Object.fromEntries(['ui-source','core-source'].map(key=>[key,{files:100,bytes:1000,inventorySha256:key==='ui-source'?'33a2fe61469e27e455222042f4ce2a11f9475328052438c05433ec521b8fcc96':'ffeeacc05f3f409fff877fd75ecf8d33d251794b0245e22cb09f8b0d4407d06f'}])),
  recipeSha256:'2beef9b635f8fefeb36470722b0b87089810b0666ecbf37b0d60a6dcf4236fd1',localizerSha256:'b1dd31880f82f91d2f9151d05cb01c29ca702ce057595ff18c2708378d2167f5',builderImage:'sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1'});
 build.coreCompilerArtifacts=f.write('core-artifacts.json',['marty-crypto','marty-didcomm','marty-oid4vci','marty-verification'].map(name=>({name,manifest:'/build/core/'+name+'/Cargo.toml',features:['kms-only'],fresh:false,filenames:['/target/debug/deps/lib'+name+'.rlib']})));
 const buildReceipt=f.write('issuer-build.json',build),roles=Object.fromEntries(['issuance','issuance-native'].map((role,index)=>[role,{
  containerId:sha('new:'+role),imageId:image,startedAt:'2026-10-26T01:00:00Z',hostPid:200+index,configuredRuntimeUid:0,effectiveUid:0,
  binaryMount:{type:'bind',source:path.join(path.dirname(base.path),'owned-issuer'),destination:'/usr/local/bin/marty-issuance-service',writable:false},
  processExecutablePath:'/usr/local/bin/marty-issuance-service',processExecutableSha256:H('9'),mountedBinarySha256:H('9')}]));
 const deployed={scope:'ISSUANCE_ONLY_NATIVE_FUNCTIONAL_OVERLAY',state:'APPLIED_FUNCTIONAL_ONLY',baseProfileSha256:base.sha256,
  buildReceiptSha256:buildReceipt.sha256,sourceRevision:ISSUANCE_SOURCE,coreRevision:ISSUANCE_CORE,binarySha256:H('9'),productionTouched:false,
  imagesBuilt:false,releaseQualified:false,recordingQualified:false,roles,beforeRuntimeBinding:f.write('before-actual.json',{baseProfileSha256:base.sha256,binding:before})};
 const profile={schema:'marty.functional-mixed-runtime/v2',scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false,baseProfile:base,
  issuanceOverlay:{buildReceipt,deploymentReceipt:f.write('issuer-applied.json',deployed)}};
 const observe=row=>{
  const actual=baseObserve(row),selected=deployed.roles[row.role];
  if(row.kind==='ISSUANCE_CORE_FUNCTIONAL_OVERLAY')Object.assign(actual,{containerId:selected.containerId,startedAt:selected.startedAt,hostPid:selected.hostPid,
   binarySha256:H('9'),processExecutableSha256:H('9'),binaryMounts:[selected.binaryMount]});
  return actual;
 };
 const change=(kind,fn)=>{const value=kind==='build'?build:deployed;fn(value);const ref=f.write(kind+'-changed.json',value);
  if(kind==='build'){profile.issuanceOverlay.buildReceipt=ref;deployed.buildReceiptSha256=ref.sha256;profile.issuanceOverlay.deploymentReceipt=f.write('issuer-applied.json',deployed);}
  else profile.issuanceOverlay.deploymentReceipt=ref;};
 return {...f,profile,observe,baseObserve,build,deployed,before,change};
}

test('v2 changes only two issuer sources and pins full other20 actual observations',t=>{
 const f=issuanceFixture(t),bytes=fs.readFileSync(f.profile.baseProfile.path),result=verifyFunctionalRuntime(f.profile,{observe:f.observe});
 assert.equal(result.schema,'marty.functional-mixed-runtime-binding/v2');assert.equal(result.roles.length,22);
 assert.equal(result.roles.filter(row=>row.kind==='ISSUANCE_CORE_FUNCTIONAL_OVERLAY').length,2);
 for(const row of result.roles.filter(row=>!['issuance','issuance-native'].includes(row.role))){
  const old=f.before.roles.find(value=>value.role===row.role);
  for(const field of ['containerId','hostPid','startedAt','source','sha256','imageId','binaryMounts','effectiveUid','configuredRuntimeUid'])assert.deepEqual(row[field],old[field]);
 }
 assert.deepEqual(fs.readFileSync(f.profile.baseProfile.path),bytes);assert.equal(result.releaseQualified,false);assert.equal(result.recordingQualified,false);
});
for(const mutation of ['source','core','features','qualification','extraRole','oldId','mounted','writable','uid','missingBefore','wrongBase'])test('v2 rejects invalid overlay receipt '+mutation,t=>{
 const f=issuanceFixture(t);
 if(['source','core','features','qualification'].includes(mutation))f.change('build',build=>{
  if(mutation==='source')build.sourceRevision=R('0');if(mutation==='core')build.coreRevision=R('0');
  if(mutation==='features')build.features='extra features';if(mutation==='qualification')build.releaseQualified=true;
 });
 else f.change('deploy',row=>{
  if(mutation==='extraRole')row.roles.gateway={...row.roles.issuance};
  if(mutation==='oldId')row.roles.issuance.containerId=f.before.roles.find(old=>old.role==='issuance').containerId;
  if(mutation==='mounted')row.roles.issuance.mountedBinarySha256=H('0');if(mutation==='writable')row.roles.issuance.binaryMount.writable=true;
  if(mutation==='uid')row.roles.issuance.effectiveUid=1000;if(mutation==='missingBefore')delete row.beforeRuntimeBinding;
  if(mutation==='wrongBase')row.baseProfileSha256=H('0');
 });
 assert.throws(()=>verifyFunctionalRuntime(f.profile,{observe:()=>assert.fail('Reject before runtime observation')}));
});
for(const field of ['containerId','startedAt','hostPid','binaryMounts','effectiveUid','imageId'])test('v2 rejects changed non-issuer actual '+field,t=>{
 const f=issuanceFixture(t);assert.throws(()=>verifyFunctionalRuntime(f.profile,{observe:row=>{const actual=f.observe(row);if(row.role==='auth'){
  actual[field]=({containerId:H('0'),startedAt:'2026-10-26T02:00:00Z',hostPid:999,binaryMounts:[{type:'bind',source:'/different',destination:'/different',writable:false}],effectiveUid:1234,imageId:'sha256:'+H('0')})[field];
 }return actual;}}));
});
for(const field of ['containerId','processExecutableSha256','binaryMounts','configuredRuntimeUid'])test('v2 rejects changed issuer actual '+field,t=>{
 const f=issuanceFixture(t);assert.throws(()=>verifyFunctionalRuntime(f.profile,{observe:row=>{const actual=f.observe(row);if(row.role==='issuance'){
  actual[field]=({containerId:H('0'),processExecutableSha256:H('0'),binaryMounts:[],configuredRuntimeUid:1000})[field];
 }return actual;}}));
});

for(const mutation of ['missing','sourcePath','traversal','kms','forbidden','oid4vci','coreTree','baselineUid'])test('v2 rejects unbound compiler or baseline evidence '+mutation,t=>{
 const f=issuanceFixture(t);
 if(mutation==='baselineUid'){
  delete f.before.roles[0].effectiveUid;
  f.change('deploy',row=>{row.beforeRuntimeBinding=f.write('before-invalid.json',{baseProfileSha256:f.profile.baseProfile.sha256,binding:f.before});});
 }else f.change('build',build=>{
  if(mutation==='missing'){delete build.coreCompilerArtifacts;return;}
  if(mutation==='coreTree'){const source=JSON.parse(fs.readFileSync(build.sourcePreparation.path,'utf8'));source.coreTree=R('0');build.sourcePreparation=f.write('source-invalid.json',source);return;}
  const artifacts=JSON.parse(fs.readFileSync(build.coreCompilerArtifacts.path,'utf8'));
  if(mutation==='sourcePath')artifacts[0].manifest='/unowned/core/Cargo.toml';
  if(mutation==='traversal')artifacts[0].manifest='/build/core/../other/Cargo.toml';
  if(mutation==='kms')artifacts[0].features=[];if(mutation==='forbidden')artifacts[0].features.push('test-fixtures');
  if(mutation==='oid4vci'){artifacts[2].name='marty-status';artifacts[2].manifest='/build/core/marty-status/Cargo.toml';}build.coreCompilerArtifacts=f.write('compiler-invalid.json',artifacts);
 });
 assert.throws(()=>verifyFunctionalRuntime(f.profile,{observe:()=>assert.fail('Reject before runtime observation')}));
});

for(const mutation of ['missingCrypto','unknownPackage','inventory','recipe','localizer','oldUidChanged','collidingId'])test('v2 rejects changed permitted-layer boundary '+mutation,t=>{
 const f=issuanceFixture(t);
 if(['oldUidChanged','collidingId'].includes(mutation))f.change('deploy',row=>{
  if(mutation==='oldUidChanged'){row.roles.issuance.configuredRuntimeUid=1000;row.roles.issuance.effectiveUid=1000;}
  else row.roles.issuance.containerId=f.before.roles.find(old=>old.role==='auth').containerId;
 });
 else f.change('build',build=>{
  if(['inventory','recipe','localizer'].includes(mutation)){const source=JSON.parse(fs.readFileSync(build.sourcePreparation.path,'utf8'));if(mutation==='inventory')source.sourceInventories['core-source'].inventorySha256=H('0');else source[mutation==='recipe'?'recipeSha256':'localizerSha256']=H('0');build.sourcePreparation=f.write('inventory-invalid.json',source);return;}
  const artifacts=JSON.parse(fs.readFileSync(build.coreCompilerArtifacts.path,'utf8'));
  if(mutation==='missingCrypto')artifacts.shift();else artifacts.push({name:'invented-core',manifest:'/build/core/invented-core/Cargo.toml',features:[],fresh:false,filenames:['/target/a.rlib']});
  build.coreCompilerArtifacts=f.write('packages-invalid.json',artifacts);
 });
 assert.throws(()=>verifyFunctionalRuntime(f.profile,{observe:()=>assert.fail('Reject before runtime observation')}));
});


test('readDocker transport reuses actual per-role PID1, inode, UID and mount inspection',t=>{
 assert.equal(require('./functional-debug-runtime').DOCKER_READ_TRANSPORT_SCHEMA,'marty.functional-runtime-docker-read/v1');
 const f=fixture(t),expected=expectedRuntime(f.profile);let selected;const calls=[];
 const readDocker=args=>{
  calls.push(args);
  if(args[0]==='ps'){const service=args.find(v=>v.startsWith('label=com.docker.compose.service=')).split('=').at(-1);selected=expected.find(r=>r.role===service);return f.observe(selected).containerId;}
  const actual=f.observe(selected);
  if(args[0]==='inspect')return JSON.stringify([{Id:actual.containerId,Image:selected.imageId,Config:{Labels:{'com.docker.compose.project':selected.project,'com.docker.compose.service':selected.role},User:'1000'},State:{Running:true,Status:'running',Health:actual.health?{Status:actual.health}:undefined,Pid:actual.hostPid,StartedAt:actual.startedAt},Mounts:actual.binaryMounts.map(m=>({Type:m.type,Source:m.source,Destination:m.destination,RW:m.writable}))}]);
  if(args[2]==='readlink')return actual.executablePath;
  if(args[2]==='sha256sum')return selected.sha256+'  '+args[3];
  if(args[2]==='cat')return 'Uid:\t1000\t1000\t1000\t1000\n';
  assert.fail('Unexpected engine read');
 };
 const result=verifyFunctionalRuntime(f.profile,{readDocker});
 assert.equal(result.roles.length,22);assert.equal(result.releaseQualified,false);assert.equal(result.recordingQualified,false);
 assert.equal(calls.filter(a=>a[0]==='ps').length,22);
 assert.equal(calls.filter(a=>a[2]==='readlink'&&a[3]==='/proc/1/exe').length,21);
 assert.equal(calls.filter(a=>a[2]==='sha256sum'&&a[3]==='/proc/1/exe').length,21);
 assert.equal(result.roles.find(r=>r.role==='gateway').effectiveUid,1000);
 assert.throws(()=>verifyFunctionalRuntime(f.profile,{observe:f.observe,readDocker}),/one observation transport/);
 assert.throws(()=>verifyFunctionalRuntime(f.profile,{readDocker:()=>{throw Error('CONTROLLED_PRIVATE_ERROR')}}),e=>e.code==='FUNCTIONAL_RUNTIME_OBSERVATION_FAILED'&&!e.message.includes('PRIVATE'));
 for(const qualification of ['RELEASE','RECORDING'])assert.throws(()=>verifyFunctionalRuntime(f.profile,{qualification,readDocker:()=>assert.fail('No engine reads')}),/cannot qualify/);
});

function mountEquivalenceFixture(t){
 const f=issuanceFixture(t);
 for(const row of f.before.roles)row.binaryMounts=row.binaryMounts.map(mount=>({...mount,source:'C:\\owned\\'+row.role+'\\'+row.binary}));
 f.change('deploy',row=>{
  row.beforeRuntimeBinding=f.write('before-windows-mounts.json',{baseProfileSha256:f.profile.baseProfile.sha256,binding:f.before});
  for(const role of ['issuance','issuance-native'])row.roles[role].binaryMount.source='/run/desktop/mnt/host/d/owned/'+role+'/marty-issuance-service';
 });
 const observe=row=>{
  const actual=f.observe(row);
  actual.binaryMounts=(row.kind==='ISSUANCE_CORE_FUNCTIONAL_OVERLAY'
   ?actual.binaryMounts.map(mount=>({...mount,source:'D:\\owned\\'+row.role+'\\marty-issuance-service'}))
   :f.before.roles.find(old=>old.role===row.role).binaryMounts.map(mount=>({...mount,source:mount.source.replace(/^C:\\/, '/run/desktop/mnt/host/c/').replaceAll('\\','/')})));
  return actual;
 };
 return {...f,observe};
}

test('v2 compares Windows and canonical desktop mounts for base20 and issuer2 without rewriting evidence',t=>{
 const f=mountEquivalenceFixture(t),before=JSON.stringify(f.before),deployed=fs.readFileSync(f.profile.issuanceOverlay.deploymentReceipt.path);
 const result=verifyFunctionalRuntime(f.profile,{observe:f.observe});
 assert.equal(result.roles.length,22);assert.equal(result.roles.filter(row=>row.kind==='ISSUANCE_CORE_FUNCTIONAL_OVERLAY').length,2);
 assert(result.roles.find(row=>row.role==='credential-template').binaryMounts[0].source.startsWith('/run/desktop/mnt/host/c/'));
 assert(result.roles.find(row=>row.role==='issuance').binaryMounts[0].source.startsWith('D:\\'));
 assert.equal(JSON.stringify(f.before),before);assert.deepEqual(fs.readFileSync(f.profile.issuanceOverlay.deploymentReceipt.path),deployed);
 assert.equal(result.releaseQualified,false);assert.equal(result.recordingQualified,false);
});

for(const role of ['credential-template','issuance'])test('mount equivalence retains exact ownership and fields for '+role,t=>{
 const f=mountEquivalenceFixture(t);
 for(const mutation of ['drive','path','destination','writable','type','alias','foreignDrive','dot','control']){
  assert.throws(()=>verifyFunctionalRuntime(f.profile,{observe:row=>{
   const actual=f.observe(row);if(row.role===role){const mount=actual.binaryMounts[0];
    if(mutation==='drive')mount.source=mount.source.replace('/host/c/','/host/d/').replace(/^D:/,'C:');
    if(mutation==='path')mount.source+='-foreign';
    if(mutation==='destination')mount.destination='/usr/local/bin/foreign';
    if(mutation==='writable')mount.writable=true;if(mutation==='type')mount.type='volume';
    if(mutation==='alias')mount.source='/mnt/host/c/owned/'+role;
    if(mutation==='foreignDrive')mount.source='E:\\owned\\'+role;
    if(mutation==='dot')mount.source='/run/desktop/mnt/host/c/owned/../'+role;
    if(mutation==='control')mount.source+='\n';
   }return actual;
  }}),mutation);
 }
});


function maintenanceFixture(t){
 const f=issuanceFixture(t),api=require('./functional-debug-runtime'),engineId='11111111-2222-3333-4444-555555555555';
 const expected=expectedRuntime(f.profile),base=f.write('restart-base.json',f.profile);
 const operator=f.write('synthetic-maintenance-source.json',{sourceControlOnly:true}),restoreSource=f.write('synthetic-restore-source.json',{sourceControlOnly:true});
 const ids=expected.map(row=>row.requiredContainerId||row.requiredObservation.containerId);
 while(ids.length<67)ids.push(crypto.createHash('sha256').update('maintenance-extra:'+ids.length).digest('hex'));
 const journal={sourceSha256:operator.sha256,phase:'RESTORED_225_CONFIG_67_RUNNING',state:'RESTORED_PENDING_ROOT_ENDPOINT_AND_RUNTIME_REBIND',appStopIntent:true,appStartIntent:true,freshBackupComplete:true,freshBackupFileCount:2,originalRunning:ids,stopIntents:[...ids]};
 const restore={sourceSha256:operator.sha256,scope:'RESTORE_ONLY_NO_DESKTOP_COMMAND',normalization:{Dns:'None to []',DnsSearch:'None to []',DnsOptions:'None to []'},expectedContainerCount:225,observedRunningBeforeRestore:4};
 const authority={schema:'marty.functional-runtime-maintenance-authority/v1',scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false,engineId,restoredCounts:{containers:225,running:67},operator,restoreSource,journal:f.write('maintenance-journal.json',journal),restoreIntent:f.write('maintenance-restore-intent.json',restore),freshBackupIntegrity:f.write('maintenance-backups.json',{dump:{bytes:1,sha256:H('a')}})};
 let selected,mutateActual=null,mutateEngine=null;
 const readDocker=args=>{
  if(args[0]==='info'){const value={ID:engineId,Containers:225,ContainersRunning:67};mutateEngine?.(value);return JSON.stringify(value);}
  if(args[0]==='ps')selected=expected.find(row=>args.includes('label=com.docker.compose.service='+row.role));
  assert(selected);const actual=structuredClone(f.observe(selected));actual.startedAt='2026-10-27T16:00:00Z';actual.hostPid+=10000;mutateActual?.(actual,selected);
  if(args[0]==='ps')return actual.containerId;
  if(args[0]==='inspect')return JSON.stringify([{Id:actual.containerId,Image:actual.imageId,Config:{User:String(actual.configuredRuntimeUid),Labels:{'com.docker.compose.project':actual.project,'com.docker.compose.service':actual.role}},State:{Running:actual.running,Status:actual.status,Health:actual.health?{Status:actual.health}:undefined,Pid:actual.hostPid,StartedAt:actual.startedAt},Mounts:actual.binaryMounts.map(m=>({Type:m.type,Source:m.source,Destination:m.destination,RW:m.writable}))}]);
  if(args[2]==='readlink')return actual.executablePath;
  if(args[2]==='sha256sum')return (args[3]==='/proc/1/exe'?actual.processExecutableSha256:actual.binarySha256)+'  '+args[3];
  if(args[2]==='cat')return 'Uid:\t'+actual.effectiveUid+'\t'+actual.effectiveUid+'\t0\t0\n';
  assert.fail('Unexpected Docker read');
 };
 const authorityRef=()=>f.write('maintenance-authority.json',authority);
 const produce=()=>api.produceMaintenanceRestart(base,authorityRef(),{readDocker});
 const bind=receipt=>({...f.profile,maintenanceRestart:f.write('maintenance-restart.json',receipt)});
 return {...f,api,base,authority,journal,restore,readDocker,produce,bind,authorityRef,
  mutateActual:fn=>{mutateActual=fn;},mutateEngine:fn=>{mutateEngine=fn;},
  changeJournal:()=>{authority.journal=f.write('maintenance-journal.json',journal);},changeRestore:()=>{authority.restoreIntent=f.write('maintenance-restore-intent.json',restore);}};
}

test('maintenance actual-reader producer rebinds only newer generations and preserves prior receipts',t=>{
 const f=maintenanceFixture(t),prior=fs.readFileSync(f.base.path);
 assert.throws(()=>verifyFunctionalRuntime(f.profile,{readDocker:f.readDocker}),/startedAt/);
 const receipt=f.produce(),profile=f.bind(receipt),result=verifyFunctionalRuntime(profile,{readDocker:f.readDocker});
 assert.equal(receipt.roles.length,22);assert.equal(result.roles.length,22);assert.equal(result.receiptDigests.maintenanceRestart,profile.maintenanceRestart.sha256);
 assert(result.roles.every(row=>row.startedAt==='2026-10-27T16:00:00Z'));assert.equal(result.releaseQualified,false);assert.equal(result.recordingQualified,false);
 assert.deepEqual(fs.readFileSync(f.base.path),prior);
 assert.throws(()=>verifyFunctionalRuntime(profile,{observe:()=>assert.fail('No supplied rows')}),/actual Docker transport/);
 assert.throws(()=>f.api.produceMaintenanceRestart(f.base,f.authorityRef(),{observe:()=>{}}),/actual Docker reads/);
 for(const qualification of ['RELEASE','RECORDING'])assert.throws(()=>verifyFunctionalRuntime(profile,{qualification,readDocker:()=>assert.fail('No reads')}),/cannot qualify/);
});

test('maintenance producer records unrelated container churn while still rejecting missing or replaced managed roles',t=>{
 const f=maintenanceFixture(t);let engineReads=0;
 f.mutateEngine(value=>{engineReads++;value.Containers=149+engineReads;value.ContainersRunning=67+engineReads;});
 const receipt=f.produce();
 assert.deepEqual(receipt.engineCounts,{before:{containers:150,running:68},after:{containers:151,running:69}});
 assert.equal(receipt.roles.length,22);assert.equal(verifyFunctionalRuntime(f.bind(receipt),{readDocker:f.readDocker}).roles.length,22);
 f.mutateActual((actual,row)=>{if(row.role==='gateway')actual.containerId='';});
 assert.throws(f.produce,'Missing managed gateway must fail despite healthy engine counts');
 f.mutateActual((actual,row)=>{if(row.role==='gateway')actual.containerId=H('0');});
 assert.throws(f.produce,'Replaced managed gateway must fail despite healthy engine counts');
});

for(const field of ['container','image','mounted','process','uid','mount','writable','health','staleGeneration'])test('maintenance producer refuses changed '+field,t=>{
 const f=maintenanceFixture(t);f.mutateActual((actual,row)=>{if(row.role!=='gateway')return;
  if(field==='container')actual.containerId=H('0');if(field==='image')actual.imageId='sha256:'+H('0');
  if(field==='mounted')actual.binarySha256=H('0');if(field==='process')actual.processExecutableSha256=H('0');
  if(field==='uid')actual.effectiveUid=99;if(field==='mount')actual.binaryMounts[0].source+='/foreign';
  if(field==='writable')actual.binaryMounts[0].writable=true;if(field==='health')actual.health='unhealthy';
  if(field==='staleGeneration')actual.startedAt='2026-10-26T00:00:00Z';
 });assert.throws(f.produce);
});

for(const field of ['release','recording','stopAck','startAck','restoreCount','backupCount','missingStoppedRole','engine'])test('maintenance refuses invalid authority '+field,t=>{
 const f=maintenanceFixture(t);
 if(field==='release')f.authority.releaseQualified=true;if(field==='recording')f.authority.recordingQualified=true;
 if(field==='stopAck')f.journal.appStopIntent=false;if(field==='startAck')f.journal.appStartIntent=false;
 if(field==='restoreCount')f.restore.observedRunningBeforeRestore=5;if(field==='backupCount')f.journal.freshBackupFileCount=3;
 if(field==='missingStoppedRole')f.journal.stopIntents.pop();if(field==='engine')f.mutateEngine(value=>{value.ID='00000000-0000-0000-0000-000000000000';});
 f.changeJournal();f.changeRestore();assert.throws(f.produce);
});

test('maintenance receipt rejects missing role, foreign profile and later process drift',t=>{
 const f=maintenanceFixture(t),receipt=f.produce();
 const missing=structuredClone(receipt);missing.roles.pop();assert.throws(()=>expectedRuntime(f.bind(missing)));
 const wrong=structuredClone(receipt);wrong.baseProfile=f.write('foreign-prior.json',{...f.profile,scope:'RELEASE'});assert.throws(()=>expectedRuntime(f.bind(wrong)));
 const profile=f.bind(receipt);f.mutateActual(actual=>{actual.hostPid++;});assert.throws(()=>verifyFunctionalRuntime(profile,{readDocker:f.readDocker}));
});

function scopedRowsFixture(t){
 const f=issuanceFixture(t),expected=expectedRuntime(f.profile),before=verifyFunctionalRuntime(f.profile,{observe:f.observe});
 const roles=['signing-keys','gateway'],hashes={'marty-signing-keys':H('6'),'marty-gateway':H('7')};
 const deployed={roles:Object.fromEntries(roles.map((role,index)=>{const old=before.roles.find(row=>row.role===role),binary='marty-'+role;return [role,{
  containerId:crypto.createHash('sha256').update('scoped:'+role).digest('hex'),imageId:old.imageId,startedAt:'2026-10-26T02:00:00Z',hostPid:400+index,
  configuredRuntimeUid:old.configuredRuntimeUid,effectiveUid:old.effectiveUid,
  binaryMount:{type:'bind',source:path.join(path.dirname(f.profile.baseProfile.path),'candidate-'+binary),destination:'/usr/local/bin/'+binary,writable:false},
  processExecutablePath:'/usr/local/bin/'+binary,processExecutableSha256:hashes[binary],mountedBinarySha256:hashes[binary]}]}))};
 const selection={roles,source:'3b862bebdd2cc0707d9a38f6df55db198b6be417',coreSource:'4320b5fa1c6f41231ee0aa2bc57d8008549f67ac',kind:'SCOPED_NATIVE_FUNCTIONAL_OVERLAY',hashes};
 return {f,expected,before,deployed,selection};
}
test('shared native overlay changes exactly signing/gateway and preserves actual other20 generations',t=>{
 const {applyNativeOverlayRows}=require('./functional-debug-runtime'),x=scopedRowsFixture(t);
 const result=applyNativeOverlayRows(x.expected,x.before,x.deployed,x.selection);assert.equal(result.length,22);
 assert.equal(result.filter(row=>row.kind==='SCOPED_NATIVE_FUNCTIONAL_OVERLAY').length,2);
 for(const row of result){const old=x.before.roles.find(item=>item.role===row.role);
  if(x.selection.roles.includes(row.role)){assert.equal(row.source,x.selection.source);assert.equal(row.coreSource,x.selection.coreSource);assert.equal(row.sha256,x.selection.hashes[row.binary]);assert.equal(row.requiredContainerId,x.deployed.roles[row.role].containerId);assert.equal(row.requiredObservation,undefined);}
  else{assert.equal(row.source,old.source);assert.equal(row.sha256,old.sha256);assert.equal(row.coreSource,old.coreSource);for(const [field,value]of Object.entries(row.requiredObservation))assert.deepEqual(value,old[field]);}
 }
 assert.deepEqual(result.filter(row=>['issuance','issuance-native'].includes(row.role)).map(row=>row.coreSource),[require('./functional-debug-runtime').ISSUANCE_CORE,require('./functional-debug-runtime').ISSUANCE_CORE]);
});
for(const fault of ['wrongRole','extraRole','source','elf','mountedElf','generation','untouchedPid','coreSource'])test('shared native overlay rejects '+fault,t=>{
 const {applyNativeOverlayRows}=require('./functional-debug-runtime'),x=scopedRowsFixture(t);
 if(fault==='wrongRole'){x.deployed.roles.flow=x.deployed.roles.gateway;delete x.deployed.roles.gateway;}
 if(fault==='extraRole')x.deployed.roles.flow=x.deployed.roles.gateway;
 if(fault==='source')x.before.roles.find(row=>row.role==='signing-keys').source=R('0');
 if(fault==='elf')x.deployed.roles.gateway.processExecutableSha256=H('0');
 if(fault==='mountedElf')x.deployed.roles.gateway.mountedBinarySha256=H('0');
 if(fault==='generation')x.deployed.roles.gateway.startedAt=x.before.roles.find(row=>row.role==='gateway').startedAt;
 if(fault==='untouchedPid')x.before.roles.find(row=>row.role==='issuance').hostPid++;
 if(fault==='coreSource')x.before.roles.find(row=>row.role==='issuance').coreSource=R('0');
 assert.throws(()=>applyNativeOverlayRows(x.expected,x.before,x.deployed,x.selection));
});
test('native envelope rejects foreign base and supplied observation before any runtime read',t=>{
 const f=issuanceFixture(t),profile={schema:'marty.functional-mixed-runtime/v2',scope:'FUNCTIONAL_ONLY',releaseQualified:false,recordingQualified:false,baseProfile:f.write('foreign-v2.json',f.profile),nativeOverlay:{profile:'d02-signing-cas'}};
 assert.throws(()=>expectedRuntime(profile),/Foreign native-overlay base/);
 assert.throws(()=>verifyFunctionalRuntime(profile,{observe:()=>assert.fail('No supplied observations')}));
});

for(const kind of ['ISSUANCE_CORE_FUNCTIONAL_OVERLAY','SCOPED_NATIVE_FUNCTIONAL_OVERLAY']){
 function liveOverlayContract(t){
  const x=scopedRowsFixture(t),row=require('./functional-debug-runtime').applyNativeOverlayRows(x.expected,x.before,x.deployed,x.selection).find(item=>item.role==='gateway');
  row.kind=kind;row.requiredEffectiveUid=10001;
  const actual={...x.before.roles.find(item=>item.role==='gateway'),role:'gateway',service:'gateway',project:row.project,imageId:row.imageId,
   containerId:row.requiredContainerId,startedAt:row.requiredStartedAt,hostPid:row.requiredHostPid,effectiveUid:10001,configuredRuntimeUid:10001,
   running:true,status:'running',health:'healthy',binarySha256:row.sha256,processExecutableSha256:row.sha256,
   executablePath:'/usr/local/bin/marty-gateway',binaryMounts:structuredClone(row.requiredBinaryMounts)};
  return {row,actual};
 }
 test(kind+' live observation enforces UID and exact reviewed mount',t=>{
  const {row,actual}=liveOverlayContract(t),validate=require('./functional-debug-runtime').validateRuntimeObservation;
  assert.equal(validate(row,actual).effectiveUid,10001);
  row.requiredBinaryMounts[0].source='C:/owned/runtime/marty-gateway';actual.binaryMounts[0].source='/run/desktop/mnt/host/c/owned/runtime/marty-gateway';
  assert.equal(validate(row,actual).effectiveUid,10001);
 });
 for(const fault of ['uid0','configuredUid0','missingMount','writableMount','wrongSource','staleGeneration','wrongPid'])test(kind+' rejects actual '+fault,t=>{
  const {row,actual}=liveOverlayContract(t),validate=require('./functional-debug-runtime').validateRuntimeObservation;
  if(fault==='uid0')actual.effectiveUid=0;
  if(fault==='configuredUid0')actual.configuredRuntimeUid=0;
  if(fault==='missingMount')actual.binaryMounts=[];
  if(fault==='writableMount')actual.binaryMounts[0].writable=true;
  if(fault==='wrongSource')actual.binaryMounts[0].source='/foreign/marty-gateway';
  if(fault==='staleGeneration')actual.startedAt='2026-10-26T00:00:00Z';
  if(fault==='wrongPid')actual.hostPid++;
  assert.throws(()=>validate(row,actual));
 });
}
