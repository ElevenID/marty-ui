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
