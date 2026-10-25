#!/usr/bin/env node
'use strict';
const fs=require('node:fs'),path=require('node:path'),{createHash,randomUUID}=require('node:crypto'),{execFileSync}=require('node:child_process');
const {createDemoLiveEvidence,applyLocalNativeReadiness}=require('./demo-live-evidence');
async function main(){
 const root=path.resolve(__dirname,'../..'),revision=execFileSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).trim();
 const python=process.env.DEMO_PYTHON_EXECUTABLE,validator=process.env.DEMO_SIGNING_CAPABILITY_BIN;
 if(!python||!path.isAbsolute(python)||!validator||!path.isAbsolute(validator))throw Error('D10 requires explicit Python and native signing-validator executables');
 const endpoint=process.env.DEMO_D10_KMS_URL||'';const kms=new URL(endpoint);
 if(kms.protocol!=='https:'||kms.origin!==endpoint.replace(/\/$/,'')||kms.username||kms.password)throw Error('D10 KMS input must be a public HTTPS origin without credentials');
 let client;
 try{
  client=await createDemoLiveEvidence();
  const capture=await client.runPythonCapture({repository:root,revision,entrypoint:'scripts/beta_org_console_audit.py',pythonExecutable:python,fixtureFile:'organization-run-input.json',args:['--record-video'],inputs:{
   runId:new Date().toISOString().replace(/[^0-9]/g,'').slice(0,14)+'-'+randomUUID().slice(0,8),recordVideo:process.env.RECORD_VIDEO!=='0',recordingPauseMs:1300,
   signing:{endpoint:process.env.DEMO_D10_KMS_URL||'',mount:process.env.DEMO_D10_KMS_MOUNT||'',namespace:process.env.DEMO_D10_KMS_NAMESPACE||'',keyReference:process.env.DEMO_D10_KMS_KEY_REFERENCE||'',caCertFile:process.env.DEMO_D10_KMS_CA_CERT_FILE||'',validatorSha256:createHash('sha256').update(fs.readFileSync(validator)).digest('hex')}
  }});
  if(client.nativeRuntimeBinding){
   const reportFile=path.join(process.env.DEMO_ARTIFACT_DIR,'report.json');
   if(fs.lstatSync(reportFile).isSymbolicLink()||!fs.statSync(reportFile).isFile())throw Error('D10 requires its actual owned Python report');
   const report=JSON.parse(fs.readFileSync(reportFile,'utf8'));
   // The Python producer's release checks include exact run-owned API-key
   // revocation. Its engineering configuration is deliberately retained, not
   // described as deleted or reusable after the scoped transit leaf is retired.
   const ready=report.releaseReady===true&&report.release_checks?.status==='pass';
   report.cleanup={scope:'RUN_OWNED_API_KEYS_RETAINED_ENGINEERING_CONFIGURATION',
    retainedConfigurationReusableAfterLeafRevocation:false};
   applyLocalNativeReadiness(report,client,{ready,cleanupComplete:ready});
   fs.writeFileSync(reportFile,JSON.stringify(report,null,2)+'\n');
   if(!report.functionalReady)throw Error('D10 actual operations or scoped cleanup incomplete');
  }
  return capture;
 }finally{client?.close();}
}
if(require.main===module)main().catch(error=>{console.error(error.message);process.exitCode=1;});
module.exports={main};
