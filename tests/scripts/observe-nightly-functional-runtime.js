#!/usr/bin/env node
'use strict';
// Produce actual read-only image/PID observations for the existing functional IPC.
const fs=require('node:fs'),path=require('node:path'),{createHash}=require('node:crypto');
const {parseArgs}=require('node:util');
const verifier=require('./functional-debug-runtime');
const nightly=require('./nightly-functional-runtime');
function main(){
 const {values}=parseArgs({options:{profile:{type:'string'},sha256:{type:'string'},output:{type:'string'},check:{type:'boolean'}},strict:true});
 const profile=verifier.boundJson({path:values.profile,sha256:values.sha256});
 nightly.authority(profile,{boundJson:verifier.boundJson});
 if(values.check){console.log(JSON.stringify({state:'FUNCTIONAL_IMAGE_INPUTS_CHECKED',dockerCommands:0,releaseQualified:false}));return;}
 if(!path.isAbsolute(values.output||''))throw Error('Explicit absolute private observation output required');
 const proof=verifier.produceSignedImageObservation(profile),bytes=Buffer.from(JSON.stringify(proof,null,2)+'\n');
 const fd=fs.openSync(values.output,'wx',0o600);
 try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
 console.log(JSON.stringify({state:'FUNCTIONAL_IMAGE_READBACK_OBSERVED',path:values.output,sha256:createHash('sha256').update(bytes).digest('hex'),bytes:bytes.length,roles:proof.roles.length,releaseQualified:false,recordingQualified:false}));
}
if(require.main===module){try{main();}catch(error){console.error(error.message);process.exitCode=1;}}
module.exports={main};
