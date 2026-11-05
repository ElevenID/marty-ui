'use strict';
const fs=require('node:fs');
const cp=require('node:child_process');
const assert=require('node:assert/strict');
const runtime=require('../tests/scripts/functional-debug-runtime');
function authority(ref){
 const profile=runtime.boundJson(ref);
 const transition=runtime.resourceRecreationSuccessor(profile.baseProfile,profile);
 const rows=transition.replacements.map(row=>({role:row.role,cid:row.newCid}));
 assert.equal(rows.length,28);assert.equal(new Set(rows.map(row=>row.cid)).size,28);
 assert.equal(runtime.expectedRuntime(profile).length,22);
 return {schema:'marty.northstar-resource-scope/v1',profileSha256:ref.sha256,rows,off:runtime.retainedBetaOffAuthority(profile)};
}
function main(){
 const raw=fs.readFileSync(0);assert(raw.length<=32768);
 const input=JSON.parse(raw),result=authority(input.profile);
 assert.equal(typeof input.verifyLive,'boolean');
 if(input.verifyLive){
  const readDocker=args=>cp.execFileSync(input.docker,['--context','desktop-linux',...args],
   {encoding:'utf8',windowsHide:true,timeout:30000,maxBuffer:16*1024*1024});
  runtime.verifyResourceAncillary(runtime.boundJson(input.profile),readDocker);
 }
 process.stdout.write(JSON.stringify(result));
}
if(require.main===module)main();
module.exports={authority};
