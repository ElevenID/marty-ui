'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
test('D05 keeps the policy-bound source credential template and owns only new application/Flow configuration',async()=>{
 const org='00000000-0000-0000-0000-000000000001',template='50000000-0000-0000-0000-000000000040',sourceApplication='0ab66d45-0d84-5fbd-837f-25788d32279e';
 const created=[],source=fs.readFileSync(path.join(__dirname,'demo-owned-membership.js'),'utf8'),module={exports:{}};
 const credential={id:template,organization_id:org,status:'ACTIVE',credential_type:'open_badge',vct:'https://example.invalid/member'};
 const application={id:sourceApplication,organization_id:org,status:'ACTIVE',credential_template_id:template,description:'Governed membership badge',form_fields:[],claim_collection_rules:['name','description'].map(name=>({claim_name:`achievement_${name}`,source:'SYSTEM',source_config:{system_field:`template.${name}`}}))};
 vm.runInNewContext(source,{module,require:name=>{
  if(name==='node:assert/strict')return assert;
  if(name==='./beta-demo-resource-helpers')return {requireJson:async(_,route)=>route.includes('/credential-templates/')?credential:application,approvedApplicationFlowPayload:({credentialTemplateId})=>({credential_template_id:credentialTemplateId})};
  if(name==='./demo-owned-configuration')return {createOwnedActiveConfiguration:async(_,owned,options)=>{
   created.push(options);return {id:options.collectionPath.endsWith('application-templates')?'owned-application-template':'owned-flow',credential_template_id:options.payload.credential_template_id};}};
  throw Error(name);
 }});
 const control=module.exports.createOwnedMembership({}, {organizationId:org,runId:'owned-run',credentialTemplateId:template,sourceApplicationTemplateId:sourceApplication,configurationId:'open_badge',vct:credential.vct});
 const result=await control.configure();assert.equal(result.credential.id,template);assert.equal(control.owned.credentialTemplateId,template);
 assert.deepEqual(created.map(row=>row.collectionPath),['/v1/application-templates','/v1/flows/definitions']);
 assert.equal(created[0].payload.credential_template_id,template);assert.equal(created[1].payload.credential_template_id,template);
});
