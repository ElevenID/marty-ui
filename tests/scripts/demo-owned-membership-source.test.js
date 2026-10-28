'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const {DEFAULT_LOGIN_BADGE_FLOW_ID}=require('./beta-credential-contract');
test('D05 uses the stock governed membership Flow and real applicant login helper',()=>{
 const seeded=require('../../contracts/flow-seed-behavior.json');
 assert.ok(JSON.stringify(seeded).includes(DEFAULT_LOGIN_BADGE_FLOW_ID));
 assert.equal(typeof require('./verify-beta-waltid-acceptance').loginToBetaApplicant,'function');
});
test('D05 refuses an approval-time offer and dispatches explicit issue once',async()=>{
 const org='00000000-0000-0000-0000-000000000001',template='50000000-0000-0000-0000-000000000040';
 const appTemplate='0ab66d45-0d84-5fbd-837f-25788d32279e',appId='c0b66d45-0d84-5fbd-837f-25788d32279e';
 const flow={id:DEFAULT_LOGIN_BADGE_FLOW_ID,organization_id:org,credential_template_id:template,status:'ACTIVE',flow_type:'custom',extension:{extends_flow_type:'oid4vci_pre_authorized'},trigger:{trigger_type:'WEBHOOK',config:{event_type:'APPLICATION_APPROVED'}}};
 const credential={id:template,organization_id:org,status:'ACTIVE',credential_type:'open_badge',vct:'https://example.invalid/member'};
 const application={id:appTemplate,organization_id:org,credential_template_id:template,status:'ACTIVE',description:'Governed membership badge',form_fields:[],claim_collection_rules:['name','description'].map(name=>({claim_name:`achievement_${name}`,source:'SYSTEM',source_config:{system_field:`template.${name}`}}))};
 let transaction=null,issueCalls=0,profileCalls=0;
 const source=fs.readFileSync(path.join(__dirname,'demo-owned-membership.js'),'utf8'),module={exports:{}};
 vm.runInNewContext(source,{module,require:name=>{
  if(name==='node:assert/strict')return assert;
  if(name==='./demo-owned-configuration')return {createOwnedActiveConfiguration:async()=>({id:'owned-app-template'}),retireOwnedConfiguration:async()=>({ok:true})};
  if(name==='./beta-demo-resource-helpers')return {
   requireJson:async(_,route,options)=>route.includes('/credential-templates/')?credential:route.includes('/application-templates/')?application:route.includes('/definitions?')?[flow]:route.includes('/flows/definitions/')?flow:route.endsWith('/approve')?{id:appId,organization_id:org,status:'APPROVED'}:{id:appId,organization_id:org},
   ensureApplicantProfile:async()=>{profileCalls++;return {id:'applicant',email:'test@example.invalid'};},
   createOwnedApplication:async(_,owned)=>{owned.applicationId=appId;},submitOwnedApplication:async()=>{},
   requireOwnedApplication:value=>value,readApplicationTransaction:async()=>transaction,
   issueOwnedApplication:async(_,owned)=>{issueCalls++;transaction={id:'transaction',application_id:appId,organization_id:org,credential_template_id:template};owned.transactionId=transaction.id;},
  };
  throw Error(name);
 }});
 const inputs={organizationId:org,runId:'run',credentialTemplateId:template,sourceApplicationTemplateId:appTemplate,sourceFlowDefinitionId:flow.id,configurationId:'open_badge',vct:credential.vct,email:'test@example.invalid',givenName:'Test',familyName:'Applicant'};
 const control=module.exports.createOwnedMembership({},inputs);
 await control.prepare({});assert.equal(issueCalls,1);assert.equal(profileCalls,1);assert.equal(control.owned.transactionId,'transaction');
 const conflicting=module.exports.createOwnedMembership({},inputs);transaction={id:'other'};
 await assert.rejects(conflicting.prepare({}),/Approval unexpectedly created/);assert.equal(issueCalls,1);
});
test('D05 permits only the exact governed active Flow before application mutation',async()=>{
 const {requireGovernedMembershipFlow}=require('./demo-owned-membership');
 const owned={organizationId:'org',credentialTemplateId:'template'};
 const flow={id:DEFAULT_LOGIN_BADGE_FLOW_ID,organization_id:'org',credential_template_id:'template',status:'ACTIVE',flow_type:'custom',extension:{extends_flow_type:'oid4vci_pre_authorized'},trigger:{trigger_type:'WEBHOOK',config:{event_type:'APPLICATION_APPROVED'}}};
 const read=async(_,route)=>route.includes('/definitions?')?[flow]:flow;
 assert.equal((await requireGovernedMembershipFlow({},owned,flow.id,read)).id,flow.id);
 const filler=Array.from({length:499},(_,index)=>({...flow,id:`filler-${index}`,status:'DRAFT'}));
 const paged=async(_,route)=>route.includes('/definitions?')
  ?route.includes('offset=500')?[]:[flow,...filler]:flow;
 assert.equal((await requireGovernedMembershipFlow({},owned,flow.id,paged)).id,flow.id);
 await assert.rejects(requireGovernedMembershipFlow({},owned,flow.id,async(_,route)=>route.includes('/definitions?')?[flow,...filler]:flow),/repeated a definition|bounded scan/);
 await assert.rejects(requireGovernedMembershipFlow({},owned,flow.id,async(_,route)=>route.includes('/definitions?')?[flow,{...flow,id:'foreign'}]:flow),/One governed membership issuance Flow/);
 await assert.rejects(requireGovernedMembershipFlow({},owned,flow.id,async(_,route)=>route.includes('/definitions?')?[flow]:{...flow,status:'DRAFT'}),/DRAFT/);
 await assert.rejects(requireGovernedMembershipFlow({},owned,flow.id,async(_,route)=>route.includes('/definitions?')?[flow]:{...flow,extension:{extends_flow_type:'oid4vp_presentation'}}),/oid4vci_pre_authorized/);
});
test('D05 owns only application configuration and retires it even if application cleanup is ambiguous',async()=>{
 const org='00000000-0000-0000-0000-000000000001',template='50000000-0000-0000-0000-000000000040',sourceApplication='0ab66d45-0d84-5fbd-837f-25788d32279e';
 const created=[],source=fs.readFileSync(path.join(__dirname,'demo-owned-membership.js'),'utf8'),module={exports:{}};
 const credential={id:template,organization_id:org,status:'ACTIVE',credential_type:'open_badge',vct:'https://example.invalid/member'};
 const application={id:sourceApplication,organization_id:org,status:'ACTIVE',credential_template_id:template,description:'Governed membership badge',form_fields:[],claim_collection_rules:['name','description'].map(name=>({claim_name:`achievement_${name}`,source:'SYSTEM',source_config:{system_field:`template.${name}`}}))};
 const flow={id:DEFAULT_LOGIN_BADGE_FLOW_ID,organization_id:org,credential_template_id:template,status:'ACTIVE',flow_type:'custom',extension:{extends_flow_type:'oid4vci_pre_authorized'},trigger:{trigger_type:'WEBHOOK',config:{event_type:'APPLICATION_APPROVED'}}};
 let observedCredential=credential,retired=0,applicationThrows=true,definitions=[flow];
 vm.runInNewContext(source,{module,require:name=>{
  if(name==='node:assert/strict')return assert;
  if(name==='./beta-demo-resource-helpers')return {requireJson:async(_,route)=>route.includes('/credential-templates/')?observedCredential:route.includes('/application-templates/')?application:route.includes('/definitions?')?definitions:route.includes('/flows/definitions/')?flow:application,
   cleanupApplicationCredential:async()=>{if(applicationThrows)throw Error('ambiguous transactions');return {ok:true};}};
  if(name==='./demo-owned-configuration')return {createOwnedActiveConfiguration:async(_,owned,options)=>{created.push(options);return {id:'owned-application-template',credential_template_id:options.payload.credential_template_id};},retireOwnedConfiguration:async()=>{retired++;return {ok:true};}};
  throw Error(name);
 }});
 const inputs={organizationId:org,runId:'owned-run',credentialTemplateId:template,sourceApplicationTemplateId:sourceApplication,sourceFlowDefinitionId:flow.id,configurationId:'open_badge',vct:credential.vct};
 const control=module.exports.createOwnedMembership({},inputs);
 const result=await control.configure();assert.equal(result.flow.id,flow.id);assert.equal(control.owned.credentialTemplateId,template);
 assert.deepEqual(created.map(row=>row.collectionPath),['/v1/application-templates']);
 const failed=await control.cleanup();assert.equal(failed.complete,false);assert.equal(failed.configuration.ok,true);assert.equal(retired,1);assert.equal(failed.sharedFlowReadback.unchanged,true);assert.match(failed.failures[0].detail,/ambiguous transactions/);
 applicationThrows=false;const cleaned=await control.cleanup();assert.equal(cleaned.complete,true);assert.equal(cleaned.sharedTemplateReadback.unchanged,true);
 definitions=[flow,{...flow,id:'foreign'}];const conflicting=module.exports.createOwnedMembership({},inputs);await assert.rejects(conflicting.configure(),/One governed membership issuance Flow/);assert.equal(created.length,1);
 observedCredential={...credential,status:'DEPRECATED'};const changed=await control.cleanup();assert.equal(changed.complete,false);assert.equal(changed.failures[0].operation,'shared_authority_readback');
});
