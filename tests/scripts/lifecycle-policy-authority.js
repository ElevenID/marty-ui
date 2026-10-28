'use strict';
const assert = require('node:assert/strict');
const REQUIRED_CLAIMS = ['employeeId', 'givenName', 'familyName', 'department'];
function requireLifecyclePolicySelection(environment=process.env) {
  const value=environment.BETA_AUDIT_POLICY_ID;
  assert(typeof value==='string'&&value.length>0&&value.length<=255&&value.trim()===value&&!/[\x00-\x1f\x7f]/.test(value),
    'Live lifecycle runs require an explicit governed BETA_AUDIT_POLICY_ID');
  return value;
}
function validateLifecyclePolicyAuthority(expected, observed) {
  const {policy,template,trust,issuers,relationships}=observed;
  if(expected.requestedClaims!==undefined)assert.deepEqual(expected.requestedClaims,REQUIRED_CLAIMS);
  if(expected.verifierHolderBindingRequired!==undefined)assert.equal(expected.verifierHolderBindingRequired,false);
  const active=(row,id)=>assert(row&&row.id===id&&row.organization_id===expected.organizationId
    &&String(row.status).toUpperCase()==='ACTIVE','Lifecycle authority must be exact, active and organization-owned');
  active(template,expected.templateId);active(policy,expected.policyId);
  assert.equal(template.credential_payload_format,'SD_JWT_VC');
  assert(typeof template.vct==='string'&&template.vct&&typeof template.issuer_did==='string'&&template.issuer_did,'Template VCT and issuer are required');
  for(const [field,key] of [['vct','vct'],['issuerDid','issuer_did']])if(expected[field]!==undefined)assert.equal(template[key],expected[field]);
  if(expected.trustProfileId!==undefined)assert.equal(policy.trust_profile_id,expected.trustProfileId);
  active(trust,policy.trust_profile_id);
  assert.deepEqual(trust.trust_sources||[],[],'This governed policy requires explicit local issuer trust');
  assert.deepEqual(trust.system_issuer_overrides||{},{} ,'Unreviewed system issuer overrides are unsupported');
  assert(trust.supported_formats?.includes('SD_JWT_VC')&&trust.allowed_algorithms?.includes('ES256'),'Trust must permit the actual format and algorithm');
  assert(Array.isArray(policy.credential_requirements)&&policy.credential_requirements.length===1,'One exact lifecycle credential requirement is required');
  assert.deepEqual(policy.alternative_requirements||[],[],'Alternative credentials are outside this lifecycle contract');
  const requirement=policy.credential_requirements[0];
  assert.equal(requirement.credential_template_id,template.id);assert.equal(requirement.required,true);
  assert.equal(requirement.credential_payload_format,'SD_JWT_VC');
  assert(!requirement.trust_profile_id||requirement.trust_profile_id===trust.id,'Requirement trust must match policy trust');
  assert(!requirement.issuer_constraints||Object.keys(requirement.issuer_constraints).length===0,'Unreviewed issuer constraints are unsupported');
  assert.deepEqual(policy.accepted_credential_types,[template.id]);
  const names=new Set(template.claims?.map(claim=>claim.name));
  assert(Array.isArray(requirement.requested_claims)&&requirement.requested_claims.length===REQUIRED_CLAIMS.length,'Exact employee claim contract is required');
  for(const name of REQUIRED_CLAIMS){const matches=requirement.requested_claims.filter(claim=>claim.claim_name===name);
    assert(names.has(name)&&matches.length===1&&matches[0].required===true,'Required employee claim is missing');
    assert.deepEqual(matches[0].constraints||[],[],'Unreviewed claim constraints are unsupported');}
  assert.equal(policy.holder_binding?.required,false,'This reviewed policy does not assert verifier holder binding');
  assert(Array.isArray(issuers)&&Array.isArray(relationships),'Actual issuer relationships are required');
  const matching=issuers.filter(row=>row.issuer_id===template.issuer_did
    &&(row.organization_id===expected.organizationId||(row.organization_id===null&&row.is_system_issuer===true)));
  assert(matching.length===1,'Exact governed issuer entity is required');
  assert(relationships.every(row=>row.trust_profile_id===trust.id),'Foreign trust relationship returned');
  assert(relationships.some(row=>row.issuer_id===matching[0].id&&row.relationship_status==='TRUSTED'),'Selected issuer is not explicitly trusted');
  assert(!(trust.denied_issuers||[]).includes(template.issuer_did),'Selected issuer is denied');
  return {policyId:policy.id,templateId:template.id,trustProfileId:trust.id,issuerDid:template.issuer_did,
    vct:template.vct,requestedClaims:[...REQUIRED_CLAIMS],verifierHolderBindingRequired:false};
}
async function readLifecyclePolicyAuthority(read,expected){
  const get=async route=>{const result=await read(route);assert(result.ok,'Lifecycle authority read failed');return result.body;};
  const template=await get('/v1/credential-templates/'+encodeURIComponent(expected.templateId));
  const policy=await get('/v1/presentation-policies/'+encodeURIComponent(expected.policyId));
  assert(typeof policy.trust_profile_id==='string'&&policy.trust_profile_id,'Exact policy trust is required');
  const trust=await get('/v1/trust-profiles/'+encodeURIComponent(policy.trust_profile_id));
  const relationships=await get('/v1/trust-profiles/'+encodeURIComponent(policy.trust_profile_id)+'/issuers');
  const issuers=await get('/v1/issuer-entities?organization_id='+encodeURIComponent(expected.organizationId));
  return validateLifecyclePolicyAuthority(expected,{template,policy,trust,relationships,issuers});
}
module.exports={requireLifecyclePolicySelection,validateLifecyclePolicyAuthority,readLifecyclePolicyAuthority};
