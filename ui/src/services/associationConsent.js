// SPDX-License-Identifier: AGPL-3.0-only
// Same-origin public Gateway only. No shared SDK write retries or bearer credentials.
export class AssociationConsentError extends Error {
 constructor(code) {super('Association request could not be completed.');this.name='AssociationConsentError';this.code=code;}
}
const fail=code=>{throw new AssociationConsentError(code);};
const uuid=v=>typeof v==='string'&&/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(v)&&v!=='00000000-0000-0000-0000-000000000000';
const id=v=>typeof v==='string'&&/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(v);
const version=v=>Number.isSafeInteger(v)&&v>=1;
function exact(value,names) {
 if(value===null||typeof value!=='object'||![Object.prototype,null].includes(Object.getPrototypeOf(value)))fail('invalid_response');
 const d=Object.getOwnPropertyDescriptors(value),keys=Reflect.ownKeys(d);
 if(keys.length!==names.length||keys.some(k=>!names.includes(k)||!Object.hasOwn(d[k],'value')||!d[k].enumerable))fail('invalid_response');
 return Object.freeze(Object.fromEntries(keys.map(k=>[k,d[k].value])));
}
function parse(text) {
 const stack=[];
 for(let i=0;i<text.length;) {
  const char=text[i];
  if(char==='"') {
   const start=i++;while(i<text.length){if(text[i]==='\\')i+=2;else if(text[i++]==='"')break;}
   const value=JSON.parse(text.slice(start,i));if(!value.isWellFormed())fail('invalid_response');
   const parent=stack.at(-1);
   if(parent?.object&&parent.key){if(parent.keys.has(value))fail('invalid_response');parent.keys.add(value);parent.key=false;}
   continue;
  }
  if(char==='{'||char==='['){if(stack.length>=16)fail('invalid_response');stack.push({object:char==='{',key:true,keys:new Set()});}
  else if(char==='}'||char===']')stack.pop();else if(char===','&&stack.at(-1)?.object)stack.at(-1).key=true;i++;
 }
 return JSON.parse(text);
}
async function read(response,limit) {
 if(response.status!==200||response.redirected||!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(response.headers.get('content-type')??'')
  ||!/(?:^|,)\s*no-store\s*(?:,|$)/i.test(response.headers.get('cache-control')??''))fail('unavailable');
 if(!response.body||Number(response.headers.get('content-length')??0)>limit)fail('invalid_response');
 const reader=response.body.getReader(),chunks=[];let size=0;
 try {
  for(;;){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>limit)fail('invalid_response');chunks.push(value);}
  const bytes=new Uint8Array(size);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
  return parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
 }finally{try{await reader.cancel();}catch{/* A closed stream needs no further cancellation. */}reader.releaseLock();}
}
async function request(path,body,signal) {
 const response=await fetch(path,{method:body===undefined?'GET':'POST',credentials:'same-origin',cache:'no-store',
  redirect:'error',referrerPolicy:'no-referrer',signal,headers:{Accept:'application/json',...body===undefined?{}:{'Content-Type':'application/json'}},
  ...body===undefined?{}:{body:JSON.stringify(body)}});
 if(response.status===401)fail('authentication_required');return read(response,body===undefined?32768:8192);
}
async function actor(signal) {
 const result=await request('/v1/auth/me',undefined,signal);
 if(result?.authenticated!==true||!id(result.user?.user_id)||result.user?.impersonation||result.impersonation)fail('authentication_required');
 return result.user.user_id;
}
function record(value,challengeId) {
 const envelope=exact(value,['kind','record']);if(envelope.kind!=='current')fail('invalid_response');
 const r=exact(envelope.record,['challenge_id','source_id','binding_id','revision','phase','current','expired','expires_at_ms',
  'application_id','subject_id','identity','can_relink']);
 if(r.challenge_id!==challengeId||!id(r.source_id)||!id(r.binding_id)||!id(r.application_id)
  ||typeof r.subject_id!=='string'||r.subject_id.length<1||r.subject_id.length>1024||!r.subject_id.isWellFormed()
  ||!['pending','confirmed','denied','abandoned','expired'].includes(r.phase)||r.revision!==(r.phase==='pending'?1:2)
  ||!version(r.expires_at_ms)||typeof r.current!=='boolean'||typeof r.expired!=='boolean'||typeof r.can_relink!=='boolean'
  ||r.current&&!(r.phase==='confirmed'||r.phase==='pending'&&!r.expired))fail('invalid_response');
 let identity=null;
 if(r.identity!==null){identity=exact(r.identity,['identity_id','revision','active']);if(!uuid(identity.identity_id)||!version(identity.revision)||typeof identity.active!=='boolean')fail('invalid_response');}
 if(r.can_relink&&!(r.phase==='pending'&&!r.expired&&!r.current&&identity&&!identity.active))fail('invalid_response');
 return Object.freeze({...r,identity});
}
const intentNames=['version','organizationId','challengeId','userId','operationId','action','expectedRevision','expectedIdentityRevision'];
function intent(value,org,challenge) {
 const i=exact(value,intentNames);
 if(i.version!==1||i.organizationId!==org||i.challengeId!==challenge||!id(i.userId)||!uuid(i.operationId)
  ||!['confirm','deny','relink'].includes(i.action)||i.expectedRevision!==1
  ||(i.action==='relink'?!version(i.expectedIdentityRevision):i.expectedIdentityRevision!==null))fail('invalid_request');
 return i;
}
function receipt(value,i) {
 const r=exact(value,['operation_id','challenge_id','action','revision','phase']);
 if(r.operation_id!==i.operationId||r.challenge_id!==i.challengeId||r.action!==i.action||r.revision!==2
  ||r.phase!==(i.action==='deny'?'denied':'confirmed'))fail('invalid_response');return r;
}
function unlinkIntent(value,org,identityId,revision) {
 const i=exact(value,['version','organizationId','challengeId','identityId','userId','operationId','action','expectedRevision']);
 if(i.version!==1||i.organizationId!==org||!uuid(i.challengeId)||i.identityId!==identityId||i.expectedRevision!==revision
  ||i.action!=='unlink'||!id(i.userId)||!uuid(i.operationId))fail('invalid_request');return i;
}
function unlinkReceipt(value,i) {
 const r=exact(value,['operation_id','identity_id','action','revision','active']);
 if(r.operation_id!==i.operationId||r.identity_id!==i.identityId||r.action!=='unlink'||r.revision!==i.expectedRevision+1||r.active!==false)fail('invalid_response');return r;
}
export function createAssociationConsentClient(configuration) {
 const {organizationId,challengeId}=exact(configuration,['organizationId','challengeId']);
 if(!uuid(organizationId)||!uuid(challengeId))fail('invalid_request');
 const base=`/v1/organizations/${organizationId}/external-association-challenges/${challengeId}`;
 const journalKey=`elevenid.association-consent.v1:${organizationId}:${challengeId}`;
 const load=()=>{const saved=window.sessionStorage.getItem(journalKey);if(saved!==null&&saved.length>2048)fail('invalid_request');return saved===null?null:intent(parse(saved),organizationId,challengeId);};
 const unlinkKey=(identityId,revision)=>{
  if(!uuid(identityId)||!version(revision)||revision>=Number.MAX_SAFE_INTEGER)fail('invalid_request');
  return `elevenid.association-unlink.v1:${organizationId}:${identityId}:${revision}`;
 };
 const loadUnlink=(identityId,revision)=>{
  const saved=window.sessionStorage.getItem(unlinkKey(identityId,revision));if(saved!==null&&saved.length>2048)fail('invalid_request');
  return saved===null?null:unlinkIntent(parse(saved),organizationId,identityId,revision);
 };
 async function within(operation) {
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),15000);
  try{return await operation(controller.signal);}catch(error){if(error instanceof AssociationConsentError)throw error;fail('unavailable');}
  finally{clearTimeout(timer);}
 }
 async function current(userId,signal) {
  const r=record(await request(`${base}/inspect`,{},signal),challengeId);
  if(await actor(signal)!==userId)fail('authentication_required');return Object.freeze({userId,record:r});
 }
 async function unlinkCurrent(i,signal) {
  const result=await current(i.userId,signal);
  if(result.record.identity?.identity_id!==i.identityId)fail('invalid_response');return result;
 }
 return Object.freeze({
  hasRecovery:()=>load()!==null,
  hasUnlinkRecovery:(identityId,revision)=>loadUnlink(identityId,revision)!==null,
  recoverUnlink:(identityId,revision)=>within(async signal=>{
   const i=loadUnlink(identityId,revision);if(!i)fail('invalid_request');
   if(await actor(signal)!==i.userId)fail('authentication_required');
   const envelope=exact(await request(`/v1/organizations/${organizationId}/external-associations/${identityId}/receipt`,
    {operation_id:i.operationId},signal),['kind','receipt']);
   if(envelope.kind!=='receipt')fail('invalid_response');const original=unlinkReceipt(envelope.receipt,i);
   return Object.freeze({receipt:original,...await unlinkCurrent(i,signal)});
  }),
  unlink:(identityId,revision,expectedUserId)=>within(async signal=>{
   const key=unlinkKey(identityId,revision);if(!id(expectedUserId))fail('invalid_request');
   if(loadUnlink(identityId,revision)!==null)fail('recovery_required');
   const userId=await actor(signal);if(userId!==expectedUserId)fail('authentication_required');
   const i=unlinkIntent({version:1,organizationId,challengeId,identityId,userId,operationId:crypto.randomUUID(),action:'unlink',expectedRevision:revision},
    organizationId,identityId,revision);
   window.sessionStorage.setItem(key,JSON.stringify(i));if(JSON.stringify(loadUnlink(identityId,revision))!==JSON.stringify(i))fail('unavailable');
   try {
    const original=unlinkReceipt(await request(`/v1/organizations/${organizationId}/external-associations/${identityId}/unlink`,
     {operation_id:i.operationId,expected_revision:revision},signal),i);
    return Object.freeze({receipt:original,...await unlinkCurrent(i,signal)});
   }catch{fail('commit_unknown');}
  }),
  inspect:()=>within(async signal=>current(await actor(signal),signal)),
  recover:()=>within(async signal=>{
   const i=load();if(!i)fail('invalid_request');const userId=await actor(signal);
   if(userId!==i.userId)fail('authentication_required');
   const envelope=exact(await request(`${base}/receipt`,{operation_id:i.operationId},signal),['kind','receipt']);
   if(envelope.kind!=='receipt')fail('invalid_response');const original=receipt(envelope.receipt,i);
   return Object.freeze({receipt:original,...await current(userId,signal)});
  }),
  act:(action,code,expectedRevision,expectedIdentityRevision=null,expectedUserId)=>within(async signal=>{
   if(!['confirm','deny','relink'].includes(action)||typeof code!=='string'||!/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(code)
    ||expectedRevision!==1||!id(expectedUserId)||(action==='relink'?!version(expectedIdentityRevision):expectedIdentityRevision!==null))fail('invalid_request');
   if(load()!==null)fail('recovery_required');const userId=await actor(signal);
   if(userId!==expectedUserId)fail('authentication_required');
   const i=intent({version:1,organizationId,challengeId,userId,operationId:crypto.randomUUID(),action,expectedRevision,expectedIdentityRevision},organizationId,challengeId);
   // Persist only original-operation metadata. No raw code, provider identifier or response.
   window.sessionStorage.setItem(journalKey,JSON.stringify(i));
   if(JSON.stringify(load())!==JSON.stringify(i))fail('unavailable');
   const body={operation_id:i.operationId,expected_revision:expectedRevision,code,
    ...action==='relink'?{expected_identity_revision:expectedIdentityRevision}:{}};
   try {
    const original=receipt(await request(`${base}/${action}`,body,signal),i);
    return Object.freeze({receipt:original,...await current(userId,signal)});
   }catch{fail('commit_unknown');}
  }),
 });
}
