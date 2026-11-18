// SPDX-License-Identifier: AGPL-3.0-only
import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {createAssociationConsentClient} from '../associationConsent';
const organizationId='10000000-0000-4000-8000-000000000001',challengeId='20000000-0000-4000-8000-000000000002';
const code='A'.repeat(43),scope={organizationId,challengeId};
const key=`elevenid.association-consent.v1:${organizationId}:${challengeId}`;
const principal=(user='learner-one')=>({authenticated:true,user:{user_id:user}});
const current=(change={})=>({kind:'current',record:{challenge_id:challengeId,source_id:'source-one',binding_id:'binding-one',
 revision:1,phase:'pending',current:true,expired:false,expires_at_ms:Date.now()+120000,
 application_id:'application-one',subject_id:'urn:subject:one',identity:null,can_relink:false,...change}});
const reply=(body:unknown,status=200)=>new Response(typeof body==='string'?body:JSON.stringify(body),
 {status,headers:{'content-type':'application/json','cache-control':'no-store'}});
let fetchMock:ReturnType<typeof vi.fn>;
beforeEach(()=>{window.sessionStorage.clear();fetchMock=vi.fn();vi.stubGlobal('fetch',fetchMock);});
afterEach(()=>{vi.unstubAllGlobals();vi.restoreAllMocks();});
function queue(...values:unknown[]) {for(const value of values)fetchMock.mockResolvedValueOnce(reply(value));}
function mutationReply(action='confirm') {
 const saved=JSON.parse(window.sessionStorage.getItem(key)!);
 return {operation_id:saved.operationId,challenge_id:challengeId,action,revision:2,phase:action==='deny'?'denied':'confirmed'};
}
describe('public Gateway learner consent',()=>{
 it('binds all consent actions to the reviewed actor before journaling or dispatch',async()=>{
  for(const action of ['confirm','deny','relink']) {
   fetchMock.mockReset();queue(principal('another-learner'));
   await expect(createAssociationConsentClient(scope).act(action,code,1,action==='relink'?7:null,'learner-one'))
    .rejects.toMatchObject({code:'authentication_required'});
   expect(window.sessionStorage.length).toBe(0);expect(fetchMock).toHaveBeenCalledTimes(1);
   expect(fetchMock.mock.calls[0][0]).toBe('/v1/auth/me');
  }
 });
 it('inspects using only same-origin session routes and verifies the actor after current state',async()=>{
  queue(principal(),current(),principal());const result=await createAssociationConsentClient(scope).inspect();
  expect(result.record.application_id).toBe('application-one');expect(fetchMock.mock.calls.map(c=>c[0])).toEqual([
   '/v1/auth/me',`/v1/organizations/${organizationId}/external-association-challenges/${challengeId}/inspect`,'/v1/auth/me']);
  for(const [,options] of fetchMock.mock.calls){expect(options).toMatchObject({credentials:'same-origin',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer'});
   expect(JSON.stringify(options.headers)).not.toMatch(/authorization|api-key|x-user|x-organization/i);}
  expect(window.sessionStorage.length).toBe(0);
 });
 it('persists original operation metadata before one consent write and never stores the code',async()=>{
  queue(principal());fetchMock.mockImplementationOnce(async(path,options)=>{
   expect(path).toMatch(/\/confirm$/);const saved=JSON.parse(window.sessionStorage.getItem(key)!);
   expect(saved).toMatchObject({userId:'learner-one',organizationId,challengeId,action:'confirm',expectedRevision:1});
   expect(window.sessionStorage.getItem(key)).not.toContain(code);
   const body=JSON.parse(options.body);expect(body).toEqual({operation_id:saved.operationId,expected_revision:1,code});
   return reply(mutationReply());
  });queue(current({phase:'confirmed',revision:2}),principal());
  const client=createAssociationConsentClient(scope),result=await client.act('confirm',code,1,null,'learner-one');
  expect(result.record.phase).toBe('confirmed');expect(result.receipt.operation_id).toBe(JSON.parse(window.sessionStorage.getItem(key)!).operationId);
  await expect(client.act('confirm',code,1,null,'learner-one')).rejects.toMatchObject({code:'recovery_required'});
  expect(fetchMock).toHaveBeenCalledTimes(4);
 });
 it('recovers a lost reply through the original receipt and separate current read without write retry',async()=>{
  queue(principal());fetchMock.mockRejectedValueOnce(new Error('synthetic dropped reply'));
  const client=createAssociationConsentClient(scope);await expect(client.act('confirm',code,1,null,'learner-one')).rejects.toMatchObject({code:'commit_unknown'});
  const original=JSON.parse(window.sessionStorage.getItem(key)!);queue(principal(),{kind:'receipt',receipt:mutationReply()},
   current({phase:'confirmed',revision:2,current:false}),principal());
  const result=await createAssociationConsentClient(scope).recover();
  expect(result.record.current).toBe(false);expect(result.receipt.operation_id).toBe(original.operationId);
  expect(fetchMock.mock.calls.map(c=>String(c[0]).split('/').at(-1))).toEqual(['me','confirm','me','receipt','inspect','me']);
  expect(JSON.parse(fetchMock.mock.calls[3][1].body)).toEqual({operation_id:original.operationId});
 });
 it('classifies any failure after dispatch as uncertain, including wrong receipt and changed session',async()=>{
  for(const failure of ['http','receipt','actor']) {
   window.sessionStorage.clear();fetchMock.mockReset();queue(principal());
   fetchMock.mockImplementationOnce(async()=>failure==='http'?reply({},403):reply({...mutationReply(),...failure==='receipt'?{operation_id:challengeId}:{}}));
   if(failure==='actor')queue(current({phase:'confirmed',revision:2}),principal('another-learner'));
   await expect(createAssociationConsentClient(scope).act('confirm',code,1,null,'learner-one')).rejects.toMatchObject({code:'commit_unknown'});
   expect(JSON.parse(window.sessionStorage.getItem(key)!).action).toBe('confirm');
  }
 });
 it('rejects a different session before original receipt lookup',async()=>{
  queue(principal());fetchMock.mockRejectedValueOnce(new Error('lost'));const c=createAssociationConsentClient(scope);
  await expect(c.act('deny',code,1,null,'learner-one')).rejects.toMatchObject({code:'commit_unknown'});queue(principal('other'));
  await expect(c.recover()).rejects.toMatchObject({code:'authentication_required'});expect(fetchMock).toHaveBeenCalledTimes(3);
 });
 it('requires canonical scope and code, and rejects impersonated or unauthenticated sessions',async()=>{
  expect(()=>createAssociationConsentClient({...scope,organizationId:'../private'})).toThrow();
  expect(()=>createAssociationConsentClient({...scope,apiKey:'forbidden'})).toThrow();
  const c=createAssociationConsentClient(scope);await expect(c.act('confirm','A'.repeat(42)+'B',1)).rejects.toMatchObject({code:'invalid_request'});
  expect(fetchMock).not.toHaveBeenCalled();
  queue({authenticated:false,user:null});await expect(c.inspect()).rejects.toMatchObject({code:'authentication_required'});
  queue({authenticated:true,user:{user_id:'learner-one',impersonation:{active:true}}});
  await expect(c.inspect()).rejects.toMatchObject({code:'authentication_required'});
 });
 it('a journal storage failure prevents consent dispatch',async()=>{
  queue(principal());vi.spyOn(Storage.prototype,'setItem').mockImplementation(()=>{throw new Error('blocked storage');});
  await expect(createAssociationConsentClient(scope).act('confirm',code,1,null,'learner-one')).rejects.toMatchObject({code:'unavailable'});
  expect(fetchMock).toHaveBeenCalledTimes(1);
 });
 it('rejects duplicate keys, oversized bodies, redirects and identity-bearing malformed current state',async()=>{
  for(const value of [JSON.stringify(current()).replace('"kind":"current"','"kind":"receipt","kind":"current"'),
   ' '.repeat(8193),JSON.stringify(current({challenge_id:organizationId})),JSON.stringify(current({identity:{identity_id:challengeId,revision:1,active:true,secret:'no'}}))]) {
   fetchMock.mockReset();queue(principal(),value);await expect(createAssociationConsentClient(scope).inspect()).rejects.toBeDefined();
  }
  fetchMock.mockReset();queue(principal());fetchMock.mockResolvedValueOnce(reply({},302));
  await expect(createAssociationConsentClient(scope).inspect()).rejects.toBeDefined();
 });
 it('relink pins the current inactive identity revision and deny never needs authority overrides',async()=>{
  for(const action of ['relink','deny']) {
   window.sessionStorage.clear();fetchMock.mockReset();queue(principal());
   fetchMock.mockImplementationOnce(async(_path,options)=>{
    const body=JSON.parse(options.body);expect(body.expected_identity_revision).toBe(action==='relink'?7:undefined);
    expect(Object.keys(body)).toHaveLength(action==='relink'?4:3);return reply(mutationReply(action));
   });queue(current({phase:action==='deny'?'denied':'confirmed',revision:2,current:action!=='deny'}),principal());
   await createAssociationConsentClient(scope).act(action,code,1,action==='relink'?7:null,'learner-one');
  }
 });
});
