// SPDX-License-Identifier: AGPL-3.0-only
import {afterEach,beforeEach,expect,it,vi} from 'vitest';
import {Route,Routes,MemoryRouter} from 'react-router';
import {renderWithoutRouter,screen,waitFor} from '@test/utils';
import AssociationConsentPage from './AssociationConsentPage';
const memory=vi.hoisted(()=>({code:'A'.repeat(43)}));
vi.mock('../../application/associations/consentCode',()=>({
 readAssociationConsentCode:()=>memory.code||null,clearAssociationConsentCode:()=>{memory.code='';},
}));
const org='10000000-0000-4000-8000-000000000001',challenge='20000000-0000-4000-8000-000000000002';
const key=`elevenid.association-consent.v1:${org}:${challenge}`;
const principal={authenticated:true,user:{user_id:'learner-one'}};
const current=(change={})=>({kind:'current',record:{challenge_id:challenge,source_id:'learning-source',binding_id:'binding-one',revision:1,
 phase:'pending',current:true,expired:false,expires_at_ms:Date.now()+120000,application_id:'application-one',subject_id:'subject-one',identity:null,can_relink:false,...change}});
const response=(value:unknown)=>new Response(JSON.stringify(value),{status:200,headers:{'content-type':'application/json','cache-control':'no-store'}});
let fetchMock:ReturnType<typeof vi.fn>;
beforeEach(()=>{window.sessionStorage.clear();memory.code='A'.repeat(43);fetchMock=vi.fn();vi.stubGlobal('fetch',fetchMock);});
afterEach(()=>{vi.unstubAllGlobals();});
function queue(...values:unknown[]) {for(const value of values)fetchMock.mockResolvedValueOnce(response(value));}
function mount() {return renderWithoutRouter(<MemoryRouter initialEntries={[`/console/identity/associations/${org}/${challenge}`]}>
 <Routes><Route path="/console/identity/associations/:organizationId/:challengeId" element={<AssociationConsentPage/>}/></Routes>
 </MemoryRouter>);}
it('renders exact current application and learner, and dispatches only after an explicit click',async()=>{
 queue(principal,current(),principal);const {user}=mount();
 const button=await screen.findByRole('button',{name:'Confirm connection'});
 expect(screen.getByText('Application: application-one')).toBeInTheDocument();
 expect(screen.getByText('Signed-in account: learner-one')).toBeInTheDocument();
 expect(fetchMock).toHaveBeenCalledTimes(3);expect(window.sessionStorage.length).toBe(0);
 queue(principal);fetchMock.mockImplementationOnce(async()=>{
  const i=JSON.parse(window.sessionStorage.getItem(key)!);return response({operation_id:i.operationId,challenge_id:challenge,
   action:'confirm',revision:2,phase:'confirmed'});
 });queue(current({phase:'confirmed',revision:2}),principal);
 await user.click(button);await screen.findByText('This connection is active.');
 expect(screen.queryByRole('button',{name:'Confirm connection'})).not.toBeInTheDocument();expect(memory.code).toBe('');
 expect(fetchMock.mock.calls.filter(c=>String(c[0]).endsWith('/confirm'))).toHaveLength(1);
});
it('keeps authentication in a separate tab with no proof in its link or browser storage',async()=>{
 queue({authenticated:false,user:null});mount();const login=await screen.findByRole('link',{name:'Sign in'});
 expect(login).toHaveAttribute('href','/console/login');expect(login).toHaveAttribute('target','_blank');
 expect(login).toHaveAttribute('rel','noopener noreferrer');expect(window.sessionStorage.length).toBe(0);
 expect(screen.queryByRole('button',{name:'Confirm connection'})).not.toBeInTheDocument();
});
it('a lost confirmation reply offers read-only recovery and reload never submits again',async()=>{
 queue(principal,current(),principal);const {user,unmount}=mount();const button=await screen.findByRole('button',{name:'Confirm connection'});
 queue(principal);fetchMock.mockRejectedValueOnce(new Error('lost write reply'));
 await user.click(button);await screen.findByText(/The reply was not confirmed/);expect(memory.code).toBe('');
 const i=JSON.parse(window.sessionStorage.getItem(key)!);unmount();
 queue(principal,{kind:'receipt',receipt:{operation_id:i.operationId,challenge_id:challenge,action:'confirm',revision:2,phase:'confirmed'}},
  current({phase:'confirmed',revision:2,current:false}),principal);mount();
 await waitFor(()=>expect(screen.queryByRole('progressbar')).not.toBeInTheDocument());
 expect(screen.queryByText('This connection is active.')).not.toBeInTheDocument();
 expect(fetchMock.mock.calls.filter(c=>String(c[0]).endsWith('/confirm'))).toHaveLength(1);
 expect(fetchMock.mock.calls.filter(c=>String(c[0]).endsWith('/receipt'))).toHaveLength(1);
});
it('offers explicit relink only for a current inactive identity and suppresses stale or missing-code consent',async()=>{
 queue(principal,current({current:false,can_relink:true,identity:{identity_id:challenge,revision:4,active:false}}),principal);
 const {unmount}=mount();await screen.findByRole('button',{name:'Reconnect this application'});
 expect(screen.queryByRole('button',{name:'Confirm connection'})).not.toBeInTheDocument();unmount();memory.code='';
 queue(principal,current(),principal);mount();await screen.findByText(/Reopen the connection/);
 expect(screen.queryByRole('button',{name:'Confirm connection'})).not.toBeInTheDocument();
});
