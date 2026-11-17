// SPDX-License-Identifier: AGPL-3.0-only
import {useEffect,useMemo,useRef,useState} from 'react';
import {useParams} from 'react-router';
import {Alert,Box,Button,CircularProgress,Link,Stack,Typography} from '@mui/material';
import {createAssociationConsentClient} from '../../services/associationConsent';
import {clearAssociationConsentCode,readAssociationConsentCode} from '../../application/associations/consentCode';

export default function AssociationConsentPage() {
 const {organizationId,challengeId}=useParams();
 const client=useMemo(()=>{try{return createAssociationConsentClient({organizationId,challengeId});}catch{return null;}},[organizationId,challengeId]);
 const latest=useRef(client),inFlight=useRef(false);
 const [state,setState]=useState({loading:true,result:null,error:null});
 useEffect(()=>{
  latest.current=client;inFlight.current=false;let active=true;
  setState({loading:true,result:null,error:null});
  if(!client){setState({loading:false,result:null,error:'invalid_request'});return undefined;}
  // Entry always reads. React strict mode and reloads cannot dispatch consent.
  const operation=Promise.resolve().then(()=>{
   if(client.hasRecovery()){clearAssociationConsentCode();return client.recover();}return client.inspect();
  });
  operation.then(result=>{if(result.record.phase!=='pending')clearAssociationConsentCode();if(active)setState({loading:false,result,error:null});},
   error=>{if(active)setState({loading:false,result:null,error:error.code??'unavailable'});});
  return ()=>{active=false;};
 },[client]);
 async function run(action) {
  if(!client||inFlight.current)return;inFlight.current=true;
  setState(previous=>({...previous,loading:true,error:null}));
  try {
   const code=readAssociationConsentCode(organizationId,challengeId),r=state.result?.record;
   const identity=r?.identity,unlinkRevision=identity?.active?identity.revision:identity?.revision-1;
   const recovery=state.recoveryContext??{identityId:identity?.identity_id,revision:unlinkRevision};
   const result=action==='read'?(client.hasRecovery()?await client.recover():await client.inspect())
    :action==='unlink'?await client.unlink(identity?.identity_id,unlinkRevision,state.result?.userId)
    :action==='recover-unlink'?await client.recoverUnlink(recovery.identityId,recovery.revision)
    :await client.act(action,code,r?.revision,action==='relink'?r?.identity?.revision:null,state.result?.userId);
   if(result.record.phase!=='pending'||action==='unlink'||action==='recover-unlink')clearAssociationConsentCode();
   if(latest.current===client)setState({loading:false,result,error:null});
  }catch(error){
   const identity=state.result?.record?.identity;
   const recoveryContext=action==='unlink'&&error.code==='commit_unknown'&&identity
    ?{identityId:identity.identity_id,revision:identity.revision}
    :action==='recover-unlink'?state.recoveryContext:null;
   if(latest.current===client)setState({loading:false,result:null,error:error.code??'unavailable',recoveryContext});
  }
  finally {
   try{if(client.hasRecovery())clearAssociationConsentCode();}catch{clearAssociationConsentCode();}
   if(action==='unlink'||action==='recover-unlink')clearAssociationConsentCode();
   if(latest.current===client)inFlight.current=false;
  }
 }
 const r=state.result?.record,code=readAssociationConsentCode(organizationId,challengeId);
 const pending=r?.phase==='pending'&&!r.expired&&r.expires_at_ms>Date.now();
 const canConfirm=pending&&r.current&&!!code,canRelink=pending&&r.can_relink&&!!code;
 let unlinkRecovery=!!state.recoveryContext,unlinkStorageUnavailable=false;
 if(client&&r?.identity) {
  const revision=r.identity.active?r.identity.revision:r.identity.revision-1;
  try{if(revision>0)unlinkRecovery=client.hasUnlinkRecovery(r.identity.identity_id,revision);}catch{unlinkStorageUnavailable=true;}
 }
 return <Box component="main" sx={{maxWidth:640,mx:'auto',p:3}}>
  <Stack spacing={2}>
   <Typography variant="h4" component="h1">Connect your learning account</Typography>
   <Typography>Review this connection while signed in to your own ElevenID account. Connecting does not verify learning results or issue a credential.</Typography>
   {state.loading&&<CircularProgress aria-label="Checking connection" size={28}/>}
   {state.error==='authentication_required'?<Alert severity="info">Sign in in a separate tab, then check this connection again. <Link href="/console/login" target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">Sign in</Link></Alert>
    :state.error&&<Alert severity="warning">{state.error==='commit_unknown'||state.error==='recovery_required'
     ?'The reply was not confirmed. Check the original request before taking another action.'
     :'The connection could not be checked. Return to the learning tool if the link has expired.'}</Alert>}
   {r&&<>
    <Typography>Signed-in account: {state.result.userId}</Typography>
    <Typography>Application: {r.application_id}</Typography>
    <Typography>Learning source: {r.source_id}</Typography>
    <Typography>Connection: {r.binding_id}</Typography>
    {r.phase==='confirmed'&&r.current?<Alert severity="success">This connection is active.</Alert>
     :r.phase==='confirmed'?<Alert severity="warning">This connection is no longer active.</Alert>
     :r.phase==='pending'?<Alert severity={r.current||r.can_relink?'info':'warning'}>{r.can_relink
      ?'This account was disconnected. Reconnecting requires your explicit consent for this application.'
      :r.current?'Confirm only if you recognize this learning account and application.':'This connection is no longer available.'}</Alert>
     :<Alert severity="info">This request is {r.phase}.</Alert>}
    {pending&&!code&&<Alert severity="info">Reopen the connection from your learning tool to provide a fresh confirmation code.</Alert>}
    {canConfirm&&<Button variant="contained" disabled={state.loading} onClick={()=>run('confirm')}>Confirm connection</Button>}
    {canRelink&&<Button variant="contained" disabled={state.loading} onClick={()=>run('relink')}>Reconnect this application</Button>}
    {pending&&!!code&&<Button disabled={state.loading} onClick={()=>run('deny')}>Decline connection</Button>}
    {r.identity?.active&&<>
     <Alert severity="warning">Disconnecting removes this learning account from every application. Reconnecting requires a fresh link from your learning tool.</Alert>
     {!unlinkRecovery&&<Button color="error" disabled={state.loading||unlinkStorageUnavailable} onClick={()=>run('unlink')}>Disconnect learning account</Button>}
    </>}
   </>}
   {unlinkRecovery&&<Button disabled={state.loading} onClick={()=>run('recover-unlink')}>Check disconnection</Button>}
   <Button disabled={!client||state.loading} onClick={()=>run('read')}>Check connection</Button>
  </Stack>
 </Box>;
}
