import { useEffect, useRef, useState } from 'react';
import { Alert, Box, Button, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, MenuItem, Paper, Stack, Table, TableBody, TableCell, TableHead, TableRow, TextField, Typography } from '@mui/material';
import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import { usePermissions } from '../../../hooks/usePermissions';
import { isAgentTrustFeatureEnabled } from '../../../application/agentTrustFeatures';
import { agentTrustErrorMessage, changeAgentIdentity, isAgentTrustId, listAgentHistory, listAgentIdentities, registerAgentIdentity, updateAgentIdentity, validateAgentPublicKey } from '../../../services/agentTrustApi';

const emptyForm = { kind: 'EXTERNAL', display_name: '', description: '', logical_application_ref: '', issuer: '', subject: '', runtime_instance_ref: '', public_key_jwk: '' };
const actionLabels = { register: 'Register identity', update: 'Edit metadata', suspend: 'Suspend access', revoke: 'Revoke identity', retire: 'Retire identity', 'rotate-key': 'Replace public key' };
function publicKey(text) {
  return validateAgentPublicKey(JSON.parse(text));
}

function Directory({ organizationId, can }) {
  const [page, setPage] = useState({ items: [], total: 0 });
  const [offset, setOffset] = useState(0); const [reload, setReload] = useState(0);
  const [loading, setLoading] = useState(true); const [busy, setBusy] = useState(false);
  const [stateVerified, setStateVerified] = useState(false);
  const [error, setError] = useState(null); const [formError, setFormError] = useState(null);
  const [uncertainMutation, setUncertainMutation] = useState(false);
  const [dialog, setDialog] = useState(null); const [form, setForm] = useState(emptyForm);
  const [history, setHistory] = useState(null);
  const pending = useRef(false); const generation = useRef(0); const alive = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; generation.current += 1; }; }, []);
  useEffect(() => {
    const scope = ++generation.current; setLoading(true); setStateVerified(false); setError(null); setPage({ items: [], total: 0 });
    listAgentIdentities(organizationId, offset).then(result => {
      if (alive.current && generation.current === scope) { setPage(result); setLoading(false); setStateVerified(true); setUncertainMutation(false); }
    }, failure => { if (alive.current && generation.current === scope) { setError(failure); setLoading(false); } });
    return () => { generation.current += 1; };
  }, [organizationId, offset, reload]);
  function open(action, identity) {
    if (busy || !stateVerified || uncertainMutation) return;
    setError(null); setFormError(null); setHistory(null);
    setDialog({ action, identity });
    setForm(identity ? { ...emptyForm, ...identity.metadata } : { ...emptyForm });
  }
  async function submit(event) {
    event.preventDefault();
    if (!dialog || pending.current || !can('agent-identity', dialog.action === 'register' ? 'create' : dialog.action)) return;
    if (uncertainMutation || !stateVerified) return;
    let key;
    try { if (['register', 'rotate-key'].includes(dialog.action)) key = publicKey(form.public_key_jwk); }
    catch { setFormError('Enter a public ES256 or Ed25519 JWK. Private or symmetric keys cannot be sent. Unrecognized fields are rejected.'); return; }
    pending.current = true; setBusy(true); setError(null); setFormError(null);
    try {
      if (dialog.action === 'register') await registerAgentIdentity(organizationId, { ...form, public_key_jwk: key });
      else if (dialog.action === 'update') await updateAgentIdentity(organizationId, dialog.identity, {
        display_name: form.display_name, description: form.description, logical_application_ref: form.logical_application_ref,
      });
      else await changeAgentIdentity(organizationId, dialog.identity, dialog.action, key);
      if (alive.current) { setDialog(null); setReload(value => value + 1); }
    } catch (failure) { if (alive.current) {
      // An unverified successful reply is as uncertain as a lost reply. Keep
      // writes blocked across dialog dismissal until a fresh list succeeds.
      if (['commit_unknown', 'invalid_response'].includes(failure?.code)) setUncertainMutation(true);
      setError(failure);
    } }
    finally { if (alive.current) { pending.current = false; setBusy(false); } }
  }
  async function inspect(identity) {
    if (pending.current) return;
    pending.current = true; setBusy(true); setError(null);
    const scope = generation.current;
    try {
      const result = await listAgentHistory(organizationId, identity.id);
      if (alive.current && generation.current === scope) setHistory({ identity, ...result });
    } catch (failure) { if (alive.current && generation.current === scope) setError(failure); }
    finally { if (alive.current) { pending.current = false; setBusy(false); } }
  }
  const editField = (name, label, options = {}) => <TextField label={label} value={form[name] ?? ''} disabled={busy}
    onChange={event => setForm(previous => ({ ...previous, [name]: event.target.value }))} {...options} />;
  return <Stack spacing={2}>
    <Stack direction="row" spacing={2} sx={{ justifyContent: 'space-between', alignItems: 'center' }}>
      <Typography variant="h4" component="h1">Agent identities</Typography>
      {can('agent-identity', 'create') && <Button variant="contained" disabled={busy || !stateVerified || uncertainMutation} onClick={() => open('register')}>Register identity</Button>}
    </Stack>
    <Typography>Manage identity ownership, public keys and access eligibility. Runs, prompts and tasks are managed in the connected application.</Typography>
    <Alert severity="info">Enabled directory entries still require current authentication and authority checks. Managed entries await enrollment before they can be used.</Alert>
    {(loading || busy) && <CircularProgress size={24} aria-label="Loading agent identities" />}
    {error && !dialog && <Alert severity="error">{agentTrustErrorMessage(error)}</Alert>}
    {uncertainMutation && !dialog && <Alert severity="warning">The previous change may have been recorded. Reload and inspect the current identities before making another change.</Alert>}
    <Button variant="outlined" disabled={busy || loading} onClick={() => { setHistory(null); setReload(value => value + 1); }}>Reload current state</Button>
    {!loading && <Paper variant="outlined" sx={{ overflowX: 'auto' }}><Table aria-label="Agent identity directory">
      <TableHead><TableRow><TableCell>Identity</TableCell><TableCell>Access eligibility</TableCell><TableCell>Owner at registration</TableCell><TableCell>Runtime activity</TableCell><TableCell>Actions</TableCell></TableRow></TableHead>
      <TableBody>{page.items.map(identity => <TableRow key={identity.id}>
        <TableCell><Typography fontWeight={600}>{identity.metadata.display_name}</Typography><Typography variant="body2">{identity.kind === 'EXTERNAL' ? 'External principal' : 'Managed inventory'}</Typography><Typography variant="caption" sx={{ overflowWrap: 'anywhere' }}>{identity.principal.id}</Typography></TableCell>
        <TableCell>{({ ACTIVE: 'Enabled', PROVISIONED: 'Enrollment pending', SUSPENDED: 'Suspended', REVOKED: 'Revoked', RETIRED: 'Retired' })[identity.status]}<Typography variant="caption" display="block">Authority requires a separate check</Typography></TableCell>
        <TableCell sx={{ overflowWrap: 'anywhere' }}>{identity.owner_user_id}</TableCell>
        <TableCell>Managed by your application</TableCell>
        <TableCell><Stack direction="row" spacing={1} useFlexGap sx={{ flexWrap: 'wrap' }}>
          <Button size="small" disabled={busy} onClick={() => inspect(identity)}>Inspect history</Button>
          {['update', 'rotate-key', 'suspend', 'revoke', 'retire'].filter(action => can('agent-identity', action)
            && (action === 'retire' ? identity.status !== 'RETIRED' : !['REVOKED', 'RETIRED'].includes(identity.status))
            && (action !== 'suspend' || identity.status !== 'SUSPENDED')).map(action => <Button size="small" key={action} disabled={busy || uncertainMutation} onClick={() => open(action, identity)}>{actionLabels[action]}</Button>)}
        </Stack></TableCell>
      </TableRow>)}{!page.items.length && <TableRow><TableCell colSpan={5}>No agent identities are listed.</TableCell></TableRow>}</TableBody>
    </Table></Paper>}
    <Stack direction="row" spacing={2} sx={{ alignItems: 'center' }}><Button disabled={loading || busy || uncertainMutation || offset === 0} onClick={() => setOffset(value => Math.max(0, value - 50))}>Previous</Button><Typography>{page.total} identities</Typography><Button disabled={loading || busy || uncertainMutation || offset + page.items.length >= page.total} onClick={() => setOffset(value => value + 50)}>Next</Button></Stack>
    {history && <Paper variant="outlined" sx={{ p: 2, overflowWrap: 'anywhere' }}>
      <Typography variant="h6" component="h2">{history.identity.metadata.display_name}: administrative history</Typography>
      <Typography>Source issuer: {history.identity.issuer}</Typography><Typography>Source subject: {history.identity.subject}</Typography>
      <Typography>Runtime reference: {history.identity.runtime_instance_ref}</Typography>
      <Typography>Application reference: {history.identity.metadata.logical_application_ref}</Typography>
      <Typography variant="body2">Source details are operator declarations. Registration does not verify an external issuer or host.</Typography>
      {history.items.map(event => <Box key={event.revision} sx={{ mt: 2 }}>
        <Typography>Revision {event.revision}: {event.action} by {event.actor_user_id} at {event.occurred_at}</Typography>
        {event.snapshot.keys.map(key => <Typography key={key.key_id} variant="body2">Public key fingerprint ({key.fingerprint.basis}): {key.fingerprint.value}</Typography>)}
      </Box>)}
      {history.total > history.items.length && <Typography variant="body2">Showing the first {history.items.length} historical revisions. Further history is available through the directory API.</Typography>}
    </Paper>}
    <Dialog open={!!dialog} onClose={() => { if (!busy) setDialog(null); }} fullWidth maxWidth="sm">
      <Box component="form" onSubmit={submit}>
        <DialogTitle>{actionLabels[dialog?.action]}</DialogTitle><DialogContent><Stack spacing={2} sx={{ pt: 1 }}>
          {error && <Alert severity="error">{agentTrustErrorMessage(error)}</Alert>}{formError && <Alert severity="error">{formError}</Alert>}
          {dialog?.identity && <Typography>{dialog.identity.metadata.display_name} · Revision {dialog.identity.revision}</Typography>}
          {dialog?.action === 'register' && <TextField select label="Identity kind" value={form.kind} onChange={event => setForm(previous => ({ ...previous, kind: event.target.value }))} disabled={busy}>
            <MenuItem value="EXTERNAL">External principal</MenuItem><MenuItem value="MANAGED">Managed inventory awaiting enrollment</MenuItem>
          </TextField>}
          {['register', 'update'].includes(dialog?.action) && <>{editField('display_name', 'Display name', { required: true })}{editField('description', 'Description', { multiline: true, minRows: 2 })}{editField('logical_application_ref', 'Logical application reference', { required: true })}</>}
          {dialog?.action === 'register' && <>{editField('issuer', 'Declared source issuer', { required: true })}{editField('subject', 'Source subject', { required: true })}{editField('runtime_instance_ref', 'Runtime instance reference', { required: true })}<Typography variant="body2">The organization owner and your administrator attribution are assigned by Marty.</Typography></>}
          {['register', 'rotate-key'].includes(dialog?.action) && editField('public_key_jwk', 'Public JWK', { required: true, multiline: true, minRows: 5 })}
          {dialog?.action === 'rotate-key' && <Alert severity="warning">The previous key will no longer match current identity lookup. Existing grant bindings remain unchanged and require new approval for the replacement key.</Alert>}
          {['suspend', 'revoke', 'retire'].includes(dialog?.action) && <Alert severity="warning">This changes access eligibility for new uses. Your application continues to manage running tasks. {dialog?.action === 'suspend' ? 'There is no resume action for a suspended identity.' : 'This lifecycle change is permanent.'}</Alert>}
        </Stack></DialogContent><DialogActions>
          <Button disabled={busy} onClick={() => setDialog(null)}>Cancel</Button>
          {uncertainMutation ? <Button disabled={busy} onClick={() => { setDialog(null); setReload(value => value + 1); }}>Reload current state</Button>
            : <Button variant="contained" type="submit" disabled={busy}>{actionLabels[dialog?.action]}</Button>}
        </DialogActions>
      </Box>
    </Dialog>
  </Stack>;
}

export default function AgentDirectoryPage() {
  const { activeOrgId } = useConsole(); const { user } = useAuth();
  const { can, isLoading, error, refresh } = usePermissions();
  const actorId = user?.user_id || user?.sub || user?.id;
  if (!isAgentTrustFeatureEnabled('agentDirectory')) return <Alert severity="info">Agent identity administration is not enabled in this application.</Alert>;
  if (isLoading) return <CircularProgress aria-label="Checking permissions" />;
  if (error) return <Alert severity="error" action={<Button color="inherit" onClick={refresh}>Retry</Button>}>Agent identity permissions could not be checked.</Alert>;
  if (!can('agent-identity', 'view')) return <Alert severity="error">You do not have permission to view agent identities in this organization.</Alert>;
  if (!isAgentTrustId(activeOrgId) || !actorId) return <Alert severity="info">Select an organization to manage its agent identities.</Alert>;
  return <Box sx={{ p: 3 }}><Directory key={`${activeOrgId}:${actorId}`} organizationId={activeOrgId} can={can} /></Box>;
}
