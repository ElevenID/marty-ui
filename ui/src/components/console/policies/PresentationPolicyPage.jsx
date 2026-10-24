import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle, LinearProgress, Paper, Stack, TextField, Typography } from '@mui/material';
import ResourcePage from '../../common/ResourcePage';
import { useConsole } from '../../../contexts/ConsoleContext';
import { usePermissions } from '../../../hooks/usePermissions';
import { activatePresentationPolicy, deletePresentationPolicy, getPresentationPolicy, suspendPresentationPolicy, updatePresentationPolicy } from '../../../services/presentationPolicyApi';

const BASE = '/console/org/policies/presentation';
const METADATA = { name: 'Name', description: 'Description', purpose: 'Purpose' };
const REQUIREMENTS = ['display_metadata', 'required_claims', 'accepted_credential_types', 'credential_requirements', 'alternative_requirements', 'trust_profile_id', 'compliance_profile_id', 'holder_binding', 'freshness', 'issuer_constraints', 'presentation_proof_required', 'credential_ranking_strategy', 'credential_ranking_weights', 'prefer_predicates', 'fallback_policy', 'supported_circuits', 'version'];
const fields = (policy) => Object.fromEntries(Object.keys(METADATA).map((key) => [key, policy[key] ?? '']));
const inScope = (policy, id, org) => policy?.id === id && policy.organization_id === org && typeof policy.name === 'string';

function PolicyContent({ organizationId, policyId, editing, can }) {
  const navigate = useNavigate();
  const alive = useRef(false);
  const [policy, setPolicy] = useState(null);
  const [values, setValues] = useState({ name: '', description: '', purpose: '' });
  const [initial, setInitial] = useState(values);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [attempt, setAttempt] = useState(0);
  const [deleteOpen, setDeleteOpen] = useState(false);
  useEffect(() => {
    let current = true; alive.current = true;
    setLoading(true); setError(''); setPolicy(null);
    getPresentationPolicy(policyId, { organization_id: organizationId }).then((result) => {
      if (!current) return;
      if (!inScope(result, policyId, organizationId)) throw new Error('This policy is not available in the selected organization.');
      setPolicy(result); const next = fields(result); setValues(next); setInitial(next);
    }).catch((failure) => { if (current) setError(failure?.message || 'Unable to load presentation policy.'); })
      .finally(() => { if (current) setLoading(false); });
    return () => { current = false; alive.current = false; };
  }, [organizationId, policyId, attempt]);

  const save = async (event) => {
    event.preventDefault();
    if (busy || policy?.status !== 'draft' || !can('presentation-policy', 'edit')) return;
    setError('');
    if (!values.name.trim()) { setError('Name is required.'); return; }
    const changes = Object.fromEntries(Object.keys(METADATA).filter((key) => values[key] !== initial[key]).map((key) => [key, values[key]]));
    if (!Object.keys(changes).length) { setError('No changes to save.'); return; }
    setBusy(true);
    try {
      const result = await updatePresentationPolicy(policyId, { organization_id: organizationId, ...changes });
      if (!alive.current) return;
      if (!inScope(result, policyId, organizationId)) throw new Error('The API returned a policy outside the selected organization.');
      navigate(`${BASE}/${encodeURIComponent(policyId)}`);
    } catch (failure) { if (alive.current) setError(failure?.message || 'Unable to save policy metadata.'); }
    finally { if (alive.current) setBusy(false); }
  };
  const lifecycle = async (action) => {
    if (busy || !policy || !can('presentation-policy', action)) return;
    if (action === 'delete' && policy.status !== 'draft') return;
    setBusy(true); setError('');
    try {
      if (action === 'delete') {
        await deletePresentationPolicy(policyId);
        if (alive.current) navigate(BASE);
      } else {
        const result = await (action === 'activate' ? activatePresentationPolicy : suspendPresentationPolicy)(policyId);
        if (!alive.current) return;
        if (!inScope(result, policyId, organizationId)) throw new Error('The API returned a policy outside the selected organization.');
        setPolicy(result);
      }
    } catch (failure) { if (alive.current) setError(failure?.message || 'Unable to change policy status.'); }
    finally { if (alive.current) { setBusy(false); setDeleteOpen(false); } }
  };
  return <ResourcePage title={editing ? 'Edit Presentation Policy' : policy?.name || 'Presentation Policy'}
    description={editing ? 'Update policy metadata.' : 'Inspect credential requirements, trust references and verification controls.'}
    breadcrumbs={[{ label: 'Presentation Policies', path: BASE }]}
    actions={<Button component={Link} to={BASE}>Back to policies</Button>}>
    {error && <Alert severity="error" sx={{ mb: 2 }}>{error}<Button disabled={busy} onClick={() => setAttempt((value) => value + 1)}>Reload</Button></Alert>}
    {loading ? <LinearProgress /> : !policy ? null : <Stack spacing={2}>
      <Chip sx={{ alignSelf: 'start' }} label={policy.status} />
      {editing && policy.status !== 'draft' ? <Alert severity="info">Only draft policies can be edited. This policy remains available for inspection.</Alert> : editing ? <Paper component="form" onSubmit={save} sx={{ p: 3 }}><Stack spacing={2}>
        {Object.entries(METADATA).map(([key, label]) => <TextField key={key} label={label} required={key === 'name'} value={values[key]} disabled={busy}
          multiline={key !== 'name'} minRows={key === 'name' ? undefined : 2}
          onChange={(event) => setValues((previous) => ({ ...previous, [key]: event.target.value }))} />)}
        <Button type="submit" variant="contained" disabled={busy}>{busy ? 'Saving...' : 'Save changes'}</Button>
      </Stack></Paper> : <>
        <Typography>{policy.description}</Typography><Typography>{policy.purpose}</Typography>
        <Stack direction="row" spacing={1}>
          {policy.status === 'draft' && can('presentation-policy', 'edit') && <Button component={Link} to={`${BASE}/${encodeURIComponent(policyId)}/edit`}>Edit metadata</Button>}
          {['draft', 'suspended'].includes(policy.status) && can('presentation-policy', 'activate') && <Button disabled={busy} onClick={() => lifecycle('activate')}>Activate policy</Button>}
          {policy.status === 'active' && can('presentation-policy', 'suspend') && <Button disabled={busy} onClick={() => lifecycle('suspend')}>Suspend policy</Button>}
          {policy.status === 'draft' && can('presentation-policy', 'delete') && <Button color="error" disabled={busy} onClick={() => setDeleteOpen(true)}>Delete policy</Button>}
        </Stack>
      </>}
      <Paper sx={{ p: 2 }}><Typography variant="h6">Verification requirements</Typography>
        <Box component="pre" sx={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(Object.fromEntries(REQUIREMENTS.filter((key) => policy[key] !== undefined).map((key) => [key, policy[key]])), null, 2)}</Box>
      </Paper>
    </Stack>}
    <Dialog open={deleteOpen} onClose={() => !busy && setDeleteOpen(false)}><DialogTitle>Delete presentation policy?</DialogTitle>
      <DialogContent>Delete {policy?.name}? Flows that reference this policy may become unavailable.</DialogContent>
      <DialogActions><Button disabled={busy} onClick={() => setDeleteOpen(false)}>Cancel</Button><Button disabled={busy} color="error" onClick={() => lifecycle('delete')}>Confirm deletion</Button></DialogActions>
    </Dialog>
  </ResourcePage>;
}

export default function PresentationPolicyPage({ mode = 'view' }) {
  const { activeOrgId } = useConsole();
  const { policyId } = useParams();
  const { can, isLoading } = usePermissions();
  if (!activeOrgId) return <Alert severity="error">Select an organization before opening a presentation policy.</Alert>;
  if (isLoading) return <LinearProgress />;
  const action = mode === 'edit' ? 'edit' : 'view';
  if (!can('presentation-policy', action)) return <Alert severity="error">You do not have permission to {action} presentation policies.</Alert>;
  return <PolicyContent key={`${activeOrgId}:${policyId}:${mode}`} organizationId={activeOrgId} policyId={policyId} editing={mode === 'edit'} can={can} />;
}
