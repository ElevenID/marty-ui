import { useEffect, useRef, useState } from 'react';
import { useNavigate, useParams } from 'react-router';
import { Alert, Box, Button, Chip, CircularProgress, Container, Dialog, DialogActions, DialogContent, DialogContentText, DialogTitle, Paper, Stack, TextField, Typography } from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import { useConsole } from '../../../contexts/ConsoleContext';
import { usePermissions } from '../../../hooks/usePermissions';
import { activatePolicySet, archivePolicySet, getPolicySet, updatePolicySetMetadata } from '../../../services/policySetsApi';
import { requirePolicySet } from './policySetGuards';

function ScopedPolicySet({ organizationId, policySetId, canView, canCreate, canEdit, grantsLoading }) {
  const navigate = useNavigate();
  const [policySet, setPolicySet] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [requiresRefresh, setRequiresRefresh] = useState(false);
  const [revision, setRevision] = useState(0);
  const [action, setAction] = useState(null);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const mounted = useRef(false);
  const grants = useRef(null);
  grants.current = { canView, canCreate, canEdit, grantsLoading };
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => {
    let current = true;
    setPolicySet(null); setAction(null); setError(''); setLoading(true); setRequiresRefresh(false);
    if (canView && !grantsLoading) {
      getPolicySet(organizationId, policySetId)
        .then((record) => { const scoped = requirePolicySet(record, organizationId, policySetId); if (current) setPolicySet(scoped); })
        .catch((cause) => { if (current) setError(cause.message || 'Policy Set could not be loaded.'); })
        .finally(() => { if (current) setLoading(false); });
    }
    return () => { current = false; };
  }, [organizationId, policySetId, canView, grantsLoading, revision]);

  const patch = {};
  if (policySet && name.trim() !== policySet.name) patch.name = name.trim();
  if (policySet && (description.trim() || null) !== (policySet.description || null)) patch.description = description.trim() || null;
  const disabled = loading || busy || requiresRefresh || grantsLoading;
  const authorized = (operation) => grants.current.canView && !grants.current.grantsLoading
    && (operation === 'edit' ? grants.current.canEdit : grants.current.canCreate);
  const confirm = async () => {
    if (disabled || !action || !authorized(action) || (action === 'edit' && (!name.trim() || !Object.keys(patch).length))) return;
    const operation = action;
    setBusy(true); setError('');
    try {
      const fresh = requirePolicySet(await getPolicySet(organizationId, policySetId), organizationId, policySetId);
      if (!mounted.current || !authorized(operation)) return;
      if (['status', 'updated_at', 'name', 'description'].some((key) => fresh[key] !== policySet[key])) {
        throw new Error('Policy Set changed. Refresh and review it before making changes.');
      }
      if ((operation === 'edit' || operation === 'activate') && fresh.status !== 'DRAFT') throw new Error('The Policy Set is no longer a draft.');
      if (operation === 'archive' && fresh.status !== 'ACTIVE') throw new Error('The Policy Set is no longer active.');
      const result = operation === 'edit' ? await updatePolicySetMetadata(organizationId, policySetId, patch)
        : await (operation === 'activate' ? activatePolicySet : archivePolicySet)(organizationId, policySetId);
      const scoped = requirePolicySet(result, organizationId, policySetId);
      if (mounted.current) { setPolicySet(scoped); setAction(null); }
    } catch (cause) {
      if (mounted.current) { setAction(null); setRequiresRefresh(true); setError(`${cause.message || 'Request failed.'} Refresh before making another change.`); }
    } finally { if (mounted.current) setBusy(false); }
  };

  return <Container maxWidth="md" sx={{ py: 4 }}>
    <Stack direction="row" justifyContent="space-between" sx={{ mb: 2 }}>
      <Button startIcon={<ArrowBackIcon />} onClick={() => navigate('/console/org/policies/sets')}>Policy Sets</Button>
      {canView && <Button disabled={busy || grantsLoading} onClick={() => setRevision((value) => value + 1)}>Refresh</Button>}
    </Stack>
    {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
    {grantsLoading ? <CircularProgress /> : !canView ? <Alert severity="warning">You do not have permission to view Policy Sets in this organization.</Alert>
      : loading ? <Box sx={{ textAlign: 'center', py: 8 }}><CircularProgress /></Box> : policySet && <>
        <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" gap={2} sx={{ mb: 3 }}>
          <Box><Typography variant="h4">{policySet.name}</Typography><Typography color="text.secondary">{policySet.description}</Typography>
            <Stack direction="row" gap={1} sx={{ mt: 1 }}><Chip label={policySet.status} color={policySet.status === 'ACTIVE' ? 'success' : 'default'} /><Chip label={policySet.policy_type} variant="outlined" /><Chip label={policySet.cedar_schema_version} variant="outlined" /></Stack>
          </Box>
          <Stack direction="row" spacing={1} alignItems="center">
            {policySet.status === 'DRAFT' && canEdit && <Button disabled={disabled} onClick={() => { setName(policySet.name); setDescription(policySet.description || ''); setAction('edit'); }}>Edit metadata</Button>}
            {policySet.status === 'DRAFT' && canCreate && <Button variant="contained" disabled={disabled} onClick={() => setAction('activate')}>Activate</Button>}
            {policySet.status === 'ACTIVE' && canCreate && <Button variant="outlined" disabled={disabled} onClick={() => setAction('archive')}>Archive</Button>}
          </Stack>
        </Stack>
        <Stack spacing={2}>{policySet.cedar_policies.map((policy) => <Paper key={policy.policy_id} variant="outlined" sx={{ p: 2.5 }}>
          <Stack direction="row" justifyContent="space-between" alignItems="center"><Typography variant="subtitle1" fontWeight={600}>{policy.description || policy.policy_id}</Typography><Chip label={policy.effect} size="small" color={policy.effect === 'forbid' ? 'error' : 'success'} variant="outlined" /></Stack>
          <Typography variant="caption" color="text.secondary">{policy.policy_id}</Typography><Box component="pre" sx={{ mt: 2, mb: 0, p: 2, overflow: 'auto', bgcolor: 'grey.50', fontSize: 12, whiteSpace: 'pre-wrap' }}>{policy.cedar_text}</Box>
        </Paper>)}</Stack>
      </>}
    <Dialog open={Boolean(action) && canView && !grantsLoading && authorized(action)} onClose={() => { if (!busy) setAction(null); }} fullWidth maxWidth="sm">
      <DialogTitle>{action === 'edit' ? 'Edit Policy Set metadata' : action === 'activate' ? 'Activate Policy Set' : 'Archive Policy Set'}</DialogTitle>
      <DialogContent>{action === 'edit' ? <Stack spacing={2} sx={{ pt: 1 }}>
        <TextField required label="Name" value={name} disabled={busy} onChange={(event) => setName(event.target.value)} slotProps={{ htmlInput: { maxLength: 128 } }} />
        <TextField label="Description" value={description} disabled={busy} multiline minRows={2} onChange={(event) => setDescription(event.target.value)} slotProps={{ htmlInput: { maxLength: 1024 } }} />
      </Stack> : <DialogContentText>{action === 'activate' ? 'Activate these Cedar policies for the selected organization. Review their permissions and conditions before applying them.' : 'Archive this Policy Set so it no longer contributes to authorization decisions for the selected organization.'}</DialogContentText>}</DialogContent>
      <DialogActions><Button disabled={busy} onClick={() => setAction(null)}>Back</Button><Button onClick={confirm} disabled={disabled || (action === 'edit' && (!name.trim() || !Object.keys(patch).length))}>{action === 'edit' ? 'Save changes' : action === 'activate' ? 'Confirm activation' : 'Confirm archive'}</Button></DialogActions>
    </Dialog>
  </Container>;
}

export default function PolicySetDetailPage() {
  const { policySetId } = useParams();
  const { activeOrgId: organizationId } = useConsole();
  const { can, isLoading } = usePermissions();
  if (!organizationId) return <Alert severity="info">Select an organization to inspect its Policy Sets.</Alert>;
  return <ScopedPolicySet key={`${organizationId}:${policySetId}`} organizationId={organizationId} policySetId={policySetId}
    canView={can('policy-set', 'view')} canCreate={can('policy-set', 'create')} canEdit={can('policy-set', 'edit')} grantsLoading={isLoading} />;
}
