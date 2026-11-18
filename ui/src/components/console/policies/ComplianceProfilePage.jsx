import { useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { Alert, Box, Button, Checkbox, Chip, Dialog, DialogActions, DialogContent, DialogTitle, FormControlLabel, LinearProgress, MenuItem, Paper, Stack, TextField, Typography } from '@mui/material';
import ResourcePage from '../../common/ResourcePage';
import { useConsole } from '../../../contexts/ConsoleContext';
import { usePermissions } from '../../../hooks/usePermissions';
import { activateComplianceProfile, createComplianceProfile, deleteComplianceProfile, getComplianceProfile, getSystemPresets, suspendComplianceProfile, updateComplianceProfile } from '../../../services/complianceProfilesApi';

const BASE = '/console/org/policies/compliance';
const SCALARS = ['name', 'description', 'compliance_code', 'credential_format', 'issuance_protocol', 'verification_policy_set_id'];
const NESTED = ['issuer_artifact_requirements', 'trust_profile_constraints', 'api_surface'];
const LABELS = {
  name: 'Name', description: 'Description', compliance_code: 'Compliance code', credential_format: 'Credential format',
  issuance_protocol: 'Issuance protocol', verification_policy_set_id: 'Verification policy set ID',
  issuer_artifact_requirements: 'Issuer artifact requirements', trust_profile_constraints: 'Trust profile constraints', api_surface: 'API surface',
};
function inScope(profile, org) {
  return typeof profile?.id === 'string' && typeof profile?.name === 'string'
    && (profile.is_system === true ? profile.organization_id == null : profile.organization_id === org);
}
function draft(profile = {}) {
  return { ...Object.fromEntries(SCALARS.map((field) => [field, profile[field] ?? ''])),
    discoverable: profile.discoverable ?? true,
    ...Object.fromEntries(NESTED.map((field) => [field, JSON.stringify(profile[field] ?? (field === 'api_surface' ? [] : {}), null, 2)])),
  };
}
function requestBody(values, initial, creating) {
  if (!values.name.trim() || !values.credential_format.trim()) throw new Error('Name and credential format are required.');
  const result = {};
  for (const field of SCALARS) {
    if (creating ? values[field] !== '' : values[field] !== initial[field]) {
      if (!creating && ['issuance_protocol', 'verification_policy_set_id'].includes(field) && !values[field].trim()) {
        throw new Error(`${LABELS[field]} cannot be cleared; choose a replacement value.`);
      }
      result[field] = values[field];
    }
  }
  if (creating || values.discoverable !== initial.discoverable) result.discoverable = values.discoverable;
  for (const field of NESTED) {
    let value;
    try { value = JSON.parse(values[field]); } catch { throw new Error(`${LABELS[field]} must be valid JSON.`); }
    if (field === 'api_surface' ? !Array.isArray(value) : !value || Array.isArray(value) || typeof value !== 'object') {
      throw new Error(`${LABELS[field]} must be a JSON ${field === 'api_surface' ? 'array' : 'object'}.`);
    }
    if (creating || JSON.stringify(value) !== JSON.stringify(JSON.parse(initial[field]))) result[field] = value;
  }
  return result;
}

function ComplianceProfileContent({ organizationId, profileId, mode, can }) {
  const navigate = useNavigate();
  const creating = mode === 'create', editing = mode !== 'view';
  const alive = useRef(false);
  const [attempt, setAttempt] = useState(0);
  const [loading, setLoading] = useState(true);
  const [profile, setProfile] = useState(null);
  const [presets, setPresets] = useState([]);
  const [values, setValues] = useState(() => draft());
  const [initial, setInitial] = useState(() => draft());
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  useEffect(() => {
    let current = true; alive.current = true;
    setLoading(true); setError('');
    const load = creating ? getSystemPresets({ organization_id: organizationId }) : getComplianceProfile(profileId);
    load.then((result) => {
      if (!current) return;
      if (creating) { setPresets(result); return; }
      if (!inScope(result, organizationId) || result.id !== profileId) throw new Error('This profile is not available in the selected organization.');
      setProfile(result); const next = draft(result); setValues(next); setInitial(next);
    }).catch((failure) => { if (current) setError(failure?.message || 'Unable to load compliance profiles.'); })
      .finally(() => { if (current) setLoading(false); });
    return () => { current = false; alive.current = false; };
  }, [organizationId, profileId, creating, attempt]);

  const save = async (event) => {
    event.preventDefault();
    if (busy || !can('compliance-profile', creating ? 'create' : 'edit') || profile?.is_system) return;
    setError('');
    try {
      const body = requestBody(values, initial, creating);
      if (!creating && Object.keys(body).length === 0) { setError('No changes to save.'); return; }
      setBusy(true);
      const result = creating ? await createComplianceProfile({ ...body, organization_id: organizationId }) : await updateComplianceProfile(profileId, body);
      if (!alive.current) return;
      if (!inScope(result, organizationId) || result.is_system || (!creating && result.id !== profileId)) throw new Error('The API returned a profile outside the selected organization.');
      navigate(`${BASE}/${encodeURIComponent(result.id)}`);
    } catch (failure) { if (alive.current) setError(failure?.message || 'Unable to save compliance profile.'); }
    finally { if (alive.current) setBusy(false); }
  };
  const lifecycle = async (action) => {
    if (busy || profile?.is_system || !can('compliance-profile', action)) return;
    setBusy(true); setError('');
    try {
      if (action === 'delete') {
        await deleteComplianceProfile(profileId);
        if (alive.current) navigate(BASE);
      } else {
        const result = await (action === 'activate' ? activateComplianceProfile : suspendComplianceProfile)(profileId);
        if (!alive.current) return;
        if (!inScope(result, organizationId) || result.id !== profileId || result.is_system) throw new Error('The API returned a profile outside the selected organization.');
        setProfile(result);
      }
    } catch (failure) { if (alive.current) setError(failure?.message || 'Unable to change profile status.'); }
    finally { if (alive.current) { setBusy(false); setDeleteOpen(false); } }
  };
  const update = (field, value) => setValues((previous) => ({ ...previous, [field]: value }));
  const system = profile?.is_system === true;
  return <ResourcePage title={creating ? 'Create Compliance Profile' : mode === 'edit' ? 'Edit Compliance Profile' : profile?.name || 'Compliance Profile'}
    description="Configure credential format, issuance protocol, issuer requirements, and trust constraints."
    breadcrumbs={[{ label: 'Compliance Profiles', path: BASE }, { label: creating ? 'Create' : 'Profile', path: creating ? `${BASE}/new` : `${BASE}/${encodeURIComponent(profileId)}` }]}
    actions={<Button component={Link} to={BASE}>Back to profiles</Button>}>
    {error && <Alert severity="error" sx={{ mb: 2 }}>{error}<Button onClick={() => setAttempt((v) => v + 1)} disabled={busy}>Reload</Button></Alert>}
    {loading ? <LinearProgress /> : (!creating && !profile) ? null : system && editing ? <Alert severity="info">System presets are immutable. Create an organization profile from a preset to customize it.</Alert> : editing ?
      <Paper component="form" onSubmit={save} sx={{ p: 3 }}>
        <Stack spacing={2}>
          {creating && <TextField select label="Copy public preset requirements" defaultValue="" onChange={(event) => {
            const selected = presets.find((item) => item.id === event.target.value);
            if (selected) setValues({ ...draft(selected), name: values.name || `${selected.name} (organization)` });
          }}><MenuItem value="">Custom profile</MenuItem>{presets.map((item) => <MenuItem key={item.id} value={item.id}>{item.name} - {item.credential_format}</MenuItem>)}</TextField>}
          {SCALARS.map((field) => <TextField key={field} label={LABELS[field]} value={values[field]} required={['name', 'credential_format'].includes(field)} disabled={busy}
            multiline={field === 'description'} minRows={field === 'description' ? 2 : undefined}
            onChange={(event) => update(field, event.target.value)}
            helperText={field === 'credential_format' ? 'Use the format supplied by a preset or supported by your API.' : field === 'issuance_protocol' ? 'Use the issuance protocol supplied by your preset.' : undefined} />)}
          <FormControlLabel label="Discoverable" control={<Checkbox checked={values.discoverable} disabled={busy} onChange={(event) => update('discoverable', event.target.checked)} />} />
          <Typography variant="h6">Requirements and trust constraints</Typography>
          {NESTED.map((field) => <TextField key={field} label={`${LABELS[field]} (JSON)`} value={values[field]} multiline minRows={3} disabled={busy}
            onChange={(event) => update(field, event.target.value)} />)}
          <Typography variant="body2" color="text.secondary">{creating ? 'New profiles use the service privacy defaults.' : 'Existing privacy enforcement settings are retained when you edit this profile.'}</Typography>
          <Button variant="contained" type="submit" disabled={busy}>{busy ? 'Saving...' : creating ? 'Create profile' : 'Save changes'}</Button>
        </Stack>
      </Paper> : <Stack spacing={2}>
        <Stack direction="row" spacing={1}><Chip label={profile.status} /><Chip label={system ? 'System preset' : 'Organization profile'} /><Chip label={profile.credential_format} /></Stack>
        <Typography>{profile.description}</Typography>
        {system && <Alert severity="info">This system preset is managed by the platform and cannot be changed.</Alert>}
        <Stack direction="row" spacing={1}>
          {!system && can('compliance-profile', 'edit') && <Button component={Link} to={`${BASE}/${encodeURIComponent(profileId)}/edit`}>Edit profile</Button>}
          {!system && profile.status !== 'ACTIVE' && can('compliance-profile', 'activate') && <Button onClick={() => lifecycle('activate')} disabled={busy}>Activate profile</Button>}
          {!system && profile.status === 'ACTIVE' && can('compliance-profile', 'suspend') && <Button onClick={() => lifecycle('suspend')} disabled={busy}>Suspend profile</Button>}
          {!system && can('compliance-profile', 'delete') && <Button color="error" onClick={() => setDeleteOpen(true)} disabled={busy}>Delete profile</Button>}
          {can('compliance-profile', 'create') && <Button component={Link} to={`${BASE}/new`}>Create organization profile</Button>}
          {profile.status === 'ACTIVE' && <Button component={Link} to="/console/org/templates/credentials/new">Use in a credential template</Button>}
        </Stack>
        <Paper sx={{ p: 2 }}><Typography variant="h6">Profile configuration</Typography>
          <Box component="pre" sx={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{JSON.stringify(Object.fromEntries([...SCALARS, ...NESTED, 'discoverable', 'created_at', 'updated_at'].filter((field) => profile[field] !== undefined).map((field) => [field, profile[field]])), null, 2)}</Box>
        </Paper>
        <Typography variant="body2">Activation makes an organization profile available for template selection.</Typography>
      </Stack>}
    <Dialog open={deleteOpen} onClose={() => !busy && setDeleteOpen(false)}><DialogTitle>Delete compliance profile?</DialogTitle>
      <DialogContent>Delete {profile?.name}? Templates that reference this profile may become unavailable.</DialogContent>
      <DialogActions><Button onClick={() => setDeleteOpen(false)} disabled={busy}>Cancel</Button><Button color="error" onClick={() => lifecycle('delete')} disabled={busy}>Confirm deletion</Button></DialogActions>
    </Dialog>
  </ResourcePage>;
}

export default function ComplianceProfilePage({ mode = 'view' }) {
  const { activeOrgId } = useConsole();
  const { profileId } = useParams();
  const { can, isLoading } = usePermissions();
  if (!activeOrgId) return <Alert severity="error">Select an organization before opening compliance profiles.</Alert>;
  if (isLoading) return <LinearProgress />;
  const action = mode === 'create' ? 'create' : mode === 'edit' ? 'edit' : 'view';
  if (!can('compliance-profile', action)) return <Alert severity="error">You do not have permission to {action} compliance profiles.</Alert>;
  return <ComplianceProfileContent key={`${activeOrgId}:${profileId}:${mode}`} organizationId={activeOrgId} profileId={profileId} mode={mode} can={can} />;
}
