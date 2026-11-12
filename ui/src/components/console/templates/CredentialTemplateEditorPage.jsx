import { useBrowserEntry, useIsCurrentBrowserEntry } from '../../../hooks/useBrowserEntry';
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { Link, useLocation, useNavigate, useParams } from 'react-router';
import {
  Alert, Box, Button, Dialog, DialogActions, DialogContent, DialogTitle,
  LinearProgress, Paper, Stack, TextField, Typography,
} from '@mui/material';
import { ResourcePage } from '../../common';
import { useConsole } from '../../../contexts/ConsoleContext';
import { useAuth } from '../../../hooks/useAuth';
import { usePermissions } from '../../../hooks/usePermissions';
import { useAsyncActionScope } from '../../../hooks/useAsyncActionScope';
import { getCredentialTemplate, updateCredentialTemplate } from '../../../services/presentationPolicyApi';
import { createTemplateVersionOperation } from '../../../services/credentialTemplateVersionOperation';
import { MAX_VALIDITY_DAYS, MIN_VALIDITY_OFFSET, MAX_VALIDITY_OFFSET } from './credentialTemplateValidity';

const validityFields = [
  ['default_validity_days', 'Default validity (days)', 1, MAX_VALIDITY_DAYS],
  ['max_validity_days', 'Maximum validity (days)', 1, MAX_VALIDITY_DAYS],
  ['not_before_offset_seconds', 'Not-before offset (seconds)', MIN_VALIDITY_OFFSET, MAX_VALIDITY_OFFSET],
];
const byteLength = (value) => new TextEncoder().encode(value).length;
const settingsFor = (template) => ({
  name: template.name || '', description: template.description || '',
  ...Object.fromEntries(validityFields.map(([key]) => [key, String(template.validity_rules?.[key] ?? '')])),
});

function CredentialTemplateEditor({ organizationId, principalId, templateId, canEdit, canVersion, browserEntry }) {
  const navigate = useNavigate();
  const beginAction = useAsyncActionScope();
  const busyRef = useRef(false);
  const [template, setTemplate] = useState(null);
  const [settings, setSettings] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadGeneration, setLoadGeneration] = useState(0);
  const [loadError, setLoadError] = useState('');
  const [error, setError] = useState('');
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [separateOpen, setSeparateOpen] = useState(false);
  const versionOperation = useMemo(() => createTemplateVersionOperation(organizationId, principalId, templateId), [organizationId, principalId, templateId]);
  const [versionRecord, setVersionRecord] = useState(null);
  const [journalError, setJournalError] = useState('');
  const isCurrentBrowserEntry = useIsCurrentBrowserEntry(browserEntry);

  useLayoutEffect(() => {
    if (typeof window === 'undefined') return undefined;
    const invalidate = () => { beginAction(); };
    window.addEventListener('popstate', invalidate, true);
    return () => window.removeEventListener('popstate', invalidate, true);
  }, [beginAction]);

  const refreshVersionRecord = useCallback(() => {
    try { setVersionRecord(versionOperation.read()); setJournalError(''); }
    catch { setJournalError('The previous draft-version request could not be read. Check the template inventory before continuing.'); }
  }, [versionOperation]);
  useEffect(() => { refreshVersionRecord(); }, [refreshVersionRecord]);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setLoadError('');
    getCredentialTemplate(templateId).then((result) => {
      if (!active) return;
      if (result?.id !== templateId || result?.organization_id !== organizationId
        || !['draft', 'active', 'deprecated', 'archived'].includes(String(result.status).toLowerCase())) {
        throw new Error('This credential template is not available in the selected organization.');
      }
      setTemplate(result);
      setSettings(settingsFor(result));
    }).catch((cause) => { if (active) setLoadError(cause.message || String(cause)); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [templateId, organizationId, loadGeneration]);

  const original = template ? settingsFor(template) : null;
  const isDraft = String(template?.status).toLowerCase() === 'draft';
  const dirty = settings && original && Object.keys(settings).some((key) => settings[key] !== original[key]);
  const update = (key, value) => { if (!busyRef.current) { setSettings((current) => ({ ...current, [key]: value })); setSaved(false); } };
  const detailPath = `/console/org/templates/credentials/${encodeURIComponent(templateId)}`;
  const currentAction = () => {
    const action = beginAction();
    return () => action.isCurrent() && isCurrentBrowserEntry();
  };

  const save = async () => {
    if (busyRef.current || !canEdit || !isDraft || !settings || !dirty || !isCurrentBrowserEntry()) return;
    const name = settings.name.trim();
    if (!name || byteLength(name) > 255 || byteLength(settings.description) > 2000) {
      setError(!name ? 'Enter a template name.' : byteLength(name) > 255
        ? 'The template name is too long. Use a shorter name.' : 'The description is too long. Use a shorter description.');
      return;
    }
    const patch = { organization_id: organizationId };
    if (settings.name !== original.name) patch.name = name;
    if (settings.description !== original.description) patch.description = settings.description;
    const rules = {};
    for (const [key, label, minimum, maximum] of validityFields) {
      if (settings[key] === original[key]) continue;
      const value = settings[key].trim() === '' ? NaN : Number(settings[key]);
      if (!Number.isInteger(value) || value < minimum || value > maximum) {
        setError(`${label} must be a whole number from ${minimum} to ${maximum}.`);
        return;
      }
      rules[key] = value;
    }
    if (Object.keys(rules).length) patch.validity_rules = rules;
    const isCurrent = currentAction();
    busyRef.current = true;
    setBusy(true); setError(''); setSaved(false);
    try {
      const result = await updateCredentialTemplate(templateId, patch);
      if (!isCurrent()) return;
      if (result?.id !== templateId || result.organization_id !== organizationId || String(result.status).toLowerCase() !== 'draft') {
        throw new Error('The saved draft could not be confirmed. Your entered settings have been kept; review the template before retrying.');
      }
      setTemplate(result); setSettings(settingsFor(result)); setSaved(true);
    } catch (cause) {
      if (isCurrent()) setError(cause.message || String(cause));
    } finally {
      if (isCurrent()) { busyRef.current = false; setBusy(false); }
    }
  };

  const createVersion = async (separate = false) => {
    if (busyRef.current || !canVersion || !template || isDraft || !isCurrentBrowserEntry() || journalError) return;
    const isCurrent = currentAction();
    busyRef.current = true;
    setBusy(true); setError(''); setSeparateOpen(false);
    try {
      const result = await versionOperation.create({ isCurrent, separate });
      if (!isCurrent()) return;
      navigate(`/console/org/templates/credentials/${encodeURIComponent(result.id)}${canEdit ? '/edit' : ''}`);
    } catch (cause) {
      if (isCurrent()) setError(cause.message || String(cause));
    } finally {
      if (isCurrent()) { busyRef.current = false; setBusy(false); refreshVersionRecord(); }
    }
  };

  return (
    <ResourcePage title="Edit credential template" description="Update the name, description, and validity settings of a draft."
      breadcrumbs={[
        { label: 'Console', path: '/console' },
        { label: 'Credential Templates', path: '/console/org/templates/credentials' },
        { label: template?.name || 'Template', path: detailPath },
        { label: 'Edit', path: `${detailPath}/edit` },
      ]}>
      <Stack spacing={3}>
        <Box><Button component={Link} to={detailPath} disabled={busy}>Back to template</Button></Box>
        {loading && <LinearProgress />}
        {loadError && <Alert severity="error" action={<Button color="inherit" onClick={() => setLoadGeneration((value) => value + 1)}>Retry</Button>}>{loadError}</Alert>}
        {!loading && !loadError && template && <>
          <Paper variant="outlined" sx={{ p: 2 }}>
            <Typography variant="h6">{template.name}</Typography>
            <Typography color="text.secondary">{template.credential_type} · {template.credential_payload_format} · {template.status}</Typography>
            <Typography sx={{ overflowWrap: 'anywhere' }}>{template.issuer_did}</Typography>
            <Typography variant="body2">{Array.isArray(template.claims) ? template.claims.length : 0} claims</Typography>
          </Paper>
          {error && <Alert severity="error">{error}</Alert>}
          {saved && <Alert severity="success">Draft settings saved.</Alert>}
          {isDraft ? <>
            {!canEdit && <Alert severity="info">You do not have permission to edit this draft.</Alert>}
            <Stack component="fieldset" disabled={busy || !canEdit} spacing={3} sx={{ border: 0, p: 0, m: 0, minWidth: 0 }} aria-label="Draft settings">
              <TextField label="Template name" required value={settings.name} onChange={(event) => update('name', event.target.value)} fullWidth />
              <TextField label="Description" multiline minRows={3} value={settings.description} onChange={(event) => update('description', event.target.value)} fullWidth />
              {validityFields.map(([key, label]) => <TextField key={key} label={label} type="number" value={settings[key]} onChange={(event) => update(key, event.target.value)} fullWidth />)}
            </Stack>
            <Box><Button variant="contained" disabled={busy || !canEdit || !dirty} onClick={save}>{busy ? 'Saving…' : 'Save draft'}</Button></Box>
          </> : <>
            <Alert severity="info">This template is {template.status}. Create a new draft version to change its settings.</Alert>
            {journalError && <Alert severity="error">{journalError}</Alert>}
            {versionRecord?.resourceId ? <Alert severity="success" action={<Button component={Link} color="inherit" to={`/console/org/templates/credentials/${encodeURIComponent(versionRecord.resourceId)}${canEdit ? '/edit' : ''}`}>Open draft</Button>}>A draft version has already been created from this template.</Alert>
              : versionRecord ? <Alert severity="warning">
                A draft-version request was sent without a confirmed result. Check the template inventory before creating another version; a draft may already exist.
                <Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}>Request reference: {versionRecord.key}</Typography>
                <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} sx={{ mt: 1 }}>
                  <Button component={Link} to="/console/org/templates/credentials">View templates</Button>
                  {canVersion && <Button onClick={() => setSeparateOpen(true)} disabled={busy}>Start a separate draft version</Button>}
                </Stack>
              </Alert> : <Box><Button variant="contained" disabled={busy || !canVersion || Boolean(journalError)} onClick={() => createVersion()}>{busy ? 'Creating draft…' : 'Create new draft version'}</Button></Box>}
            {!canVersion && <Alert severity="info">You do not have permission to create draft versions.</Alert>}
          </>}
        </>}
      </Stack>
      <Dialog open={separateOpen && canVersion} onClose={() => setSeparateOpen(false)}>
        <DialogTitle>Create a separate draft version?</DialogTitle>
        <DialogContent>A previous request may already have created a draft. This creates another draft version. Check the template inventory first.</DialogContent>
        <DialogActions><Button onClick={() => setSeparateOpen(false)}>Cancel</Button><Button onClick={() => createVersion(true)}>Create separate draft</Button></DialogActions>
      </Dialog>
    </ResourcePage>
  );
}

export default function CredentialTemplateEditorPage() {
  const { activeOrgId } = useConsole();
  const { user, isAuthenticated } = useAuth();
  const { templateId } = useParams();
  const location = useLocation();
  const { can, isLoading } = usePermissions();
  const browserEntry = useBrowserEntry(location);
  if (!activeOrgId) return <Alert severity="error">Select an organization before editing credential templates.</Alert>;
  if (typeof templateId !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(templateId)) return <Alert severity="error">Select a valid credential template.</Alert>;
  if (isLoading) return <LinearProgress />;
  if (!isAuthenticated || !can('credential-template', 'view')) return <Alert severity="error">You do not have permission to view credential templates.</Alert>;
  const canEdit = can('credential-template', 'edit');
  const canVersion = can('credential-template', 'version');
  const principalId = user?.user_id || user?.sub || user?.id || null;
  return <CredentialTemplateEditor
    key={JSON.stringify([activeOrgId, templateId, principalId, isAuthenticated, canEdit, canVersion,
      location.key, location.pathname, location.search, location.hash, browserEntry.generation])}
    organizationId={activeOrgId} principalId={principalId} templateId={templateId}
    canEdit={canEdit} canVersion={canVersion} browserEntry={browserEntry}
  />;
}
