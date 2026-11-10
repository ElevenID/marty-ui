import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useLocation, useNavigate, useParams } from 'react-router';
import {
  Alert, Box, Button, Chip, CircularProgress, Container, Dialog, DialogActions,
  DialogContent, DialogTitle, Divider, Paper, Stack, Typography,
} from '@mui/material';
import ArchiveIcon from '@mui/icons-material/Archive';
import CheckIcon from '@mui/icons-material/Check';
import DeleteIcon from '@mui/icons-material/Delete';
import EditIcon from '@mui/icons-material/Edit';
import PreviewIcon from '@mui/icons-material/Preview';
import RuleIcon from '@mui/icons-material/Rule';
import { useConsole } from '../../../contexts/ConsoleContext';
import { usePermissions } from '../../../hooks/usePermissions';
import { useAsyncActionScope } from '../../../hooks/useAsyncActionScope';
import { publicEntryHref } from '../../../application/routing/publicEntry';
import {
  activateApplicationTemplate,
  deleteApplicationTemplate,
  deprecateApplicationTemplate,
  getApplicationTemplate,
  validateApplicationTemplate,
} from '../../../services/applicationTemplatesApi';

function statusOf(template) {
  return String(template?.status || '').toUpperCase();
}

function evidenceLabel(requirement) {
  if (typeof requirement === 'string') return requirement;
  return requirement?.label || requirement?.evidence_type || requirement?.check_type || 'Configured evidence';
}

function checkedValidation(value) {
  if (!value || typeof value.valid !== 'boolean' || !Array.isArray(value.errors)
    || value.valid !== (value.errors.length === 0)
    || value.errors.some((item) => !item || ['section', 'field', 'code', 'message'].some((key) => typeof item[key] !== 'string'))) {
    throw new Error('The validation response is invalid. Try validating again.');
  }
  return value;
}

function ApplicationTemplateDetailContent({ organizationId, templateId, canCreate, canEdit, canDelete }) {
  const navigate = useNavigate();
  const beginLoad = useAsyncActionScope();
  const beginAction = useAsyncActionScope();
  const busyRef = useRef(false);
  const [template, setTemplate] = useState(null);
  const [validation, setValidation] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [confirmation, setConfirmation] = useState(null);
  const inScope = useCallback((value) => value?.id === templateId && value.organization_id === organizationId, [templateId, organizationId]);

  const load = useCallback(async () => {
    const action = beginLoad();
    busyRef.current = true;
    setLoading(true);
    setBusy(true);
    setTemplate(null);
    setValidation(null);
    setError('');
    try {
      const result = await action.run(getApplicationTemplate, templateId, organizationId);
      if (!action.isCurrent()) return;
      if (!inScope(result)) throw new Error('This Application Template is not available in the selected organization.');
      setTemplate(result);
      if (statusOf(result) === 'DRAFT' && canCreate) {
        const validationResult = await action.run(validateApplicationTemplate, templateId);
        if (action.isCurrent()) setValidation(checkedValidation(validationResult));
      }
    } catch (reason) {
      if (action.isCurrent()) setError(reason.message || String(reason));
    } finally {
      if (action.isCurrent()) {
        busyRef.current = false;
        setBusy(false);
        setLoading(false);
      }
    }
  }, [beginLoad, templateId, organizationId, inScope, canCreate]);

  useEffect(() => { load(); }, [load]);

  const errorsBySection = useMemo(() => {
    const groups = new Map();
    for (const item of validation?.errors || []) {
      const section = item.section || 'template';
      groups.set(section, [...(groups.get(section) || []), item]);
    }
    return [...groups.entries()];
  }, [validation]);

  if (!template && loading) {
    return <Box sx={{ display: 'flex', justifyContent: 'center', py: 10 }}><CircularProgress /></Box>;
  }

  const status = statusOf(template);
  const isDraft = status === 'DRAFT';
  const isActive = status === 'ACTIVE';

  const runAction = async (operation) => {
    if (busyRef.current) return;
    const action = beginAction();
    busyRef.current = true;
    setBusy(true);
    setError('');
    try {
      await operation(action);
    } catch (reason) {
      if (action.isCurrent()) setError(reason.message || String(reason));
    } finally {
      if (action.isCurrent()) {
        busyRef.current = false;
        setBusy(false);
      }
    }
  };

  const validate = async () => {
    if (!inScope(template) || !isDraft || !canCreate) return;
    await runAction(async (action) => {
      setValidation(null);
      const result = await action.run(validateApplicationTemplate, templateId);
      if (action.isCurrent()) setValidation(checkedValidation(result));
    });
  };

  const activate = async () => {
    if (!inScope(template) || !isDraft || !canCreate || validation?.valid !== true) return;
    await runAction(async (action) => {
      setValidation(null);
      const validationResult = await action.run(validateApplicationTemplate, templateId);
      if (!action.isCurrent()) return;
      const checked = checkedValidation(validationResult);
      setValidation(checked);
      if (!checked.valid) return;
      const result = await action.run(activateApplicationTemplate, templateId);
      if (!action.isCurrent()) return;
      if (!inScope(result) || statusOf(result) !== 'ACTIVE') throw new Error('The activation response did not match this Application Template and its active lifecycle.');
      setTemplate(result);
      setValidation(null);
    });
  };

  const remove = async () => {
    if (!inScope(template) || !isDraft || !canDelete || confirmation !== 'delete') return;
    await runAction(async (action) => {
      await action.run(deleteApplicationTemplate, templateId);
      if (action.isCurrent()) navigate('/console/org/templates/applications');
    });
  };

  const deprecate = async () => {
    if (!inScope(template) || !isActive || !canCreate || confirmation !== 'deprecate') return;
    await runAction(async (action) => {
      const result = await action.run(deprecateApplicationTemplate, templateId);
      if (!action.isCurrent()) return;
      if (!inScope(result) || statusOf(result) !== 'DEPRECATED') throw new Error('The deprecation response did not match this Application Template and its deprecated lifecycle.');
      setTemplate(result);
      setConfirmation(null);
    });
  };

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      {error && !confirmation && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      {!template && !loading && <Button onClick={load}>Retry loading template</Button>}
      {template && <Stack spacing={3}>
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} sx={{ justifyContent: 'space-between' }}>
          <Box>
            <Stack direction="row" spacing={1} useFlexGap sx={{ alignItems: 'center', flexWrap: 'wrap' }}>
              <Typography variant="h4">{template.name}</Typography>
              <Chip label={status} color={isActive ? 'success' : 'default'} />
            </Stack>
            <Typography color="text.secondary">{template.description}</Typography>
          </Box>
          <Stack direction="row" spacing={1} useFlexGap sx={{ flexWrap: 'wrap' }}>
            {isDraft && canEdit && <Button component={Link} to={`/console/org/templates/applications/${encodeURIComponent(templateId)}/edit`} startIcon={<EditIcon />}>Edit</Button>}
            <Button component="a" href={publicEntryHref(`/applicant/preview/applications/${encodeURIComponent(templateId)}?organization_id=${encodeURIComponent(organizationId)}`)} target="_blank" rel="noopener noreferrer" startIcon={<PreviewIcon />}>Preview</Button>
            {isDraft && canCreate && <Button startIcon={<RuleIcon />} disabled={busy} onClick={validate}>Validate</Button>}
            {isDraft && canCreate && validation?.valid && <Button variant="contained" startIcon={<CheckIcon />} disabled={busy} onClick={activate}>Activate</Button>}
            {isDraft && canDelete && <Button color="error" startIcon={<DeleteIcon />} disabled={busy} onClick={() => { setError(''); setConfirmation('delete'); }}>Delete</Button>}
            {isActive && canCreate && <Button color="warning" startIcon={<ArchiveIcon />} disabled={busy} onClick={() => { setError(''); setConfirmation('deprecate'); }}>Deprecate</Button>}
          </Stack>
        </Stack>

        {isDraft && validation && (
          validation.valid
            ? <Alert severity="success">This draft is valid and can be activated.</Alert>
            : <Alert severity="warning">
              <Typography sx={{ fontWeight: 600, mb: 1 }}>Resolve validation issues before activation.</Typography>
              <Stack spacing={1}>
                {errorsBySection.map(([section, items]) => (
                  <Box key={section}>
                    <Typography variant="subtitle2" sx={{ textTransform: 'capitalize' }}>{section.replaceAll('_', ' ')}</Typography>
                    {items.map((item) => <Typography key={`${item.field}-${item.code}`} variant="body2">{item.message}</Typography>)}
                  </Box>
                ))}
              </Stack>
            </Alert>
        )}

        <Paper variant="outlined" sx={{ p: 3 }}>
          <Stack spacing={2}>
            <Box><Typography variant="subtitle2" color="text.secondary">Credential Template</Typography><Typography sx={{ overflowWrap: 'anywhere' }}>{template.credential_template_id || 'Not selected'}</Typography></Box>
            <Divider />
            <Box><Typography variant="subtitle2" color="text.secondary">Workflow</Typography><Typography>{template.approval_strategy} approval, valid for {template.application_validity_days} days</Typography>{template.approval_policy_set_id && <Typography variant="body2">Policy Set: {template.approval_policy_set_id}</Typography>}</Box>
            <Divider />
            <Box>
              <Typography variant="subtitle2" color="text.secondary">Form fields</Typography>
              {(template.form_fields || []).map((field) => <Typography key={field.field_id}>{field.label || field.field_id} ({field.field_type}){field.required ? ' - required' : ''}</Typography>)}
              {(template.form_fields || []).length === 0 && <Typography>None</Typography>}
            </Box>
            <Box><Typography variant="subtitle2" color="text.secondary">Evidence</Typography><Typography>{(template.evidence_requirements || []).map(evidenceLabel).join(', ') || 'None'}</Typography></Box>
            <Box><Typography variant="subtitle2" color="text.secondary">Required checks</Typography><Typography>{(template.required_checks || []).map((check) => check.check_type).join(', ') || 'None'}</Typography></Box>
          </Stack>
        </Paper>
      </Stack>}

      <Dialog open={confirmation === 'delete'} onClose={() => { if (!busy) setConfirmation(null); }} fullWidth>
        <DialogTitle>Delete Application Template?</DialogTitle>
        <DialogContent>
          This draft and its applicant form configuration will be permanently deleted.
          {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
        </DialogContent>
        <DialogActions><Button disabled={busy} onClick={() => setConfirmation(null)}>Cancel</Button><Button color="error" disabled={busy} onClick={remove}>Delete</Button></DialogActions>
      </Dialog>
      <Dialog open={confirmation === 'deprecate'} onClose={() => { if (!busy) setConfirmation(null); }} fullWidth>
        <DialogTitle>Deprecate Application Template?</DialogTitle>
        <DialogContent>
          New applications will no longer use this template. Existing applications and their history are preserved.
          {error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}
        </DialogContent>
        <DialogActions><Button disabled={busy} onClick={() => setConfirmation(null)}>Cancel</Button><Button color="warning" disabled={busy} onClick={deprecate}>Deprecate</Button></DialogActions>
      </Dialog>
    </Container>
  );
}

export default function ApplicationTemplateDetailPage() {
  const { activeOrgId } = useConsole();
  const { templateId } = useParams();
  const location = useLocation();
  const { can, isLoading } = usePermissions();
  if (!activeOrgId) return <Alert severity="error">Select an organization before opening Application Templates.</Alert>;
  if (isLoading) return <CircularProgress />;
  if (!can('application-template', 'view')) return <Alert severity="error">You do not have permission to view Application Templates.</Alert>;
  const canCreate = can('application-template', 'create');
  const canEdit = can('application-template', 'edit');
  const canDelete = can('application-template', 'delete');
  return <ApplicationTemplateDetailContent
    key={JSON.stringify([activeOrgId, templateId, location.key, location.pathname, location.search, location.hash, canCreate, canEdit, canDelete])}
    organizationId={activeOrgId} templateId={templateId} canCreate={canCreate} canEdit={canEdit} canDelete={canDelete}
  />;
}
