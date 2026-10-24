import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
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

function ApplicationTemplateDetailContent({ organizationId, templateId, can }) {
  const navigate = useNavigate();
  const alive = useRef(false);
  const [template, setTemplate] = useState(null);
  const [validation, setValidation] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [confirmation, setConfirmation] = useState(null);
  const inScope = useCallback((value) => value?.id === templateId && value.organization_id === organizationId, [templateId, organizationId]);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);

  const validate = useCallback(async () => {
    if (!can('application-template', 'create')) return null;
    setBusy(true);
    setError('');
    try {
      const result = await validateApplicationTemplate(templateId);
      if (!alive.current) return null;
      setValidation(result);
      return result;
    } catch (reason) {
      if (alive.current) setError(reason.message || String(reason));
      return null;
    } finally {
      if (alive.current) setBusy(false);
    }
  }, [templateId, can]);

  useEffect(() => {
    let current = true;
    (async () => {
      try {
        const result = await getApplicationTemplate(templateId, organizationId);
        if (!current) return;
        if (!inScope(result)) throw new Error('This Application Template is not available in the selected organization.');
        setTemplate(result);
        if (statusOf(result) === 'DRAFT' && can('application-template', 'create')) {
          const validationResult = await validateApplicationTemplate(templateId);
          if (current) setValidation(validationResult);
        }
      } catch (reason) {
        if (current) { setTemplate(null); setError(reason.message || String(reason)); }
      }
    })();
    return () => { current = false; };
  }, [templateId, organizationId, inScope, can]);

  const errorsBySection = useMemo(() => {
    const groups = new Map();
    for (const item of validation?.errors || []) {
      const section = item.section || 'template';
      groups.set(section, [...(groups.get(section) || []), item]);
    }
    return [...groups.entries()];
  }, [validation]);

  if (!template && !error) {
    return <Box sx={{ display: 'flex', justifyContent: 'center', py: 10 }}><CircularProgress /></Box>;
  }

  const status = statusOf(template);
  const isDraft = status === 'DRAFT';
  const isActive = status === 'ACTIVE';

  const activate = async () => {
    if (!inScope(template) || !can('application-template', 'create')) return;
    const result = await validate();
    if (!result?.valid) return;
    setBusy(true);
    try {
      const result = await activateApplicationTemplate(templateId);
      if (!alive.current) return;
      if (!inScope(result)) throw new Error('The API returned an Application Template outside the selected organization.');
      setTemplate(result);
      setValidation(null);
    } catch (reason) {
      if (alive.current) setError(reason.message || String(reason));
    } finally {
      if (alive.current) setBusy(false);
    }
  };

  const remove = async () => {
    if (!inScope(template) || !can('application-template', 'delete')) return;
    setBusy(true);
    try {
      await deleteApplicationTemplate(templateId);
      if (alive.current) navigate('/console/org/templates/applications');
    } catch (reason) {
      if (alive.current) { setError(reason.message || String(reason)); setBusy(false); }
    }
  };

  const deprecate = async () => {
    if (!inScope(template) || !can('application-template', 'create')) return;
    setBusy(true);
    try {
      const result = await deprecateApplicationTemplate(templateId);
      if (!alive.current) return;
      if (!inScope(result)) throw new Error('The API returned an Application Template outside the selected organization.');
      setTemplate(result);
      setConfirmation(null);
    } catch (reason) {
      if (alive.current) setError(reason.message || String(reason));
    } finally {
      if (alive.current) setBusy(false);
    }
  };

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      {template && <Stack spacing={3}>
        <Stack direction={{ xs: 'column', sm: 'row' }} justifyContent="space-between" spacing={2}>
          <Box>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
              <Typography variant="h4">{template.name}</Typography>
              <Chip label={status} color={isActive ? 'success' : 'default'} />
            </Stack>
            <Typography color="text.secondary">{template.description}</Typography>
          </Box>
          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
            {isDraft && can('application-template', 'edit') && <Button component={Link} to={`/console/org/templates/applications/${templateId}/edit`} startIcon={<EditIcon />}>Edit</Button>}
            <Button component="a" href={`/applicant/preview/applications/${templateId}?organization_id=${encodeURIComponent(organizationId)}`} target="_blank" startIcon={<PreviewIcon />}>Preview</Button>
            {isDraft && can('application-template', 'create') && <Button startIcon={<RuleIcon />} disabled={busy} onClick={validate}>Validate</Button>}
            {isDraft && can('application-template', 'create') && validation?.valid && <Button variant="contained" startIcon={<CheckIcon />} disabled={busy} onClick={activate}>Activate</Button>}
            {isDraft && can('application-template', 'delete') && <Button color="error" startIcon={<DeleteIcon />} disabled={busy} onClick={() => setConfirmation('delete')}>Delete</Button>}
            {isActive && can('application-template', 'create') && <Button color="warning" startIcon={<ArchiveIcon />} disabled={busy} onClick={() => setConfirmation('deprecate')}>Deprecate</Button>}
          </Stack>
        </Stack>

        {isDraft && validation && (
          validation.valid
            ? <Alert severity="success">This draft is valid and can be activated.</Alert>
            : <Alert severity="warning">
              <Typography fontWeight={600} sx={{ mb: 1 }}>Resolve validation issues before activation.</Typography>
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

      <Dialog open={confirmation === 'delete'} onClose={() => setConfirmation(null)} fullWidth>
        <DialogTitle>Delete Application Template?</DialogTitle>
        <DialogContent>This draft and its applicant form configuration will be permanently deleted.</DialogContent>
        <DialogActions><Button onClick={() => setConfirmation(null)}>Cancel</Button><Button color="error" disabled={busy} onClick={remove}>Delete</Button></DialogActions>
      </Dialog>
      <Dialog open={confirmation === 'deprecate'} onClose={() => setConfirmation(null)} fullWidth>
        <DialogTitle>Deprecate Application Template?</DialogTitle>
        <DialogContent>New applications will no longer use this template. Existing applications and their history are preserved.</DialogContent>
        <DialogActions><Button onClick={() => setConfirmation(null)}>Cancel</Button><Button color="warning" disabled={busy} onClick={deprecate}>Deprecate</Button></DialogActions>
      </Dialog>
    </Container>
  );
}

export default function ApplicationTemplateDetailPage() {
  const { activeOrgId } = useConsole();
  const { templateId } = useParams();
  const { can, isLoading } = usePermissions();
  if (!activeOrgId) return <Alert severity="error">Select an organization before opening Application Templates.</Alert>;
  if (isLoading) return <CircularProgress />;
  if (!can('application-template', 'view')) return <Alert severity="error">You do not have permission to view Application Templates.</Alert>;
  return <ApplicationTemplateDetailContent key={`${activeOrgId}:${templateId}`} organizationId={activeOrgId} templateId={templateId} can={can} />;
}
