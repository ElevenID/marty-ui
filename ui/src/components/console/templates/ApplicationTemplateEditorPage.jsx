import { useEffect, useMemo, useState } from 'react';
import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import {
  Alert, Box, Button, Checkbox, CircularProgress, Container, FormControl,
  FormControlLabel, IconButton, InputLabel, MenuItem, Paper, Select, Stack,
  TextField, Typography,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import DeleteIcon from '@mui/icons-material/Delete';
import SaveIcon from '@mui/icons-material/Save';

import { useConsole } from '../../../contexts/ConsoleContext';
import { listCredentialTemplates } from '../../../services/presentationPolicyApi';
import {
  createApplicationTemplate,
  getApplicationTemplate,
  updateApplicationTemplate,
} from '../../../services/applicationTemplatesApi';

const EMPTY = {
  name: '', description: '', credential_template_id: '', form_fields: [],
  evidence_requirements: [], required_checks: [], claim_collection_rules: [], approval_strategy: 'MANUAL',
  approval_policy_set_id: null, application_validity_days: 30, notification_config: {},
  ui_config: {},
};

function normalizeFieldType(value) {
  const type = String(value || '').trim().toUpperCase();
  if (['DATE', 'DATETIME', 'INTEGER', 'NUMBER', 'BOOLEAN', 'EMAIL', 'URL', 'SELECT', 'FILE_UPLOAD'].includes(type)) return type;
  if (['ENUM', 'CHOICE'].includes(type)) return 'SELECT';
  return 'TEXT';
}

function claimField(claim) {
  const fieldId = claim.field_id || claim.name;
  return {
    field_id: fieldId,
    label: claim.display_name || claim.label || fieldId,
    field_type: normalizeFieldType(claim.field_type || claim.claim_type || claim.type),
    required: Boolean(claim.required),
    options: claim.options || claim.enum || undefined,
    validation_pattern: claim.validation_pattern || claim.pattern || undefined,
    minimum: claim.minimum,
    maximum: claim.maximum,
    claim_mapping: fieldId,
  };
}

export default function ApplicationTemplateEditorPage() {
  const navigate = useNavigate();
  const { templateId } = useParams();
  const [searchParams] = useSearchParams();
  const advanced = searchParams.get('mode') === 'advanced';
  const { activeOrgId: organizationId } = useConsole();
  const [data, setData] = useState(EMPTY);
  const [credentialTemplates, setCredentialTemplates] = useState([]);
  const [loading, setLoading] = useState(Boolean(templateId));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    if (!organizationId) {
      setCredentialTemplates([]);
      setError('Select an organization before editing Application Templates.');
      setLoading(false);
      return () => { active = false; };
    }
    Promise.all([
      listCredentialTemplates({ organization_id: organizationId }),
      templateId ? getApplicationTemplate(templateId) : Promise.resolve(null),
    ]).then(([templates, existing]) => {
      if (!active) return;
      setCredentialTemplates(templates.filter((item) => String(item.status || '').toUpperCase() === 'ACTIVE'));
      if (existing) {
        setData({ ...EMPTY, ...existing });
        if (String(existing.status || '').toUpperCase() !== 'DRAFT') {
          setError('Only draft Application Templates can be edited.');
        }
      }
    }).catch((reason) => active && setError(reason.message || String(reason)))
      .finally(() => active && setLoading(false));
    return () => { active = false; };
  }, [organizationId, templateId]);

  const selectedCredential = useMemo(
    () => credentialTemplates.find((item) => item.id === data.credential_template_id),
    [credentialTemplates, data.credential_template_id],
  );

  const selectCredential = (credentialTemplateId) => {
    const selected = credentialTemplates.find((item) => item.id === credentialTemplateId);
    const derivedFields = Array.isArray(selected?.claims) ? selected.claims.map(claimField).filter((field) => field.field_id) : [];
    setData((current) => ({
      ...current,
      credential_template_id: credentialTemplateId,
      form_fields: current.form_fields.length > 0 ? current.form_fields : derivedFields,
    }));
  };

  const updateField = (index, changes) => setData((current) => ({
    ...current,
    form_fields: current.form_fields.map((field, fieldIndex) => fieldIndex === index ? { ...field, ...changes } : field),
  }));

  const save = async () => {
    if (!organizationId || !data.name.trim() || !data.credential_template_id || data.form_fields.length === 0) {
      setError('Name, active Credential Template, and at least one form field are required.');
      return;
    }
    setSaving(true);
    setError('');
    try {
      const payload = {
        name: data.name.trim(),
        description: data.description || null,
        credential_template_id: data.credential_template_id,
        form_fields: data.form_fields,
        evidence_requirements: data.evidence_requirements,
        required_checks: data.required_checks,
        claim_collection_rules: data.claim_collection_rules,
        approval_strategy: data.approval_strategy,
        approval_policy_set_id: data.approval_strategy === 'RULES_BASED' ? data.approval_policy_set_id : null,
        application_validity_days: data.application_validity_days,
        notification_config: data.notification_config,
        ui_config: data.ui_config,
      };
      const saved = templateId
        ? await updateApplicationTemplate(templateId, payload)
        : await createApplicationTemplate({ ...payload, organization_id: organizationId });
      navigate(`/console/org/templates/applications/${saved.id || templateId}`);
    } catch (reason) {
      setError(reason.message || String(reason));
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <Box sx={{ display: 'flex', justifyContent: 'center', py: 10 }}><CircularProgress /></Box>;

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 3 }}>
        <IconButton aria-label="Back" onClick={() => navigate('/console/org/templates/applications')}><ArrowBackIcon /></IconButton>
        <Box>
          <Typography variant="h4">{templateId ? 'Edit Application Template' : 'Create Application Template'}</Typography>
          <Typography color="text.secondary">Draft applicant form and approval contract</Typography>
        </Box>
      </Stack>
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      <Paper variant="outlined" sx={{ p: { xs: 2, sm: 3 } }}>
        <Stack spacing={2.5}>
          <TextField required label="Name" value={data.name} onChange={(event) => setData({ ...data, name: event.target.value })} />
          <TextField label="Description" multiline minRows={2} value={data.description || ''} onChange={(event) => setData({ ...data, description: event.target.value })} />
          <FormControl required>
            <InputLabel>Credential Template</InputLabel>
            <Select label="Credential Template" value={data.credential_template_id} onChange={(event) => selectCredential(event.target.value)}>
              {credentialTemplates.map((item) => <MenuItem key={item.id} value={item.id}>{item.name}</MenuItem>)}
            </Select>
          </FormControl>

          <Box>
            <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1 }}>
              <Typography variant="h6">Form fields</Typography>
              <Button startIcon={<AddIcon />} onClick={() => setData((current) => ({ ...current, form_fields: [...current.form_fields, { field_id: '', label: '', field_type: 'TEXT', required: false }] }))}>Add field</Button>
            </Stack>
            <Stack spacing={1.5}>
              {data.form_fields.map((field, index) => (
                <Paper key={`${field.field_id}-${index}`} variant="outlined" sx={{ p: 2 }}>
                  <Stack spacing={1.5}>
                    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1} alignItems={{ sm: 'center' }}>
                      <TextField required label="Field ID" value={field.field_id || ''} onChange={(event) => updateField(index, { field_id: event.target.value })} sx={{ flex: 1 }} />
                      <TextField required label="Label" value={field.label || ''} onChange={(event) => updateField(index, { label: event.target.value })} sx={{ flex: 1 }} />
                      <FormControl sx={{ minWidth: 145 }}><InputLabel>Type</InputLabel><Select label="Type" value={field.field_type || 'TEXT'} onChange={(event) => updateField(index, { field_type: event.target.value })}>
                        {['TEXT', 'DATE', 'DATETIME', 'INTEGER', 'NUMBER', 'BOOLEAN', 'SELECT', 'EMAIL', 'URL', 'FILE_UPLOAD'].map((type) => <MenuItem key={type} value={type}>{type}</MenuItem>)}
                      </Select></FormControl>
                      <FormControlLabel control={<Checkbox checked={Boolean(field.required)} onChange={(event) => updateField(index, { required: event.target.checked })} />} label="Required" />
                      <IconButton aria-label={`Delete ${field.label || field.field_id || 'field'}`} onClick={() => setData((current) => ({ ...current, form_fields: current.form_fields.filter((_, fieldIndex) => fieldIndex !== index) }))}><DeleteIcon /></IconButton>
                    </Stack>
                    <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1}>
                      <TextField label="Claim mapping" value={field.claim_mapping || ''} onChange={(event) => updateField(index, { claim_mapping: event.target.value || null })} sx={{ flex: 1 }} />
                      <TextField label="Validation pattern" value={field.validation_pattern || ''} onChange={(event) => updateField(index, { validation_pattern: event.target.value || null })} sx={{ flex: 1 }} />
                      {field.field_type === 'SELECT' && <TextField label="Options" helperText="Comma-separated" value={(field.options || []).join(', ')} onChange={(event) => updateField(index, { options: event.target.value.split(',').map((item) => item.trim()).filter(Boolean) })} sx={{ flex: 1 }} />}
                      {['INTEGER', 'NUMBER'].includes(field.field_type) && <TextField type="number" label="Minimum" value={field.minimum ?? ''} onChange={(event) => updateField(index, { minimum: event.target.value === '' ? null : Number(event.target.value) })} sx={{ width: { sm: 120 } }} />}
                      {['INTEGER', 'NUMBER'].includes(field.field_type) && <TextField type="number" label="Maximum" value={field.maximum ?? ''} onChange={(event) => updateField(index, { maximum: event.target.value === '' ? null : Number(event.target.value) })} sx={{ width: { sm: 120 } }} />}
                    </Stack>
                  </Stack>
                </Paper>
              ))}
            </Stack>
          </Box>

          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <FormControl fullWidth><InputLabel>Approval</InputLabel><Select label="Approval" value={data.approval_strategy || 'MANUAL'} onChange={(event) => setData({ ...data, approval_strategy: event.target.value })}>
              <MenuItem value="MANUAL">Manual review</MenuItem><MenuItem value="AUTO">Automatic</MenuItem><MenuItem value="RULES_BASED">Rules based</MenuItem>
            </Select></FormControl>
            <TextField fullWidth type="number" label="Valid for days" value={data.application_validity_days || 30} inputProps={{ min: 1, max: 365 }} onChange={(event) => setData({ ...data, application_validity_days: Number(event.target.value) })} />
          </Stack>

          {data.approval_strategy === 'RULES_BASED' && <TextField required label="Approval Policy Set ID" value={data.approval_policy_set_id || ''} onChange={(event) => setData({ ...data, approval_policy_set_id: event.target.value })} />}

          {advanced && (
            <>
              <TextField label="Evidence requirements" helperText="Comma-separated evidence identifiers" value={(data.evidence_requirements || []).join(', ')} onChange={(event) => setData({ ...data, evidence_requirements: event.target.value.split(',').map((value) => value.trim()).filter(Boolean) })} />
              <TextField label="Required checks" helperText="Comma-separated check types" value={(data.required_checks || []).map((item) => item.check_type).filter(Boolean).join(', ')} onChange={(event) => setData({ ...data, required_checks: event.target.value.split(',').map((value, index) => value.trim()).filter(Boolean).map((check_type, index) => ({ check_type, is_required: true, order: index + 1 })) })} />
              <TextField label="Submission instructions" multiline minRows={2} value={data.ui_config?.submission_instructions || ''} onChange={(event) => setData({ ...data, ui_config: { ...(data.ui_config || {}), submission_instructions: event.target.value } })} />
              <Stack direction={{ xs: 'column', sm: 'row' }}>
                <FormControlLabel control={<Checkbox checked={data.notification_config?.send_confirmation !== false} onChange={(event) => setData({ ...data, notification_config: { ...(data.notification_config || {}), send_confirmation: event.target.checked } })} />} label="Send confirmation" />
                <FormControlLabel control={<Checkbox checked={data.notification_config?.send_status_updates !== false} onChange={(event) => setData({ ...data, notification_config: { ...(data.notification_config || {}), send_status_updates: event.target.checked } })} />} label="Send status updates" />
              </Stack>
            </>
          )}

          <Stack direction="row" justifyContent="flex-end" spacing={1}>
            <Button onClick={() => navigate('/console/org/templates/applications')}>Cancel</Button>
            <Button variant="contained" startIcon={saving ? <CircularProgress size={18} /> : <SaveIcon />} disabled={saving || !selectedCredential || String(data.status || 'DRAFT').toUpperCase() !== 'DRAFT'} onClick={save}>Save draft</Button>
          </Stack>
        </Stack>
      </Paper>
    </Container>
  );
}
