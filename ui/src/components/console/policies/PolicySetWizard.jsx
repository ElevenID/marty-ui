import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router';
import {
  Alert,
  Box,
  Button,
  Card,
  CardActionArea,
  CardContent,
  Chip,
  CircularProgress,
  Container,
  FormControlLabel,
  Grid,
  IconButton,
  Paper,
  Stack,
  Switch,
  TextField,
  Typography,
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import CheckIcon from '@mui/icons-material/Check';
import DeleteIcon from '@mui/icons-material/Delete';
import SaveIcon from '@mui/icons-material/Save';

import { useConsole } from '../../../contexts/ConsoleContext';
import { usePermissions } from '../../../hooks/usePermissions';
import { createPolicySet, listPolicySetTemplates, validatePolicySet } from '../../../services/policySetsApi';
import { requirePolicySet, requirePolicySetTemplates, requirePolicySetValidation } from './policySetGuards';

const ScopedPolicySetWizard = ({ organizationId, canCreate, canValidate, grantsLoading }) => {
  const navigate = useNavigate();
  const [templates, setTemplates] = useState([]);
  const [selectedTemplate, setSelectedTemplate] = useState('');
  const [advanced, setAdvanced] = useState(false);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [policyType, setPolicyType] = useState('CUSTOM');
  const [policies, setPolicies] = useState([]);
  const [validation, setValidation] = useState(null);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [validating, setValidating] = useState(false);
  const [templatesLoading, setTemplatesLoading] = useState(true);
  const [templatesError, setTemplatesError] = useState('');
  const [revision, setRevision] = useState(0);
  const mounted = useRef(false);
  const permitted = useRef(false);
  permitted.current = canCreate && canValidate && !grantsLoading;
  const applies = () => mounted.current && permitted.current;
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);

  useEffect(() => {
    let current = true;
    setTemplates([]); setTemplatesLoading(true); setTemplatesError('');
    if (canCreate && !grantsLoading) listPolicySetTemplates(organizationId)
      .then((records) => { const presets = requirePolicySetTemplates(records); if (current) setTemplates(presets); })
      .catch((cause) => { if (current) setTemplatesError(cause.message || 'Policy Set templates could not be loaded.'); })
      .finally(() => { if (current) setTemplatesLoading(false); });
    return () => { current = false; };
  }, [organizationId, canCreate, grantsLoading, revision]);

  const chooseTemplate = (template) => {
    if (!applies() || saving || validating) return;
    setSelectedTemplate(template.template_id);
    setPolicyType(template.policy_type);
    setName(template.name);
    setDescription(template.description);
    setPolicies(template.cedar_policies.map((policy) => ({ ...policy })));
    setValidation(null);
  };

  const updatePolicy = (index, updates) => {
    setPolicies((current) => current.map((policy, policyIndex) => policyIndex === index ? { ...policy, ...updates } : policy));
    setValidation(null);
  };

  const runValidation = async () => {
    if (!mounted.current || !canValidate || grantsLoading || saving || validating || !policies.length) return;
    setValidating(true);
    setError('');
    try {
      const result = requirePolicySetValidation(await validatePolicySet(organizationId, policies));
      if (mounted.current && permitted.current) setValidation(result);
    } catch (cause) {
      if (applies()) setError(cause.message);
    } finally { if (mounted.current) setValidating(false); }
  };

  const save = async () => {
    if (!applies() || saving || validating || !name.trim() || !policies.length) return;
    setSaving(true);
    setError('');
    try {
      const result = requirePolicySetValidation(await validatePolicySet(organizationId, policies));
      if (!applies()) return;
      setValidation(result);
      if (!result.valid) return;
      const created = await createPolicySet(organizationId, {
        name: name.trim(),
        description: description.trim() || null,
        policy_type: policyType,
        cedar_policies: policies,
      });
      const scoped = requirePolicySet(created, organizationId);
      if (applies()) navigate(`/console/org/policies/sets/${scoped.id}`);
    } catch (cause) {
      if (applies()) setError(cause.message || 'Policy Set could not be created.');
    } finally {
      if (mounted.current) setSaving(false);
    }
  };

  if (grantsLoading) return <CircularProgress />;
  if (!canCreate) return <Alert severity="warning">You do not have permission to create Policy Sets in this organization.</Alert>;
  const busy = saving || validating;
  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Button startIcon={<ArrowBackIcon />} onClick={() => navigate('/console/org/policies/sets')} sx={{ mb: 2 }}>Policy Sets</Button>
      <Typography variant="h4" gutterBottom>Create Policy Set</Typography>
      {!canValidate && <Alert severity="warning" sx={{ mb: 2 }}>You do not have permission to validate Policy Sets. Validation permission is required before this wizard can create a draft.</Alert>}
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      {templatesError && <Alert severity="error" sx={{ mb: 2 }}>{templatesError}<Button disabled={busy} onClick={() => setRevision((value) => value + 1)}>Reload templates</Button></Alert>}
      {templatesLoading && <CircularProgress />}
      <Typography variant="h6" sx={{ mb: 1.5 }}>Start from a template</Typography>
      <Grid container spacing={1.5} sx={{ mb: 3 }}>
        {templates.map((template) => (
          <Grid item xs={12} sm={4} key={template.template_id}>
            <Card variant="outlined" sx={{ height: '100%', borderColor: selectedTemplate === template.template_id ? 'primary.main' : 'divider' }}>
              <CardActionArea disabled={busy || !canValidate} onClick={() => chooseTemplate(template)} sx={{ height: '100%' }}>
                <CardContent>
                  <Typography variant="subtitle2">{template.name}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>{template.description}</Typography>
                  <Chip label={template.policy_type} size="small" variant="outlined" sx={{ mt: 1.5 }} />
                </CardContent>
              </CardActionArea>
            </Card>
          </Grid>
        ))}
      </Grid>
      <Paper variant="outlined" sx={{ p: { xs: 2, sm: 3 } }}>
        <Stack component="fieldset" disabled={busy} spacing={2.5} sx={{ border: 0, p: 0, m: 0, minWidth: 0 }}>
          <TextField required label="Name" value={name} onChange={(event) => setName(event.target.value)} slotProps={{
            htmlInput: { maxLength: 128 }
          }} />
          <TextField multiline minRows={2} label="Description" value={description} onChange={(event) => setDescription(event.target.value)} slotProps={{
            htmlInput: { maxLength: 1024 }
          }} />

          <FormControlLabel control={<Switch checked={advanced} onChange={(event) => setAdvanced(event.target.checked)} />} label="Advanced Cedar editor" />

          {policies.length === 0 ? (
            <Alert severity="info">Select a template to continue.</Alert>
          ) : advanced ? (
            <Stack spacing={2}>
              {policies.map((policy, index) => (
                <Box key={`${policy.policy_id}-${index}`} sx={{ borderTop: index ? 1 : 0, borderColor: 'divider', pt: index ? 2 : 0 }}>
                  <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5} sx={{ mb: 1.5 }}>
                    <TextField fullWidth label="Policy ID" value={policy.policy_id} onChange={(event) => updatePolicy(index, { policy_id: event.target.value })} />
                    <TextField fullWidth label="Effect" value={policy.effect} disabled />
                    <IconButton aria-label={`Delete ${policy.policy_id}`} disabled={policies.length === 1} onClick={() => { setPolicies(policies.filter((_, policyIndex) => policyIndex !== index)); setValidation(null); }}><DeleteIcon /></IconButton>
                  </Stack>
                  <TextField
                    fullWidth
                    multiline
                    minRows={10}
                    label="Cedar policy"
                    value={policy.cedar_text}
                    onChange={(event) => updatePolicy(index, { cedar_text: event.target.value })}
                    slotProps={{
                      htmlInput: { style: { fontFamily: 'monospace', fontSize: 13 } }
                    }}
                  />
                </Box>
              ))}
            </Stack>
          ) : (
            <Stack spacing={1}>
              {policies.map((policy) => (
                <Stack key={policy.policy_id} direction="row" alignItems="center" gap={1.5}>
                  <CheckIcon color="success" fontSize="small" />
                  <Box sx={{ minWidth: 0, flex: 1 }}>
                    <Typography variant="body2" fontWeight={600}>{policy.description || policy.policy_id}</Typography>
                    <Typography variant="caption" color="text.secondary">{policy.effect} / {policy.policy_id}</Typography>
                  </Box>
                </Stack>
              ))}
            </Stack>
          )}

          {validation && <Alert severity={validation.valid ? 'success' : 'error'}>{validation.valid ? 'Policy Set is valid.' : validation.errors.join(' ')}</Alert>}

          <Stack direction="row" justifyContent="flex-end" spacing={1.5}>
            <Button variant="outlined" onClick={runValidation} disabled={!policies.length || busy || !canValidate}>Validate</Button>
            <Button variant="contained" startIcon={<SaveIcon />} onClick={save} disabled={!name.trim() || !policies.length || busy || !canValidate}>Create draft</Button>
          </Stack>
        </Stack>
      </Paper>
    </Container>
  );
};

export default function PolicySetWizard() {
  const { activeOrgId: organizationId } = useConsole();
  const { can, isLoading } = usePermissions();
  if (!organizationId) return <Alert severity="info">Select an organization before creating a Policy Set.</Alert>;
  return <ScopedPolicySetWizard key={organizationId} organizationId={organizationId} canCreate={can('policy-set', 'create')}
    canValidate={can('policy-set', 'validate')} grantsLoading={isLoading} />;
}
