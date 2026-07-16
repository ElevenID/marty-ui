import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Alert,
  Box,
  Button,
  Container,
  FormControl,
  IconButton,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import DeleteIcon from '@mui/icons-material/Delete';
import SaveIcon from '@mui/icons-material/Save';

import { useConsole } from '../../../contexts/ConsoleContext';
import { createFlow, getFlowCapabilities } from '../../../services/flowsApi';

const NEW_STEP = { action: '', description: '', step_id: '' };

function buildTransitions(steps) {
  return steps.slice(0, -1).map((step, index) => ({
    from_step_id: step.step_id,
    to_step_id: steps[index + 1].step_id,
    outcome: 'SUCCESS',
  }));
}

const CustomFlowBuilder = () => {
  const navigate = useNavigate();
  const { activeOrgId: organizationId } = useConsole();
  const [capabilities, setCapabilities] = useState(null);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [form, setForm] = useState({
    baseType: 'oid4vci_pre_authorized',
    description: '',
    extensionUri: 'urn:elevenid:flow-extension:custom:v1',
    extensionVersion: '1.0.0',
    name: '',
    steps: [
      { action: 'collect_input', description: '', step_id: 'collect_input' },
      { action: 'complete', description: '', step_id: 'complete' },
    ],
  });

  useEffect(() => {
    getFlowCapabilities().then(setCapabilities).catch((cause) => setError(cause.message));
  }, []);

  const valid = useMemo(() => {
    const ids = form.steps.map((step) => step.step_id);
    return Boolean(
      organizationId
      && form.name.trim()
      && form.extensionUri.includes(':')
      && form.extensionVersion.trim()
      && form.steps.length
      && form.steps.every((step) => /^[a-z][a-z0-9_-]*$/.test(step.step_id) && /^[a-z][a-z0-9_.:-]*$/.test(step.action))
      && ids.length === new Set(ids).size
    );
  }, [form, organizationId]);

  const updateStep = (index, updates) => {
    setForm((current) => ({
      ...current,
      steps: current.steps.map((step, stepIndex) => stepIndex === index ? { ...step, ...updates } : step),
    }));
  };

  const save = async () => {
    if (!valid) return;
    setSaving(true);
    setError('');
    try {
      const flow = await createFlow({
        organization_id: organizationId,
        name: form.name.trim(),
        description: form.description.trim() || null,
        flow_type: 'custom',
        approval_strategy: 'AUTO',
        hooks: {},
        trigger: { trigger_type: 'API_CALL', config: {} },
        deployment_profile_ids: [],
        extension: {
          extension_uri: form.extensionUri.trim(),
          extension_version: form.extensionVersion.trim(),
          extends_flow_type: form.baseType,
          entry_step_id: form.steps[0].step_id,
          steps: form.steps.map((step) => ({
            step_id: step.step_id,
            action: step.action,
            ...(step.description.trim() ? { description: step.description.trim() } : {}),
            config: {},
          })),
          transitions: buildTransitions(form.steps),
          config: {},
        },
      });
      navigate(`/console/org/flows/definitions/${flow.id}`);
    } catch (cause) {
      setError(cause.message || 'Custom flow could not be created.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Button startIcon={<ArrowBackIcon />} onClick={() => navigate('/console/org/flows/definitions/new')} sx={{ mb: 2 }}>
        Standard flows
      </Button>
      <Typography variant="h4" gutterBottom>Custom flow extension</Typography>
      <Typography color="text.secondary" sx={{ mb: 3 }}>MIP 0.3 extension envelope</Typography>
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <Paper variant="outlined" sx={{ p: { xs: 2, sm: 3 } }}>
        <Stack spacing={2.5}>
          <TextField required label="Flow name" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} />
          <TextField multiline minRows={2} label="Description" value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} />
          <FormControl fullWidth>
            <InputLabel>Extends standard flow</InputLabel>
            <Select value={form.baseType} label="Extends standard flow" onChange={(event) => setForm({ ...form, baseType: event.target.value })}>
              {(capabilities?.standard_flow_types || []).map((flowType) => <MenuItem key={flowType} value={flowType}>{flowType}</MenuItem>)}
            </Select>
          </FormControl>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <TextField fullWidth required label="Extension URI" value={form.extensionUri} onChange={(event) => setForm({ ...form, extensionUri: event.target.value })} />
            <TextField fullWidth required label="Version" value={form.extensionVersion} onChange={(event) => setForm({ ...form, extensionVersion: event.target.value })} />
          </Stack>

          <Box>
            <Stack direction="row" justifyContent="space-between" alignItems="center" sx={{ mb: 1.5 }}>
              <Typography variant="subtitle1">Steps</Typography>
              <Button size="small" startIcon={<AddIcon />} onClick={() => setForm({ ...form, steps: [...form.steps, { ...NEW_STEP }] })}>Add step</Button>
            </Stack>
            <Stack spacing={1.5}>
              {form.steps.map((step, index) => (
                <Stack key={index} direction={{ xs: 'column', sm: 'row' }} spacing={1} alignItems="center">
                  <TextField required fullWidth label="Step ID" value={step.step_id} onChange={(event) => updateStep(index, { step_id: event.target.value })} />
                  <TextField required fullWidth label="Action" value={step.action} onChange={(event) => updateStep(index, { action: event.target.value })} />
                  <TextField fullWidth label="Description" value={step.description} onChange={(event) => updateStep(index, { description: event.target.value })} />
                  <IconButton
                    aria-label={`Remove step ${index + 1}`}
                    disabled={form.steps.length === 1}
                    onClick={() => setForm({ ...form, steps: form.steps.filter((_, stepIndex) => stepIndex !== index) })}
                  >
                    <DeleteIcon />
                  </IconButton>
                </Stack>
              ))}
            </Stack>
          </Box>

          <Box sx={{ display: 'flex', justifyContent: 'flex-end' }}>
            <Button variant="contained" startIcon={<SaveIcon />} disabled={!valid || saving} onClick={save}>
              Create draft
            </Button>
          </Box>
        </Stack>
      </Paper>
    </Container>
  );
};

export default CustomFlowBuilder;
