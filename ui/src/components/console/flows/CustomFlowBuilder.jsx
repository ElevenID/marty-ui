import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router';
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
import { listCredentialTemplates } from '../../../services/presentationPolicyApi';

const NEW_STEP = { action: '', description: '', step_id: '' };

function buildTransitions(steps) {
  return steps.slice(0, -1).map((step, index) => ({
    from_step_id: step.step_id,
    to_step_id: steps[index + 1].step_id,
    outcome: 'SUCCESS',
  }));
}

const CustomFlowBuilderForm = ({ organizationId }) => {
  const navigate = useNavigate();
  const mounted = useRef(true);
  const [capabilities, setCapabilities] = useState(null);
  const [capabilityError, setCapabilityError] = useState('');
  const [capabilityAttempt, setCapabilityAttempt] = useState(0);
  const [applicationApproved, setApplicationApproved] = useState(false);
  const [templates, setTemplates] = useState({ items: [], loading: false, error: '' });
  const [templateAttempt, setTemplateAttempt] = useState(0);
  const [templateId, setTemplateId] = useState('');
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
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);

  useEffect(() => {
    let current = true;
    setCapabilities(null); setCapabilityError('');
    getFlowCapabilities().then((value) => { if (current) setCapabilities(value); })
      .catch((cause) => { if (current) setCapabilityError(cause.message || 'Flow capabilities could not be loaded.'); });
    return () => { current = false; };
  }, [capabilityAttempt]);

  useEffect(() => {
    let current = true;
    setTemplateId('');
    setTemplates({ items: [], loading: applicationApproved && Boolean(organizationId), error: '' });
    if (applicationApproved && organizationId) {
      (async () => {
        const items = []; const seen = new Set();
        for (let offset = 0; current; offset += 100) {
          const page = await listCredentialTemplates({ organization_id: organizationId, limit: 100, offset });
          if (!current) return;
          if (!Array.isArray(page)) throw new Error('Credential template catalog is malformed.');
          for (const item of page) {
            if (!item?.id || seen.has(item.id)) throw new Error('Credential template pagination did not advance.');
            seen.add(item.id); items.push(item);
          }
          if (page.length < 100) break;
        }
        if (current) setTemplates({ items: items.filter((item) => item.organization_id === organizationId
          && String(item.status).toUpperCase() === 'ACTIVE' && item.issuance_protocol === 'OID4VCI_PRE_AUTH'
          && item.trust_profile_id), loading: false, error: '' });
      })().catch((cause) => {
        if (current) setTemplates({ items: [], loading: false, error: cause.message || 'Credential templates could not be loaded.' });
      });
    }
    return () => { current = false; };
  }, [applicationApproved, organizationId, templateAttempt]);

  const applicationSupported = capabilities?.flow_types?.includes('custom')
    && capabilities?.standard_flow_types?.includes('oid4vci_pre_authorized') && capabilities?.triggers?.includes('WEBHOOK');
  const selectedTemplate = templates.items.find((item) => item.id === templateId);
  const effectiveSteps = applicationApproved ? [{ action: 'issuance.issue', description: '', step_id: 'issue' }] : form.steps;

  const ids = effectiveSteps.map((step) => step.step_id);
  const valid = Boolean(
      organizationId
      && !saving
      && capabilities?.flow_types?.includes('custom')
      && capabilities?.standard_flow_types?.includes(form.baseType)
      && (applicationApproved || capabilities?.triggers?.includes('API_CALL'))
      && (!applicationApproved || (applicationSupported && !templates.loading && !templates.error && selectedTemplate))
      && form.name.trim()
      && form.extensionUri.includes(':')
      && form.extensionVersion.trim()
      && effectiveSteps.length
      && effectiveSteps.every((step) => /^[a-z][a-z0-9_-]*$/.test(step.step_id) && /^[a-z][a-z0-9_.:-]*$/.test(step.action))
      && ids.length === new Set(ids).size
    );

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
        trigger: applicationApproved
          ? { trigger_type: 'WEBHOOK', config: { event_type: 'APPLICATION_APPROVED' } }
          : { trigger_type: 'API_CALL', config: {} },
        ...(applicationApproved ? { credential_template_id: selectedTemplate.id, trust_profile_id: selectedTemplate.trust_profile_id } : {}),
        deployment_profile_ids: [],
        extension: {
          extension_uri: form.extensionUri.trim(),
          extension_version: form.extensionVersion.trim(),
          extends_flow_type: form.baseType,
          entry_step_id: effectiveSteps[0].step_id,
          steps: effectiveSteps.map((step) => ({
            step_id: step.step_id,
            action: step.action,
            ...(step.description.trim() ? { description: step.description.trim() } : {}),
            config: {},
          })),
          transitions: buildTransitions(effectiveSteps),
          config: {},
        },
      });
      if (mounted.current) navigate(`/console/org/flows/definitions/${flow.id}`);
    } catch (cause) {
      if (mounted.current) setError(cause.message || 'Custom flow could not be created.');
    } finally {
      if (mounted.current) setSaving(false);
    }
  };

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Button startIcon={<ArrowBackIcon />} onClick={() => navigate('/console/org/flows/definitions/new')} sx={{ mb: 2 }}>
        Standard flows
      </Button>
      <Typography variant="h4" gutterBottom>Custom flow extension</Typography>
      <Typography color="text.secondary" sx={{ mb: 3 }}>MIP 0.4 extension envelope</Typography>
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      {capabilityError && <Alert severity="error" sx={{ mb: 2 }} action={<Button onClick={() => setCapabilityAttempt((n) => n + 1)}>Retry capabilities</Button>}>{capabilityError}</Alert>}

      <Paper variant="outlined" sx={{ p: { xs: 2, sm: 3 } }}>
        <Stack spacing={2.5}>
          <FormControl fullWidth>
            <InputLabel id="custom-flow-setup-label">Flow setup</InputLabel>
            <Select labelId="custom-flow-setup-label" label="Flow setup" value={applicationApproved ? 'application-approved' : 'api'} disabled={saving}
              onChange={(event) => {
                const approved = event.target.value === 'application-approved';
                setApplicationApproved(approved); setTemplateId('');
                if (approved) setForm((value) => ({ ...value, baseType: 'oid4vci_pre_authorized' }));
              }}>
              <MenuItem value="api">Custom API flow</MenuItem>
              <MenuItem value="application-approved" disabled={!applicationSupported}>Approved application issuance</MenuItem>
            </Select>
          </FormControl>
          {applicationApproved && <Alert severity="info">Issue the selected credential after a trusted application approval. This flow uses the applicant service approval event; creating a draft does not issue a credential.</Alert>}
          <TextField required label="Flow name" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} />
          <TextField multiline minRows={2} label="Description" value={form.description} onChange={(event) => setForm({ ...form, description: event.target.value })} />
          <FormControl fullWidth>
            <InputLabel id="custom-flow-base-label">Extends standard flow</InputLabel>
            <Select labelId="custom-flow-base-label" value={form.baseType} label="Extends standard flow" disabled={applicationApproved || saving} onChange={(event) => setForm({ ...form, baseType: event.target.value })}>
              {(capabilities?.standard_flow_types || []).map((flowType) => <MenuItem key={flowType} value={flowType}>{flowType}</MenuItem>)}
            </Select>
          </FormControl>
          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <TextField fullWidth required label="Extension URI" value={form.extensionUri} onChange={(event) => setForm({ ...form, extensionUri: event.target.value })} />
            <TextField fullWidth required label="Version" value={form.extensionVersion} onChange={(event) => setForm({ ...form, extensionVersion: event.target.value })} />
          </Stack>

          {applicationApproved ? <Box>
            {templates.error && <Alert severity="error" action={<Button onClick={() => setTemplateAttempt((n) => n + 1)}>Retry templates</Button>}>{templates.error}</Alert>}
            <FormControl fullWidth required sx={{ mt: 2 }} disabled={templates.loading || saving || Boolean(templates.error)}>
              <InputLabel id="approved-flow-template-label">Credential template</InputLabel>
              <Select labelId="approved-flow-template-label" label="Credential template" value={templateId} onChange={(event) => setTemplateId(event.target.value)}>
                {templates.items.map((item) => <MenuItem key={item.id} value={item.id}>{item.name || item.id}</MenuItem>)}
              </Select>
            </FormControl>
            {!templates.loading && !templates.error && templates.items.length === 0 && <Alert severity="warning" sx={{ mt: 2 }}>No active pre-authorized credential template with a trust profile is available in this organization.</Alert>}
            <Typography sx={{ mt: 2 }}>Step: Issue credential</Typography>
          </Box> : <Box>
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
          </Box>}

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

export default function CustomFlowBuilder() {
  const { activeOrgId: organizationId } = useConsole();
  return <CustomFlowBuilderForm key={organizationId || 'no-organization'} organizationId={organizationId} />;
}
