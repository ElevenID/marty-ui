import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Alert,
  Box,
  Button,
  Card,
  CardActionArea,
  CardContent,
  Chip,
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

import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
import { createPolicySet, listPolicySetTemplates, validatePolicySet } from '../../../services/policySetsApi';

const PolicySetWizard = () => {
  const navigate = useNavigate();
  const { organizationId: authOrganizationId } = useAuth();
  const { activeOrgId } = useConsole();
  const organizationId = activeOrgId;
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

  useEffect(() => {
    if (!organizationId) return;
    listPolicySetTemplates(organizationId).then(setTemplates).catch((cause) => setError(cause.message));
  }, [organizationId]);

  const chooseTemplate = (template) => {
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
    setError('');
    try {
      setValidation(await validatePolicySet(organizationId, policies));
    } catch (cause) {
      setError(cause.message);
    }
  };

  const save = async () => {
    setSaving(true);
    setError('');
    try {
      const result = await validatePolicySet(organizationId, policies);
      setValidation(result);
      if (!result.valid) return;
      const created = await createPolicySet(organizationId, {
        name: name.trim(),
        description: description.trim() || null,
        policy_type: policyType,
        cedar_policies: policies,
      });
      navigate(`/console/org/policies/sets/${created.id}`);
    } catch (cause) {
      setError(cause.message || 'Policy Set could not be created.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Container maxWidth="md" sx={{ py: 4 }}>
      <Button startIcon={<ArrowBackIcon />} onClick={() => navigate('/console/org/policies/sets')} sx={{ mb: 2 }}>Policy Sets</Button>
      <Typography variant="h4" gutterBottom>Create Policy Set</Typography>
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <Typography variant="h6" sx={{ mb: 1.5 }}>Start from a template</Typography>
      <Grid container spacing={1.5} sx={{ mb: 3 }}>
        {templates.map((template) => (
          <Grid item xs={12} sm={4} key={template.template_id}>
            <Card variant="outlined" sx={{ height: '100%', borderColor: selectedTemplate === template.template_id ? 'primary.main' : 'divider' }}>
              <CardActionArea onClick={() => chooseTemplate(template)} sx={{ height: '100%' }}>
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
        <Stack spacing={2.5}>
          <TextField required label="Name" value={name} onChange={(event) => setName(event.target.value)} inputProps={{ maxLength: 128 }} />
          <TextField multiline minRows={2} label="Description" value={description} onChange={(event) => setDescription(event.target.value)} inputProps={{ maxLength: 1024 }} />

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
                    <IconButton aria-label={`Delete ${policy.policy_id}`} disabled={policies.length === 1} onClick={() => setPolicies(policies.filter((_, policyIndex) => policyIndex !== index))}><DeleteIcon /></IconButton>
                  </Stack>
                  <TextField
                    fullWidth
                    multiline
                    minRows={10}
                    label="Cedar policy"
                    value={policy.cedar_text}
                    onChange={(event) => updatePolicy(index, { cedar_text: event.target.value })}
                    inputProps={{ style: { fontFamily: 'monospace', fontSize: 13 } }}
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
            <Button variant="outlined" onClick={runValidation} disabled={!policies.length}>Validate</Button>
            <Button variant="contained" startIcon={<SaveIcon />} onClick={save} disabled={!name.trim() || !policies.length || saving}>Create draft</Button>
          </Stack>
        </Stack>
      </Paper>
    </Container>
  );
};

export default PolicySetWizard;
