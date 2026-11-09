import { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  CircularProgress,
  Alert,
  AlertTitle,
  Button,
  Stack,
  Chip,
} from '@mui/material';
import PolicyIcon from '@mui/icons-material/Policy';
import { Link as RouterLink } from 'react-router';
import { listPresentationPolicies } from '../../../../services/presentationPolicyApi';
import { listFlows } from '../../../../services/flowsApi';
import { loadScopedCatalog } from '../../../../services/loadScopedCatalog';

function isVerificationFlow(flow = {}) {
  const type = String(flow.flow_type || flow.type || '').toLowerCase();
  return Boolean(
    flow.presentation_policy_id
    && (
      type.includes('verification')
      || type.includes('oid4vp')
      || type.includes('presentation')
    )
  );
}

function isActive(resource) {
  return String(resource?.status || '').toLowerCase() === 'active';
}

function PolicySelectStep({ value, onChange, organizationId, onValidityChange }) {
  const [policies, setPolicies] = useState([]);
  const [flows, setFlows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [retryCount, setRetryCount] = useState(0);

  useEffect(() => {
    let mounted = true;
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    setPolicies([]);
    setFlows([]);

    if (!organizationId) {
      setPolicies([]);
      setFlows([]);
      setError('An active organization is required before loading presentation policies.');
      setLoading(false);
      return () => { mounted = false; };
    }

    Promise.all([
      loadScopedCatalog(listPresentationPolicies, organizationId, { signal: controller.signal }),
      loadScopedCatalog(listFlows, organizationId, { signal: controller.signal }),
    ])
      .then(([policyData, flowData]) => {
        if (mounted) {
          const activePolicies = policyData.filter(isActive);
          const policyIds = new Set(activePolicies.map((policy) => policy.id));
          setPolicies(activePolicies);
          setFlows(flowData.filter((flow) => (
            isActive(flow) && isVerificationFlow(flow) && policyIds.has(flow.presentation_policy_id)
          )));
          setLoading(false);
        }
      })
      .catch((err) => {
        if (mounted) {
          setError(err.message || 'Failed to load verification policies and flows');
          setLoading(false);
        }
      });
    return () => { mounted = false; controller.abort(); };
  }, [organizationId, retryCount]);

  const selectedPolicy = policies.find((policy) => policy.id === value?.policy_id);
  const selectedFlow = flows.find((flow) => (
    flow.id === value?.flow_id && flow.presentation_policy_id === value?.policy_id
  ));
  const selectionValid = Boolean(!loading && !error && selectedPolicy && (!value?.flow_id || selectedFlow));

  useEffect(() => {
    onValidityChange?.(selectionValid);
  }, [selectionValid, onValidityChange]);

  const handlePolicyChange = (e) => {
    onChange({
      ...value,
      flow_id: null,
      flow_name: null,
      policy_id: e.target.value,
      trust_profile_id: null,
      deployment_profile_id: null,
    });
  };

  const handleFlowChange = (e) => {
    const flow = flows.find((item) => item.id === e.target.value);
    if (!flow) {
      onChange({
        ...value,
        flow_id: null,
        flow_name: null,
        policy_id: null,
        trust_profile_id: null,
        deployment_profile_id: null,
      });
      return;
    }
    onChange({
      ...value,
      flow_id: flow.id,
      flow_name: flow.name || flow.id,
      policy_id: flow.presentation_policy_id,
      trust_profile_id: flow.trust_profile_id,
      deployment_profile_id: flow.deployment_profile_id,
    });
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <PolicyIcon color="primary" />
        <Typography variant="h6">Select Presentation Policy</Typography>
      </Box>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Choose an active presentation policy that defines which credentials and
        claims the wallet holder must present.
      </Typography>

      {error && <Alert severity="error" sx={{ mb: 2 }} action={<Button color="inherit" size="small" onClick={() => setRetryCount((count) => count + 1)}>Retry</Button>}>{error}</Alert>}

      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
          <CircularProgress aria-label="Loading verification policies and flows" />
        </Box>
      ) : error ? null : policies.length === 0 ? (
        <Alert severity="info">
          <AlertTitle>No active presentation policies</AlertTitle>
          Create and activate a presentation policy before starting a verification session.
          <Box sx={{ mt: 1 }}>
            <Button component={RouterLink} to="/console/org/policies/presentation" color="inherit" size="small">
              Manage Presentation Policies
            </Button>
          </Box>
        </Alert>
      ) : (
        <Stack spacing={2}>
          {flows.length > 0 ? (
            <FormControl fullWidth>
              <InputLabel>Verification Flow</InputLabel>
              <Select
                value={selectedFlow?.id || ''}
                onChange={handleFlowChange}
                label="Verification Flow"
                inputProps={{ 'aria-label': 'Verification Flow' }}
              >
                <MenuItem value="">
                  Start from presentation policy
                </MenuItem>
                {flows.map((flow) => (
                  <MenuItem key={flow.id} value={flow.id}>
                    {flow.name || flow.id}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          ) : (
            <Alert severity="info">
              No active verification flows are available. Select an active presentation policy below to create a session.
            </Alert>
          )}

          {selectedFlow && (
            <Alert severity="info">
              Starting from <strong>{selectedFlow.name || selectedFlow.id}</strong>. ElevenID will use the presentation policy, trust profile, and deployment profile configured on that flow.
            </Alert>
          )}

          <FormControl fullWidth disabled={Boolean(selectedFlow)}>
            <InputLabel>Presentation Policy</InputLabel>
            <Select
              data-testid="verification-policy-select"
              value={value?.flow_id && !selectedFlow ? '' : (selectedPolicy?.id || '')}
              onChange={handlePolicyChange}
              label="Presentation Policy"
              inputProps={{ 'aria-label': 'Presentation Policy' }}
            >
              {policies.map((policy) => (
                <MenuItem key={policy.id} value={policy.id}>
                  {policy.name || policy.id}
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          {selectedFlow && (
            <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap' }} useFlexGap>
              <Chip size="small" label={`Policy: ${value.policy_id}`} variant="outlined" />
              {value.trust_profile_id && <Chip size="small" label={`Trust: ${value.trust_profile_id}`} variant="outlined" />}
              {value.deployment_profile_id && <Chip size="small" label={`Deployment: ${value.deployment_profile_id}`} variant="outlined" />}
            </Stack>
          )}
        </Stack>
      )}
    </Box>
  );
}

export default PolicySelectStep;
