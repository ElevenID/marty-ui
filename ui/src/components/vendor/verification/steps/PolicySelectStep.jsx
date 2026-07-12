import { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormControlLabel,
  Switch,
  CircularProgress,
  Alert,
  Button,
  Divider,
  Stack,
  Chip,
} from '@mui/material';
import PolicyIcon from '@mui/icons-material/Policy';
import { listPresentationPolicies } from '../../../../services/presentationPolicyApi';
import { listFlows } from '../../../../services/flowsApi';

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

function PolicySelectStep({ value, onChange, organizationId }) {
  const [policies, setPolicies] = useState([]);
  const [flows, setFlows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [useInline, setUseInline] = useState(false);
  const [retryCount, setRetryCount] = useState(0);

  useEffect(() => {
    let mounted = true;
    setLoading(true);
    setError(null);

    if (!organizationId) {
      setPolicies([]);
      setFlows([]);
      setError('An active organization is required before loading presentation policies.');
      setLoading(false);
      return () => { mounted = false; };
    }

    Promise.all([
      listPresentationPolicies({ organization_id: organizationId }),
      listFlows({ organization_id: organizationId }),
    ])
      .then(([policyData, flowData]) => {
        if (mounted) {
          setPolicies(policyData);
          setFlows(flowData.filter(isVerificationFlow));
          setLoading(false);
        }
      })
      .catch((err) => {
        if (mounted) {
          setError(err.message || 'Failed to load presentation policies');
          setLoading(false);
        }
      });
    return () => { mounted = false; };
  }, [organizationId, retryCount]);

  const handlePolicyChange = (e) => {
    onChange({ ...value, flow_id: null, flow_name: null, policy_id: e.target.value, inline_policy: null });
  };

  const handleFlowChange = (e) => {
    const flow = flows.find((item) => item.id === e.target.value);
    if (!flow) {
      onChange({ ...value, flow_id: null, flow_name: null });
      return;
    }
    onChange({
      ...value,
      flow_id: flow.id,
      flow_name: flow.name || flow.id,
      policy_id: flow.presentation_policy_id,
      trust_profile_id: flow.trust_profile_id,
      deployment_profile_id: flow.deployment_profile_id,
      inline_policy: null,
    });
  };

  const handleInlineToggle = (e) => {
    setUseInline(e.target.checked);
    if (e.target.checked) {
      onChange({ ...value, flow_id: null, flow_name: null, policy_id: null });
    }
  };

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <PolicyIcon color="primary" />
        <Typography variant="h6">Select Presentation Policy</Typography>
      </Box>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Choose a saved presentation policy that defines which credentials and
        claims the wallet holder must present.
      </Typography>

      {error && <Alert severity="error" sx={{ mb: 2 }} action={<Button color="inherit" size="small" onClick={() => setRetryCount((count) => count + 1)}>Retry</Button>}>{error}</Alert>}

      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
          <CircularProgress />
        </Box>
      ) : error ? null : (
        <>
          <FormControlLabel
            control={<Switch checked={useInline} onChange={handleInlineToggle} />}
            label="Use ad-hoc policy (advanced)"
            sx={{ mb: 2 }}
          />

          {!useInline && (
            <Stack spacing={2}>
              <FormControl fullWidth>
                <InputLabel>Verification Flow</InputLabel>
                <Select
                  value={value?.flow_id || ''}
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

              {value?.flow_id && (
                <Alert severity="info">
                  Starting from <strong>{value.flow_name}</strong>. ElevenID will use the presentation policy, trust profile, and deployment profile configured on that flow.
                </Alert>
              )}

              <FormControl fullWidth disabled={Boolean(value?.flow_id)}>
                <InputLabel>Presentation Policy</InputLabel>
                <Select
                  value={value?.policy_id || ''}
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

              {value?.flow_id && (
                <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                  <Chip size="small" label={`Policy: ${value.policy_id}`} variant="outlined" />
                  {value.trust_profile_id && <Chip size="small" label={`Trust: ${value.trust_profile_id}`} variant="outlined" />}
                  {value.deployment_profile_id && <Chip size="small" label={`Deployment: ${value.deployment_profile_id}`} variant="outlined" />}
                </Stack>
              )}
            </Stack>
          )}

          {useInline && (
            <>
              <Divider sx={{ mb: 2 }} />
              <Alert severity="info">
                Ad-hoc inline policies can be configured after session creation
                by editing the session request parameters.
              </Alert>
            </>
          )}
        </>
      )}
    </Box>
  );
}

export default PolicySelectStep;
