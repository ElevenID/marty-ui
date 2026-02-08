/**
 * Runtime Settings Step - Deployment Profile Wizard
 * 
 * Configure default presentation policy and enabled flows.
 */

import { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormHelperText,
  FormGroup,
  FormControlLabel,
  Checkbox,
  Alert,
  CircularProgress,
  Button,
} from '@mui/material';
import { useNavigate } from 'react-router-dom';
import AddCircleOutlineIcon from '@mui/icons-material/AddCircleOutline';
import PolicyIcon from '@mui/icons-material/Policy';

import { listPresentationPolicies } from '../../../../services/presentationPolicyApi';

const FLOW_TYPES = [
  { value: 'verification', label: 'Verification', description: 'Verify credentials from holders' },
  { value: 'issuance', label: 'Issuance', description: 'Issue new credentials' },
  { value: 'combined', label: 'Combined', description: 'Both verification and issuance' },
];

const RuntimeSettingsStep = ({ data, onChange }) => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [policies, setPolicies] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    loadPolicies();
  }, []);

  const loadPolicies = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await listPresentationPolicies();
      const items = response.data || response || [];
      // Filter to active policies
      const activePolicies = items.filter((p) => p.status === 'active');
      setPolicies(activePolicies);

      // Auto-select if only one policy
      if (activePolicies.length === 1 && !data.default_policy_id) {
        onChange({ default_policy_id: activePolicies[0].id });
      }
    } catch (err) {
      console.error('Failed to load policies:', err);
      setError('Failed to load presentation policies');
    } finally {
      setLoading(false);
    }
  };

  const handleFlowToggle = (flowValue) => {
    const flows = data.enabled_flows || [];
    const updated = flows.includes(flowValue)
      ? flows.filter((f) => f !== flowValue)
      : [...flows, flowValue];
    onChange({ enabled_flows: updated });
  };

  const handleGoToPolicies = () => {
    navigate('/console/policies/presentation/new');
  };

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 8 }}>
        <CircularProgress />
      </Box>
    );
  }

  // No policies - block progression
  if (policies.length === 0) {
    return (
      <Box sx={{ textAlign: 'center', py: 4 }}>
        <PolicyIcon sx={{ fontSize: 80, color: 'warning.main', mb: 3 }} />
        
        <Typography variant="h5" gutterBottom>
          Presentation Policy Required
        </Typography>
        
        <Typography color="text.secondary" paragraph sx={{ maxWidth: 600, mx: 'auto' }}>
          Before creating a deployment profile, you need at least one active Presentation Policy.
          Presentation Policies define what credentials must be presented during verification.
        </Typography>

        <Alert severity="warning" sx={{ maxWidth: 600, mx: 'auto', mb: 3 }}>
          <Typography variant="body2">
            You cannot proceed until an active Presentation Policy exists.
          </Typography>
        </Alert>

        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center' }}>
          <Button
            variant="contained"
            startIcon={<AddCircleOutlineIcon />}
            onClick={handleGoToPolicies}
          >
            Create Presentation Policy
          </Button>
          <Button
            variant="outlined"
            onClick={() => window.location.reload()}
          >
            Refresh
          </Button>
        </Box>
      </Box>
    );
  }

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Runtime Settings
      </Typography>
      <Typography color="text.secondary" paragraph>
        Configure which presentation policy and flows this deployment will use.
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Default Presentation Policy */}
      <FormControl fullWidth required sx={{ mb: 4 }}>
        <InputLabel>Default Presentation Policy</InputLabel>
        <Select
          value={data.default_policy_id || ''}
          onChange={(e) => onChange({ default_policy_id: e.target.value })}
          label="Default Presentation Policy"
        >
          {policies.map((policy) => (
            <MenuItem key={policy.id} value={policy.id}>
              {policy.name}
            </MenuItem>
          ))}
        </Select>
        <FormHelperText>
          The presentation policy used by default in this deployment ({policies.length} active polic{policies.length !== 1 ? 'ies' : 'y'} available)
        </FormHelperText>
      </FormControl>

      {/* Enabled Flows */}
      <Typography variant="subtitle2" gutterBottom>
        Enabled Flows
      </Typography>
      <Typography variant="body2" color="text.secondary" paragraph>
        Select which types of flows this deployment supports
      </Typography>
      
      <FormGroup>
        {FLOW_TYPES.map((flow) => (
          <FormControlLabel
            key={flow.value}
            control={
              <Checkbox
                checked={(data.enabled_flows || []).includes(flow.value)}
                onChange={() => handleFlowToggle(flow.value)}
              />
            }
            label={
              <Box>
                <Typography variant="body1">{flow.label}</Typography>
                <Typography variant="body2" color="text.secondary">
                  {flow.description}
                </Typography>
              </Box>
            }
          />
        ))}
      </FormGroup>

      {data.enabled_flows && data.enabled_flows.length === 0 && (
        <Alert severity="info" sx={{ mt: 2 }}>
          Select at least one flow type to enable functionality in this deployment.
        </Alert>
      )}
    </Box>
  );
};

export default RuntimeSettingsStep;
