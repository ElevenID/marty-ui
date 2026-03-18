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
  Divider,
} from '@mui/material';
import PolicyIcon from '@mui/icons-material/Policy';
import { listPresentationPolicies } from '../../../../services/presentationPolicyApi';
import { useAuth } from '../../../../hooks/useAuth';

function PolicySelectStep({ value, onChange }) {
  const { user } = useAuth();
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [useInline, setUseInline] = useState(false);

  useEffect(() => {
    let mounted = true;
    setLoading(true);
    listPresentationPolicies({ organization_id: user?.organization_id })
      .then((data) => {
        if (mounted) {
          setPolicies(data?.items || data?.policies || []);
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
  }, [user?.organization_id]);

  const handlePolicyChange = (e) => {
    onChange({ ...value, policy_id: e.target.value, inline_policy: null });
  };

  const handleInlineToggle = (e) => {
    setUseInline(e.target.checked);
    if (e.target.checked) {
      onChange({ ...value, policy_id: null });
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

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}>
          <CircularProgress />
        </Box>
      ) : (
        <>
          <FormControlLabel
            control={<Switch checked={useInline} onChange={handleInlineToggle} />}
            label="Use ad-hoc policy (advanced)"
            sx={{ mb: 2 }}
          />

          {!useInline && (
            <FormControl fullWidth>
              <InputLabel>Presentation Policy</InputLabel>
              <Select
                value={value?.policy_id || ''}
                onChange={handlePolicyChange}
                label="Presentation Policy"
              >
                {policies.map((policy) => (
                  <MenuItem key={policy.id} value={policy.id}>
                    {policy.name || policy.id}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
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
