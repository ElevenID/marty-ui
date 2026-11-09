import {
  Box,
  Typography,
  TextField,
  MenuItem,
} from '@mui/material';
import SettingsIcon from '@mui/icons-material/Settings';

function SessionConfigStep({ value, onChange, issuerIdentities = [] }) {
  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <SettingsIcon color="primary" />
        <Typography variant="h6">Configure Session</Typography>
      </Box>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Set a human-readable purpose for this verification session.
      </Typography>

      <TextField
        inputProps={{ 'data-testid': 'verification-purpose-input' }}
        label="Verification Purpose"
        placeholder="e.g. Age verification for service access"
        fullWidth
        value={value?.purpose || ''}
        onChange={(e) => onChange({ ...value, purpose: e.target.value })}
        sx={{ mb: 3 }}
        helperText="Use a short description to identify this session."
      />

      {issuerIdentities.length > 1 && (
        <TextField
          select
          required
          label="Issuer DID"
          fullWidth
          value={value?.issuer_did || ''}
          onChange={(e) => onChange({ ...value, issuer_did: e.target.value })}
          helperText="Select the public verifier identity for this request."
          sx={{ mb: 3 }}
        >
          {issuerIdentities.map((identity) => (
            <MenuItem key={identity.issuer_did} value={identity.issuer_did}>
              {identity.issuer_did}
            </MenuItem>
          ))}
        </TextField>
      )}
    </Box>
  );
}

export default SessionConfigStep;
