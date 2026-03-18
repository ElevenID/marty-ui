import {
  Box,
  Typography,
  TextField,
  FormControlLabel,
  Switch,
  Alert,
} from '@mui/material';
import SettingsIcon from '@mui/icons-material/Settings';

function SessionConfigStep({ value, onChange }) {
  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
        <SettingsIcon color="primary" />
        <Typography variant="h6">Configure Session</Typography>
      </Box>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Set a human-readable purpose shown to the wallet holder, and enable
        deep document inspection for ISO 18013-5 mDoc / passport credentials.
      </Typography>

      <TextField
        label="Verification Purpose"
        placeholder="e.g. Age verification for service access"
        fullWidth
        value={value?.purpose || ''}
        onChange={(e) => onChange({ ...value, purpose: e.target.value })}
        sx={{ mb: 3 }}
        helperText="Displayed to the wallet holder when prompted to share credentials."
      />

      <FormControlLabel
        control={
          <Switch
            checked={!!value?.request_inspection}
            onChange={(e) =>
              onChange({ ...value, request_inspection: e.target.checked })
            }
          />
        }
        label="Enable deep document inspection (ISO 18013-5 / mDoc)"
      />
      {value?.request_inspection && (
        <Alert severity="info" sx={{ mt: 1 }}>
          Inspection results will be available after the wallet submits its
          presentation. Requires the Marty InspectionSystem service.
        </Alert>
      )}
    </Box>
  );
}

export default SessionConfigStep;
