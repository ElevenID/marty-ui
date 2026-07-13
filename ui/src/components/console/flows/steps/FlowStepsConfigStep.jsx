import {
  Alert,
  Box,
  Chip,
  FormControl,
  InputLabel,
  List,
  ListItem,
  ListItemText,
  MenuItem,
  Select,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import WebhookIcon from '@mui/icons-material/Webhook';

function titleize(value) {
  return String(value || '').replace(/_/g, ' ').replace(/\b\w/g, (character) => character.toUpperCase());
}

const FlowStepsConfigStep = ({
  approvalStrategy = 'AUTO',
  capabilities,
  description,
  flowType,
  hooks = {},
  name,
  onUpdate,
  triggerType = 'API_CALL',
}) => {
  const sequence = capabilities?.sequences?.[flowType] || [];
  const extensibleSteps = capabilities?.extensible_steps?.[flowType] || [];

  const updateHook = (stepName, url) => {
    const hookName = `post_${stepName}`;
    const nextHooks = { ...hooks };
    if (url.trim()) {
      nextHooks[hookName] = [{ hook_type: 'WEBHOOK', url: url.trim(), config: {} }];
    } else {
      delete nextHooks[hookName];
    }
    onUpdate({ hooks: nextHooks });
  };

  return (
    <Box>
      <Typography variant="h6" gutterBottom>Flow details</Typography>
      <Stack spacing={2.5}>
        <TextField
          fullWidth
          required
          label="Flow name"
          value={name}
          onChange={(event) => onUpdate({ name: event.target.value })}
          inputProps={{ maxLength: 255 }}
        />
        <TextField
          fullWidth
          multiline
          minRows={2}
          label="Description"
          value={description}
          onChange={(event) => onUpdate({ description: event.target.value })}
          inputProps={{ maxLength: 2000 }}
        />
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
          <FormControl fullWidth>
            <InputLabel id="flow-approval-label">Approval</InputLabel>
            <Select
              id="flow-approval"
              labelId="flow-approval-label"
              value={approvalStrategy}
              label="Approval"
              onChange={(event) => onUpdate({ approvalStrategy: event.target.value })}
            >
              <MenuItem value="AUTO">Automatic</MenuItem>
              <MenuItem value="MANUAL">Manual</MenuItem>
              <MenuItem value="RULES_BASED">Rules based</MenuItem>
              <MenuItem value="EXTERNAL">External decision</MenuItem>
            </Select>
          </FormControl>
          <FormControl fullWidth>
            <InputLabel id="flow-trigger-label">Trigger</InputLabel>
            <Select
              id="flow-trigger"
              labelId="flow-trigger-label"
              value={triggerType}
              label="Trigger"
              onChange={(event) => onUpdate({ triggerType: event.target.value })}
            >
              <MenuItem value="API_CALL">API call</MenuItem>
              <MenuItem value="WEBHOOK">Webhook</MenuItem>
              <MenuItem value="SCHEDULE">Schedule</MenuItem>
              <MenuItem value="APPLICATION_SUBMITTED">Application submitted</MenuItem>
            </Select>
          </FormControl>
        </Stack>

        <Box>
          <Typography variant="subtitle2" gutterBottom>MIP sequence</Typography>
          <List disablePadding>
            {sequence.map((stepName, index) => (
              <ListItem key={stepName} divider={index < sequence.length - 1} sx={{ px: 0, minHeight: 48 }}>
                <Chip label={index + 1} size="small" color="primary" sx={{ mr: 2, width: 30 }} />
                <ListItemText primary={titleize(stepName)} secondary={stepName} />
                {extensibleSteps.includes(stepName) && <Chip label="Hook" size="small" variant="outlined" />}
              </ListItem>
            ))}
          </List>
        </Box>

        {extensibleSteps.length > 0 && (
          <Box>
            <Stack direction="row" alignItems="center" gap={1} sx={{ mb: 1.5 }}>
              <WebhookIcon color="action" fontSize="small" />
              <Typography variant="subtitle2">Post-step webhooks</Typography>
            </Stack>
            <Stack spacing={2}>
              {extensibleSteps.map((stepName) => (
                <TextField
                  key={stepName}
                  fullWidth
                  type="url"
                  label={`After ${titleize(stepName)}`}
                  aria-label={`After ${titleize(stepName)} webhook URL`}
                  value={hooks[`post_${stepName}`]?.[0]?.url || ''}
                  onChange={(event) => updateHook(stepName, event.target.value)}
                />
              ))}
            </Stack>
          </Box>
        )}

        {sequence.length === 0 && <Alert severity="error">This flow type has no runtime sequence.</Alert>}
      </Stack>
    </Box>
  );
};

export default FlowStepsConfigStep;
