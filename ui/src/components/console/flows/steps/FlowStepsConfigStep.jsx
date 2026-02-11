/**
 * Flow Steps Configuration Step
 * 
 * Configure flow name, description, and define the sequence of steps
 * with drag-drop reordering and preset templates
 */

import { useState } from 'react';
import {
  Box,
  Typography,
  TextField,
  Card,
  CardContent,
  Button,
  IconButton,
  List,
  ListItem,
  ListItemText,
  ListItemSecondaryAction,
  Chip,
  Alert,
  Menu,
  MenuItem,
  FormControl,
  InputLabel,
  Select,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import DragIndicatorIcon from '@mui/icons-material/DragIndicator';
import PresetIcon from '@mui/icons-material/AutoAwesome';

// Preset flow step templates
const VERIFICATION_PRESETS = [
  {
    name: 'Standard Verification',
    steps: [
      { name: 'Display QR Code', type: 'display_qr', config: {} },
      { name: 'Request Presentation', type: 'request_presentation', config: {} },
      { name: 'Validate Credentials', type: 'validate_credentials', config: {} },
      { name: 'Show Result', type: 'show_result', config: {} },
    ],
  },
  {
    name: 'Age Verification',
    steps: [
      { name: 'Display QR Code', type: 'display_qr', config: {} },
      { name: 'Request Age Proof', type: 'request_presentation', config: { predicate_only: true } },
      { name: 'Validate Age', type: 'validate_credentials', config: {} },
      { name: 'Grant Access', type: 'grant_access', config: {} },
    ],
  },
];

const ISSUANCE_PRESETS = [
  {
    name: 'Standard Issuance',
    steps: [
      { name: 'Collect User Info', type: 'collect_data', config: {} },
      { name: 'Verify Identity', type: 'verify_identity', config: {} },
      { name: 'Generate Credential', type: 'issue_credential', config: {} },
      { name: 'Deliver to Wallet', type: 'deliver_credential', config: {} },
    ],
  },
  {
    name: 'Pre-Authorized Issuance',
    steps: [
      { name: 'Generate Pre-Auth Code', type: 'generate_code', config: {} },
      { name: 'Send Invitation', type: 'send_invitation', config: {} },
      { name: 'Issue Credential', type: 'issue_credential', config: {} },
    ],
  },
];

const OID4VCI_PRESETS = [
  {
    name: 'OID4VCI QR Code Issuance',
    steps: [
      { name: 'Check Preconditions', type: 'approval', config: { required_preconditions: [] } },
      { name: 'Create Credential Offer', type: 'issuance', config: { transport_method: 'qr_code', offer_validity_minutes: 15 } },
      { name: 'QR Code Generated', type: 'wait', config: { wait_for_event: 'qr_scanned', show_deep_link: true } },
      { name: 'Token Exchange', type: 'callback', config: { endpoint: '/api/issuance/token' } },
      { name: 'Issue Credential', type: 'issuance', config: { endpoint: '/api/issuance/credential' } },
      { name: 'Issuance Complete', type: 'end', config: { emit_event: 'credential_issued' } },
    ],
  },
  {
    name: 'OID4VCI Deep Link Issuance',
    steps: [
      { name: 'Check Preconditions', type: 'approval', config: { required_preconditions: [] } },
      { name: 'Create Credential Offer', type: 'issuance', config: { transport_method: 'deep_link', offer_validity_minutes: 60 } },
      { name: 'Send Deep Link', type: 'callback', config: { delivery_method: 'email' } },
      { name: 'Token Exchange', type: 'callback', config: { endpoint: '/api/issuance/token' } },
      { name: 'Issue Credential', type: 'issuance', config: { endpoint: '/api/issuance/credential' } },
      { name: 'Issuance Complete', type: 'end', config: { emit_event: 'credential_issued' } },
    ],
  },
];

const COMBINED_PRESETS = [
  {
    name: 'Verify Then Issue',
    steps: [
      { name: 'Request Existing Credential', type: 'request_presentation', config: {} },
      { name: 'Validate Prerequisites', type: 'validate_credentials', config: {} },
      { name: 'Issue New Credential', type: 'issue_credential', config: {} },
      { name: 'Deliver to Wallet', type: 'deliver_credential', config: {} },
    ],
  },
];

const FlowStepsConfigStep = ({ 
  flowType, 
  name, 
  description, 
  flowSteps, 
  purpose = '',
  audience = '',
  deploymentTargets = [],
  onUpdate 
}) => {
  const [presetMenuAnchor, setPresetMenuAnchor] = useState(null);

  const handleFieldChange = (field, value) => {
    onUpdate({ [field]: value });
  };

  const handleAddStep = () => {
    const newStep = {
      name: `Step ${flowSteps.length + 1}`,
      type: 'custom',
      config: {},
    };
    onUpdate({ flowSteps: [...flowSteps, newStep] });
  };

  const handleRemoveStep = (index) => {
    const updatedSteps = flowSteps.filter((_, i) => i !== index);
    onUpdate({ flowSteps: updatedSteps });
  };

  const handleStepChange = (index, field, value) => {
    const updatedSteps = [...flowSteps];
    updatedSteps[index] = {
      ...updatedSteps[index],
      [field]: value,
    };
    onUpdate({ flowSteps: updatedSteps });
  };

  const handleMoveStep = (index, direction) => {
    if (
      (direction === 'up' && index === 0) ||
      (direction === 'down' && index === flowSteps.length - 1)
    ) {
      return;
    }

    const updatedSteps = [...flowSteps];
    const targetIndex = direction === 'up' ? index - 1 : index + 1;
    [updatedSteps[index], updatedSteps[targetIndex]] = [updatedSteps[targetIndex], updatedSteps[index]];
    onUpdate({ flowSteps: updatedSteps });
  };

  const handleApplyPreset = (preset) => {
    onUpdate({ flowSteps: [...preset.steps] });
    setPresetMenuAnchor(null);
  };

  // Get presets based on flow type
  const getPresets = () => {
    switch (flowType) {
      case 'verification':
        return VERIFICATION_PRESETS;
      case 'issuance':
        return ISSUANCE_PRESETS;
      case 'issuance_oid4vci':
        return OID4VCI_PRESETS;
      case 'combined':
        return COMBINED_PRESETS;
      default:
        return [];
    }
  };

  const presets = getPresets();

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Configure Flow Steps
      </Typography>
      
      <Typography color="text.secondary" paragraph>
        Define basic information and the sequence of steps for this flow
      </Typography>

      {/* Basic Information */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600 }}>
            Basic Information
          </Typography>

          <TextField
            fullWidth
            label="Flow Name"
            value={name}
            onChange={(e) => handleFieldChange('name', e.target.value)}
            required
            sx={{ mb: 2 }}
            helperText="A descriptive name for this flow"
          />

          <TextField
            fullWidth
            label="Description"
            value={description}
            onChange={(e) => handleFieldChange('description', e.target.value)}
            multiline
            rows={2}
            sx={{ mb: 2 }}
            helperText="Optional details about what this flow accomplishes"
          />

          <FormControl fullWidth sx={{ mb: 2 }}>
            <InputLabel>Purpose</InputLabel>
            <Select
              value={purpose}
              onChange={(e) => handleFieldChange('purpose', e.target.value)}
              label="Purpose"
            >
              <MenuItem value="credential_issuance">Credential Issuance</MenuItem>
              <MenuItem value="identity_verification">Identity Verification</MenuItem>
              <MenuItem value="access_control">Access Control</MenuItem>
              <MenuItem value="combined">Combined (Verify & Issue)</MenuItem>
            </Select>
          </FormControl>

          <TextField
            fullWidth
            label="Audience"
            value={audience}
            onChange={(e) => handleFieldChange('audience', e.target.value)}
            sx={{ mb: 2 }}
            helperText="Who will use this flow? (e.g., Applicants, Partners, Internal Staff)"
            placeholder="e.g., Applicants, Partners, Internal"
          />

          <TextField
            fullWidth
            label="Deployment Targets"
            value={deploymentTargets.join(', ')}
            onChange={(e) => handleFieldChange('deploymentTargets', e.target.value.split(',').map(t => t.trim()).filter(Boolean))}
            helperText="Comma-separated deployment environments (e.g., production, staging)"
            placeholder="e.g., production, staging, development"
          />
        </CardContent>
      </Card>

      {/* Flow Steps */}
      <Card>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
            <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
              Flow Steps
            </Typography>
            <Box sx={{ display: 'flex', gap: 1 }}>
              {presets.length > 0 && (
                <Button
                  startIcon={<PresetIcon />}
                  onClick={(e) => setPresetMenuAnchor(e.currentTarget)}
                  variant="outlined"
                  size="small"
                >
                  Use Preset
                </Button>
              )}
              <Button
                startIcon={<AddIcon />}
                onClick={handleAddStep}
                variant="contained"
                size="small"
              >
                Add Step
              </Button>
            </Box>
          </Box>

          {/* Preset Menu */}
          <Menu
            anchorEl={presetMenuAnchor}
            open={Boolean(presetMenuAnchor)}
            onClose={() => setPresetMenuAnchor(null)}
          >
            {presets.map((preset, idx) => (
              <MenuItem key={idx} onClick={() => handleApplyPreset(preset)}>
                {preset.name}
              </MenuItem>
            ))}
          </Menu>

          {flowSteps.length === 0 && (
            <Alert severity="info">
              Add flow steps or use a preset template to get started
            </Alert>
          )}

          {flowSteps.length > 0 && (
            <List>
              {flowSteps.map((step, index) => (
                <ListItem
                  key={index}
                  sx={{
                    border: 1,
                    borderColor: 'divider',
                    mb: 1,
                    borderRadius: 1,
                    bgcolor: 'background.paper',
                  }}
                >
                  <DragIndicatorIcon sx={{ mr: 1, color: 'text.secondary', cursor: 'grab' }} />
                  
                  <ListItemText
                    primary={
                      <TextField
                        fullWidth
                        value={step.name}
                        onChange={(e) => handleStepChange(index, 'name', e.target.value)}
                        variant="standard"
                        placeholder="Step name"
                        size="small"
                      />
                    }
                    secondary={
                      <Chip
                        label={step.type}
                        size="small"
                        sx={{ mt: 0.5 }}
                      />
                    }
                  />

                  <ListItemSecondaryAction>
                    <IconButton
                      size="small"
                      onClick={() => handleMoveStep(index, 'up')}
                      disabled={index === 0}
                    >
                      ▲
                    </IconButton>
                    <IconButton
                      size="small"
                      onClick={() => handleMoveStep(index, 'down')}
                      disabled={index === flowSteps.length - 1}
                    >
                      ▼
                    </IconButton>
                    <IconButton
                      size="small"
                      onClick={() => handleRemoveStep(index)}
                      color="error"
                    >
                      <DeleteIcon />
                    </IconButton>
                  </ListItemSecondaryAction>
                </ListItem>
              ))}
            </List>
          )}
        </CardContent>
      </Card>
    </Box>
  );
};

export default FlowStepsConfigStep;
