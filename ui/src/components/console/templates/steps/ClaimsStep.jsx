/**
 * Claims Step - Credential Template Wizard
 * 
 * Define the structure of the credential: what claims it contains.
 * Claims can be reordered and marked as required or optional.
 */

import { useState } from 'react';
import {
  Box,
  Typography,
  TextField,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  List,
  ListItem,
  ListItemText,
  IconButton,
  Checkbox,
  FormControlLabel,
  Chip,
  Alert,
  Paper,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import DeleteIcon from '@mui/icons-material/Delete';
import DragHandleIcon from '@mui/icons-material/DragHandle';
import InfoIcon from '@mui/icons-material/Info';

const CLAIM_TYPES = [
  { value: 'string', label: 'Text (string)' },
  { value: 'number', label: 'Number' },
  { value: 'integer', label: 'Integer' },
  { value: 'boolean', label: 'True/False (boolean)' },
  { value: 'date', label: 'Date' },
  { value: 'datetime', label: 'Date & Time' },
  { value: 'object', label: 'Object (nested)' },
  { value: 'array', label: 'Array (list)' },
];

const CLAIM_PRESETS = {
  identity: [
    { name: 'given_name', type: 'string', required: true },
    { name: 'family_name', type: 'string', required: true },
    { name: 'birth_date', type: 'date', required: true },
    { name: 'email', type: 'string', required: false },
    { name: 'phone_number', type: 'string', required: false },
  ],
  age: [
    { name: 'birth_date', type: 'date', required: true },
    { name: 'age_over_18', type: 'boolean', required: true },
    { name: 'age_over_21', type: 'boolean', required: false },
  ],
  employee: [
    { name: 'employee_id', type: 'string', required: true },
    { name: 'given_name', type: 'string', required: true },
    { name: 'family_name', type: 'string', required: true },
    { name: 'department', type: 'string', required: true },
    { name: 'position', type: 'string', required: true },
    { name: 'start_date', type: 'date', required: true },
  ],
};

const ClaimsStep = ({ data, onChange }) => {
  const [newClaimName, setNewClaimName] = useState('');
  const [newClaimType, setNewClaimType] = useState('string');
  const [newClaimRequired, setNewClaimRequired] = useState(true);

  const handleApplyPreset = (presetKey) => {
    const preset = CLAIM_PRESETS[presetKey];
    if (!preset) return;

    onChange({ claims: [...preset] });
  };

  const handleAddClaim = () => {
    if (!newClaimName.trim()) return;

    const claims = [...(data.claims || [])];
    
    // Check for duplicates
    if (claims.some((claim) => claim.name === newClaimName.trim())) {
      return;
    }

    claims.push({
      name: newClaimName.trim(),
      type: newClaimType,
      required: newClaimRequired,
    });

    onChange({ claims });
    setNewClaimName('');
    setNewClaimType('string');
    setNewClaimRequired(true);
  };

  const handleRemoveClaim = (index) => {
    const claims = [...(data.claims || [])];
    claims.splice(index, 1);
    onChange({ claims });
  };

  const handleToggleRequired = (index) => {
    const claims = [...(data.claims || [])];
    claims[index].required = !claims[index].required;
    onChange({ claims });
  };

  const handleMoveClaim = (index, direction) => {
    const claims = [...(data.claims || [])];
    const newIndex = direction === 'up' ? index - 1 : index + 1;
    
    if (newIndex < 0 || newIndex >= claims.length) return;
    
    [claims[index], claims[newIndex]] = [claims[newIndex], claims[index]];
    onChange({ claims });
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleAddClaim();
    }
  };

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Define Claims
      </Typography>
      <Typography color="text.secondary" paragraph>
        Specify what information (claims) this credential contains.
      </Typography>

      <Alert severity="info" sx={{ mb: 3 }} icon={<InfoIcon />}>
        Claims are the individual pieces of information in the credential (e.g., &quot;family_name&quot;, &quot;birth_date&quot;, &quot;license_number&quot;).
      </Alert>

      {/* Claim Presets */}
      <Box sx={{ mb: 3 }}>
        <Typography variant="subtitle2" gutterBottom>
          Quick Start Templates
        </Typography>
        <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 1 }}>
          Choose a preset to auto-populate common claim structures
        </Typography>
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
          <Button
            variant="outlined"
            size="small"
            onClick={() => handleApplyPreset('identity')}
          >
            Identity Profile
          </Button>
          <Button
            variant="outlined"
            size="small"
            onClick={() => handleApplyPreset('age')}
          >
            Age Verification
          </Button>
          <Button
            variant="outlined"
            size="small"
            onClick={() => handleApplyPreset('employee')}
          >
            Employee Badge
          </Button>
        </Box>
      </Box>

      {/* Add Claim Form */}
      <Paper sx={{ p: 2, mb: 3, bgcolor: 'action.hover' }}>
        <Typography variant="subtitle2" gutterBottom>
          Add Claim
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'flex-start' }}>
          <TextField
            label="Claim Name"
            placeholder="given_name"
            value={newClaimName}
            onChange={(e) => setNewClaimName(e.target.value)}
            onKeyPress={handleKeyPress}
            sx={{ flex: 2 }}
            size="small"
          />
          <FormControl sx={{ flex: 1 }} size="small">
            <InputLabel>Type</InputLabel>
            <Select
              value={newClaimType}
              onChange={(e) => setNewClaimType(e.target.value)}
              label="Type"
            >
              {CLAIM_TYPES.map((type) => (
                <MenuItem key={type.value} value={type.value}>
                  {type.label}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <FormControlLabel
            control={
              <Checkbox
                checked={newClaimRequired}
                onChange={(e) => setNewClaimRequired(e.target.checked)}
                size="small"
              />
            }
            label="Required"
          />
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={handleAddClaim}
            disabled={!newClaimName.trim()}
          >
            Add
          </Button>
        </Box>
      </Paper>

      {/* Claims List */}
      {data.claims && data.claims.length > 0 ? (
        <Box>
          <Typography variant="subtitle2" gutterBottom>
            Claims ({data.claims.length})
          </Typography>
          <List>
            {data.claims.map((claim, index) => (
              <ListItem
                key={index}
                sx={{
                  bgcolor: 'background.paper',
                  mb: 1,
                  borderRadius: 1,
                  border: '1px solid',
                  borderColor: 'divider',
                }}
                secondaryAction={
                  <IconButton
                    edge="end"
                    onClick={() => handleRemoveClaim(index)}
                    color="error"
                  >
                    <DeleteIcon />
                  </IconButton>
                }
              >
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5, mr: 2 }}>
                  <IconButton
                    size="small"
                    onClick={() => handleMoveClaim(index, 'up')}
                    disabled={index === 0}
                  >
                    ▲
                  </IconButton>
                  <DragHandleIcon color="action" />
                  <IconButton
                    size="small"
                    onClick={() => handleMoveClaim(index, 'down')}
                    disabled={index === data.claims.length - 1}
                  >
                    ▼
                  </IconButton>
                </Box>
                <ListItemText
                  primary={
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Typography
                        variant="body1"
                        sx={{ fontFamily: 'monospace', fontWeight: 'medium' }}
                      >
                        {claim.name}
                      </Typography>
                      <Chip label={claim.type} size="small" />
                      {claim.required && (
                        <Chip label="Required" size="small" color="primary" />
                      )}
                    </Box>
                  }
                />
                <Checkbox
                  checked={claim.required}
                  onChange={() => handleToggleRequired(index)}
                  edge="end"
                />
              </ListItem>
            ))}
          </List>
        </Box>
      ) : (
        <Box
          sx={{
            p: 4,
            textAlign: 'center',
            border: '2px dashed',
            borderColor: 'divider',
            borderRadius: 1,
          }}
        >
          <Typography color="text.secondary">
            No claims defined yet. Add claims above to define the credential structure.
          </Typography>
        </Box>
      )}
    </Box>
  );
};

export default ClaimsStep;
