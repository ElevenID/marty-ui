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
import { useTranslation } from 'react-i18next';

const getClaimTypes = (t) => [
  { value: 'string', label: t('wizards.credentialTemplate.claimsStep.claimTypeLabels.string') },
  { value: 'number', label: t('wizards.credentialTemplate.claimsStep.claimTypeLabels.number') },
  { value: 'integer', label: t('wizards.credentialTemplate.claimsStep.claimTypeLabels.integer') },
  { value: 'boolean', label: t('wizards.credentialTemplate.claimsStep.claimTypeLabels.boolean') },
  { value: 'date', label: t('wizards.credentialTemplate.claimsStep.claimTypeLabels.date') },
  { value: 'datetime', label: t('wizards.credentialTemplate.claimsStep.claimTypeLabels.datetime') },
  { value: 'object', label: t('wizards.credentialTemplate.claimsStep.claimTypeLabels.object') },
  { value: 'array', label: t('wizards.credentialTemplate.claimsStep.claimTypeLabels.array') },
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
  const { t } = useTranslation('console');
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
        {t('wizards.credentialTemplate.claimsStep.title')}
      </Typography>
      <Typography color="text.secondary" paragraph>
        {t('wizards.credentialTemplate.claimsStep.description')}
      </Typography>

      <Alert severity="info" sx={{ mb: 3 }} icon={<InfoIcon />}>
        {t('wizards.credentialTemplate.claimsStep.info')}
      </Alert>

      {/* Claim Presets */}
      <Box sx={{ mb: 3 }}>
        <Typography variant="subtitle2" gutterBottom>
          {t('wizards.credentialTemplate.claimsStep.quickStart.title')}
        </Typography>
        <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 1 }}>
          {t('wizards.credentialTemplate.claimsStep.quickStart.description')}
        </Typography>
        <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
          <Button
            variant="outlined"
            size="small"
            onClick={() => handleApplyPreset('identity')}
          >
            {t('wizards.credentialTemplate.claimsStep.quickStart.identity')}
          </Button>
          <Button
            variant="outlined"
            size="small"
            onClick={() => handleApplyPreset('age')}
          >
            {t('wizards.credentialTemplate.claimsStep.quickStart.age')}
          </Button>
          <Button
            variant="outlined"
            size="small"
            onClick={() => handleApplyPreset('employee')}
          >
            {t('wizards.credentialTemplate.claimsStep.quickStart.employee')}
          </Button>
        </Box>
      </Box>

      {/* Add Claim Form */}
      <Paper sx={{ p: 2, mb: 3, bgcolor: 'action.hover' }}>
        <Typography variant="subtitle2" gutterBottom>
          {t('wizards.credentialTemplate.claimsStep.addClaim.title')}
        </Typography>
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'flex-start' }}>
          <TextField
            label={t('wizards.credentialTemplate.claimsStep.addClaim.nameLabel')}
            placeholder={t('wizards.credentialTemplate.claimsStep.addClaim.namePlaceholder')}
            value={newClaimName}
            onChange={(e) => setNewClaimName(e.target.value)}
            onKeyPress={handleKeyPress}
            sx={{ flex: 2 }}
            size="small"
          />
          <FormControl sx={{ flex: 1 }} size="small">
            <InputLabel>{t('wizards.credentialTemplate.claimsStep.addClaim.typeLabel')}</InputLabel>
            <Select
              value={newClaimType}
              onChange={(e) => setNewClaimType(e.target.value)}
              label={t('wizards.credentialTemplate.claimsStep.addClaim.typeLabel')}
            >
              {getClaimTypes(t).map((type) => (
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
            label={t('wizards.credentialTemplate.claimsStep.addClaim.requiredLabel')}
          />
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={handleAddClaim}
            disabled={!newClaimName.trim()}
          >
            {t('wizards.credentialTemplate.claimsStep.addClaim.addButton')}
          </Button>
        </Box>
      </Paper>

      {/* Claims List */}
      {data.claims && data.claims.length > 0 ? (
        <Box>
          <Typography variant="subtitle2" gutterBottom>
            {t('wizards.credentialTemplate.claimsStep.claimsTitle', { count: data.claims.length })}
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
                        <Chip
                          label={t('wizards.credentialTemplate.claimsStep.addClaim.requiredLabel')}
                          size="small"
                          color="primary"
                        />
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
            {t('wizards.credentialTemplate.claimsStep.emptyState')}
          </Typography>
        </Box>
      )}
    </Box>
  );
};

export default ClaimsStep;
